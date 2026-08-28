"""PresenceWriter - projects ``presence_set`` events into ``presence.jsonl``.

Identity Presence consolidation writer.
The PresenceWriter is a long-lived :class:`alter_runtime.daemon.Component`
that subscribes to the in-process :class:`EventBus` ``identity.event`` topic,
filters frames whose payload ``kind`` equals ``"presence_set"``, and atomically
appends one compact JSON object per line to
``$XDG_DATA_HOME/alter-runtime/presence.jsonl``.

The record shape is fixed by the bundled presence schema:

* ``id``, ``version``, ``kind`` (``"presence_set"``), ``handle``, ``state``
  (``here|focus|open|quiet``), ``provenance_class`` (``active_declaration``),
  ``consent_tier``, ``set_at``, ``set_via`` are required.
* ``expires_at`` and ``supersedes_id`` are optional.

Dedupe key is ``(id, version)``: a higher ``version`` for the same ``id``
supersedes - the writer keeps the latest non-superseded checkpoint per id
in ``$XDG_STATE_HOME/alter-runtime/presence.json``.

Like :class:`InboxWriter`, the writer:

* writes mode ``0o600`` files under parent dir mode ``0o700`` (relies on the
  daemon ``UMask=0077``);
* rotates the JSONL to ``presence.jsonl.1`` once the file exceeds 10 MiB;
* swallows and logs all errors so a single malformed event, full disk, or
  permission failure cannot crash the daemon supervisor.

Data handling: every record carries ``provenance_class`` +
``consent_tier`` per the schema - presence states are always
``active_declaration`` (user explicitly emits the state).
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import fcntl
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from alter_runtime.config import DaemonConfig, data_dir, runtime_state_dir
from alter_runtime.daemon import Component

if TYPE_CHECKING:
    from alter_runtime.subscribers.bus import EventBus

__all__ = [
    "PRESENCE_FILENAME",
    "PRESENCE_ROTATED_FILENAME",
    "PRESENCE_STATE_FILENAME",
    "ROTATION_THRESHOLD_BYTES",
    "PresenceWriter",
]

logger = logging.getLogger("alter_runtime.subscribers.presence_writer")

#: Rotate the JSONL file once it exceeds this many bytes (10 MiB, matching
#: :mod:`inbox_writer`).
ROTATION_THRESHOLD_BYTES: int = 10 * 1024 * 1024

#: Filename for the presence JSONL (within ``data_dir()``).
PRESENCE_FILENAME: str = "presence.jsonl"

#: Filename for the rotated tail (single generation).
PRESENCE_ROTATED_FILENAME: str = "presence.jsonl.1"

#: Filename for the dedup checkpoint sidecar (within ``runtime_state_dir()``).
PRESENCE_STATE_FILENAME: str = "presence.json"

#: Schema enums - kept in sync with the bundled presence schema.
_VALID_STATES: frozenset[str] = frozenset({"here", "focus", "open", "quiet"})
_VALID_SET_VIA: frozenset[str] = frozenset(
    {"alter-cli", "widget", "cc", "codex", "cursor", "android", "obsidian"}
)


class PresenceWriter(Component):
    """Subscribes to ``identity.event`` and projects ``presence_set`` events.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig` (reserved for future knobs).
    bus:
        Shared :class:`EventBus`. The writer subscribes to ``identity.event``
        in :meth:`run` and unsubscribes on :meth:`stop`.
    rotation_threshold_bytes:
        Override the rotation threshold (defaults to 10 MiB). Tests use a
        small value to exercise the rotation path.
    presence_path:
        Override the JSONL path. Tests redirect writes to ``tmp_path``.
    state_path:
        Override the checkpoint path.
    """

    name = "presence_writer"

    def __init__(
        self,
        config: DaemonConfig,
        bus: EventBus,
        *,
        rotation_threshold_bytes: int = ROTATION_THRESHOLD_BYTES,
        presence_path: Path | None = None,
        state_path: Path | None = None,
    ) -> None:
        self._config = config
        self._bus = bus
        self._rotation_threshold_bytes = rotation_threshold_bytes

        self._presence_path: Path = (
            presence_path if presence_path is not None else data_dir() / PRESENCE_FILENAME
        )
        self._state_path: Path = (
            state_path if state_path is not None else runtime_state_dir() / PRESENCE_STATE_FILENAME
        )

        self._lock = asyncio.Lock()
        # Dedup checkpoint: maps record ``id`` -> highest seen ``version``.
        self._seen_versions: dict[str, int] = {}
        self._shutdown_event = asyncio.Event()

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        await self._load_checkpoint()
        self._bus.subscribe("identity.event", self.handle_event)
        logger.info(
            "presence_writer started presence=%s known_ids=%d",
            self._presence_path,
            len(self._seen_versions),
        )
        try:
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            raise
        finally:
            with contextlib.suppress(Exception):
                self._bus.unsubscribe("identity.event", self.handle_event)
            logger.info("presence_writer stopped")

    async def stop(self) -> None:
        """Cooperative shutdown - release the run loop."""
        self._shutdown_event.set()

    # ------------------------------------------------------------------
    # Event ingest - public surface (also called directly by tests)
    # ------------------------------------------------------------------

    async def handle_event(self, event: dict[str, Any]) -> None:
        """Project a single bus event dict into ``presence.jsonl``.

        The bus delivers ``identity.event`` payloads in either the canonical
        envelope (``kind`` at top-level) or the egress wrapper used by local
        adapters (``{"kind": ..., "payload": {...}}``). Both shapes are
        accepted.
        """
        if not isinstance(event, dict):
            return

        # ---- 1. Filter on kind ---------------------------------------
        if event.get("kind") != "presence_set":
            return

        # ---- 2. Build the record ------------------------------------
        record = self._serialise(event)
        if record is None:
            return  # already logged

        record_id = record["id"]
        record_version = record["version"]

        async with self._lock:
            # ---- 3. Deduplicate on (id, version) ---------------------
            prior = self._seen_versions.get(record_id)
            if prior is not None and record_version <= prior:
                logger.debug(
                    "presence_writer: dedupe drop id=%s version=%d <= seen=%d",
                    record_id,
                    record_version,
                    prior,
                )
                return

            line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)

            # ---- 4. Rotate if oversized ------------------------------
            try:
                self._maybe_rotate()
            except OSError as exc:
                logger.warning("presence_writer: rotation failed: %s", exc)

            # ---- 5. Atomic append + fsync ----------------------------
            try:
                self._append_line(line)
            except OSError as exc:
                logger.warning("presence_writer: append failed: %s - dropping event", exc)
                return

            # ---- 6. Advance + persist checkpoint --------------------
            self._seen_versions[record_id] = record_version
            try:
                self._save_checkpoint()
            except OSError as exc:
                logger.warning("presence_writer: checkpoint save failed: %s", exc)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def _serialise(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Build the JSONL record for one ``presence_set`` event.

        Returns ``None`` if a required field is missing or invalid - caller
        treats that as "drop and continue".
        """
        # Tolerate both the canonical top-level envelope and the local-adapter
        # ``{"kind": ..., "payload": {...}}`` wrapper.
        body = event.get("payload") if isinstance(event.get("payload"), dict) else event

        record_id = event.get("id") or body.get("id")
        version_raw = event.get("version") if "version" in event else body.get("version")
        handle = body.get("handle") or event.get("handle")
        state = body.get("state")
        provenance_class = body.get("provenance_class", "active_declaration")
        consent_tier_raw = body.get("consent_tier")
        set_at = (
            body.get("set_at") or event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        )
        set_via = body.get("set_via")
        expires_at = body.get("expires_at")
        supersedes_id = body.get("supersedes_id")

        try:
            version_int = int(version_raw) if version_raw is not None else None
        except (TypeError, ValueError):
            logger.warning("presence_writer: non-integer version=%r - dropping", version_raw)
            return None
        if version_int is None or version_int < 0:
            logger.warning("presence_writer: missing/negative version - dropping id=%r", record_id)
            return None

        if not record_id or not isinstance(record_id, str):
            logger.warning("presence_writer: missing id - dropping event")
            return None
        if not handle or not isinstance(handle, str):
            logger.warning("presence_writer: missing handle - dropping id=%s", record_id)
            return None
        if state not in _VALID_STATES:
            logger.warning("presence_writer: invalid state=%r - dropping id=%s", state, record_id)
            return None
        if set_via not in _VALID_SET_VIA:
            logger.warning(
                "presence_writer: invalid set_via=%r - dropping id=%s", set_via, record_id
            )
            return None

        try:
            consent_tier_int = int(consent_tier_raw) if consent_tier_raw is not None else None
        except (TypeError, ValueError):
            consent_tier_int = None
        if consent_tier_int not in (1, 2, 3, 4):
            logger.warning(
                "presence_writer: invalid consent_tier=%r - dropping id=%s",
                consent_tier_raw,
                record_id,
            )
            return None

        record: dict[str, Any] = {
            "id": str(record_id),
            "version": version_int,
            "kind": "presence_set",
            "handle": str(handle),
            "state": str(state),
            "provenance_class": "active_declaration",
            "consent_tier": consent_tier_int,
            "set_at": str(set_at),
            "set_via": str(set_via),
        }
        # Optional fields - emit explicitly (including null) so consumers
        # don't have to .get with a default; the schema allows ``null``.
        if expires_at is not None:
            record["expires_at"] = str(expires_at) if expires_at else None
        if supersedes_id is not None:
            record["supersedes_id"] = str(supersedes_id) if supersedes_id else None

        # Ignore caller-supplied provenance_class - the schema locks it to
        # ``active_declaration`` for this kind.
        _ = provenance_class
        return record

    # ------------------------------------------------------------------
    # File operations - atomic append, rotation, checkpoint
    # ------------------------------------------------------------------

    def _ensure_parent(self, path: Path) -> None:
        parent = path.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            os.chmod(parent, 0o700)

    def _append_line(self, line: str) -> None:
        self._ensure_parent(self._presence_path)

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(self._presence_path, flags, 0o600)
        try:
            with contextlib.suppress(OSError):
                os.fchmod(fd, 0o600)

            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError as exc:  # pragma: no cover - exotic FS
                if exc.errno not in (errno.ENOTSUP, errno.EINVAL):
                    raise

            try:
                os.write(fd, line.encode("utf-8") + b"\n")
                os.fsync(fd)
            finally:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _maybe_rotate(self) -> None:
        try:
            size = self._presence_path.stat().st_size
        except FileNotFoundError:
            return
        if size <= self._rotation_threshold_bytes:
            return

        rotated = self._presence_path.parent / PRESENCE_ROTATED_FILENAME
        os.replace(self._presence_path, rotated)
        logger.info(
            "presence_writer: rotated %s -> %s (size=%d > threshold=%d)",
            self._presence_path,
            rotated,
            size,
            self._rotation_threshold_bytes,
        )

    # ------------------------------------------------------------------
    # Checkpoint persistence
    # ------------------------------------------------------------------

    async def _load_checkpoint(self) -> None:
        """Load the per-id version map from ``presence.json`` (empty if absent)."""
        if not self._state_path.exists():
            self._seen_versions = {}
            return
        try:
            raw = self._state_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning(
                "presence_writer: unable to load checkpoint at %s: %s - starting empty",
                self._state_path,
                exc,
            )
            self._seen_versions = {}
            return
        if not isinstance(data, dict):
            self._seen_versions = {}
            return
        seen = data.get("seen_versions")
        if not isinstance(seen, dict):
            self._seen_versions = {}
            return
        cleaned: dict[str, int] = {}
        for key, value in seen.items():
            try:
                cleaned[str(key)] = int(value)
            except (TypeError, ValueError):
                continue
        self._seen_versions = cleaned

    def _save_checkpoint(self) -> None:
        """Atomically write the per-id version map via tmp + ``os.replace``."""
        self._ensure_parent(self._state_path)
        payload = {
            "seen_versions": dict(self._seen_versions),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        tmp_path = self._state_path.with_suffix(self._state_path.suffix + ".tmp")

        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(tmp_path, flags, 0o600)
        try:
            with contextlib.suppress(OSError):
                os.fchmod(fd, 0o600)
            os.write(fd, json.dumps(payload, separators=(",", ":")).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

        os.replace(tmp_path, self._state_path)
        with contextlib.suppress(OSError):
            os.chmod(self._state_path, 0o600)

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def presence_path(self) -> Path:
        return self._presence_path

    @property
    def state_path(self) -> Path:
        return self._state_path

    @property
    def seen_versions(self) -> dict[str, int]:
        return dict(self._seen_versions)
