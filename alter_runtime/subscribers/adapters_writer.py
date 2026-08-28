"""AdaptersWriter - projects ``adapter_status`` events into ``adapters.jsonl``.

Tracks adapter status for the Obsidian and eBPF adapters. Records when an
adapter is paired, actively streaming, or in error. Latest record per
``adapter`` is the current state; ``status=error`` surfaces an alert tile
in the widget.

Sources
-------

The writer subscribes to two bus topics:

* ``identity.event`` - for ``adapter_status`` frames flowing in from the DO SSE
  ingress (e.g. server-side declarations of pairing state).
* ``local.signal`` - for the *local adapter* pattern used by
  :mod:`alter_runtime.adapters.git_watcher` and its successors. Local
  adapters publish ``{"kind": "adapter_status", "payload": {...},
  "source": "<adapter_name>"}`` onto the egress topic; this writer
  projects those into the same JSONL so the widget sees one merged
  stream regardless of provenance.

The record shape is fixed by the bundled adapter schema. Allowed adapters
are ``obsidian | ebpf``; other client surfaces are recorded in
``active-sessions.jsonl``, not here.

Data handling: every record carries ``provenance_class`` +
``consent_tier`` per the schema. The schema enumerates which
``provenance_class`` values are valid for each adapter (obsidian =
``passive_local_document``; ebpf = ``passive_individual_local_only``,
which stays local-only).
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
    "ADAPTERS_FILENAME",
    "ADAPTERS_ROTATED_FILENAME",
    "ADAPTERS_STATE_FILENAME",
    "ROTATION_THRESHOLD_BYTES",
    "AdaptersWriter",
]

logger = logging.getLogger("alter_runtime.subscribers.adapters_writer")

#: Rotate the JSONL file once it exceeds this many bytes (10 MiB).
ROTATION_THRESHOLD_BYTES: int = 10 * 1024 * 1024

#: Filename for the adapters JSONL (within ``data_dir()``).
ADAPTERS_FILENAME: str = "adapters.jsonl"

#: Filename for the rotated tail (single generation).
ADAPTERS_ROTATED_FILENAME: str = "adapters.jsonl.1"

#: Filename for the dedup checkpoint sidecar (within ``runtime_state_dir()``).
ADAPTERS_STATE_FILENAME: str = "adapters.json"

#: Schema enums - kept in sync with the bundled adapters schema.
_VALID_ADAPTERS: frozenset[str] = frozenset({"obsidian", "ebpf"})
_VALID_STATES: frozenset[str] = frozenset({"paired", "streaming", "attached", "idle", "error"})
_VALID_PROVENANCE: frozenset[str] = frozenset(
    {"passive_local_document", "passive_individual_local_only", "active_declaration"}
)


class AdaptersWriter(Component):
    """Subscribes to ``identity.event`` + ``local.signal`` and projects
    adapter status records.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`.
    bus:
        Shared :class:`EventBus`.
    rotation_threshold_bytes:
        Override the rotation threshold (defaults to 10 MiB).
    adapters_path:
        Override the JSONL path. Tests redirect writes to ``tmp_path``.
    state_path:
        Override the checkpoint path.
    """

    name = "adapters_writer"

    def __init__(
        self,
        config: DaemonConfig,
        bus: EventBus,
        *,
        rotation_threshold_bytes: int = ROTATION_THRESHOLD_BYTES,
        adapters_path: Path | None = None,
        state_path: Path | None = None,
    ) -> None:
        self._config = config
        self._bus = bus
        self._rotation_threshold_bytes = rotation_threshold_bytes

        self._adapters_path: Path = (
            adapters_path if adapters_path is not None else data_dir() / ADAPTERS_FILENAME
        )
        self._state_path: Path = (
            state_path if state_path is not None else runtime_state_dir() / ADAPTERS_STATE_FILENAME
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
        self._bus.subscribe("local.signal", self.handle_event)
        logger.info(
            "adapters_writer started adapters=%s known_ids=%d",
            self._adapters_path,
            len(self._seen_versions),
        )
        try:
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            raise
        finally:
            with contextlib.suppress(Exception):
                self._bus.unsubscribe("identity.event", self.handle_event)
            with contextlib.suppress(Exception):
                self._bus.unsubscribe("local.signal", self.handle_event)
            logger.info("adapters_writer stopped")

    async def stop(self) -> None:
        self._shutdown_event.set()

    # ------------------------------------------------------------------
    # Event ingest
    # ------------------------------------------------------------------

    async def handle_event(self, event: dict[str, Any]) -> None:
        """Project a single bus event dict into ``adapters.jsonl``.

        Accepts both the canonical envelope (``identity.event`` shape) and
        the local-adapter wrapper (``local.signal``: ``{"kind": ...,
        "payload": {...}, "source": ...}``).
        """
        if not isinstance(event, dict):
            return

        if event.get("kind") != "adapter_status":
            return

        record = self._serialise(event)
        if record is None:
            return

        record_id = record["id"]
        record_version = record["version"]

        async with self._lock:
            prior = self._seen_versions.get(record_id)
            if prior is not None and record_version <= prior:
                logger.debug(
                    "adapters_writer: dedupe drop id=%s version=%d <= seen=%d",
                    record_id,
                    record_version,
                    prior,
                )
                return

            line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)

            try:
                self._maybe_rotate()
            except OSError as exc:
                logger.warning("adapters_writer: rotation failed: %s", exc)

            try:
                self._append_line(line)
            except OSError as exc:
                logger.warning("adapters_writer: append failed: %s - dropping event", exc)
                return

            self._seen_versions[record_id] = record_version
            try:
                self._save_checkpoint()
            except OSError as exc:
                logger.warning("adapters_writer: checkpoint save failed: %s", exc)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def _serialise(self, event: dict[str, Any]) -> dict[str, Any] | None:
        body = event.get("payload") if isinstance(event.get("payload"), dict) else event

        record_id = event.get("id") or body.get("id")
        version_raw = event.get("version") if "version" in event else body.get("version")
        handle = body.get("handle") or event.get("handle")
        adapter = body.get("adapter")
        stream_subtag = body.get("stream_subtag")
        state = body.get("state")
        provenance_class = body.get("provenance_class")
        consent_tier_raw = body.get("consent_tier")
        last_event_at = (
            body.get("last_event_at")
            or event.get("timestamp")
            or datetime.now(timezone.utc).isoformat()
        )
        error_msg = body.get("error_msg")

        try:
            version_int = int(version_raw) if version_raw is not None else None
        except (TypeError, ValueError):
            logger.warning("adapters_writer: non-integer version=%r - dropping", version_raw)
            return None
        if version_int is None or version_int < 0:
            logger.warning("adapters_writer: missing/negative version - dropping id=%r", record_id)
            return None

        if not record_id or not isinstance(record_id, str):
            logger.warning("adapters_writer: missing id - dropping event")
            return None
        if not handle or not isinstance(handle, str):
            logger.warning("adapters_writer: missing handle - dropping id=%s", record_id)
            return None
        if adapter not in _VALID_ADAPTERS:
            logger.warning(
                "adapters_writer: invalid adapter=%r - dropping id=%s",
                adapter,
                record_id,
            )
            return None
        if state not in _VALID_STATES:
            logger.warning("adapters_writer: invalid state=%r - dropping id=%s", state, record_id)
            return None
        if provenance_class not in _VALID_PROVENANCE:
            logger.warning(
                "adapters_writer: invalid provenance_class=%r - dropping id=%s",
                provenance_class,
                record_id,
            )
            return None

        try:
            consent_tier_int = int(consent_tier_raw) if consent_tier_raw is not None else None
        except (TypeError, ValueError):
            consent_tier_int = None
        if consent_tier_int not in (1, 2, 3, 4):
            logger.warning(
                "adapters_writer: invalid consent_tier=%r - dropping id=%s",
                consent_tier_raw,
                record_id,
            )
            return None

        record: dict[str, Any] = {
            "id": str(record_id),
            "version": version_int,
            "kind": "adapter_status",
            "handle": str(handle),
            "adapter": str(adapter),
            "state": str(state),
            "provenance_class": str(provenance_class),
            "consent_tier": consent_tier_int,
            "last_event_at": str(last_event_at),
        }
        if stream_subtag is not None:
            record["stream_subtag"] = str(stream_subtag) if stream_subtag else None
        if error_msg is not None:
            record["error_msg"] = str(error_msg) if error_msg else None
        return record

    # ------------------------------------------------------------------
    # File operations
    # ------------------------------------------------------------------

    def _ensure_parent(self, path: Path) -> None:
        parent = path.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            os.chmod(parent, 0o700)

    def _append_line(self, line: str) -> None:
        self._ensure_parent(self._adapters_path)

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(self._adapters_path, flags, 0o600)
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
            size = self._adapters_path.stat().st_size
        except FileNotFoundError:
            return
        if size <= self._rotation_threshold_bytes:
            return

        rotated = self._adapters_path.parent / ADAPTERS_ROTATED_FILENAME
        os.replace(self._adapters_path, rotated)
        logger.info(
            "adapters_writer: rotated %s -> %s (size=%d > threshold=%d)",
            self._adapters_path,
            rotated,
            size,
            self._rotation_threshold_bytes,
        )

    # ------------------------------------------------------------------
    # Checkpoint persistence
    # ------------------------------------------------------------------

    async def _load_checkpoint(self) -> None:
        if not self._state_path.exists():
            self._seen_versions = {}
            return
        try:
            raw = self._state_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning(
                "adapters_writer: unable to load checkpoint at %s: %s - starting empty",
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
    def adapters_path(self) -> Path:
        return self._adapters_path

    @property
    def state_path(self) -> Path:
        return self._state_path

    @property
    def seen_versions(self) -> dict[str, int]:
        return dict(self._seen_versions)
