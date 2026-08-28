"""ActiveSessionsWriter - projects session lifecycle events into JSONL.

DISTINCTION FROM ``SessionPresenceWriter`` (``session_presence.py``)
-------------------------------------------------------------------

* ``SessionPresenceWriter`` writes ``~/.local/share/org-alter/state/sessions.json``
  - a *server projection*. It polls the server presence endpoint and persists
  the aggregated cross-host view read by the shell awareness hook.
* ``ActiveSessionsWriter`` (this module) writes
  ``~/.local/share/alter-runtime/active-sessions.jsonl`` - a stream of
  *local-observed events*. It consumes ``session_started`` /
  ``session_heartbeat`` / ``session_ended`` payloads from the in-process
  EventBus (sourced from DO SSE or local adapters) and appends them
  append-only.

Both surfaces coexist. The server projection is the cross-host truth;
the JSONL is the per-host raw event log. Readers dedup on
``(tool, session_id)`` keeping the newest ``last_activity``; ``status=complete``
is the tombstone (the record shape is fixed by the bundled schema).

These tool-neutral active-session events are emitted by every supported
client on session start, heartbeat, and end.

Data handling: every record carries ``provenance_class`` +
``consent_tier`` per the schema - sessions are always
``active_composition`` (user is actively driving the tool).
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
    "ACTIVE_SESSIONS_FILENAME",
    "ACTIVE_SESSIONS_ROTATED_FILENAME",
    "ACTIVE_SESSIONS_STATE_FILENAME",
    "ROTATION_THRESHOLD_BYTES",
    "ActiveSessionsWriter",
]

logger = logging.getLogger("alter_runtime.subscribers.active_sessions_writer")

#: Rotate the JSONL file once it exceeds this many bytes (10 MiB).
ROTATION_THRESHOLD_BYTES: int = 10 * 1024 * 1024

#: Filename for the active-sessions JSONL (within ``data_dir()``).
ACTIVE_SESSIONS_FILENAME: str = "active-sessions.jsonl"

#: Filename for the rotated tail (single generation).
ACTIVE_SESSIONS_ROTATED_FILENAME: str = "active-sessions.jsonl.1"

#: Filename for the dedup checkpoint sidecar (within ``runtime_state_dir()``).
ACTIVE_SESSIONS_STATE_FILENAME: str = "active-sessions.json"

#: Schema enums - kept in sync with the bundled active-sessions schema.
_VALID_KINDS: frozenset[str] = frozenset({"session_started", "session_heartbeat", "session_ended"})
_VALID_TOOLS: frozenset[str] = frozenset(
    {"cc", "codex", "cursor", "cron", "mcp", "alter-cli", "android", "widget", "obsidian"}
)
_VALID_STATUSES: frozenset[str] = frozenset({"active", "idle", "complete"})

#: Maximum files_touched entries persisted per record (schema default: 16).
MAX_FILES_TOUCHED: int = 16


class ActiveSessionsWriter(Component):
    """Subscribes to ``identity.event`` and appends session-lifecycle records.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`.
    bus:
        Shared :class:`EventBus`. Subscribes to ``identity.event``.
    rotation_threshold_bytes:
        Override the rotation threshold (defaults to 10 MiB).
    sessions_path:
        Override the JSONL path. Tests redirect writes to ``tmp_path``.
    state_path:
        Override the checkpoint path.
    """

    name = "active_sessions_writer"

    def __init__(
        self,
        config: DaemonConfig,
        bus: EventBus,
        *,
        rotation_threshold_bytes: int = ROTATION_THRESHOLD_BYTES,
        sessions_path: Path | None = None,
        state_path: Path | None = None,
    ) -> None:
        self._config = config
        self._bus = bus
        self._rotation_threshold_bytes = rotation_threshold_bytes

        self._sessions_path: Path = (
            sessions_path if sessions_path is not None else data_dir() / ACTIVE_SESSIONS_FILENAME
        )
        self._state_path: Path = (
            state_path
            if state_path is not None
            else runtime_state_dir() / ACTIVE_SESSIONS_STATE_FILENAME
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
            "active_sessions_writer started sessions=%s known_ids=%d",
            self._sessions_path,
            len(self._seen_versions),
        )
        try:
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            raise
        finally:
            with contextlib.suppress(Exception):
                self._bus.unsubscribe("identity.event", self.handle_event)
            logger.info("active_sessions_writer stopped")

    async def stop(self) -> None:
        self._shutdown_event.set()

    # ------------------------------------------------------------------
    # Event ingest
    # ------------------------------------------------------------------

    async def handle_event(self, event: dict[str, Any]) -> None:
        """Project a single bus event dict into ``active-sessions.jsonl``."""
        if not isinstance(event, dict):
            return

        # ---- 1. Filter on kind ---------------------------------------
        if event.get("kind") not in _VALID_KINDS:
            return

        # ---- 2. Build the record ------------------------------------
        record = self._serialise(event)
        if record is None:
            return

        record_id = record["id"]
        record_version = record["version"]

        async with self._lock:
            # ---- 3. Deduplicate on (id, version) ---------------------
            prior = self._seen_versions.get(record_id)
            if prior is not None and record_version <= prior:
                logger.debug(
                    "active_sessions_writer: dedupe drop id=%s version=%d <= seen=%d",
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
                logger.warning("active_sessions_writer: rotation failed: %s", exc)

            # ---- 5. Atomic append + fsync ----------------------------
            try:
                self._append_line(line)
            except OSError as exc:
                logger.warning("active_sessions_writer: append failed: %s - dropping event", exc)
                return

            # ---- 6. Advance + persist checkpoint --------------------
            self._seen_versions[record_id] = record_version
            try:
                self._save_checkpoint()
            except OSError as exc:
                logger.warning("active_sessions_writer: checkpoint save failed: %s", exc)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def _serialise(self, event: dict[str, Any]) -> dict[str, Any] | None:
        body = event.get("payload") if isinstance(event.get("payload"), dict) else event

        record_id = event.get("id") or body.get("id")
        version_raw = event.get("version") if "version" in event else body.get("version")
        kind = event.get("kind")
        handle = body.get("handle") or event.get("handle")
        tool = body.get("tool")
        session_id = body.get("session_id")
        machine_id = body.get("machine_id")
        started_at = body.get("started_at")
        last_activity = body.get("last_activity") or event.get("timestamp")
        working_on = body.get("working_on")
        branch = body.get("branch")
        files_touched = body.get("files_touched")
        status = body.get("status")
        consent_tier_raw = body.get("consent_tier")

        try:
            version_int = int(version_raw) if version_raw is not None else None
        except (TypeError, ValueError):
            logger.warning(
                "active_sessions_writer: non-integer version=%r - dropping",
                version_raw,
            )
            return None
        if version_int is None or version_int < 0:
            logger.warning(
                "active_sessions_writer: missing/negative version - dropping id=%r",
                record_id,
            )
            return None

        if not record_id or not isinstance(record_id, str):
            logger.warning("active_sessions_writer: missing id - dropping event")
            return None
        if not handle or not isinstance(handle, str):
            logger.warning("active_sessions_writer: missing handle - dropping id=%s", record_id)
            return None
        if tool not in _VALID_TOOLS:
            logger.warning(
                "active_sessions_writer: invalid tool=%r - dropping id=%s",
                tool,
                record_id,
            )
            return None
        if not session_id or not isinstance(session_id, str):
            logger.warning("active_sessions_writer: missing session_id - dropping id=%s", record_id)
            return None
        if not machine_id or not isinstance(machine_id, str):
            logger.warning("active_sessions_writer: missing machine_id - dropping id=%s", record_id)
            return None
        if not started_at:
            logger.warning("active_sessions_writer: missing started_at - dropping id=%s", record_id)
            return None
        if status not in _VALID_STATUSES:
            logger.warning(
                "active_sessions_writer: invalid status=%r - dropping id=%s",
                status,
                record_id,
            )
            return None

        if not last_activity:
            last_activity = datetime.now(timezone.utc).isoformat()

        try:
            consent_tier_int = int(consent_tier_raw) if consent_tier_raw is not None else None
        except (TypeError, ValueError):
            consent_tier_int = None
        if consent_tier_int not in (1, 2, 3, 4):
            logger.warning(
                "active_sessions_writer: invalid consent_tier=%r - dropping id=%s",
                consent_tier_raw,
                record_id,
            )
            return None

        # Bound files_touched to most-recent N (schema default 16) so a
        # runaway client cannot bloat individual records.
        bounded_files: list[str] = []
        if isinstance(files_touched, list):
            bounded_files = [str(p) for p in files_touched if p][-MAX_FILES_TOUCHED:]

        record: dict[str, Any] = {
            "id": str(record_id),
            "version": version_int,
            "kind": str(kind),
            "handle": str(handle),
            "tool": str(tool),
            "session_id": str(session_id),
            "machine_id": str(machine_id),
            "started_at": str(started_at),
            "last_activity": str(last_activity),
            "status": str(status),
            "provenance_class": "active_composition",
            "consent_tier": consent_tier_int,
        }
        # Optional fields - only emit when present; schema permits omission.
        if working_on is not None:
            record["working_on"] = str(working_on) if working_on else None
        if branch is not None:
            record["branch"] = str(branch) if branch else None
        if bounded_files:
            record["files_touched"] = bounded_files
        elif isinstance(files_touched, list):
            # Caller supplied an explicit empty list - preserve that signal.
            record["files_touched"] = []
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
        self._ensure_parent(self._sessions_path)

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(self._sessions_path, flags, 0o600)
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
            size = self._sessions_path.stat().st_size
        except FileNotFoundError:
            return
        if size <= self._rotation_threshold_bytes:
            return

        rotated = self._sessions_path.parent / ACTIVE_SESSIONS_ROTATED_FILENAME
        os.replace(self._sessions_path, rotated)
        logger.info(
            "active_sessions_writer: rotated %s -> %s (size=%d > threshold=%d)",
            self._sessions_path,
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
                "active_sessions_writer: unable to load checkpoint at %s: %s - starting empty",
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
    def sessions_path(self) -> Path:
        return self._sessions_path

    @property
    def state_path(self) -> Path:
        return self._state_path

    @property
    def seen_versions(self) -> dict[str, int]:
        return dict(self._seen_versions)
