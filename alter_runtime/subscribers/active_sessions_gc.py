"""ActiveSessionsGc - periodic sweeper for the active-sessions JSONL.

Companion to :class:`ActiveSessionsWriter`. The writer projects
``session_started`` / ``session_heartbeat`` / ``session_ended`` bus events
into ``~/.local/share/alter-runtime/active-sessions.jsonl``, but nothing
sweeps the live state to detect idle/dead sessions and emit the
corresponding lifecycle transitions. This component fills that gap.

Behaviour
---------

On every tick (default 60s):

1. Read the JSONL under ``LOCK_SH`` shared lock (writer uses ``LOCK_EX``
   so this serialises correctly without blocking writes), fold to
   ``{(tool, session_id) -> newest row by last_activity}``, skip rows
   already terminal (``status == "complete"``).
2. For each ``(tool, session_id)``:

   * If ``(now - last_activity) > idle_after_seconds`` and the source row
     is not already ``status == "idle"``, emit a ``session_heartbeat``
     with ``status="idle"`` and ``version = source.version + 1``.
   * If ``(now - last_activity) > terminated_after_seconds``:

     - For ``tool == "cc"``: probe ``os.kill(int(session_id), 0)`` and
       only emit if the PID is dead (catches ``ProcessLookupError``,
       ``PermissionError``, ``OSError``).
     - For other tools: emit on threshold alone (no PID semantics).
     - Emit a ``session_ended`` with ``status="complete"``.

3. Track an internal ``_emitted_versions`` map keyed on
   ``(tool, session_id)`` -> ``(last_status, version)`` so repeated ticks
   over the same stale source do not re-emit the same envelope every
   cycle.

The component NEVER writes the JSONL directly - every emit goes through
the shared :class:`EventBus`, so the writer's ``_VALID_KINDS`` gate, its
``(id, version)`` dedup, rotation, and 0o600 file mode are preserved
transparently. New envelope ``id``s are minted per emit; the dedup
contract on the writer side is that newer ``version``s for the same
``id`` win - here we always carry forward the source row's ``id`` and
bump ``version`` so the writer accepts the new envelope as the next
generation of the same session record.

Daemon-side GC pass for stale active-session records.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import fcntl
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from alter_runtime.config import DaemonConfig, data_dir
from alter_runtime.daemon import Component
from alter_runtime.subscribers.active_sessions_writer import (
    ACTIVE_SESSIONS_FILENAME,
)

if TYPE_CHECKING:
    from alter_runtime.subscribers.bus import EventBus

__all__ = ["ActiveSessionsGc"]

logger = logging.getLogger("alter_runtime.subscribers.active_sessions_gc")


def _default_pid_probe(pid: int) -> bool:
    """Return ``True`` if ``pid`` is alive, ``False`` otherwise.

    ``os.kill(pid, 0)`` is the canonical liveness probe on POSIX:

    * Returns silently when the process exists and the caller is
      permitted to signal it.
    * Raises ``ProcessLookupError`` when no such PID exists - the
      definitive "dead" signal.
    * Raises ``PermissionError`` when the PID exists but is owned by a
      different user - treat as "alive" (we cannot reap a process we do
      not own).
    * Raises ``OSError(errno.ESRCH)`` on some exotic kernels - same as
      ``ProcessLookupError``.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        # Any other error class is treated conservatively as "alive" so a
        # transient probe failure does not surface as a spurious
        # session_ended.
        return True
    return True


class ActiveSessionsGc(Component):
    """Periodic sweeper that emits idle / terminated session envelopes.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`. Reads
        ``active_sessions_gc_interval_seconds``,
        ``active_sessions_idle_after_seconds``,
        ``active_sessions_terminated_after_seconds``.
    bus:
        Shared :class:`EventBus`. Emits via ``identity.event``.
    sessions_path:
        Override the JSONL path. Tests redirect reads to ``tmp_path``.
    pid_probe:
        Override the PID-liveness probe. Tests inject a stub so they do
        not depend on the host's real process table.
    now:
        Override the clock. Tests pass a frozen ``datetime`` provider.
    """

    name = "active_sessions_gc"

    def __init__(
        self,
        config: DaemonConfig,
        bus: EventBus,
        *,
        sessions_path: Path | None = None,
        pid_probe: Callable[[int], bool] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._config = config
        self._bus = bus
        self._sessions_path: Path = (
            sessions_path if sessions_path is not None else data_dir() / ACTIVE_SESSIONS_FILENAME
        )
        self._pid_probe: Callable[[int], bool] = pid_probe or _default_pid_probe
        self._now: Callable[[], datetime] = now or (lambda: datetime.now(timezone.utc))

        self._stop_event = asyncio.Event()
        # Tracks the last (status, version) we emitted for a given
        # (tool, session_id) so we never re-emit the same idle/complete
        # envelope on a subsequent tick.
        self._emitted_versions: dict[tuple[str, str], tuple[str, int]] = {}

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        logger.info(
            "active_sessions_gc starting sessions=%s interval=%.1fs "
            "idle_after=%.1fs terminated_after=%.1fs",
            self._sessions_path,
            self._config.active_sessions_gc_interval_seconds,
            self._config.active_sessions_idle_after_seconds,
            self._config.active_sessions_terminated_after_seconds,
        )
        try:
            while not self._stop_event.is_set():
                try:
                    await self._tick()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 - last-resort safety net
                    logger.exception("active_sessions_gc tick failed: %s", exc)
                await self._sleep_interruptible(self._config.active_sessions_gc_interval_seconds)
        finally:
            logger.info("active_sessions_gc stopped")

    async def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Tick
    # ------------------------------------------------------------------

    async def _tick(self) -> None:
        """One sweep: read live state, emit idle/terminated where due."""
        rows = self._read_live_rows()
        if not rows:
            return

        live = self._fold_newest(rows)
        now = self._now()
        idle_after = self._config.active_sessions_idle_after_seconds
        terminated_after = self._config.active_sessions_terminated_after_seconds

        for key, source in live.items():
            tool, session_id = key
            last_activity_raw = source.get("last_activity")
            if not isinstance(last_activity_raw, str) or not last_activity_raw:
                continue
            try:
                last_activity = datetime.fromisoformat(last_activity_raw.replace("Z", "+00:00"))
            except ValueError:
                continue
            if last_activity.tzinfo is None:
                last_activity = last_activity.replace(tzinfo=timezone.utc)

            age = (now - last_activity).total_seconds()
            if age <= 0:
                continue

            current_status = source.get("status")
            current_version = source.get("version")
            if not isinstance(current_version, int):
                continue

            # ----- 1. Terminated (overrides idle) -------------------
            if age > terminated_after:
                if tool == "cc":
                    pid = self._parse_pid(session_id)
                    if pid is None:
                        # Non-numeric session id - cannot probe, skip
                        # the terminated emit (the row will keep ageing
                        # but we never reap what we cannot probe).
                        continue
                    if self._pid_probe(pid):
                        continue
                await self._emit(
                    source,
                    kind="session_ended",
                    new_status="complete",
                    now=now,
                )
                continue

            # ----- 2. Idle ------------------------------------------
            if age > idle_after and current_status != "idle":
                await self._emit(
                    source,
                    kind="session_heartbeat",
                    new_status="idle",
                    now=now,
                )

    # ------------------------------------------------------------------
    # Emit
    # ------------------------------------------------------------------

    async def _emit(
        self,
        source: dict[str, Any],
        *,
        kind: str,
        new_status: str,
        now: datetime,
    ) -> None:
        """Publish a new envelope via the bus iff we haven't already."""
        tool = source.get("tool")
        session_id = source.get("session_id")
        if not isinstance(tool, str) or not isinstance(session_id, str):
            return
        key = (tool, session_id)

        next_version = int(source["version"]) + 1
        prior = self._emitted_versions.get(key)
        if prior is not None:
            prior_status, prior_version = prior
            if prior_status == new_status and prior_version >= next_version:
                # We already emitted this transition; nothing to do.
                return

        payload: dict[str, Any] = {
            "id": source.get("id") or str(uuid.uuid4()),
            "version": next_version,
            "kind": kind,
            "handle": source.get("handle"),
            "tool": tool,
            "session_id": session_id,
            "machine_id": source.get("machine_id"),
            "started_at": source.get("started_at"),
            "last_activity": now.isoformat(),
            "status": new_status,
            "consent_tier": source.get("consent_tier"),
            "provenance_class": source.get("provenance_class", "active_composition"),
        }
        # Optional fields - carry forward only when present.
        if "working_on" in source:
            payload["working_on"] = source.get("working_on")
        if "files_touched" in source:
            payload["files_touched"] = source.get("files_touched")

        # Reassign envelope id to a fresh value per the design lock:
        # writer dedup is by (id, version), but here we are minting a NEW
        # envelope that represents a new lifecycle transition. Carrying
        # the source id forward bumps the same record; minting a fresh
        # id makes the GC emit independently observable. The brief
        # spec'd ``str(uuid.uuid4())`` - honour that.
        payload["id"] = str(uuid.uuid4())

        await self._bus.publish("identity.event", payload)
        self._emitted_versions[key] = (new_status, next_version)
        logger.debug(
            "active_sessions_gc emitted kind=%s status=%s tool=%s session=%s version=%d",
            kind,
            new_status,
            tool,
            session_id,
            next_version,
        )

    # ------------------------------------------------------------------
    # File reading
    # ------------------------------------------------------------------

    def _read_live_rows(self) -> list[dict[str, Any]]:
        """Read every line of the JSONL under a shared lock.

        Returns an empty list when the file is missing or unreadable.
        """
        if not self._sessions_path.exists():
            return []

        rows: list[dict[str, Any]] = []
        flags = os.O_RDONLY
        try:
            fd = os.open(self._sessions_path, flags)
        except OSError as exc:
            logger.warning("active_sessions_gc: open failed: %s", exc)
            return []

        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH)
            except OSError as exc:  # pragma: no cover - exotic FS
                if exc.errno not in (errno.ENOTSUP, errno.EINVAL):
                    logger.warning("active_sessions_gc: LOCK_SH failed: %s", exc)
                    return []
            try:
                buf = b""
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    buf += chunk
            finally:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

        for raw_line in buf.decode("utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                continue
            if isinstance(row, dict):
                rows.append(row)
        return rows

    def _fold_newest(self, rows: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
        """Fold rows to ``{(tool, session_id): newest non-tombstone row}``.

        ``status == "complete"`` is the tombstone - once a session ends
        we never want to resurrect it as idle/terminated.
        """
        folded: dict[tuple[str, str], dict[str, Any]] = {}
        for row in rows:
            tool = row.get("tool")
            session_id = row.get("session_id")
            if not isinstance(tool, str) or not isinstance(session_id, str):
                continue
            key = (tool, session_id)
            current = folded.get(key)
            if current is None:
                folded[key] = row
                continue
            if self._compare_last_activity(row, current) > 0:
                folded[key] = row

        # Drop tombstones - sessions already complete are not GC's
        # business.
        return {key: row for key, row in folded.items() if row.get("status") != "complete"}

    @staticmethod
    def _compare_last_activity(a: dict[str, Any], b: dict[str, Any]) -> int:
        """Return >0 if ``a`` is newer than ``b``, <0 if older, 0 equal."""
        a_ts = a.get("last_activity") or ""
        b_ts = b.get("last_activity") or ""
        if a_ts == b_ts:
            # Tie-breaker on version so a heartbeat at the same ISO
            # timestamp beats the prior start.
            a_v = a.get("version") if isinstance(a.get("version"), int) else -1
            b_v = b.get("version") if isinstance(b.get("version"), int) else -1
            return (a_v or -1) - (b_v or -1)
        return 1 if a_ts > b_ts else -1

    @staticmethod
    def _parse_pid(session_id: str) -> int | None:
        """Return ``session_id`` as ``int`` if it parses, else ``None``."""
        try:
            pid = int(session_id)
        except (TypeError, ValueError):
            return None
        return pid if pid > 0 else None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _sleep_interruptible(self, seconds: float) -> None:
        """Sleep ``seconds`` or until stop is set, whichever comes first."""
        if seconds <= 0:
            return
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
        except (TimeoutError, asyncio.TimeoutError):
            return

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def sessions_path(self) -> Path:
        return self._sessions_path

    @property
    def emitted_versions(self) -> dict[tuple[str, str], tuple[str, int]]:
        return dict(self._emitted_versions)
