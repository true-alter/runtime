"""PresenceFeedWriter - projects peer ``presence_set`` events into the
CLI-facing ``presence-feed.jsonl``.

This is the writer half of the ``alter room`` presence pane. The CLI reader
reads ``$XDG_DATA_HOME/alter-runtime/presence-feed.jsonl`` and renders one line per
granted peer who has voluntarily broadcast a presence state. Until this writer
landed the feed file never existed, so the pane always showed the
"no peers active right now" placeholder.

Where :class:`PresenceWriter` projects the *canonical* presence envelope into
``presence.jsonl`` (full schema: ``id``/``version``/``consent_tier``/``…`` for
downstream consumers), this writer projects the *CLI-shaped* subset into a
separate file:

    {"sender": "~peer", "state": "focus",
     "sent_at": "2026-04-24T10:42:11Z", "until": "2026-04-24T11:42:11Z"}

``until`` is optional and mirrors the envelope's ``expires_at``.

Voluntary-broadcast model (consent floor):
    * A peer appears only because THEY explicitly emitted a presence state and
      granted the caller. Nothing is sampled, synthesised, or inferred.
    * Self-echoes are filtered: a ``presence_set`` whose ``handle`` equals the
      daemon's own bound handle is the caller's own broadcast looping back
      through the stream; it is NOT a peer and is skipped.

TTL / expiry:
    The CLI reader captures ``until`` but does not itself drop expired rows.
    Expiry filtering is therefore owned here: a ``presence_set`` whose
    ``expires_at`` is already in the past at write time is skipped, so the feed
    never surfaces a peer whose declared presence window has closed.

The writer follows the same atomic-append + rotation + ``0o600`` conventions as
:class:`PresenceWriter` and :class:`InboxWriter`, and swallows all errors so a
single malformed event, full disk, or permission failure cannot crash the
daemon supervisor.
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

from alter_runtime.config import DaemonConfig, data_dir
from alter_runtime.daemon import Component

if TYPE_CHECKING:
    from alter_runtime.subscribers.bus import EventBus

__all__ = [
    "PRESENCE_FEED_FILENAME",
    "PRESENCE_FEED_ROTATED_FILENAME",
    "ROTATION_THRESHOLD_BYTES",
    "PresenceFeedWriter",
]

logger = logging.getLogger("alter_runtime.subscribers.presence_feed_writer")

#: Rotate the JSONL file once it exceeds this many bytes (10 MiB, matching
#: :mod:`presence_writer` / :mod:`inbox_writer`).
ROTATION_THRESHOLD_BYTES: int = 10 * 1024 * 1024

#: Filename for the CLI-facing presence feed (within ``data_dir()``). MUST
#: match the path read by the CLI's ``alter room`` reader
#: (``PRESENCE_FEED_FILE``).
PRESENCE_FEED_FILENAME: str = "presence-feed.jsonl"

#: Filename for the rotated tail (single generation).
PRESENCE_FEED_ROTATED_FILENAME: str = "presence-feed.jsonl.1"

#: Canonical presence states - kept in sync with the CLI's ``VALID_STATES``
#: and the canonical presence-state set.
_VALID_STATES: frozenset[str] = frozenset({"here", "focus", "open", "quiet"})


def _parse_iso(value: Any) -> datetime | None:
    """Best-effort parse of an ISO-8601 UTC string into an aware datetime.

    Accepts a trailing ``Z`` or an explicit offset. Returns ``None`` on any
    failure - callers treat that as "not parseable, do not filter on it".
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        stripped = value.rstrip("Z")
        if "+" in stripped or stripped.count("-") > 2:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(stripped).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _normalise_handle(value: Any) -> str | None:
    """Return a ``~``-prefixed handle string, or ``None`` if unusable."""
    if not isinstance(value, str) or not value.strip():
        return None
    h = value.strip()
    return h if h.startswith("~") else f"~{h}"


class PresenceFeedWriter(Component):
    """Subscribes to ``identity.event`` and projects peer ``presence_set``
    events into ``presence-feed.jsonl`` for the ``alter room`` CLI pane.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig` (reserved for future knobs).
    bus:
        Shared :class:`EventBus`. The writer subscribes to ``identity.event``
        in :meth:`run` and unsubscribes on :meth:`stop`.
    own_handle:
        The daemon's own bound ``~handle``. ``presence_set`` events whose
        ``handle`` equals this are self-echoes and are skipped - the feed is
        peer presence only. ``None`` disables self-echo filtering (every
        presence event is written; used only when no session is bound).
    rotation_threshold_bytes:
        Override the rotation threshold (defaults to 10 MiB). Tests use a
        small value to exercise the rotation path.
    feed_path:
        Override the JSONL path. Tests redirect writes to ``tmp_path``.
    """

    name = "presence_feed_writer"

    def __init__(
        self,
        config: DaemonConfig,
        bus: EventBus,
        *,
        own_handle: str | None = None,
        rotation_threshold_bytes: int = ROTATION_THRESHOLD_BYTES,
        feed_path: Path | None = None,
    ) -> None:
        self._config = config
        self._bus = bus
        self._own_handle = _normalise_handle(own_handle)
        self._rotation_threshold_bytes = rotation_threshold_bytes

        self._feed_path: Path = (
            feed_path if feed_path is not None else data_dir() / PRESENCE_FEED_FILENAME
        )

        self._lock = asyncio.Lock()
        self._shutdown_event = asyncio.Event()

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        self._bus.subscribe("identity.event", self.handle_event)
        logger.info(
            "presence_feed_writer started feed=%s own_handle=%s",
            self._feed_path,
            self._own_handle,
        )
        try:
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            raise
        finally:
            with contextlib.suppress(Exception):
                self._bus.unsubscribe("identity.event", self.handle_event)
            logger.info("presence_feed_writer stopped")

    async def stop(self) -> None:
        """Cooperative shutdown - release the run loop."""
        self._shutdown_event.set()

    # ------------------------------------------------------------------
    # Event ingest - public surface (also called directly by tests)
    # ------------------------------------------------------------------

    async def handle_event(self, event: dict[str, Any]) -> None:
        """Project a single bus event into ``presence-feed.jsonl``.

        Accepts both the canonical top-level envelope (``kind`` at top level)
        and an optional payload wrapper
        (``{"kind": ..., "payload": {...}}``).
        """
        if not isinstance(event, dict):
            return

        # ---- 1. Filter on kind ---------------------------------------
        if event.get("kind") != "presence_set":
            return

        # ---- 2. Build the CLI-shaped record -------------------------
        record = self._serialise(event)
        if record is None:
            return  # already logged / filtered

        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)

        async with self._lock:
            # ---- 3. Rotate if oversized ------------------------------
            try:
                self._maybe_rotate()
            except OSError as exc:
                logger.warning("presence_feed_writer: rotation failed: %s", exc)

            # ---- 4. Atomic append + fsync ----------------------------
            try:
                self._append_line(line)
            except OSError as exc:
                logger.warning("presence_feed_writer: append failed: %s - dropping event", exc)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def _serialise(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Build the CLI ``presence-feed.jsonl`` record for one event.

        Returns ``None`` when the event should be skipped: missing/invalid
        fields, a self-echo (handle == own handle), or already expired.
        """
        body = event.get("payload") if isinstance(event.get("payload"), dict) else event

        sender = _normalise_handle(body.get("handle") or event.get("handle"))
        state = body.get("state")
        sent_at = (
            body.get("set_at") or event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        )
        expires_at = body.get("expires_at")

        if sender is None:
            logger.warning("presence_feed_writer: missing handle - dropping event")
            return None
        if state not in _VALID_STATES:
            logger.warning(
                "presence_feed_writer: invalid state=%r - dropping sender=%s", state, sender
            )
            return None

        # ---- Self-echo filter: the feed is peer presence only --------
        if self._own_handle is not None and sender == self._own_handle:
            logger.debug(
                "presence_feed_writer: self-echo handle=%s - skipping (peer feed only)",
                sender,
            )
            return None

        # ---- TTL / expiry filter (the writer owns this; CLI does not) --
        if expires_at is not None:
            expiry_dt = _parse_iso(expires_at)
            if expiry_dt is not None and expiry_dt <= datetime.now(timezone.utc):
                logger.debug(
                    "presence_feed_writer: expired until=%s sender=%s - skipping",
                    expires_at,
                    sender,
                )
                return None

        record: dict[str, Any] = {
            "sender": sender,
            "state": str(state),
            "sent_at": str(sent_at),
        }
        # ``until`` is optional - only emit when the envelope carried a
        # non-null ``expires_at`` (matches the CLI's optional ``until`` field).
        if isinstance(expires_at, str) and expires_at:
            record["until"] = expires_at
        return record

    # ------------------------------------------------------------------
    # File operations - atomic append, rotation
    # ------------------------------------------------------------------

    def _ensure_parent(self, path: Path) -> None:
        parent = path.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            os.chmod(parent, 0o700)

    def _append_line(self, line: str) -> None:
        self._ensure_parent(self._feed_path)

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(self._feed_path, flags, 0o600)
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
            size = self._feed_path.stat().st_size
        except FileNotFoundError:
            return
        if size <= self._rotation_threshold_bytes:
            return

        rotated = self._feed_path.parent / PRESENCE_FEED_ROTATED_FILENAME
        os.replace(self._feed_path, rotated)
        logger.info(
            "presence_feed_writer: rotated %s -> %s (size=%d > threshold=%d)",
            self._feed_path,
            rotated,
            size,
            self._rotation_threshold_bytes,
        )

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def feed_path(self) -> Path:
        return self._feed_path

    @property
    def own_handle(self) -> str | None:
        return self._own_handle
