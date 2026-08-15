"""AgentFrameSubscriber - projects ``agent_frame`` deliveries to a local JSONL cache.

Implements the agent-frame channel projection.

The subscriber is a long-lived :class:`alter_runtime.daemon.Component` that:

1. Subscribes to the in-process :class:`EventBus` on the ``identity.event``
   topic published by :class:`DoSseSubscriber`.
2. Filters frames whose ``content_type`` equals ``"x-alter-agent"`` (the
   agent-channel discriminator).
3. Deduplicates on ``frame_id``; a bounded LRU window prevents DO replay
   bursts from writing the same frame twice.
4. Atomically appends one compact JSON line per frame to
   ``$XDG_CACHE_HOME/alter/agent-frames.jsonl`` (mode ``0o600``, parent dir
   ``0o700``), rotating to ``agent-frames.jsonl.1`` once the file exceeds
   10 MiB.
5. Publishes to the in-process bus topic ``alter.agent.frame.{kind}`` so hook
   subscribers (client hooks, adapters) can react to specific frame kinds without
   polling the JSONL cache.

The projection path is a pure subscriber; it never sends an acknowledgement
back to the DO. The DO replays from ``Last-Event-ID`` on reconnect, so write
failures simply mean the frame is re-offered on the next connection.

The component is designed to swallow and log all errors so that a single
malformed frame, full disk, or transient misbehaviour cannot crash the daemon
supervisor. The supervisor will still restart the component with exponential
backoff if :meth:`run` raises, but :meth:`handle_event` only ever logs and
returns.

Scope note (future work):
- D-Bus signal (``dev.alter.agent.frame``): not yet implemented.
- Cross-org federation is not yet implemented.
- Subscription filter enforcement (DO-side): not yet implemented here.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import fcntl
import json
import logging
import os
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from alter_runtime.config import cache_dir
from alter_runtime.daemon import Component

if TYPE_CHECKING:
    from alter_runtime.subscribers.bus import EventBus

__all__ = ["AgentFrameSubscriber", "DEFAULT_ROTATION_THRESHOLD_BYTES", "InstrumentRecord"]

logger = logging.getLogger("alter_runtime.subscribers.agent_frames")

#: SSE ``content_type`` value that discriminates agent channel frames from
#: human Messenger frames.
AGENT_CONTENT_TYPE: str = "x-alter-agent"

#: Filename for the agent-frames JSONL cache (within ``cache_dir()``).
FRAMES_FILENAME: str = "agent-frames.jsonl"

#: Filename for the rotated tail (single generation).
FRAMES_ROTATED_FILENAME: str = "agent-frames.jsonl.1"

#: Rotate the JSONL file once it exceeds this many bytes (10 MiB, matching the
#: inbox.jsonl rotation threshold from InboxWriter).
DEFAULT_ROTATION_THRESHOLD_BYTES: int = 10 * 1024 * 1024

#: Maximum number of ``frame_id`` values retained for in-memory dedup. Sized
#: to absorb a DO replay burst (the same ceiling as do_sse.py FRAME_DEDUP_WINDOW)
#: while staying cheap in-memory.
FRAME_DEDUP_WINDOW: int = 256

#: Hard cap on the per-frame ``payload`` serialised size written to the cache.
#: Prevents a pathological large payload from bloating the cache file past the
#: rotation threshold in a single write.
MAX_PAYLOAD_BYTES: int = 64 * 1024

#: Bus topic pattern for per-kind agent frame events.  Callers subscribe to
#: e.g. ``alter.agent.frame.agent_advisory``.  The subscriber publishes the
#: full deserialised frame dict as the payload.
TOPIC_AGENT_FRAME_PREFIX: str = "alter.agent.frame."


@dataclass
class InstrumentRecord:
    """A single entry in the in-memory instrument roster.

    Populated from observed ``agent_frame`` sender fields.  Represents one
    agentic surface (an AI coding session, Codex window, Cursor IDE, CLI verb,
    alter-runtime daemon) that has emitted at least one frame visible to
    this daemon instance.

    Fields mirror the ``alter_agent_roster`` MCP verb shape
    so the unix-socket ``agent/roster`` route can
    return the same shape without a DO round-trip.
    """

    handle: str
    instrument: str
    tool: str
    session_id: str | None = None
    started_at: str | None = None
    last_seen_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AgentFrameSubscriber(Component):
    """Projects ``agent_frame`` deliveries to a local JSONL cache.

    Parameters
    ----------
    bus:
        The shared :class:`EventBus` instance.  Used both to subscribe to
        ``identity.event`` (ingress) and to re-publish per-kind frame topics
        (fan-out to hook subscribers).
    frames_path:
        Override the JSONL output path.  Tests use this to redirect writes
        to a ``tmp_path`` fixture without touching ``~/.cache/alter/``.
    rotation_threshold_bytes:
        Override the rotation threshold.  Tests pass a small value to
        exercise the rotation path without writing megabytes.
    """

    name = "agent_frames"

    def __init__(
        self,
        bus: EventBus,
        *,
        frames_path: Path | None = None,
        rotation_threshold_bytes: int = DEFAULT_ROTATION_THRESHOLD_BYTES,
    ) -> None:
        self._bus = bus
        self._frames_path: Path = (
            frames_path if frames_path is not None else cache_dir() / FRAMES_FILENAME
        )
        self._rotation_threshold_bytes = rotation_threshold_bytes
        self._lock = asyncio.Lock()
        self._shutdown_event = asyncio.Event()
        # Bounded LRU dedup window keyed on ``frame_id``.  Uses OrderedDict so
        # we can efficiently evict the oldest entry when the window is full.
        self._seen_frame_ids: OrderedDict[str, None] = OrderedDict()
        # In-memory instrument roster: keyed on ``(handle, instrument)`` so
        # that the unix-socket ``agent/roster`` route can return observed
        # instruments without a DO round-trip.
        self._roster: dict[tuple[str, str], InstrumentRecord] = {}

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Subscribe to the bus and block until stop() is called.

        The subscription is registered inside ``run()`` (not ``__init__``) so
        that tests can construct the subscriber without side-effects and call
        :meth:`handle_event` directly.
        """
        self._bus.subscribe("identity.event", self.handle_event)
        logger.info(
            "agent_frames subscriber started frames=%s",
            self._frames_path,
        )
        try:
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            raise
        finally:
            self._bus.unsubscribe("identity.event", self.handle_event)
            logger.info("agent_frames subscriber stopped")

    async def stop(self) -> None:
        """Cooperative shutdown: release the run loop."""
        self._shutdown_event.set()

    # ------------------------------------------------------------------
    # Frame ingest: public surface for the bus and tests
    # ------------------------------------------------------------------

    async def handle_event(self, event: Any) -> None:
        """Project a single parsed identity-event dict if it is an agent_frame.

        This is the unit-test seam; the test suite calls this directly with
        synthesised dicts to avoid having to drive a real SSE socket or event
        bus.
        """
        if not isinstance(event, dict):
            return

        # ---- 1. Discriminate + unwrap ------------------------------------
        # Two live shapes reach this subscriber:
        #
        # (a) The DO identity-event wrapper (the shape the /events/{handle}/
        #     stream actually fans out, captured live 2026-06-06):
        #       {"v": "alter1", "version": N, "handle": "~example",
        #        "kind": "agent_frame", "timestamp": ...,
        #        "payload": {<AgentFrame envelope: envelope_version, kind,
        #                     frame_id, sender_handle, ...>}}
        #     The projected row is the INNER AgentFrame envelope, which is
        #     what readers (client hooks and other local consumers) key on.
        #
        # (b) The legacy Messenger-borne agent post, discriminated by
        #     content_type == "x-alter-agent" with frame fields at the top
        #     level. Kept for back-compat.
        #
        # The original implementation filtered ONLY on (b)'s content_type,
        # a field the wrapper shape does not carry, so every DO-fanned
        # frame was silently dropped (mocks were synthesised, never
        # captured from the live stream; the wrapper shape was not verified
        # against the live stream).
        if event.get("kind") == "agent_frame" and isinstance(event.get("payload"), dict):
            event = event["payload"]
        elif event.get("content_type") != AGENT_CONTENT_TYPE:
            return

        # ---- 2. Extract frame_id for dedup ------------------------------
        frame_id = event.get("frame_id")
        if not isinstance(frame_id, str) or not frame_id:
            logger.warning(
                "agent_frames: agent_frame missing frame_id - dropping: kind=%r",
                event.get("kind"),
            )
            return

        # ---- 3. Dedup on frame_id ----------------------------------------
        async with self._lock:
            if frame_id in self._seen_frame_ids:
                logger.debug(
                    "agent_frames: duplicate frame_id=%s kind=%r - dropping",
                    frame_id,
                    event.get("kind"),
                )
                return

            self._seen_frame_ids[frame_id] = None
            if len(self._seen_frame_ids) > FRAME_DEDUP_WINDOW:
                self._seen_frame_ids.popitem(last=False)

            # ---- 4. Project the row ---------------------------------------
            line = self._serialise(event)
            if line is None:
                return  # already logged

            # ---- 5. Rotate if oversized -----------------------------------
            try:
                self._maybe_rotate()
            except OSError as exc:
                logger.warning("agent_frames: rotation failed: %s", exc)
                # Continue anyway; better to grow past threshold than drop.

            # ---- 6. Atomic append -----------------------------------------
            try:
                self._append_line(line)
            except OSError as exc:
                logger.warning("agent_frames: append failed: %s - dropping frame", exc)
                return

            # ---- 7. Update the in-memory roster ---------------------------
            self._update_roster(event)

        # ---- 9. Re-publish per-kind bus topic (outside the lock) ---------
        # Re-publish after releasing the lock so hook subscribers can
        # consume the event without risk of deadlocking on the write lock.
        kind = event.get("kind")
        if isinstance(kind, str) and kind:
            topic = TOPIC_AGENT_FRAME_PREFIX + kind
            try:
                await self._bus.publish(topic, event)
            except Exception as exc:  # noqa: BLE001 - defensive; bus publish should not raise
                logger.warning(
                    "agent_frames: bus publish failed topic=%s: %s",
                    topic,
                    exc,
                )

    # ------------------------------------------------------------------
    # Roster
    # ------------------------------------------------------------------

    def _update_roster(self, event: dict[str, Any]) -> None:
        """Update the in-memory instrument roster from a successfully projected frame.

        Called inside the write lock so roster state stays consistent with
        the JSONL projection.  The roster is best-effort; it only reflects
        instruments that have emitted frames observable to this daemon instance.
        It is NOT a canonical view of all active instruments (that lives
        server-side).
        """
        sender = event.get("sender") or event.get("from_handle") or event.get("sender_handle")
        if not isinstance(sender, str) or not sender:
            return

        instrument = event.get("instrument") or event.get("tool") or "unknown"
        tool = event.get("tool") or "unknown"
        session_id = event.get("session_id")
        now_iso = datetime.now(timezone.utc).isoformat()

        key = (sender, str(instrument))
        if key in self._roster:
            rec = self._roster[key]
            # Mutate in-place; dataclass fields are not frozen.
            rec.last_seen_at = now_iso
            if session_id:
                rec.session_id = str(session_id)
        else:
            self._roster[key] = InstrumentRecord(
                handle=sender,
                instrument=str(instrument),
                tool=str(tool),
                session_id=str(session_id) if session_id else None,
                started_at=now_iso,
                last_seen_at=now_iso,
            )

    def get_roster(self) -> list[dict[str, Any]]:
        """Return the current in-memory roster as a list of dicts.

        Safe to call from outside the write lock because Python dict iteration
        is GIL-protected for reads and the roster is only mutated inside
        :meth:`_update_roster` (which is called under the write lock in the
        async path).  The returned list is a snapshot; callers should not
        cache it.
        """
        return [asdict(rec) for rec in self._roster.values()]

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def _serialise(self, event: dict[str, Any]) -> str | None:
        """Build the JSONL line for one ``agent_frame`` event.

        Returns ``None`` if a required field is missing; the caller treats
        that as "drop and continue".
        """
        kind = event.get("kind")
        if not isinstance(kind, str) or not kind:
            logger.warning(
                "agent_frames: agent_frame missing kind - dropping frame_id=%r",
                event.get("frame_id"),
            )
            return None

        frame_id = event.get("frame_id")
        sender = event.get("sender") or event.get("from_handle") or event.get("sender_handle")
        received_at = (
            event.get("timestamp")
            or event.get("sent_at")
            or event.get("created_at")  # AgentFrame envelope timestamp (live DO shape)
            or datetime.now(timezone.utc).isoformat()
        )
        payload = event.get("payload")

        record: dict[str, Any] = {
            "frame_id": str(frame_id),
            "kind": kind,
            "sender": str(sender) if sender else None,
            "received_at": str(received_at),
        }

        if payload is not None:
            # Serialise the payload to check its size and guard against bloat.
            try:
                payload_str = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            except (TypeError, ValueError) as exc:
                logger.warning(
                    "agent_frames: payload not serialisable for frame_id=%s: %s",
                    frame_id,
                    exc,
                )
                payload_str = None

            if payload_str is not None:
                payload_bytes = payload_str.encode("utf-8")
                if len(payload_bytes) > MAX_PAYLOAD_BYTES:
                    logger.warning(
                        "agent_frames: payload exceeds %d bytes for frame_id=%s "
                        "- truncating local cache entry",
                        MAX_PAYLOAD_BYTES,
                        frame_id,
                    )
                    payload_str = (
                        payload_bytes[:MAX_PAYLOAD_BYTES].decode("utf-8", errors="ignore")
                        + " [... payload truncated at 64 KiB]"
                    )
                    record["payload"] = payload_str
                    record["payload_truncated"] = True
                else:
                    record["payload"] = payload

        return json.dumps(record, separators=(",", ":"), ensure_ascii=False)

    # ------------------------------------------------------------------
    # File operations: atomic append, rotation
    # ------------------------------------------------------------------

    def _ensure_parent(self, path: Path) -> None:
        """Create the parent directory with mode ``0o700`` if missing."""
        parent = path.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            os.chmod(parent, 0o700)

    def _append_line(self, line: str) -> None:
        """Atomically append ``line + '\\n'`` to the cache file.

        Uses :func:`os.open` with ``O_APPEND | O_CREAT`` and mode ``0o600``,
        followed by an :func:`fcntl.flock` exclusive lock around the write.
        ``O_APPEND`` makes the write itself atomic against concurrent writers
        on POSIX, and ``flock`` serialises us against a hypothetical second
        daemon instance on the same XDG dir.
        """
        self._ensure_parent(self._frames_path)

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(self._frames_path, flags, 0o600)
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
        """Rotate the cache file if it exceeds the threshold.

        Renames ``agent-frames.jsonl`` to ``agent-frames.jsonl.1`` (overwriting
        any existing rotated file). The next :meth:`_append_line` call recreates
        the primary file via ``O_CREAT``. No-op if the file does not yet exist
        or is below the threshold.
        """
        try:
            size = self._frames_path.stat().st_size
        except FileNotFoundError:
            return
        if size <= self._rotation_threshold_bytes:
            return

        rotated = self._frames_path.parent / FRAMES_ROTATED_FILENAME
        os.replace(self._frames_path, rotated)
        logger.info(
            "agent_frames: rotated %s -> %s (size=%d > threshold=%d)",
            self._frames_path,
            rotated,
            size,
            self._rotation_threshold_bytes,
        )

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def frames_path(self) -> Path:
        """JSONL output path (used by tests)."""
        return self._frames_path

    @property
    def seen_frame_ids(self) -> OrderedDict[str, None]:
        """Current dedup window (used by tests)."""
        return self._seen_frame_ids

    @property
    def roster(self) -> dict[tuple[str, str], InstrumentRecord]:
        """Current in-memory roster (used by tests)."""
        return self._roster
