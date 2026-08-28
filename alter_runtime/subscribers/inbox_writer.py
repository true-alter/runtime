"""InboxWriter - projects ``alter_message`` events into a local JSONL inbox.

InboxWriter. The InboxWriter is
a long-lived :class:`alter_runtime.daemon.Component` that:

1. Opens a Server-Sent Events stream against the authenticated user's
   per-handle event endpoint at
   ``https://mcp.truealter.com/events/{handle}/stream``.
2. Filters frames whose payload ``kind`` equals ``"alter_message"``.
3. Deduplicates against a persisted ``last_seen_do_version`` checkpoint so
   the daemon survives restarts without double-writing events.
4. Atomically appends one compact JSON object per line to
   ``$XDG_DATA_HOME/alter-runtime/inbox.jsonl`` (mode ``0o600``, parent dir
   ``0o700``), rotating to ``inbox.jsonl.1`` once the file exceeds 10 MiB.
5. Updates ``$XDG_STATE_HOME/alter-runtime/messaging.json`` with the new
   checkpoint via atomic rename.

The runtime is a *pure subscriber* - it never sends an ACK back to the
server. The stream replays from ``Last-Event-ID`` on reconnect, so checkpoint
advance is local-only and a write failure simply means the next reconnect
re-fetches the frame.

The component is designed to swallow and log all errors so that a single
malformed frame, full disk, or transient SSE disconnect cannot crash the
daemon supervisor. The supervisor will still restart the component with
exponential backoff if :meth:`run` raises, but :meth:`_handle_frame` only
ever logs and returns.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import fcntl
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from alter_runtime.config import DaemonConfig, data_dir, runtime_state_dir
from alter_runtime.daemon import Component
from alter_runtime.subscribers.sse import SSEFrame

if TYPE_CHECKING:
    from alter_runtime.config import Session

__all__ = ["DEFAULT_ROTATION_THRESHOLD_BYTES", "InboxWriter"]

logger = logging.getLogger("alter_runtime.subscribers.inbox_writer")

#: Rotate the JSONL file once it exceeds this many bytes (10 MiB).
DEFAULT_ROTATION_THRESHOLD_BYTES: int = 10 * 1024 * 1024

#: Filename for the inbox cache (within ``data_dir()``).
INBOX_FILENAME: str = "inbox.jsonl"

#: Filename for the rotated tail (single generation; older rotations are not
#: retained - the server holds the canonical record, this is a hot-path cache).
INBOX_ROTATED_FILENAME: str = "inbox.jsonl.1"

#: Filename for the checkpoint (within ``runtime_state_dir()``).
STATE_FILENAME: str = "messaging.json"

#: Hard cap on the per-message ``body_md`` length written to the inbox cache.
#: The server does not itself bound message bodies, so without a cap
#: on the consumer side a single pathological message could bloat the cache
#: file and starve rotation.
MAX_BODY_MD_BYTES: int = 64 * 1024


class InboxWriter(Component):
    """Tails the per-handle SSE stream and projects messages into ``inbox.jsonl``.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`. Only ``do_sse_endpoint`` is consulted.
    session:
        Authenticated CLI session. ``session.handle`` is used to build
        the per-handle SSE URL and ``session.jwt`` is sent as a Bearer token.
    rotation_threshold_bytes:
        Override the rotation threshold (defaults to 10 MiB). Tests pass a
        small value to exercise the rotation path without writing megabytes.
    inbox_path:
        Override the inbox path. Tests use this to redirect writes to a
        ``tmp_path`` fixture without touching ``$HOME``.
    state_path:
        Override the checkpoint path, same purpose as ``inbox_path``.
    """

    name = "inbox_writer"

    def __init__(
        self,
        config: DaemonConfig,
        session: Session,
        *,
        rotation_threshold_bytes: int = DEFAULT_ROTATION_THRESHOLD_BYTES,
        inbox_path: Path | None = None,
        state_path: Path | None = None,
    ) -> None:
        self._config = config
        self._session = session
        self._rotation_threshold_bytes = rotation_threshold_bytes

        # Lazy-resolve XDG paths so tests that monkeypatch the env vars
        # before construction get the redirected directories. Tests can
        # also override either path explicitly via the keyword args.
        self._inbox_path: Path = (
            inbox_path if inbox_path is not None else data_dir() / INBOX_FILENAME
        )
        self._state_path: Path = (
            state_path if state_path is not None else runtime_state_dir() / STATE_FILENAME
        )

        self._lock = asyncio.Lock()
        self._last_seen_do_version: int = 0
        self._shutdown_event = asyncio.Event()

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Long-lived loop. Currently a stub for the SSE socket.

        The current deliverable is the projection logic (filter / dedupe /
        append / rotate / checkpoint), wired so that the backend's eventual
        Last-Event-ID replay or a future SSE client can feed frames in via
        :meth:`handle_raw_frame`. The actual long-lived ``httpx.AsyncClient``
        loop against ``do_sse_endpoint`` lands alongside the SSE subscriber
        rewrite in a future release (currently a stub).

        For now :meth:`run` simply loads the checkpoint and blocks on the
        shutdown event so the supervisor can register us cleanly without
        opening a socket. Tests exercise the projection path via
        :meth:`handle_event` directly.
        """
        await self._load_checkpoint()
        logger.info(
            "inbox_writer started handle=%s last_seen_do_version=%d inbox=%s",
            self._session.handle,
            self._last_seen_do_version,
            self._inbox_path,
        )
        try:
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            raise
        finally:
            logger.info("inbox_writer stopped handle=%s", self._session.handle)

    async def stop(self) -> None:
        """Cooperative shutdown - release the run loop."""
        self._shutdown_event.set()

    # ------------------------------------------------------------------
    # Frame ingest - public surface for the SSE socket loop and tests
    # ------------------------------------------------------------------

    async def handle_raw_frame(self, frame: SSEFrame) -> None:
        """Parse an SSE frame and dispatch to :meth:`handle_event`.

        Errors are logged and swallowed - the supervisor never sees a write
        failure (per the project convention "swallow and continue").
        """
        try:
            payload = frame.json
        except (ValueError, json.JSONDecodeError) as exc:
            logger.warning("inbox_writer: malformed SSE frame body: %s", exc)
            return
        if not isinstance(payload, dict):
            logger.warning("inbox_writer: SSE frame payload is not a dict: %r", type(payload))
            return
        await self.handle_event(payload)

    async def handle_event(self, event: dict[str, Any]) -> None:
        """Project a single parsed event dict.

        This is the unit-test seam - the test suite calls this directly with
        synthesised dicts to avoid having to drive a real SSE socket.
        """
        # ---- 1. Filter on kind ---------------------------------------
        kind = event.get("kind")
        if kind not in ("alter_message", "message_read"):
            return

        # ---- 2. Deduplicate on do_version ----------------------------
        do_version = event.get("version") or event.get("do_version")
        try:
            do_version_int = int(do_version) if do_version is not None else None
        except (TypeError, ValueError):
            logger.warning("inbox_writer: non-integer do_version=%r - dropping event", do_version)
            return
        if do_version_int is None:
            logger.warning("inbox_writer: alter_message frame missing do_version - dropping")
            return

        async with self._lock:
            if do_version_int <= self._last_seen_do_version:
                logger.debug(
                    "inbox_writer: dedupe drop do_version=%d <= checkpoint=%d",
                    do_version_int,
                    self._last_seen_do_version,
                )
                return

            # ---- 3. Project the row ----------------------------------
            # Both kinds ride the same DO stream and share the monotonic
            # ``do_version`` checkpoint above, so a read-marker at a given
            # ``do_version`` is deduped by the exact same gate as a message.
            if kind == "message_read":
                line = self._serialise_read(event, do_version_int)
            else:
                line = self._serialise(event, do_version_int)
            if line is None:
                return  # already logged

            # ---- 4. Rotate if oversized -------------------------------
            try:
                self._maybe_rotate()
            except OSError as exc:
                logger.warning("inbox_writer: rotation failed: %s", exc)
                # Continue anyway - better to grow past the threshold than
                # drop the event.

            # ---- 5. Atomic append + fsync -----------------------------
            try:
                self._append_line(line)
            except OSError as exc:
                logger.warning("inbox_writer: append failed: %s - dropping event", exc)
                return

            # ---- 6. Advance + persist checkpoint ---------------------
            self._last_seen_do_version = do_version_int
            try:
                self._save_checkpoint()
            except OSError as exc:
                logger.warning("inbox_writer: checkpoint save failed: %s", exc)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def _serialise(self, event: dict[str, Any], do_version: int) -> str | None:
        """Build the JSONL line for one ``alter_message`` event.

        Returns ``None`` if a required field is missing - the caller treats
        that as "drop and continue".
        """
        # The event envelope carries the message payload either at the top
        # level or nested under ``payload``. Try both so we are tolerant of
        # either shape during the wire-contract rollout.
        body = event.get("payload") if isinstance(event.get("payload"), dict) else event

        # The message payload carries the row id under ``payload.event_id``,
        # not a top-level ``id`` field. The event id is read from the payload,
        # preferring the explicit field when present.
        # We try the canonical name first, then fall back to top-level ``id``
        # / ``event_id`` for any legacy or future shape that surfaces it
        # elsewhere. Frames that omit the field entirely synthesise a stable
        # id from (sender, sent_at, body_md hash) so the message still lands
        # in the local cache instead of being dropped.
        message_id = (
            body.get("event_id") or event.get("event_id") or event.get("id") or body.get("id")
        )
        sender = body.get("sender_handle") or body.get("sender")
        body_md = body.get("body_md")
        thread_id = body.get("thread_id")
        received_at = (
            event.get("timestamp") or body.get("sent_at") or datetime.now(timezone.utc).isoformat()
        )

        if not message_id and sender and body_md is not None:
            # Synthesise a deterministic fallback id so pre-invariant frames
            # (which omit ``event_id``) still project into the inbox cache.
            # The server is the canonical id source; this is purely a
            # local-cache dedup key.
            sent_at_str = str(body.get("sent_at") or received_at)
            digest = hashlib.sha256(
                f"{sender}|{sent_at_str}|{body_md}".encode("utf-8")
            ).hexdigest()[:32]
            message_id = f"local-{digest}"

        if not message_id or not sender or body_md is None:
            logger.warning(
                "inbox_writer: alter_message missing required field "
                "id=%r sender=%r body_md_present=%s - dropping",
                message_id,
                sender,
                body_md is not None,
            )
            return None

        body_md_str = str(body_md)
        body_bytes = body_md_str.encode("utf-8")
        truncated = False
        if len(body_bytes) > MAX_BODY_MD_BYTES:
            # Trim at a code-point boundary and drop a marker the surfaces
            # can render if they care to. The server still holds the
            # untruncated original - this is only the local cache.
            body_md_str = body_bytes[:MAX_BODY_MD_BYTES].decode("utf-8", errors="ignore")
            body_md_str += (
                "\n\n[… body truncated at 64 KiB - see full message for complete content]"
            )
            truncated = True
            logger.warning(
                "inbox_writer: body_md exceeded %d bytes for id=%s - truncating local cache entry",
                MAX_BODY_MD_BYTES,
                message_id,
            )

        record = {
            "id": str(message_id),
            "sender": str(sender),
            "body_md": body_md_str,
            "thread_id": thread_id if thread_id else None,
            "received_at": str(received_at),
            "do_version": int(do_version),
        }
        if truncated:
            record["body_md_truncated"] = True
        return json.dumps(record, separators=(",", ":"), ensure_ascii=False)

    def _serialise_read(self, event: dict[str, Any], do_version: int) -> str | None:
        """Build the JSONL line for one ``message_read`` event.

        Projects a read-marker row ``{kind:"read", ids, read_at, do_version}``
        that the status-line reader folds into the unread count. Like
        :meth:`_serialise`, the payload may sit at the top level or nested
        under ``payload`` during the wire-contract rollout, so both shapes
        are tried. Returns ``None`` (drop and continue) if the event carries
        no message ids - a read marker over nothing is not worth a row.
        """
        body = event.get("payload") if isinstance(event.get("payload"), dict) else event

        ids = body.get("message_ids")
        if ids is None:
            ids = event.get("message_ids")
        read_at = (
            body.get("read_at")
            or event.get("read_at")
            or event.get("timestamp")
            or datetime.now(timezone.utc).isoformat()
        )

        if not isinstance(ids, (list, tuple)) or not ids:
            logger.warning("inbox_writer: message_read missing/empty message_ids - dropping")
            return None

        record = {
            "kind": "read",
            "ids": [str(i) for i in ids],
            "read_at": str(read_at),
            "do_version": int(do_version),
        }
        return json.dumps(record, separators=(",", ":"), ensure_ascii=False)

    # ------------------------------------------------------------------
    # File operations - atomic append, rotation, checkpoint
    # ------------------------------------------------------------------

    def _ensure_parent(self, path: Path) -> None:
        """Create the parent directory with mode ``0o700`` if missing."""
        parent = path.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Tighten perms in case the dir pre-existed with looser modes - best
        # effort, a chmod failure is non-fatal (e.g. on filesystems that
        # don't honour POSIX modes).
        with contextlib.suppress(OSError):
            os.chmod(parent, 0o700)

    def _append_line(self, line: str) -> None:
        """Atomically append ``line + '\\n'`` to the inbox file.

        Uses :func:`os.open` with ``O_APPEND | O_CREAT`` and mode ``0o600``,
        followed by an :func:`fcntl.flock` exclusive lock around the write.
        ``O_APPEND`` makes the write itself atomic against concurrent
        writers on POSIX, and ``flock`` serialises us against a hypothetical
        second daemon instance on the same XDG dir.
        """
        self._ensure_parent(self._inbox_path)

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(self._inbox_path, flags, 0o600)
        try:
            # Re-tighten perms (umask may have widened the mode at create
            # time, e.g. when umask is 0o000 in tests).
            with contextlib.suppress(OSError):
                os.fchmod(fd, 0o600)

            # Exclusive lock for cross-process safety on Linux/macOS.
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
        """Rotate the inbox file if it exceeds the threshold.

        Renames ``inbox.jsonl`` to ``inbox.jsonl.1`` (overwriting any
        existing rotated file). The next :meth:`_append_line` call recreates
        the primary file via ``O_CREAT``. No-op if the file does not yet
        exist or is below the threshold.
        """
        try:
            size = self._inbox_path.stat().st_size
        except FileNotFoundError:
            return
        if size <= self._rotation_threshold_bytes:
            return

        rotated = self._inbox_path.parent / INBOX_ROTATED_FILENAME
        # ``os.replace`` is atomic on POSIX and overwrites the destination
        # if present, which is exactly the single-generation rotation policy.
        os.replace(self._inbox_path, rotated)
        logger.info(
            "inbox_writer: rotated %s -> %s (size=%d > threshold=%d)",
            self._inbox_path,
            rotated,
            size,
            self._rotation_threshold_bytes,
        )

    # ------------------------------------------------------------------
    # Checkpoint persistence
    # ------------------------------------------------------------------

    async def _load_checkpoint(self) -> None:
        """Load ``last_seen_do_version`` from ``messaging.json`` (0 if absent)."""
        if not self._state_path.exists():
            self._last_seen_do_version = 0
            return
        try:
            raw = self._state_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning(
                "inbox_writer: unable to load checkpoint at %s: %s - starting from 0",
                self._state_path,
                exc,
            )
            self._last_seen_do_version = 0
            return
        if not isinstance(data, dict):
            self._last_seen_do_version = 0
            return
        try:
            self._last_seen_do_version = int(data.get("last_seen_do_version") or 0)
        except (TypeError, ValueError):
            self._last_seen_do_version = 0

    def _save_checkpoint(self) -> None:
        """Atomically write the checkpoint via tmp + ``os.replace``."""
        self._ensure_parent(self._state_path)
        payload = {
            "last_seen_do_version": int(self._last_seen_do_version),
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
    def last_seen_do_version(self) -> int:
        """Current checkpoint value (used by tests)."""
        return self._last_seen_do_version

    @property
    def inbox_path(self) -> Path:
        """Inbox JSONL path (used by tests)."""
        return self._inbox_path

    @property
    def state_path(self) -> Path:
        """Messaging checkpoint path (used by tests)."""
        return self._state_path
