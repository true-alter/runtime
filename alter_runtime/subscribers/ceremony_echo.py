"""CeremonyEchoWriter - projects recognition events into a 72h echo state.

The CeremonyEchoWriter is a long-lived :class:`alter_runtime.daemon.Component`
that sits next to :class:`InboxWriter` on the SSE bus. Where the InboxWriter
projects the full inbox JSONL, the CeremonyEchoWriter watches for
recognition-class events and maintains a tiny single-file state - the
most-recent recognition event, its declared kind, and the absolute timestamp
at which the echo expires (72 h after the event).

A consumer (the ``alter room`` CLI surface, or any future shell-greeting
renderer) reads ``ceremony-echo.json`` from the runtime data directory at
each invocation and renders an echo line iff the current time is before the
expiry. The user cannot author the echo, cannot extend it, cannot dismiss it
early. The echo is observation, not affordance.

Filtered content_types
   * ``x-alter-recognition`` - the canonical recognition event
   * ``x-alter-ceremony``    - broader ceremony class (Seat, Mirror, Discovery,
                               Accord) that should also surface a 72 h echo
   Both are members of the server's allowed content-type set.

The component is designed to swallow and log all errors so a single
malformed frame, full disk, or transient SSE disconnect cannot crash the
daemon supervisor. Like InboxWriter, the supervisor will restart on
:meth:`run` exceptions but :meth:`handle_event` only ever logs and returns.

It filters the frame stream for the ceremony-echo content_types and renders
a windowed echo to shell-greeting consumers.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from alter_runtime.config import DaemonConfig, data_dir
from alter_runtime.daemon import Component
from alter_runtime.subscribers.sse import SSEFrame

if TYPE_CHECKING:
    from alter_runtime.config import Session

__all__ = [
    "CEREMONY_ECHO_FILENAME",
    "DEFAULT_ECHO_DURATION",
    "RECOGNITION_CONTENT_TYPES",
    "CeremonyEchoWriter",
]

logger = logging.getLogger("alter_runtime.subscribers.ceremony_echo")

#: Filename for the ceremony-echo state (within ``data_dir()``).
CEREMONY_ECHO_FILENAME: str = "ceremony-echo.json"

#: How long an echo remains visible after the event arrives. Locked at
#: 72 h - long enough to catch the user across multiple shell sessions
#: and a working week's natural cadence, short enough that the echo
#: doesn't become wallpaper.
DEFAULT_ECHO_DURATION: timedelta = timedelta(hours=72)

#: Content_type values that produce a ceremony echo. Both are in
#: the server's allowed content-type set; if that taxonomy expands,
#: this set should be revisited.
RECOGNITION_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "x-alter-recognition",
        "x-alter-ceremony",
    }
)


class CeremonyEchoWriter(Component):
    """Tails the per-handle SSE stream and persists the most-recent
    recognition-class event to ``ceremony-echo.json`` for shell-greeting
    consumers.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`. Reserved for future use; not consulted
        in the current implementation.
    session:
        Authenticated CLI session. Used for log context only - the
        bus delivers the per-handle frames, the writer does not need to
        construct an SSE URL itself.
    echo_path:
        Override the state file path. Tests use this to redirect writes
        to a ``tmp_path`` fixture without touching ``$HOME``.
    echo_duration:
        Override the echo-visible window. Tests pass a short duration to
        exercise the expiry path without wall-clock waits.
    """

    name = "ceremony_echo"

    def __init__(
        self,
        config: DaemonConfig,
        session: Session,
        *,
        echo_path: Path | None = None,
        echo_duration: timedelta = DEFAULT_ECHO_DURATION,
    ) -> None:
        self._config = config
        self._session = session
        self._echo_duration = echo_duration

        self._echo_path: Path = (
            echo_path if echo_path is not None else data_dir() / CEREMONY_ECHO_FILENAME
        )

        self._lock = asyncio.Lock()
        self._shutdown_event = asyncio.Event()

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Long-lived idle loop. The bus is the actual ingress path -
        :meth:`handle_raw_frame` is the seam the supervisor wires into
        ``identity.frame``. We just block on shutdown so the supervisor
        can register us as a peer of InboxWriter without opening any
        sockets of our own.
        """
        logger.info(
            "ceremony_echo started handle=%s echo_path=%s",
            self._session.handle,
            self._echo_path,
        )
        try:
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            raise
        finally:
            logger.info("ceremony_echo stopped handle=%s", self._session.handle)

    async def stop(self) -> None:
        """Cooperative shutdown - release the run loop."""
        self._shutdown_event.set()

    # ------------------------------------------------------------------
    # Frame ingest - public surface for the SSE bus and tests
    # ------------------------------------------------------------------

    async def handle_raw_frame(self, frame: SSEFrame) -> None:
        """Parse an SSE frame and dispatch to :meth:`handle_event`.

        Errors are logged and swallowed - the supervisor never sees a
        write failure (per the project convention "swallow and continue").
        """
        try:
            payload = frame.json
        except (ValueError, json.JSONDecodeError) as exc:
            logger.warning("ceremony_echo: malformed SSE frame body: %s", exc)
            return
        if not isinstance(payload, dict):
            logger.warning("ceremony_echo: SSE frame payload is not a dict: %r", type(payload))
            return
        await self.handle_event(payload)

    async def handle_event(self, event: dict[str, Any]) -> None:
        """Project a single parsed IdentityEvent dict.

        This is the unit-test seam - the test suite calls this directly
        with synthesised dicts to avoid having to drive a real SSE socket.

        We accept ``alter_message`` events whose payload's ``content_type``
        is in :data:`RECOGNITION_CONTENT_TYPES`. Other kinds and other
        content_types are silently dropped (the InboxWriter handles the
        full inbox projection - we only care about the echo subset).
        """
        # ---- 1. Filter on kind ---------------------------------------
        if event.get("kind") != "alter_message":
            return

        # The DO emits the IdentityEvent envelope with the message
        # payload either at the top level or nested under ``payload``.
        # Tolerate both shapes during the wire-contract rollout - same
        # tolerance pattern as InboxWriter.
        body = event.get("payload") if isinstance(event.get("payload"), dict) else event

        content_type = body.get("content_type")
        if content_type not in RECOGNITION_CONTENT_TYPES:
            return

        # ---- 2. Extract the echo-state fields ------------------------
        sender = body.get("sender_handle") or body.get("sender")
        body_md = body.get("body_md")
        message_id = event.get("id") or body.get("id")
        received_at = (
            event.get("timestamp") or body.get("sent_at") or datetime.now(timezone.utc).isoformat()
        )

        if not sender:
            logger.warning(
                "ceremony_echo: %s frame missing sender - dropping (id=%r)",
                content_type,
                message_id,
            )
            return

        # ---- 3. Compute expiry --------------------------------------
        # Anchor the expiry on the event's own timestamp where possible
        # so a delayed delivery does not extend the user-visible window.
        try:
            event_time = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            event_time = datetime.now(timezone.utc)
        expires_at = (event_time + self._echo_duration).isoformat()

        # ---- 4. Persist atomically ----------------------------------
        state = {
            "schema_version": 1,
            "last_recognition": {
                "sender": sender,
                "kind": content_type,
                "body_md": str(body_md) if body_md is not None else "",
                "received_at": received_at,
            },
            "expires_at": expires_at,
        }

        async with self._lock:
            try:
                self._write_state(state)
            except OSError as exc:
                logger.warning(
                    "ceremony_echo: state write failed: %s - dropping event",
                    exc,
                )
                return

        logger.info(
            "ceremony_echo: persisted %s from %s expires_at=%s",
            content_type,
            sender,
            expires_at,
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _write_state(self, state: dict[str, Any]) -> None:
        """Atomic-rename a JSON state file with mode 0o600.

        The temp file is created in the same directory as the target so
        the rename is atomic (cross-device renames are not). Parent
        directory is created with mode 0o700 if absent.
        """
        target = self._echo_path
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=str(target.parent),
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as fh:
            tmp_path = Path(fh.name)
            try:
                json.dump(state, fh, separators=(",", ":"), ensure_ascii=False)
                fh.flush()
                os.fsync(fh.fileno())
            except Exception:
                with contextlib.suppress(OSError):
                    tmp_path.unlink()
                raise

        try:
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, target)
        except OSError:
            with contextlib.suppress(OSError):
                tmp_path.unlink()
            raise
