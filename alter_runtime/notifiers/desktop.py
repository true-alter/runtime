"""DesktopNotifier - freedesktop toast on inbound ``alter_message``.

Subscribes to the same ``identity.event`` stream the :class:`InboxWriter`
drains and shells out to ``/usr/bin/notify-send`` on each inbound message
addressed to the local ``~handle``. Designed for an awesomewm rig but
will work on any freedesktop.org-compliant desktop (GNOME, KDE, sway, i3,
bspwm, awesome, dwm + dunst, etc.) without configuration.

Design choices
--------------

* **Native feel.** Uses ``notify-send`` rather than the ``dbus-next`` path so
  existing notification daemons (dunst, mako, the GNOME/KDE services) pick up
  the message through the standard ``org.freedesktop.Notifications`` bus
  interface. The flags passed match a messaging-app toast: ``--app-name`` +
  ``--category="im.received"`` + ``--icon=mail-unread`` + a ``sound-name``
  hint so the user's notification daemon plays the system message chime.
* **Non-intrusive.** ``--urgency=normal`` (not critical) means the toast is
  dismissible and does not steal focus. ``--expire-time=8000`` keeps it on
  screen for 8s, long enough to read the first line without becoming a
  permanent shade.
* **Swallow and continue.** Every failure class (``notify-send`` missing, no
  ``DISPLAY``/``WAYLAND_DISPLAY``, dbus not running, subprocess crash) is
  logged at warning level and dropped. The notifier is a convenience surface;
  the inbox JSONL is the source of truth and already landed on disk by the
  time we see the event.
* **Privacy invariants.** The notifier is a one-way render. It
  never emits a read receipt, presence beacon, or typing indicator back onto
  the bus. The only side effect is the toast itself.

The component ignores events whose ``kind`` is not ``"alter_message"`` and
events addressed to a different recipient (e.g. room-wide broadcasts with an
explicit ``recipient_handle`` that is not the local session handle).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
from typing import TYPE_CHECKING, Any

from alter_runtime.daemon import Component

if TYPE_CHECKING:
    from alter_runtime.config import DaemonConfig, Session
    from alter_runtime.subscribers.bus import EventBus

__all__ = ["DesktopNotifier"]

logger = logging.getLogger("alter_runtime.notifiers.desktop")

#: Absolute path to ``notify-send``. Hard-coded to match the flag set validated
#: against libnotify 0.8.x; a PATH lookup at run-time would be more flexible
#: but would also silently pick up stub binaries on sandboxed hosts.
NOTIFY_SEND_BIN: str = "/usr/bin/notify-send"

#: Maximum characters of ``body_md`` rendered in the toast body. Kept short so
#: the notification stays a glance rather than a read. The InboxWriter / CLI
#: ``alter msg read`` surfaces render the full body.
BODY_PREVIEW_CHARS: int = 140

#: Default toast dwell time in milliseconds (8s - long enough to read, short
#: enough that it is gone before the user finishes a cigarette).
EXPIRE_TIME_MS: int = 8000

#: App-name displayed in the notification centre. Matches the brand wordmark.
APP_NAME: str = "Alter"

#: FDO category; ``im.received`` is the canonical message-arrival category so
#: notification daemons (dunst et al.) can route it to a chat rule.
CATEGORY: str = "im.received"

#: libnotify icon name; ``mail-unread`` is present in every freedesktop icon
#: theme we care about. Falls back silently if absent.
ICON: str = "mail-unread"

#: Sound hint - ``message-new-instant`` is the sound-theme canonical event
#: for an incoming IM. Most themes map it to a short chime.
SOUND_NAME: str = "message-new-instant"

#: Markdown stripping - good enough for toast previews. Removes emphasis
#: markers, headings, code fences, inline links, and collapses newlines.
_MD_BOLD_ITALIC = re.compile(r"(\*{1,3}|_{1,3})(.+?)\1")
_MD_CODE_INLINE = re.compile(r"`([^`]+)`")
_MD_CODE_FENCE = re.compile(r"```[\s\S]*?```")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_MD_HEADING = re.compile(r"^#{1,6}\s+", re.MULTILINE)
_MD_BLOCKQUOTE = re.compile(r"^>\s?", re.MULTILINE)
_WHITESPACE = re.compile(r"\s+")


def _strip_markdown(text: str) -> str:
    """Flatten a Markdown string to a single-line toast body."""
    if not text:
        return ""
    text = _MD_CODE_FENCE.sub("", text)
    text = _MD_CODE_INLINE.sub(r"\1", text)
    text = _MD_LINK.sub(r"\1", text)
    text = _MD_HEADING.sub("", text)
    text = _MD_BLOCKQUOTE.sub("", text)
    text = _MD_BOLD_ITALIC.sub(r"\2", text)
    text = _WHITESPACE.sub(" ", text).strip()
    return text


def _truncate(text: str, limit: int = BODY_PREVIEW_CHARS) -> str:
    """Truncate ``text`` to ``limit`` chars with an ellipsis marker."""
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


class DesktopNotifier(Component):
    """Renders inbound ``alter_message`` events to a freedesktop toast.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`. Not currently consulted - kept for
        future opt-in fields (urgency override, custom icon theme, etc.).
    session:
        Authenticated CLI session. ``session.handle`` is used to
        filter messages addressed to a different recipient.
    bus:
        The shared :class:`EventBus`. Subscribes to ``identity.event``.
    notify_send_bin:
        Override the path to ``notify-send``. Tests inject a stub here.
    """

    name = "desktop_notifier"

    def __init__(
        self,
        config: DaemonConfig,
        session: Session,
        bus: EventBus,
        *,
        notify_send_bin: str = NOTIFY_SEND_BIN,
    ) -> None:
        self._config = config
        self._session = session
        self._bus = bus
        self._notify_send_bin = notify_send_bin
        self._stop_event = asyncio.Event()
        #: Monotonic count of toasts actually rendered (test introspection).
        self._toasts_sent: int = 0
        #: Monotonic count of send failures (test introspection).
        self._send_failures: int = 0

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        # Refuse to pretend we are running a notifier if the binary is missing
        # or no graphical session exists - log loudly once, then sleep. The
        # supervisor will keep us alive (so a later ``DISPLAY`` export picks
        # up) without us spamming a failed subprocess on every message.
        if not self._has_usable_backend():
            logger.warning(
                "desktop_notifier: notify-send or graphical session unavailable; "
                "notifier started in no-op mode (messages still reach inbox.jsonl)"
            )

        self._bus.subscribe("identity.event", self._on_event)
        logger.info(
            "desktop_notifier started handle=%s bin=%s",
            self._session.handle,
            self._notify_send_bin,
        )
        try:
            await self._stop_event.wait()
        finally:
            self._bus.unsubscribe("identity.event", self._on_event)
            logger.info(
                "desktop_notifier stopped handle=%s toasts=%d failures=%d",
                self._session.handle,
                self._toasts_sent,
                self._send_failures,
            )

    async def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Bus callback
    # ------------------------------------------------------------------

    async def _on_event(self, event: Any) -> None:
        """Filter for alter_message addressed to the local handle and render."""
        if not isinstance(event, dict):
            return
        if event.get("kind") != "alter_message":
            return

        # Accept the same dual-shape the InboxWriter does: payload may be
        # nested or flat. Prefer the nested body because the DO emitter puts
        # the message fields there.
        body = event.get("payload") if isinstance(event.get("payload"), dict) else event

        # Recipient filter - a frame with an explicit recipient that isn't us
        # is probably a room broadcast or a multi-cast and the desktop should
        # not light up. Frames without a recipient field are treated as
        # implicitly-for-us (the DO only emits messages on the owner's stream).
        recipient = body.get("recipient_handle") or body.get("recipient")
        if recipient and recipient != self._session.handle:
            return

        sender = body.get("sender_handle") or body.get("sender") or "~unknown"
        body_md = body.get("body_md") or ""
        preview = _truncate(_strip_markdown(str(body_md)))

        await self._toast(sender=str(sender), preview=preview)

    # ------------------------------------------------------------------
    # notify-send invocation
    # ------------------------------------------------------------------

    async def _toast(self, *, sender: str, preview: str) -> None:
        """Fire a ``notify-send`` with the canonical messaging flags."""
        if not self._has_usable_backend():
            # Logged once in run(); stay quiet here to avoid spam.
            return

        title = sender
        body = preview or "(no body)"

        argv = [
            self._notify_send_bin,
            f"--app-name={APP_NAME}",
            "--urgency=normal",
            f"--expire-time={EXPIRE_TIME_MS}",
            f"--category={CATEGORY}",
            f"--icon={ICON}",
            f"--hint=string:sound-name:{SOUND_NAME}",
            title,
            body,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            except (TimeoutError, asyncio.TimeoutError):
                # Kill a stuck notify-send rather than leaking the subprocess.
                proc.kill()
                await proc.wait()
                self._send_failures += 1
                logger.warning("desktop_notifier: notify-send timed out; killed child")
                return
        except FileNotFoundError:
            self._send_failures += 1
            logger.warning(
                "desktop_notifier: %s not found - set ALTER_DESKTOP_NOTIFIER_DISABLED=1 "
                "to silence this warning",
                self._notify_send_bin,
            )
            return
        except Exception as exc:  # noqa: BLE001 - swallow every class of OS failure
            self._send_failures += 1
            logger.warning("desktop_notifier: spawn failed: %s", exc)
            return

        if proc.returncode != 0:
            self._send_failures += 1
            err = (stderr or b"").decode("utf-8", errors="replace").strip()
            logger.warning(
                "desktop_notifier: notify-send exit=%d stderr=%r",
                proc.returncode,
                err[:200],
            )
            return

        self._toasts_sent += 1
        logger.debug("desktop_notifier: toast sent sender=%s", sender)

    # ------------------------------------------------------------------
    # Environment probes
    # ------------------------------------------------------------------

    def _has_usable_backend(self) -> bool:
        """Best-effort check that notify-send can actually post a toast.

        Does not guarantee success - a running dbus session without a
        notification daemon will still accept the call but drop it silently -
        but catches the obvious cold-fail cases so we log once rather than
        per-message.
        """
        if not shutil.which(self._notify_send_bin) and not os.path.exists(self._notify_send_bin):
            return False
        # Either X11 or Wayland session indicator is fine. Headless systemd
        # services inherit ``XDG_RUNTIME_DIR`` but not ``DISPLAY``; dbus over
        # the user bus works without either, so this is a soft heuristic.
        if (
            not os.environ.get("DISPLAY")
            and not os.environ.get("WAYLAND_DISPLAY")
            and not os.environ.get("DBUS_SESSION_BUS_ADDRESS")
        ):
            return False
        return True

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def toasts_sent(self) -> int:
        """Count of toasts actually rendered (used by tests)."""
        return self._toasts_sent

    @property
    def send_failures(self) -> int:
        """Count of ``notify-send`` spawn / exit failures (used by tests)."""
        return self._send_failures
