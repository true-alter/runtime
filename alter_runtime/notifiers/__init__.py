"""Notifiers - local fan-out surfaces that render identity events to the user's desktop.

Each notifier is a :class:`alter_runtime.daemon.Component` that subscribes to
the shared :class:`alter_runtime.subscribers.bus.EventBus` and renders a
matching event to a platform-native surface: freedesktop notifications on
Linux, NSUserNotificationCenter on macOS, toast-XML on Windows. The notifier
tier sits downstream of the InboxWriter projection - they consume the same
bus topic, so a notifier failure cannot starve the inbox write path and vice
versa.
"""

from alter_runtime.notifiers.desktop import DesktopNotifier

__all__ = ["DesktopNotifier"]
