"""Local-transport surfaces exposed by the alter-runtime daemon.

The daemon exposes identity state on three local transports in
parallel:

* **Unix socket** at ``$XDG_RUNTIME_DIR/alter.sock`` (Linux) / Application
  Support (macOS) - used by editor hooks, shell scripts, and arbitrary
  language-agnostic callers. Line-delimited JSON-RPC.
* **D-Bus** on the session bus (Linux only, optional dependency on
  ``dbus-next``) - used by GNOME / KDE / Waybar modules and any desktop
  tooling that speaks D-Bus natively.
* **HTTP/SSE loopback** - not yet implemented.

Each transport is a :class:`alter_runtime.daemon.Component` that registers
with the supervisor and shares the single-instance :class:`EventBus`.
"""

from alter_runtime.sockets.unix import UnixSocketServer

__all__ = ["UnixSocketServer"]
