"""DBusService - ``org.alter.Identity1`` on the session bus (Linux only).

Exposes the daemon's identity event stream on the Linux session D-Bus under
the bus name ``org.alter.Identity1`` and object path ``/org/alter/Identity``.
This is the surface that Waybar / GNOME Shell / KDE Plasmoids consume.

Interface
---------

::

    <interface name="org.alter.Identity1">
        <method name="Whoami">
            <arg name="handle" type="s" direction="out"/>
            <arg name="consent_tier" type="i" direction="out"/>
        </method>
        <method name="Ingest">
            <arg name="kind" type="s" direction="in"/>
            <arg name="payload_json" type="s" direction="in"/>
            <arg name="accepted" type="b" direction="out"/>
        </method>
        <signal name="IdentityEvent">
            <arg name="event_json" type="s"/>
        </signal>
    </interface>

``IdentityEvent`` is emitted for every ``identity.event`` bus publish. The
``event_json`` argument is the JSON-encoded event payload - consumers on the
desktop side typically JSON-decode it and render a minimal subset
(attunement, handle, kind) into a status-bar widget.

Optional dependency
-------------------

The service is gated on ``dbus-next`` (installed via
``alter-runtime[dbus]``). If the import fails (module missing, or running on
a non-Linux platform) the component logs a warning and sleeps on the
shutdown event - the daemon continues to run with its other surfaces.

Tests skip this component unless ``dbus-next`` is importable *and* a session
bus is available. CI on non-Linux platforms or on headless Linux runners
without ``dbus-daemon`` will hit the fallback no-op path.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import TYPE_CHECKING, Any

from alter_runtime.config import DaemonConfig
from alter_runtime.daemon import Component
from alter_runtime.sockets.unix import INGEST_KIND_WHITELIST
from alter_runtime.subscribers.bus import EventBus

if TYPE_CHECKING:
    from alter_runtime.config import Session

__all__ = ["DBusService", "INGEST_KIND_WHITELIST", "is_dbus_available"]

logger = logging.getLogger("alter_runtime.sockets.dbus")

BUS_NAME: str = "org.alter.Identity1"
OBJECT_PATH: str = "/org/alter/Identity"
INTERFACE_NAME: str = "org.alter.Identity1"

#: Egress topic - mirrors :mod:`alter_runtime.sockets.unix`.
EGRESS_TOPIC: str = "local.signal"


def is_dbus_available() -> bool:
    """Return True if ``dbus-next`` can be imported on this platform.

    We do the import here rather than at module top so that ``sockets/dbus.py``
    is importable on every platform - the component class has to exist even
    if the optional dependency isn't installed, so the daemon can log a
    helpful warning and continue.
    """
    if not sys.platform.startswith("linux"):
        return False
    try:
        import dbus_next  # noqa: F401
    except ImportError:
        return False
    return True


class DBusService(Component):
    """Exports identity events on the Linux session D-Bus.

    When the optional ``dbus-next`` dependency is unavailable the component's
    :meth:`run` logs a single warning and blocks on shutdown, so callers can
    register it unconditionally without breaking non-Linux installs.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`.
    bus:
        Shared :class:`EventBus` - subscribes to ``identity.event`` to emit
        ``IdentityEvent`` signals, and publishes to ``local.signal`` for
        Ingest() callers.
    session:
        Authenticated CLI :class:`Session` - used for the ``Whoami``
        method. Optional; Whoami returns empty strings when absent.
    bus_name, object_path, interface_name:
        Test hooks for overriding the D-Bus identifiers. Production code
        should leave these at their defaults.
    """

    name = "dbus"

    def __init__(
        self,
        config: DaemonConfig,
        bus: EventBus,
        session: Session | None = None,
        *,
        bus_name: str = BUS_NAME,
        object_path: str = OBJECT_PATH,
        interface_name: str = INTERFACE_NAME,
    ) -> None:
        self._config = config
        self._bus = bus
        self._session = session
        self._bus_name = bus_name
        self._object_path = object_path
        self._interface_name = interface_name
        self._stop_event = asyncio.Event()
        self._message_bus: Any = None
        self._interface: Any = None
        self._bus_handler: Any = None

    async def run(self) -> None:
        """Start the D-Bus service, or fall back to a quiet no-op."""
        if not is_dbus_available():
            logger.warning(
                "dbus unavailable (install `alter-runtime[dbus]` for the Linux desktop "
                "surface) - continuing without D-Bus export"
            )
            await self._stop_event.wait()
            return

        try:
            await self._start_dbus()
        except Exception as exc:
            logger.warning(
                "dbus failed to start (%s: %s) - continuing without D-Bus export",
                type(exc).__name__,
                exc,
            )
            await self._stop_event.wait()
            return

        logger.info(
            "dbus exported bus=%s path=%s interface=%s",
            self._bus_name,
            self._object_path,
            self._interface_name,
        )

        try:
            await self._stop_event.wait()
        finally:
            await self._teardown_dbus()

    async def stop(self) -> None:
        """Cooperative shutdown."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # D-Bus lifecycle (only reached when dbus_next is importable)
    # ------------------------------------------------------------------

    async def _start_dbus(self) -> None:
        """Connect to the session bus, publish the interface, subscribe to events."""
        # Local imports guarded by is_dbus_available(). Kept inside the
        # function so that test collection on non-Linux machines doesn't
        # choke when the optional dep is missing.
        from dbus_next.aio import MessageBus  # type: ignore[import-not-found]
        from dbus_next.service import (  # type: ignore[import-not-found]
            ServiceInterface,
            method,
            signal,
        )

        session = self._session
        egress_bus = self._bus
        loop = asyncio.get_running_loop()

        class _AlterIdentityInterface(ServiceInterface):
            """Concrete implementation of the ``org.alter.Identity1`` interface."""

            def __init__(self, interface_name: str) -> None:
                super().__init__(interface_name)

            @method()
            def Whoami(self) -> tuple[str, int]:  # type: ignore[override]
                if session is None:
                    return ("", 0)
                return (session.handle, int(session.consent_tier))

            @method()
            def Ingest(self, kind: s, payload_json: s) -> b:  # type: ignore[override,valid-type]  # noqa: F821
                try:
                    payload = json.loads(payload_json) if payload_json else {}
                except ValueError:
                    return False
                if not isinstance(payload, dict):
                    return False
                # Hardening: mirror the unix-socket
                # ``INGEST_KIND_WHITELIST`` gate - without it any session-
                # bus peer could publish arbitrary ``kind`` values onto the
                # in-process bus, including kinds reserved for trusted
                # internal subscribers (``git_commit``, ``ebpf_exec`` etc.)
                # which downstream consumers would treat as authentic.
                if kind not in INGEST_KIND_WHITELIST:
                    logger.warning(
                        "dbus rejecting ingest kind=%r (not in whitelist)",
                        kind,
                    )
                    return False
                # Publish from the loop thread - D-Bus calls happen on the
                # same asyncio loop in dbus-next's aio backend. We deliberately
                # fire-and-forget the publish task; the bus guarantees its own
                # in-memory ordering and nothing here awaits the result.
                loop.create_task(  # noqa: RUF006
                    egress_bus.publish(
                        EGRESS_TOPIC,
                        {"kind": kind, "payload": payload, "source": "dbus"},
                    )
                )
                return True

            @signal()
            def IdentityEvent(self, event_json: s) -> s:  # type: ignore[override,valid-type]  # noqa: F821
                return event_json

        self._message_bus = await MessageBus().connect()
        self._interface = _AlterIdentityInterface(self._interface_name)
        self._message_bus.export(self._object_path, self._interface)
        await self._message_bus.request_name(self._bus_name)

        async def _on_identity_event(payload: dict[str, Any]) -> None:
            if self._interface is None:
                return
            try:
                body = json.dumps(payload, separators=(",", ":"))
            except (TypeError, ValueError):
                logger.debug("dbus skipping non-JSON-serialisable event")
                return
            try:
                self._interface.IdentityEvent(body)
            except Exception as exc:  # pragma: no cover
                logger.warning("dbus signal emit failed: %s", exc)

        self._bus_handler = _on_identity_event
        self._bus.subscribe("identity.event", _on_identity_event)

    async def _teardown_dbus(self) -> None:
        if self._bus_handler is not None:
            self._bus.unsubscribe("identity.event", self._bus_handler)
            self._bus_handler = None
        if self._message_bus is not None:
            try:
                self._message_bus.disconnect()
            except Exception:  # pragma: no cover
                pass
            self._message_bus = None
        self._interface = None
