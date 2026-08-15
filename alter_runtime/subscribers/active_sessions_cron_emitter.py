"""ActiveSessionsCronEmitter - translates cron routine lifecycle events
into ``tool: "cron"`` active-session envelopes.

Sibling to :class:`ActiveSessionsWriter` (the
local-disk projection), :class:`ActiveSessionsGc` (the idle/terminated
sweeper), and :class:`ActiveSessionsDoPublisher` (the cross-host
publisher). This component does NOT touch disk or the network - it
listens for cron routine lifecycle events on the in-process
:class:`EventBus` and re-publishes them as ``identity.event`` envelopes
that the shipped writer already knows how to project.

Design contract:

* **Two emits per routine invocation.** ``cron.routine.started`` on the
  bus produces a ``session_started`` envelope (``version=0``,
  ``status="active"``); ``cron.routine.finished`` produces a
  ``session_ended`` envelope (``version=1``, ``status="complete"``).
  Both envelopes share the same ``session_id`` so reader dedup folds
  them as the same lifecycle.
* **No heartbeat.** Cron routines are short by design; the start/end
  pair is sufficient. Long-running routines (>5 min) MAY emit
  heartbeats in a follow-up.
* **No per-routine code.** The SDK handles every routine
  transparently. Routine authors never call into the active-sessions
  contract directly.
* **No emit without a handle.** When the CLI session store is
  absent (degraded daemon mode), the component idles - there is no
  handle to bind a session envelope to. This mirrors
  the writer's ``handle`` required-field guard.

Field mapping for ``tool: "cron"``:

* ``session_id`` - UUIDv4 minted per routine invocation. The publisher
  of ``cron.routine.started`` is expected to mint the UUID once and
  carry it through to the matching ``cron.routine.finished`` payload.
* ``working_on`` - first 200 chars of the routine name (e.g.
  ``"phone-link-knowledge-scan"``).
* ``files_touched`` - empty list. Cron routines do not touch files via
  a tracked surface.
* ``machine_id`` - the daemon's stable host id derivation, shared with
  :class:`TokenUsageClient` for consistency across alter-runtime
  surfaces.
* ``consent_tier`` - the session's declared consent tier, unless the
  routine config carries a per-routine override.
* ``started_at`` + ``last_activity`` - ISO 8601 UTC at envelope emit.
* ``provenance_class`` - literal ``"active_composition"``.

The component is additive - no existing cron logic is refactored.
When a real CronCreate fabric lands inside alter-runtime, the
publisher emits ``cron.routine.started`` / ``cron.routine.finished``
at the right call sites and this subscriber translates each into the
envelope contract above.

Daemon-side CronCreate emitter for active-session heartbeats.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable

from alter_runtime.config import DaemonConfig
from alter_runtime.daemon import Component

if TYPE_CHECKING:
    from alter_runtime.config import Session
    from alter_runtime.subscribers.bus import EventBus

__all__ = [
    "CRON_TOOL_NAME",
    "CRON_ROUTINE_STARTED_TOPIC",
    "CRON_ROUTINE_FINISHED_TOPIC",
    "MAX_WORKING_ON_CHARS",
    "ActiveSessionsCronEmitter",
]

logger = logging.getLogger("alter_runtime.subscribers.active_sessions_cron_emitter")

#: Tool name emitted in every envelope - matches the schema enum.
CRON_TOOL_NAME: str = "cron"

#: Bus topic published by the cron fabric on routine start.
CRON_ROUTINE_STARTED_TOPIC: str = "cron.routine.started"

#: Bus topic published by the cron fabric on routine finish.
CRON_ROUTINE_FINISHED_TOPIC: str = "cron.routine.finished"

#: Cap on the routine-name string emitted as ``working_on``.
MAX_WORKING_ON_CHARS: int = 200


def _derive_machine_id() -> str:
    """Return the same stable host identifier the rest of alter-runtime
    uses for cross-host de-duplication.

    Sources the singleton derivation from
    :func:`alter_runtime.clients.token_usage_client._derive_host_id` so a
    single host emits the same ``machine_id`` across every subscriber.
    """
    # Imported lazily to avoid a hard import-time dependency on the
    # token-usage client (which itself imports ``httpx`` and friends).
    from alter_runtime.clients.token_usage_client import _derive_host_id

    return _derive_host_id()


class ActiveSessionsCronEmitter(Component):
    """Subscribes to cron routine lifecycle events and emits envelopes.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`. Not consumed today; accepted for
        symmetry with sibling components and so future config knobs
        (heartbeat cadence, per-tool consent override) can be wired
        without changing the supervisor's registration signature.
    bus:
        Shared :class:`EventBus`. Subscribes to
        :data:`CRON_ROUTINE_STARTED_TOPIC` and
        :data:`CRON_ROUTINE_FINISHED_TOPIC`; publishes to
        ``identity.event`` so the shipped writer projects each envelope.
    session:
        The CLI session (handle + consent tier). ``None`` ->
        degraded mode (no envelope emit; the GC / writer / DO publisher
        already accept this path).
    machine_id_provider:
        Override the machine-id derivation. Tests inject a stub so they
        do not depend on the host's real ``/etc/machine-id``.
    now:
        Override the clock. Tests pass a frozen ``datetime`` provider.
    """

    name = "active_sessions_cron_emitter"

    def __init__(
        self,
        config: DaemonConfig,
        bus: EventBus,
        session: Session | None,
        *,
        machine_id_provider: Callable[[], str] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._config = config
        self._bus = bus
        self._session = session
        self._machine_id_provider = machine_id_provider or _derive_machine_id
        self._now: Callable[[], datetime] = now or (lambda: datetime.now(timezone.utc))

        self._stop_event = asyncio.Event()

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        if self._session is None:
            logger.info(
                "active_sessions_cron_emitter: no CLI session - "
                "idling. Routine lifecycle events on the bus will be "
                "ignored until `alter login` populates the session store."
            )
            try:
                await self._stop_event.wait()
            except asyncio.CancelledError:
                raise
            finally:
                logger.info("active_sessions_cron_emitter stopped (degraded)")
            return

        self._bus.subscribe(CRON_ROUTINE_STARTED_TOPIC, self.handle_routine_started)
        self._bus.subscribe(CRON_ROUTINE_FINISHED_TOPIC, self.handle_routine_finished)
        logger.info(
            "active_sessions_cron_emitter started handle=%s topics=%s,%s",
            self._session.handle,
            CRON_ROUTINE_STARTED_TOPIC,
            CRON_ROUTINE_FINISHED_TOPIC,
        )
        try:
            await self._stop_event.wait()
        except asyncio.CancelledError:
            raise
        finally:
            with contextlib.suppress(Exception):
                self._bus.unsubscribe(CRON_ROUTINE_STARTED_TOPIC, self.handle_routine_started)
            with contextlib.suppress(Exception):
                self._bus.unsubscribe(CRON_ROUTINE_FINISHED_TOPIC, self.handle_routine_finished)
            logger.info("active_sessions_cron_emitter stopped")

    async def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Event ingest
    # ------------------------------------------------------------------

    async def handle_routine_started(self, event: dict[str, Any]) -> None:
        """Translate a ``cron.routine.started`` bus event into a
        ``session_started`` envelope on ``identity.event``."""
        await self._emit(event, kind="session_started", status="active", version=0)

    async def handle_routine_finished(self, event: dict[str, Any]) -> None:
        """Translate a ``cron.routine.finished`` bus event into a
        ``session_ended`` envelope on ``identity.event``.

        ``version`` defaults to ``1`` (one bump above the matching
        ``session_started``). Publishers MAY override by carrying an
        explicit ``version`` field in the payload - useful if a future
        heartbeat path lands and routines are no longer guaranteed to
        be a two-emit lifecycle.
        """
        version_override = event.get("version") if isinstance(event, dict) else None
        try:
            version = int(version_override) if version_override is not None else 1
        except (TypeError, ValueError):
            version = 1
        await self._emit(event, kind="session_ended", status="complete", version=version)

    # ------------------------------------------------------------------
    # Envelope construction
    # ------------------------------------------------------------------

    async def _emit(
        self,
        event: dict[str, Any],
        *,
        kind: str,
        status: str,
        version: int,
    ) -> None:
        """Build + publish a single envelope on ``identity.event``."""
        if not isinstance(event, dict):
            logger.warning("active_sessions_cron_emitter: non-dict event payload - dropping")
            return
        if self._session is None:
            # ``run()`` already guards against this - defensive only.
            return

        session_id = event.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            logger.warning(
                "active_sessions_cron_emitter: missing session_id on %s payload - dropping",
                kind,
            )
            return

        routine_name = event.get("routine") or event.get("name") or event.get("working_on")
        working_on: str | None
        if isinstance(routine_name, str) and routine_name:
            working_on = routine_name[:MAX_WORKING_ON_CHARS]
        else:
            working_on = None

        # Honour a per-routine consent override iff valid; otherwise
        # fall back to the session's declared tier. The writer rejects
        # any tier outside 1..4 so we sanity-check here too.
        consent_override = event.get("consent_tier")
        consent_tier: int = self._session.consent_tier
        if consent_override is not None:
            try:
                consent_int = int(consent_override)
            except (TypeError, ValueError):
                consent_int = -1
            if consent_int in (1, 2, 3, 4):
                consent_tier = consent_int
            else:
                logger.warning(
                    "active_sessions_cron_emitter: invalid consent_tier override=%r - "
                    "falling back to session tier=%d",
                    consent_override,
                    self._session.consent_tier,
                )

        started_at = event.get("started_at")
        if not isinstance(started_at, str) or not started_at:
            started_at = self._now().isoformat()

        now_iso = self._now().isoformat()

        # Per the spec - each envelope mints a fresh UUID id; dedup is
        # by (id, version) on the writer side. session_id is the
        # lifecycle key that pairs start + end.
        envelope: dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "version": version,
            "kind": kind,
            "handle": self._session.handle,
            "tool": CRON_TOOL_NAME,
            "session_id": session_id,
            "machine_id": self._machine_id_provider(),
            "started_at": started_at,
            "last_activity": now_iso,
            "status": status,
            "provenance_class": "active_composition",
            "consent_tier": consent_tier,
            "working_on": working_on,
            "files_touched": [],
        }

        await self._bus.publish("identity.event", envelope)
        logger.debug(
            "active_sessions_cron_emitter emitted kind=%s status=%s "
            "session=%s version=%d working_on=%r",
            kind,
            status,
            session_id,
            version,
            working_on,
        )
