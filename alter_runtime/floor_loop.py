"""FloorLoop: supervised daemon-side floor preflight component.

Sister to ``UpdateLoop``: the update loop
keeps the daemon fresh by polling the release manifest; the floor loop
keeps the daemon honest by polling the server-side floor and gating the
local RPC surface when the running version slips below it.

**Cadence.**

* Immediate preflight on daemon start.
* Every ``poll_interval_seconds`` afterwards (default 24h, ±5% jitter for
  fingerprint hygiene; same window as ``UpdateLoop``).

**State surface.**

The loop holds a single :class:`FloorState` shared with the Unix-socket
server. The state carries:

* The most recent :class:`FloorVerdict` (or ``None`` until the first poll
  completes; initial state is "permit, unknown" so the daemon never blocks
  during cold start).
* A monotonic counter of successful polls (used by tests + telemetry).
* A monotonic counter of failed polls.

The socket server reads ``state.is_locked()`` on every authenticated method.
Locked means "the verdict is below floor"; permit-with-warn or unknown
state never locks.

**Safety-critical carve-out.**

The state object exposes :meth:`allow_safety_critical` so the socket
server can let through ``ingest`` calls whose payload carries
``urgency: "critical"``. The carve-out is enforced at the socket layer,
not here, but lives close to the state object so the policy is single-
sourced.

**No new dependencies.** ``httpx``, ``asyncio``, and stdlib are sufficient.
The floor preflight module owns all I/O.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from typing import Any

from alter_runtime import __version__ as RUNTIME_VERSION
from alter_runtime.config import DaemonConfig
from alter_runtime.daemon import Component
from alter_runtime.floor_preflight import (
    FloorVerdict,
    preflight,
)

__all__ = [
    "FloorLoop",
    "FloorState",
    "SAFETY_CRITICAL_INGEST_KINDS",
    "SAFETY_CRITICAL_INGEST_URGENCIES",
    "is_safety_critical_call",
]


logger = logging.getLogger("alter_runtime.floor_loop")


# ---------------------------------------------------------------------------
# Safety-critical comms allowlist
# ---------------------------------------------------------------------------
#
# The MCP surface preflight MUST permit ``alter_ingest`` and
# ``alter_escalations`` calls when the payload carries ``urgency: critical``,
# even below floor. Floor MUST NOT block emergency comms.
#
# The local Unix-socket surface speaks JSON-RPC, not MCP. The closest
# faithful carry-over is:
#
# * ``ingest`` method calls whose payload includes ``urgency: critical`` or
#   ``urgency: emergency`` (both treated as critical-class to widen the
#   safety net).
# * ``escalate`` / ``escalation`` ingest kinds: pre-allowed regardless of
#   urgency tag, because the kind name is itself the critical signal.
#
# This is the daemon-local extension of the safety-critical carve-out, not
# a re-interpretation. If a new RPC-layer escalation verb lands in a
# follow-up phase, the allowlist below is the single edit point; keep the
# carve-out in sync with whatever the public MCP surfaces expose.

#: Ingest kinds that bypass the floor gate regardless of urgency tag.
#: Empty in v1; the runtime's local ingest kind whitelist is consent-
#: scoped and doesn't expose an escalation verb. Reserved for forward
#: compatibility with other local MCP surfaces once their floor
#: preflight lands.
SAFETY_CRITICAL_INGEST_KINDS: frozenset[str] = frozenset()

#: Urgency tags that promote an ``ingest`` payload to safety-critical class.
SAFETY_CRITICAL_INGEST_URGENCIES: frozenset[str] = frozenset({"critical", "emergency"})


def is_safety_critical_call(method: str, payload: dict[str, Any] | None) -> bool:
    """Return ``True`` when the local RPC call MUST bypass the floor gate.

    Applied at the Unix-socket dispatch layer after the auth handshake. The
    function is permissive by design; the cost of an unnecessary permit on
    a safety-critical-looking call is far lower than the cost of blocking a
    real emergency revoke / panic / kill-switch payload.

    Method-level allowlist:

    * ``ping``, ``auth``: always permitted (pre-auth handshake, not gated).
    * ``ingest`` with ``payload['urgency']`` in
      :data:`SAFETY_CRITICAL_INGEST_URGENCIES`: promoted to safety-critical.
    * ``ingest`` with ``kind`` in :data:`SAFETY_CRITICAL_INGEST_KINDS`:
      promoted regardless of payload.
    """
    if method in ("ping", "auth"):
        return True
    if method != "ingest":
        return False
    if not isinstance(payload, dict):
        return False
    kind = payload.get("kind")
    if isinstance(kind, str) and kind in SAFETY_CRITICAL_INGEST_KINDS:
        return True
    # Check both top-level urgency (on the request) and nested urgency
    # (inside the ingest payload dict). Either signal flips the carve-out.
    top_urgency = payload.get("urgency")
    if isinstance(top_urgency, str) and top_urgency.lower() in SAFETY_CRITICAL_INGEST_URGENCIES:
        return True
    nested = payload.get("payload")
    if isinstance(nested, dict):
        nested_urgency = nested.get("urgency")
        if (
            isinstance(nested_urgency, str)
            and nested_urgency.lower() in SAFETY_CRITICAL_INGEST_URGENCIES
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# FloorState
# ---------------------------------------------------------------------------


@dataclass
class FloorState:
    """Shared mutable state for the floor gate.

    The :class:`FloorLoop` writes; the :class:`UnixSocketServer` reads. No
    lock is needed because asyncio is single-threaded; the read is atomic
    relative to the write (Python dataclass attribute assignment is a single
    bytecode op for the reference-store case).
    """

    last_verdict: FloorVerdict | None = None
    successful_polls: int = 0
    failed_polls: int = 0
    #: Set to ``True`` after the first successful preflight. Until then the
    #: socket server treats the state as "unknown → permit" so cold-start
    #: never blocks.
    has_polled: bool = False

    def is_locked(self) -> bool:
        """Return ``True`` when the daemon is below floor.

        ``False`` covers both "above floor" and "unknown / no doc yet"; the
        server-side gate is authoritative for unknown cases, so the daemon
        does not block locally without a verdict.
        """
        if self.last_verdict is None:
            return False
        return not self.last_verdict.ok

    def envelope_payload(self) -> dict[str, Any] | None:
        """Return the canonical envelope dict for the current state.

        Returns ``None`` when not locked. The dict is byte-shape-equal to
        the server reject body and the CLI envelope.
        """
        if not self.is_locked() or self.last_verdict is None:
            return None
        envelope = self.last_verdict.envelope
        if envelope is None:
            return None
        return envelope.to_dict()


# ---------------------------------------------------------------------------
# FloorLoop component
# ---------------------------------------------------------------------------


@dataclass
class _LoopConfig:
    """Internal config snapshot; keeps the run loop pure."""

    api_base: str
    poll_interval_seconds: float
    initial_jitter_seconds: float = 0.0


class FloorLoop(Component):
    """Supervised component that drives :class:`FloorState`.

    Parameters
    ----------
    config:
        Daemon config; only ``mcp_fallback_endpoint`` is consulted. The
        floor lives at ``/api/v1/clients/min-version`` on the same host.
    state:
        Shared :class:`FloorState` written by the loop and read by the
        socket server.
    poll_interval_seconds:
        Override for the 24h default. Tests inject a tiny value to
        exercise the multi-poll path.
    api_base:
        Override the API base derived from ``config``. Tests inject a
        ``httpx.MockTransport`` URL.
    rng:
        Optional ``random.Random`` for deterministic jitter in tests.
    """

    name = "floor_loop"

    #: Default 24h cadence, same value as ``UpdateLoop``.
    DEFAULT_POLL_INTERVAL_SECONDS: float = 24 * 60 * 60

    #: Jitter window (±5 %) on the poll interval. Same magnitude as
    #: ``UpdateLoop`` so the two periodic outbound calls stay loosely
    #: phased relative to each other.
    JITTER_FRACTION: float = 0.05

    def __init__(
        self,
        config: DaemonConfig,
        state: FloorState,
        *,
        poll_interval_seconds: float | None = None,
        api_base: str | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self._state = state
        self._rng = rng or random.Random()
        interval = (
            poll_interval_seconds
            if poll_interval_seconds is not None
            else self.DEFAULT_POLL_INTERVAL_SECONDS
        )
        base = api_base if api_base is not None else self._derive_api_base(config)
        self._cfg = _LoopConfig(
            api_base=base,
            poll_interval_seconds=float(interval),
        )

    @staticmethod
    def _derive_api_base(config: DaemonConfig) -> str:
        """Derive the API base from ``mcp_fallback_endpoint``.

        ``mcp_fallback_endpoint`` is ``https://api.truealter.com/api/v1/mcp``
        by default. We strip the ``/api/v1/mcp`` suffix to recover the
        bare API base. If the endpoint shape changes the floor preflight
        URL still resolves cleanly through
        :func:`floor_preflight._resolve_floor_url`.
        """
        endpoint = (config.mcp_fallback_endpoint or "").rstrip("/")
        for tail in ("/api/v1/mcp", "/api/v1", "/v1/mcp", "/v1"):
            if endpoint.endswith(tail):
                return endpoint[: -len(tail)]
        return endpoint or "https://api.truealter.com"

    async def run(self) -> None:
        """Run the poll loop until cancelled."""
        logger.info(
            "floor_loop starting interval=%.0fs api_base=%s",
            self._cfg.poll_interval_seconds,
            self._cfg.api_base,
        )
        await self._tick()
        while True:
            wait = self._next_wait()
            try:
                await asyncio.sleep(wait)
            except asyncio.CancelledError:
                raise
            await self._tick()

    def _next_wait(self) -> float:
        """Compute the next sleep duration with ±5 % jitter."""
        base = self._cfg.poll_interval_seconds
        if base <= 0:
            return 0.0
        delta = base * self.JITTER_FRACTION
        # rng.uniform(-delta, +delta) yields the jitter offset; clamp to
        # avoid a non-positive sleep.
        jitter = self._rng.uniform(-delta, delta)
        return max(0.0, base + jitter)

    async def _tick(self) -> None:
        """One preflight pass. Updates ``state`` regardless of outcome."""
        try:
            verdict = await preflight(
                api_base=self._cfg.api_base,
                daemon_version=RUNTIME_VERSION,
            )
        except Exception as exc:  # pragma: no cover - preflight catches its own
            logger.warning("floor_loop_preflight_unhandled err=%s", exc)
            self._state.failed_polls += 1
            return

        self._state.last_verdict = verdict
        self._state.has_polled = True
        if verdict.envelope is not None:
            logger.warning(
                "floor_loop verdict=below-floor version=%s min_version=%s upgrade=%s",
                verdict.envelope.client_version,
                verdict.envelope.min_version,
                verdict.envelope.upgrade_cmd,
            )
        else:
            logger.info(
                "floor_loop verdict=ok diagnostic=%s warn=%s",
                verdict.diagnostic,
                verdict.warn or "",
            )
        if verdict.diagnostic in (
            "no-cache-no-fetch-permit",
            "stale-cache-permit-warn",
        ):
            self._state.failed_polls += 1
        else:
            self._state.successful_polls += 1
