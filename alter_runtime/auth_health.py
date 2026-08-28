"""Daemon auth health - make a dead session a distinguishable state.

Why this exists
---------------

The daemon loads a :class:`~alter_runtime.config.Session` once at boot and
holds it. When that session dies server-side, every authenticated subscriber
starts taking 401s and backing off, and the only place that says so is the
journal. Silence and health look identical from outside, so the member finds
out by accident, hours later, trying to log in for something unrelated.
The observed incident ran 155 consecutive publisher failures under unbounded
backoff and 203 HTTP 401s in one trailing hour with nothing surfaced.

This module is the surfacing rung. It does not fix, refresh, or re-mint
anything: it turns the auth outcomes the daemon *already observes* into a
state a member can read, from the CLI and from the daemon's own state file,
without opening a journal.

What it observes
----------------

Every authenticated component that already reports a 401 into
:class:`~alter_runtime.subscribers.session_refresher.RefreshTrigger` also
records the outcome here, on the same call, plus its successes. That is the
whole input: real request outcomes against the backend, never a guess from a
complaining surface about its own plumbing.

Why outcomes and not the session file
-------------------------------------

A session file on disk says a credential exists, not that it is accepted; an
empty keyring says this daemon cannot read one, not that the member is logged
out. The only thing that answers "is this session alive" is an authenticated
request that succeeds or fails, which is exactly what is recorded here.

Split-brain is a first-class state
----------------------------------

A 401 on one path beside a 200 on another is not a logged-out member, it is a
defect in the daemon's own plumbing. That case reports as ``degraded`` and
says so, so nobody is sent to re-login to clear a fault that re-login cannot
clear. Only sustained failure across every component that is trying, with no
success anywhere, reports as ``dead``.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "DEAD_AFTER_FAILURES",
    "DEAD_AFTER_SECONDS",
    "AuthHealth",
    "ComponentHealth",
    "auth_health_path",
    "read_auth_health",
]

#: Consecutive failures on a component before it counts as failing. One 401 is
#: a blip (a cap rotated, a race with a refresh); a run of them is a state.
FAILING_AFTER_FAILURES: int = 3

#: Sustained failure across every trying component for this long, with no
#: success anywhere, before the overall state reports ``dead``. Below this the
#: state is ``degraded``: a refresh may still be in flight and resolve it.
DEAD_AFTER_SECONDS: float = 300.0

#: Failure count across all components that also promotes ``degraded`` to
#: ``dead`` regardless of elapsed time. A fast-cadence subscriber reaches this
#: well before the time threshold; a slow one reaches the time threshold first.
DEAD_AFTER_FAILURES: int = 12

#: Minimum interval between state-file writes, so a subscriber taking 401s on a
#: tight loop cannot turn this into a write amplifier. A state TRANSITION always
#: writes immediately regardless.
WRITE_DEBOUNCE_SECONDS: float = 5.0

#: Bumped when the on-disk shape changes in a way a reader must notice.
STATE_VERSION: int = 1

_REMEDY_DEAD = (
    "The daemon's session is no longer accepted by the backend. "
    "Run `alter login` to re-authenticate; the daemon picks the new session up "
    "on its own. If it keeps failing after a fresh login, contact your ALTER "
    "admin - do not try to obtain a token yourself."
)

_REMEDY_DEGRADED = (
    "Some authenticated paths are failing while others still succeed, so this "
    "is a fault in the daemon's own plumbing, not a logged-out session. "
    "Re-logging in will not clear it. Report it with `alter-runtime status` "
    "output attached."
)

_REMEDY_OK = ""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def auth_health_path() -> Path:
    """Path to the daemon's auth-health state file.

    Imported lazily from :mod:`alter_runtime.config` so this module stays
    importable by the CLI without pulling the daemon's config machinery in
    when it is not needed.
    """
    from alter_runtime.config import state_dir

    return state_dir() / "auth-health.json"


@dataclass
class ComponentHealth:
    """Per-component record of authenticated-request outcomes."""

    name: str
    consecutive_failures: int = 0
    total_failures: int = 0
    total_successes: int = 0
    last_failure_at: float | None = None
    last_failure_reason: str | None = None
    last_success_at: float | None = None

    def is_failing(self) -> bool:
        """``True`` when this component has a run of failures, not a blip."""
        return self.consecutive_failures >= FAILING_AFTER_FAILURES

    def is_succeeding(self) -> bool:
        """``True`` when this component's most recent outcome was a success."""
        if self.last_success_at is None:
            return False
        if self.last_failure_at is None:
            return True
        return self.last_success_at >= self.last_failure_at

    def to_dict(self) -> dict[str, Any]:
        def _iso(ts: float | None) -> str | None:
            if ts is None:
                return None
            return (
                datetime.fromtimestamp(ts, timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            )

        return {
            "consecutive_failures": self.consecutive_failures,
            "total_failures": self.total_failures,
            "total_successes": self.total_successes,
            "last_failure_at": _iso(self.last_failure_at),
            "last_failure_reason": self.last_failure_reason,
            "last_success_at": _iso(self.last_success_at),
            "failing": self.is_failing(),
        }


class AuthHealth:
    """Shared auth-outcome state for the daemon.

    Written by every authenticated component (through the single
    ``RefreshTrigger`` fan-in for failures, and directly on their success
    paths); read by ``alter-runtime status`` off the state file.

    Thread safety mirrors :class:`~alter_runtime.config.SessionRef` and
    ``DaemonCapCache``: the daemon is a single-threaded asyncio loop, so
    reads and writes are serialised by cooperative scheduling and no lock
    is needed.
    """

    __slots__ = (
        "_components",
        "_handle",
        "_last_state",
        "_last_write_at",
        "_notify",
        "_path",
        "_started_at",
    )

    def __init__(
        self,
        path: Path | None = None,
        handle: str | None = None,
        notify: Any = None,
    ) -> None:
        self._components: dict[str, ComponentHealth] = {}
        self._path: Path | None = path
        self._handle = handle
        self._last_state: str = "unknown"
        self._last_write_at: float = 0.0
        self._started_at: float = time.time()
        #: Optional callable invoked once on each transition INTO a worse
        #: state, for the desktop toast. Never called on recovery.
        self._notify = notify

    # -- observation ------------------------------------------------------

    def record_failure(self, component: str, reason: str | None = None) -> None:
        """Record one rejected authenticated request.

        Called on every 401/403 an authenticated component sees, including
        the ones the refresh trigger debounces away: a debounced refresh is
        still an observed failure, and dropping it is how a spiral stays
        invisible.
        """
        entry = self._components.get(component)
        if entry is None:
            entry = ComponentHealth(name=component)
            self._components[component] = entry
        entry.consecutive_failures += 1
        entry.total_failures += 1
        entry.last_failure_at = time.time()
        entry.last_failure_reason = reason
        self._settle()

    def record_success(self, component: str) -> None:
        """Record one accepted authenticated request.

        This is what makes recovery observable and what distinguishes a dead
        session from a broken path: a component that succeeds clears its own
        failure run and pulls the overall state off ``dead``.
        """
        entry = self._components.get(component)
        if entry is None:
            entry = ComponentHealth(name=component)
            self._components[component] = entry
        entry.consecutive_failures = 0
        entry.total_successes += 1
        entry.last_success_at = time.time()
        self._settle()

    # -- derivation -------------------------------------------------------

    def state(self) -> str:
        """Derive the overall state from the recorded outcomes.

        ``unknown``  nothing authenticated has been attempted yet.
        ``ok``       nothing is in a failure run.
        ``degraded`` something is failing while something else still
                     succeeds, or a failure run is not yet sustained enough
                     to call the session dead.
        ``dead``     every component that is trying has been failing, with no
                     success anywhere, for long enough that a refresh in
                     flight would have landed.
        """
        if not self._components:
            return "unknown"

        failing = [c for c in self._components.values() if c.is_failing()]
        if not failing:
            return "ok"

        succeeding = [c for c in self._components.values() if c.is_succeeding()]
        if succeeding:
            # A 401 beside a 200 is split-brain: the credential is being
            # accepted somewhere, so this is a defect in the failing path,
            # never a dead session.
            return "degraded"

        # Age the run from the earliest last_failure_at across failing
        # components, so a component still retrying on a tight loop does not
        # keep resetting the clock for the others.
        oldest = min(
            (c.last_failure_at for c in failing if c.last_failure_at is not None),
            default=None,
        )
        if oldest is None:  # pragma: no cover - defensive
            return "degraded"

        elapsed = time.time() - oldest
        total_failures = sum(c.consecutive_failures for c in failing)
        if elapsed >= DEAD_AFTER_SECONDS or total_failures >= DEAD_AFTER_FAILURES:
            return "dead"
        return "degraded"

    def remedy(self) -> str:
        """Return the member-facing remedy for the current state.

        Never a mint instruction: token provisioning is admin-only, and the
        member-facing remedies are re-login, an in-place refresh, or contact
        the admin.
        """
        state = self.state()
        if state == "dead":
            return _REMEDY_DEAD
        if state == "degraded":
            return _REMEDY_DEGRADED
        return _REMEDY_OK

    def snapshot(self) -> dict[str, Any]:
        """Return the full on-disk shape."""
        state = self.state()
        return {
            "version": STATE_VERSION,
            "state": state,
            "updated_at": _now_iso(),
            "pid": os.getpid(),
            "handle": self._handle,
            "daemon_started_at": (
                datetime.fromtimestamp(self._started_at, timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            ),
            "remedy": self.remedy(),
            "components": {
                name: entry.to_dict() for name, entry in sorted(self._components.items())
            },
        }

    # -- persistence ------------------------------------------------------

    def _settle(self) -> None:
        """Log and persist after an observation, transitions first."""
        state = self.state()
        transitioned = state != self._last_state
        if transitioned:
            previous, self._last_state = self._last_state, state
            level = logging.WARNING if state in ("dead", "degraded") else logging.INFO
            logger.log(
                level,
                "auth_health: %s -> %s (%s)",
                previous,
                state,
                ", ".join(
                    f"{name}={c.consecutive_failures}f/{c.total_successes}s"
                    for name, c in sorted(self._components.items())
                ),
            )
            if state in ("dead", "degraded") and self._notify is not None:
                try:
                    self._notify(state, self.remedy())
                except Exception:  # pragma: no cover - a toast never breaks the daemon
                    logger.debug("auth_health: notify hook failed", exc_info=True)
        self.write(force=transitioned)

    def write(self, force: bool = False) -> None:
        """Persist the snapshot atomically at 0600.

        Never raises: a state file that cannot be written must not take the
        daemon down, and the log line above has already recorded the state.
        """
        if self._path is None:
            return
        now = time.time()
        if not force and now - self._last_write_at < WRITE_DEBOUNCE_SECONDS:
            return
        self._last_write_at = now
        payload = json.dumps(self.snapshot(), indent=2, sort_keys=False) + "\n"
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, tmp_name = tempfile.mkstemp(
                dir=str(self._path.parent), prefix=".auth-health-", suffix=".tmp"
            )
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(payload)
                os.replace(tmp_name, self._path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
        except Exception:
            logger.debug("auth_health: state write failed", exc_info=True)


def read_auth_health(path: Path | None = None) -> dict[str, Any] | None:
    """Read the daemon's auth-health state file.

    Returns ``None`` when the file is absent or unreadable, which the caller
    must report as "the daemon has not said" rather than as health: an absent
    file is exactly the silence this module exists to end, and reading it as
    ``ok`` would rebuild the fault.
    """
    target = path or auth_health_path()
    try:
        raw = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        parsed = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed
