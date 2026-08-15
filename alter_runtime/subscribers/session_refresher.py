"""SessionRefresher - proactive access-token rotation to stop subscriber 401 spirals.

Why this exists
---------------

The CLI access JWT has a ~6 h TTL.  Subscribers that hold a frozen
:class:`~alter_runtime.config.Session` snapshot taken at daemon start keep
using the boot-time JWT forever; at the 6 h mark every authenticated request
(capability request, SSE subscribe-cap, MCP fallback calls) returns 401 and the
affected subscriber enters its backoff spiral.  The root fix has two parts:

1. **This component** wakes a configurable lead time before the JWT expires,
   shells ``alter creds refresh --force``, reloads the session from disk, and
   updates the shared :class:`~alter_runtime.config.SessionRef` holder.
2. **SessionRef read-through** (see ``config.py``): hot JWT consumers read
   ``.current.jwt`` through the holder so the new token flows to them without
   any per-subscriber changes beyond a one-line substitution.

Safety invariants
-----------------

* The daemon NEVER calls ``POST /api/v1/oauth/token`` directly.  Token rotation
  is delegated exclusively to ``alter creds refresh --force``, which holds the
  ``~/.config/alter/refresh.lock`` cross-process single-flight guard.  This
  component adds at most ONE subprocess per expiry window (or per debounce
  window when reactively triggered — see ``RefreshTrigger`` below).
* Debounce: if the disk session already carries a newer JWT when the refresher
  wakes (e.g. a bridge or CLI process rotated it), the holder is updated and
  the subprocess is skipped.
* Refresh-expired guard: when ``refresh_expires_at`` is in the past we log once
  at WARN and idle; we never attempt a subprocess that would fail and burn the
  last rotation attempt.
* Never raises out of ``run()``.  The supervisor restart is a backstop, not
  the intended loop.

Reactive refresh (2026-07-12 fix)
----------------------------------

This component originally woke ONLY on its own schedule (``jwt_expires_at -
lead``). A server-side revoke (a full account-wide kill, or — after the
matching per-family fix on the backend — a revoke of this daemon's own
session family) can invalidate the token WELL BEFORE that scheduled wake, at
which point every cap-consuming subscriber (``DaemonCapCache``,
``SessionPresenceWriter``, ``ActiveSessionsDoPublisher``) starts seeing 401s
from capability request and backs off exponentially — up to ``MAX_POLL_BACKOFF_SECONDS``
— while the scheduled refresher keeps sleeping toward a wake time that may be
hours away (the 2026-07-12 incident: a 66-minute daemon backoff spiral after a
revoke). ``RefreshTrigger`` is a small debounced fan-in signal: any capability request
401 observer calls ``request_refresh()``, which wakes THIS component's sleep
early via the SAME code path (no parallel refresh mechanism, no direct
subprocess call from the observers) — it only ever short-circuits the wait.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from alter_runtime.config import DaemonConfig, load_session
from alter_runtime.daemon import Component

if TYPE_CHECKING:
    from alter_runtime.auth_health import AuthHealth
    from alter_runtime.config import SessionRef

__all__ = ["RefreshTrigger", "SessionRefresher"]

logger = logging.getLogger("alter_runtime.subscribers.session_refresher")

#: Minimum interval between accepted ``request_refresh()`` calls. Multiple
#: subscribers can all observe a capability request 401 within milliseconds of the same
#: underlying revoke; only the first call in this window actually wakes the
#: refresher early, so a revoke never spawns more than one extra
#: ``alter creds refresh --force`` subprocess regardless of how many
#: components saw the 401. The CLI-side ``~/.config/alter/refresh.lock``
#: remains the cross-PROCESS single-flight guard; this is the in-process
#: fan-in debounce sitting in front of it.
REFRESH_TRIGGER_DEBOUNCE_SECONDS: float = 30.0


class RefreshTrigger:
    """Debounced fan-in wake signal from capability request 401 observers to
    :class:`SessionRefresher`.

    Any component holding a reference may call :meth:`request_refresh` when it
    observes a capability request rejection that implies the underlying session JWT
    itself is dead (not merely a stale capability). ``SessionRefresher`` races
    this signal against its scheduled sleep in :meth:`SessionRefresher._sleep_interruptible`
    and, on either firing, proceeds through its EXISTING refresh path (debounce
    against disk, shell ``alter creds refresh --force``, update the shared
    ``SessionRef``): this class creates no new refresh mechanism, it only
    changes when the existing one wakes.

    It is also the single fan-in point where every authenticated 401 in the
    daemon is already observed, so it is where each one is recorded into
    :class:`~alter_runtime.auth_health.AuthHealth`. Recording happens BEFORE
    the debounce: a suppressed trigger is still an observed failure, and
    dropping the suppressed ones is how a 155-failure spiral stays invisible.
    """

    def __init__(
        self,
        debounce_seconds: float = REFRESH_TRIGGER_DEBOUNCE_SECONDS,
        auth_health: AuthHealth | None = None,
    ) -> None:
        self._event = asyncio.Event()
        self._debounce_seconds = debounce_seconds
        self._last_trigger_at: float = 0.0
        #: Count of accepted (non-debounced) triggers, test/diagnostic only.
        self.trigger_count: int = 0
        self._auth_health = auth_health

    def request_refresh(self, reason: str = "unspecified_401") -> bool:
        """Request an out-of-band refresh wake.

        Returns ``True`` if this call was accepted (the event was set),
        ``False`` if it was suppressed by the debounce window. Safe to call
        from any number of concurrent observers.

        ``reason`` doubles as the component key in the auth-health record and
        carries a default so a caller that omits it degrades to a recorded
        observation rather than a ``TypeError`` swallowed by the caller's own
        exception suppression.
        """
        if self._auth_health is not None:
            self._auth_health.record_failure(component=reason, reason=reason)
        now = time.time()
        if now - self._last_trigger_at < self._debounce_seconds:
            return False
        self._last_trigger_at = now
        self.trigger_count += 1
        logger.info("refresh_trigger: reactive refresh requested reason=%s", reason)
        self._event.set()
        return True

    async def wait(self) -> None:
        """Block until a trigger fires. Callers should ``clear()`` after."""
        await self._event.wait()

    def is_set(self) -> bool:
        return self._event.is_set()

    def clear(self) -> None:
        self._event.clear()


#: Maximum backoff between retry attempts (seconds).
MAX_REFRESH_BACKOFF_SECONDS: float = 3600.0

#: Backoff applied when the subprocess fails or times out.
BASE_FAIL_BACKOFF_SECONDS: float = 60.0

#: Long sleep used when the refresh window has expired (prompt user to re-login
#: rather than hammering a dead endpoint).
EXPIRED_WINDOW_BACKOFF_SECONDS: float = 3600.0


@dataclass
class _RefresherState:
    """Internal state for the refresher (exposed for tests)."""

    wake_count: int = 0
    subprocess_count: int = 0
    debounce_count: int = 0
    success_count: int = 0
    fail_count: int = 0
    backoff: float = 0.0
    history: list[str] = field(default_factory=list)


def _resolve_alter_bin() -> str | None:
    """Return the path to the ``alter`` CLI binary, or ``None`` if unresolvable.

    Resolution order:
    1. ``ALTER_CLI_BIN`` environment variable (operator override).
    2. ``shutil.which("alter")`` (PATH lookup).
    3. ``~/.local/bin/alter`` (default user-install location).
    4. Literal ``"alter"`` (last-resort; will fail if not on PATH, caught at
       subprocess spawn time).

    Returns ``None`` only when all four options are exhausted and the literal
    fallback would also fail (this function always returns the literal as a
    last resort rather than ``None`` unless the caller should idle).
    """
    import os

    env_override = os.environ.get("ALTER_CLI_BIN")
    if env_override:
        return env_override

    on_path = shutil.which("alter")
    if on_path:
        return on_path

    local_bin = Path.home() / ".local" / "bin" / "alter"
    if local_bin.exists():
        return str(local_bin)

    # Last resort: return literal; subprocess will raise FileNotFoundError if
    # it is truly absent (caught in run() to idle rather than crash).
    return "alter"


def _parse_iso(ts: str | None) -> float | None:
    """Parse an ISO-8601 timestamp to a Unix epoch float, or ``None``."""
    if not ts:
        return None
    try:
        from datetime import datetime

        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


class SessionRefresher(Component):
    """Proactively rotates the session JWT before it expires.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`.  Uses
        ``session_refresh_lead_seconds`` and
        ``session_refresh_subprocess_timeout_seconds``.
    session_ref:
        Shared mutable :class:`SessionRef` holder.  The refresher updates
        ``.current`` after every successful rotation so all hot JWT consumers
        immediately see the new token.
    refresh_trigger:
        Optional shared :class:`RefreshTrigger`.  When present, a capability request
        401 observed by any other subscriber (``DaemonCapCache``,
        ``SessionPresenceWriter``, ``ActiveSessionsDoPublisher``) wakes this
        component's sleep early instead of waiting for the scheduled lead
        time (2026-07-12 fix — see the module docstring "Reactive refresh").
        ``None`` preserves the original schedule-only behaviour (tests /
        degraded daemon).
    """

    name = "session_refresher"

    def __init__(
        self,
        config: DaemonConfig,
        session_ref: "SessionRef",
        refresh_trigger: "RefreshTrigger | None" = None,
    ) -> None:
        self._config = config
        self._session_ref = session_ref
        self._refresh_trigger = refresh_trigger
        self._stop_event = asyncio.Event()
        self._state = _RefresherState()
        # Resolved once at startup; None triggers the idle path.
        self._alter_bin: str | None = _resolve_alter_bin()

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Sleep until (jwt_expires_at - lead), rotate, repeat."""
        if self._alter_bin is None:
            logger.warning(
                "session_refresher: alter CLI binary not found - idling "
                "(set ALTER_CLI_BIN or install alter to enable proactive refresh)"
            )
            await self._stop_event.wait()
            return

        logger.info(
            "session_refresher starting handle=%s lead=%.0fs alter_bin=%s",
            self._session_ref.current.handle,
            self._config.session_refresh_lead_seconds,
            self._alter_bin,
        )

        _expired_window_warned = False

        try:
            while not self._stop_event.is_set():
                self._state.wake_count += 1

                session = self._session_ref.current
                expiry = _parse_iso(session.jwt_expires_at)

                if expiry is None:
                    # Malformed session - back off and try again later.
                    logger.warning(
                        "session_refresher: jwt_expires_at unparseable (%r) - backing off %.0fs",
                        session.jwt_expires_at,
                        BASE_FAIL_BACKOFF_SECONDS,
                    )
                    await self._sleep_interruptible(BASE_FAIL_BACKOFF_SECONDS)
                    continue

                import time

                now = time.time()
                sleep_until = expiry - self._config.session_refresh_lead_seconds
                remaining = sleep_until - now

                if remaining > 0:
                    self._state.history.append(f"sleep:{remaining:.0f}s")
                    await self._sleep_interruptible(remaining)

                if self._stop_event.is_set():
                    break

                # --- Check refresh_expires_at ----------------------------
                refresh_exp = _parse_iso(session.refresh_expires_at)
                import time as _time

                if refresh_exp is not None and refresh_exp < _time.time():
                    if not _expired_window_warned:
                        logger.warning(
                            "session_refresher: refresh window expired "
                            "(refresh_expires_at=%s) - run `alter login` to re-authenticate",
                            session.refresh_expires_at,
                        )
                        _expired_window_warned = True
                    self._state.history.append("expired_window")
                    await self._sleep_interruptible(EXPIRED_WINDOW_BACKOFF_SECONDS)
                    continue
                # Reset the one-shot flag once the session is replaced.
                _expired_window_warned = False

                # --- Debounce: disk already fresher? ---------------------
                disk_session = load_session()
                if disk_session is not None and disk_session.jwt != session.jwt:
                    logger.info(
                        "session_refresher: disk JWT already advanced - "
                        "updating holder and skipping subprocess (debounce)"
                    )
                    self._session_ref.set(disk_session)
                    self._state.debounce_count += 1
                    self._state.history.append("debounce")
                    # Reset backoff on a successful token advance.
                    self._state.backoff = 0.0
                    continue

                # --- Shell alter creds refresh --force -------------------
                self._state.subprocess_count += 1
                self._state.history.append("subprocess")
                success = await self._run_refresh_subprocess()

                if success:
                    fresh = load_session()
                    if fresh is not None and fresh.jwt != session.jwt:
                        self._session_ref.set(fresh)
                        self._state.success_count += 1
                        self._state.history.append("success")
                        self._state.backoff = 0.0
                        logger.info(
                            "session_refresher: token rotated successfully handle=%s",
                            fresh.handle,
                        )
                    else:
                        # subprocess exited 0 but JWT didn't advance - treat as
                        # soft failure (e.g. no-op refresh on an already-fresh
                        # token) and back off conservatively.
                        logger.warning(
                            "session_refresher: subprocess succeeded but JWT "
                            "did not advance - backing off %.0fs",
                            BASE_FAIL_BACKOFF_SECONDS,
                        )
                        await self._backoff()
                else:
                    await self._backoff()

        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover - belt-and-braces, never raise
            logger.exception("session_refresher: unexpected error in run() - suppressed")

        logger.info(
            "session_refresher stopped handle=%s",
            self._session_ref.current.handle,
        )

    async def stop(self) -> None:
        """Cooperative shutdown."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Subprocess
    # ------------------------------------------------------------------

    async def _run_refresh_subprocess(self) -> bool:
        """Shell ``alter creds refresh --force``; return True on exit-code 0.

        Uses ``asyncio.create_subprocess_exec`` (no shell) with
        ``asyncio.wait_for`` timeout.  On timeout the process is killed and
        waited for before returning ``False``.
        """
        assert self._alter_bin is not None  # guarded by caller
        argv = [self._alter_bin, "creds", "refresh", "--force"]
        timeout = self._config.session_refresh_subprocess_timeout_seconds

        logger.debug(
            "session_refresher: spawning %s timeout=%.0fs",
            " ".join(argv),
            timeout,
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.warning(
                "session_refresher: alter CLI not found at %r - idling; "
                "set ALTER_CLI_BIN or install alter to PATH",
                self._alter_bin,
            )
            # Nil out so future wakes idle immediately without re-trying.
            self._alter_bin = None
            self._state.fail_count += 1
            return False
        except OSError as exc:
            logger.warning(
                "session_refresher: failed to spawn alter creds refresh: %s",
                exc,
            )
            self._state.fail_count += 1
            return False

        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except (TimeoutError, asyncio.TimeoutError):
            logger.warning(
                "session_refresher: alter creds refresh timed out after %.0fs - killing",
                timeout,
            )
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
            self._state.fail_count += 1
            return False

        rc = proc.returncode
        if rc != 0:
            stderr_str = (stderr_b or b"").decode("utf-8", errors="replace").strip()
            logger.warning(
                "session_refresher: alter creds refresh exited %d stderr=%r",
                rc,
                stderr_str[:200],
            )
            self._state.fail_count += 1
            return False

        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _backoff(self) -> None:
        """Double the backoff (capped) and sleep."""
        self._state.backoff = min(
            max(
                self._state.backoff * 2 if self._state.backoff else BASE_FAIL_BACKOFF_SECONDS,
                BASE_FAIL_BACKOFF_SECONDS,
            ),
            MAX_REFRESH_BACKOFF_SECONDS,
        )
        logger.warning(
            "session_refresher: backing off %.0fs",
            self._state.backoff,
        )
        self._state.history.append(f"backoff:{self._state.backoff:.0f}s")
        await self._sleep_interruptible(self._state.backoff)

    async def _sleep_interruptible(self, seconds: float) -> bool:
        """Wait ``seconds``, until stopped, or until a reactive refresh is
        requested — whichever comes first.

        Returns ``True`` when the wait ended because ``refresh_trigger``
        fired early (a capability request 401 elsewhere implied the session is dead),
        so the caller can proceed straight into the refresh attempt instead
        of waiting out the rest of the scheduled sleep. Returns ``False`` on
        a normal timeout or stop. The trigger is cleared here so a single
        request never re-fires on the next loop iteration.
        """
        if seconds <= 0:
            return False
        if self._refresh_trigger is None:
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
            except (TimeoutError, asyncio.TimeoutError):
                pass
            return False

        stop_task = asyncio.ensure_future(self._stop_event.wait())
        trigger_task = asyncio.ensure_future(self._refresh_trigger.wait())
        try:
            done, pending = await asyncio.wait(
                (stop_task, trigger_task),
                timeout=seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            for task in (stop_task, trigger_task):
                if not task.done():
                    task.cancel()
            # Swallow the CancelledError each cancelled task raises when
            # awaited/gathered; never let it propagate out of a sleep helper.
            await asyncio.gather(stop_task, trigger_task, return_exceptions=True)

        if trigger_task in done and not self._stop_event.is_set():
            self._refresh_trigger.clear()
            self._state.history.append("reactive_trigger")
            logger.info("session_refresher: woken early by reactive refresh_trigger")
            return True
        return False

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def state(self) -> _RefresherState:
        """Current refresher state (used by tests)."""
        return self._state
