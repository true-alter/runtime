"""Asyncio supervisor for the alter-runtime daemon.

The supervisor runs subscribers, sockets, adapters, and the hook bridge as
long-lived asyncio tasks, coupling them through an in-process event bus.

Each component registers with the supervisor via ``Supervisor.register(...)``.
The supervisor runs them as long-lived tasks and restarts them on failure
with exponential backoff. On SIGTERM/SIGINT, the supervisor cancels all
tasks and awaits clean shutdown.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from alter_runtime.auth_health import AuthHealth, auth_health_path
from alter_runtime.config import (
    DaemonConfig,
    SessionRef,
    ensure_directories,
    load_config,
    load_session,
)

if TYPE_CHECKING:
    from alter_runtime.config import Session

__all__ = ["Component", "Supervisor", "run_daemon"]

logger = logging.getLogger("alter_runtime.daemon")


# ---------------------------------------------------------------------------
# Component ABC - everything the supervisor runs implements this
# ---------------------------------------------------------------------------


class Component(ABC):
    """A long-running component managed by the supervisor.

    Subclasses implement :meth:`run` as an async method that blocks until
    the component should exit. The supervisor cancels the task on shutdown
    and awaits cancellation propagation.
    """

    #: Human-readable name used in logs
    name: str = "component"

    @abstractmethod
    async def run(self) -> None:
        """Main event loop for the component."""

    async def stop(self) -> None:
        """Optional graceful shutdown hook.

        Called before task cancellation. Components can use this to drain
        pending work (flush queues, close sockets) before being cancelled.
        """


@dataclass
class _ManagedTask:
    """Bookkeeping for a registered component."""

    component: Component
    task: asyncio.Task[None] | None = None
    restart_count: int = 0
    restart_at: float = 0.0


# ---------------------------------------------------------------------------
# Supervisor
# ---------------------------------------------------------------------------


class Supervisor:
    """Supervises a set of Components with restart-on-failure semantics."""

    #: Base backoff in seconds; exponential to a maximum
    BASE_BACKOFF_SECONDS: float = 1.0
    MAX_BACKOFF_SECONDS: float = 60.0

    def __init__(self, config: DaemonConfig) -> None:
        self.config = config
        self._managed: list[_ManagedTask] = []
        self._stopping = asyncio.Event()
        self._on_stop_callbacks: list[Callable[[], Awaitable[None]]] = []

    def register(self, component: Component) -> None:
        """Register a component to be managed.

        May only be called before :meth:`run` starts. After startup, use
        ``add_component`` for dynamic registration.
        """
        self._managed.append(_ManagedTask(component=component))

    def on_stop(self, callback: Callable[[], Awaitable[None]]) -> None:
        """Register a callback to run during shutdown.

        Callbacks run sequentially after component tasks are cancelled.
        """
        self._on_stop_callbacks.append(callback)

    async def run(self) -> None:
        """Start the supervisor and block until shutdown is requested."""
        logger.info(
            "alter-runtime daemon starting pid=%d components=%d",
            _getpid(),
            len(self._managed),
        )

        if not self._managed:
            # No components registered yet. The supervisor still starts so
            # operators can verify `alter-runtime daemon` works end-to-end;
            # it idles until signalled.
            logger.warning("supervisor started with zero registered components")

        # Install signal handlers for clean shutdown
        self._install_signal_handlers()

        # Launch each component
        for managed in self._managed:
            managed.task = asyncio.create_task(
                self._supervise(managed),
                name=f"alter-{managed.component.name}",
            )

        # Block until stop is requested
        await self._stopping.wait()

        logger.info("alter-runtime daemon stopping")

        # Stop phase - give each component a chance to flush
        for managed in self._managed:
            try:
                await asyncio.wait_for(managed.component.stop(), timeout=5.0)
            except (TimeoutError, Exception) as exc:
                logger.warning("component %s stop() raised: %s", managed.component.name, exc)

        # Cancel tasks
        for managed in self._managed:
            if managed.task and not managed.task.done():
                managed.task.cancel()

        # Await cancellation
        for managed in self._managed:
            if managed.task:
                try:
                    await managed.task
                except asyncio.CancelledError:
                    pass
                except Exception as exc:
                    logger.warning(
                        "component %s exited with error: %s",
                        managed.component.name,
                        exc,
                    )

        # Run stop callbacks
        for callback in self._on_stop_callbacks:
            try:
                await callback()
            except Exception as exc:
                logger.warning("stop callback raised: %s", exc)

        logger.info("alter-runtime daemon stopped")

    async def stop(self) -> None:
        """Request graceful shutdown."""
        self._stopping.set()

    async def _supervise(self, managed: _ManagedTask) -> None:
        """Run a component and restart it with backoff on failure."""
        name = managed.component.name
        while not self._stopping.is_set():
            try:
                logger.info("starting component %s", name)
                await managed.component.run()
                logger.info("component %s exited cleanly", name)
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                managed.restart_count += 1
                backoff = min(
                    self.BASE_BACKOFF_SECONDS * (2 ** (managed.restart_count - 1)),
                    self.MAX_BACKOFF_SECONDS,
                )
                logger.warning(
                    "component %s crashed (attempt %d): %s - restarting in %.1fs",
                    name,
                    managed.restart_count,
                    exc,
                    backoff,
                )
                try:
                    await asyncio.wait_for(
                        self._stopping.wait(),
                        timeout=backoff,
                    )
                    return  # stop requested during backoff
                except (TimeoutError, asyncio.TimeoutError):
                    continue

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        # Windows doesn't support add_signal_handler; use signal.signal as a fallback
        if sys.platform == "win32":
            signal.signal(signal.SIGINT, lambda *_: loop.call_soon_threadsafe(self._stopping.set))
            return
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self._stopping.set)
            except NotImplementedError:
                # Fallback for exotic event loops
                signal.signal(sig, lambda *_: self._stopping.set())


# ---------------------------------------------------------------------------
# Top-level entrypoint used by the CLI `alter-runtime daemon`
# ---------------------------------------------------------------------------


async def run_daemon(config: DaemonConfig | None = None) -> None:
    """Start the supervisor and block until shutdown.

    Called by ``alter_runtime.cli.cmd_daemon``.
    """
    if config is None:
        config = load_config()

    _configure_logging(config.log_level)
    ensure_directories()

    session: Session | None = load_session()
    if session is None:
        logger.warning(
            "no CLI session found (probed the OS secure store, the "
            "encrypted store at %s, and the legacy plaintext %s) - daemon "
            "starting in degraded mode. "
            "Run `alter login` to enable identity-aware subscribers.",
            "~/.config/alter/enc/session.bin",
            "~/.config/alter/session.json",
        )
    else:
        logger.info(
            "session loaded handle=%s consent_tier=L%d api=%s",
            session.handle,
            session.consent_tier,
            session.api,
        )

    supervisor = Supervisor(config)

    # Tighten the umask before any subscriber writes the inbox / state files
    # so that O_CREAT | 0o600 always lands at the requested mode regardless
    # of the inherited shell umask.
    try:
        import os as _os

        _os.umask(0o077)
    except Exception:  # pragma: no cover - exotic environments
        pass

    # Daemon-side update observer. Polls the release host on cadence
    # and logs what it sees. No download, no verify, no apply. Runs
    # regardless of session state because the manifest is a public read
    # surface and the loop never touches an authenticated endpoint.
    if config.autoupdate_enabled:
        from alter_runtime.update_loop import UpdateLoop

        supervisor.register(
            UpdateLoop(
                manifest_url=config.autoupdate_manifest_url,
                poll_interval_seconds=config.autoupdate_poll_interval_seconds,
            )
        )

    # Daemon-side floor preflight and gate. Polls the server-side minimum
    # version floor on a 24h cadence, verifies the HMAC signature, and
    # writes a shared FloorState. The Unix-socket server reads the state on
    # every method dispatch and refuses to serve when below floor, emitting
    # the canonical ``client_below_floor`` envelope. A safety carve-out lets
    # ``urgency: critical`` ingest payloads through even when locked.
    #
    # The floor endpoint is a public read; the loop runs regardless of
    # session state.
    from alter_runtime.floor_loop import FloorLoop, FloorState

    floor_state = FloorState()
    supervisor.register(FloorLoop(config, floor_state))

    # Construct the in-process event bus that couples subscribers, sockets,
    # and adapters. The bus is a transient coupling layer - durable state
    # lives server-side.
    from alter_runtime.subscribers import (
        ActiveSessionsCronEmitter,
        ActiveSessionsDoPublisher,
        ActiveSessionsGc,
        ActiveSessionsWriter,
        AdaptersWriter,
        AgentFrameSubscriber,
        AttunementRefresher,
        CacheWriter,
        CeremonyEchoWriter,
        DoctrineProjectionPoller,
        DoSseSubscriber,
        EventBus,
        InboxWriter,
        LoomVerdictSubscriber,
        McpFallbackSubscriber,
        PresenceFeedWriter,
        PresenceWriter,
        SessionClaimsDoPublisher,
        SessionPresenceWriter,
        SessionRefresher,
    )

    event_bus = EventBus()

    # Build the shared SessionRef holder (used by hot JWT consumers so a
    # proactive token rotation propagates without per-subscriber changes).
    # When no session is present we leave session_ref as None; subscribers
    # that need it are only registered when session is not None anyway.
    session_ref: SessionRef | None = SessionRef(session) if session is not None else None

    # Build the shared RefreshTrigger (2026-07-12 fix, extended 2026-07-16 to
    # cover DoSseSubscriber). Every hot JWT consumer that accepts a
    # refresh_trigger constructor argument (DoSseSubscriber, DaemonCapCache,
    # SessionPresenceWriter, ActiveSessionsDoPublisher, SessionClaimsDoPublisher)
    # calls request_refresh() on an auth failure that implies the session JWT
    # itself is dead, waking SessionRefresher's sleep early instead of
    # waiting for its scheduled lead time. Closes the 66-minute daemon
    # backoff spiral seen after a server-side session revoke landed well
    # before the next scheduled proactive rotation. This set is pinned by
    # tests/test_daemon_refresh_trigger_wiring.py, which fails whenever a
    # class that declares a refresh_trigger parameter is registered below
    # without actually being passed one - do_sse's own omission (this fix)
    # is exactly the drift that test now catches mechanically.
    from alter_runtime.subscribers.session_refresher import RefreshTrigger

    # Auth health. The daemon already observes every authenticated outcome it
    # needs to know whether its session is still accepted; until now it kept
    # that entirely to itself, so hours of continuous 401s looked exactly like
    # hours of health from outside. AuthHealth records those outcomes into a
    # state file that ``alter-runtime status`` reads, which is what makes a
    # dead session a state a member can see without opening a journal.
    #
    # Failures fan in through RefreshTrigger (the single point every 401
    # observer already calls); successes are recorded on the capability request 200,
    # which is the request that actually answers "is this session alive".
    auth_health = AuthHealth(
        path=auth_health_path(),
        handle=session.handle if session is not None else None,
    )
    # Persist the opening state immediately, so a daemon that dies before its
    # first authenticated request still leaves a file with a timestamp rather
    # than the absence this whole component exists to end.
    auth_health.write(force=True)

    refresh_trigger: RefreshTrigger | None = (
        RefreshTrigger(auth_health=auth_health) if session is not None else None
    )

    # Register the full ingress/egress stack when we have an authenticated
    # session. Without a session there is no handle to subscribe against,
    # so the daemon idles in degraded mode until `alter login` populates
    # the session store.
    if session is not None:
        # --- Ingress ------------------------------------------------------
        # Primary: server SSE. Fallback: direct MCP polling. Both publish to
        # ``identity.frame`` / ``identity.event`` - the fan-out layer below
        # consumes from the bus so it never learns which path served a given
        # event.
        # Passed session_ref (not the frozen session) so a proactive or
        # reactive rotation actually propagates to this subscriber's next
        # reconnect, plus refresh_trigger so a bearer 401 on the stream
        # itself wakes SessionRefresher out of band (2026-07-16 fix; without
        # session_ref, refresh_trigger alone would wake the refresher but
        # this subscriber could never observe the rotated token, since
        # ``_get_session()`` only reads through a live SessionRef when one
        # was actually passed at construction).
        supervisor.register(
            DoSseSubscriber(
                config, session_ref or session, event_bus, refresh_trigger=refresh_trigger
            )
        )
        # Passed session_ref (not the frozen session) for the same reason as
        # DoSseSubscriber above: McpFallbackSubscriber only reads through a
        # live SessionRef when one was actually passed at construction (see
        # its ``_live_session = self._session_ref.current if ... else
        # self._session`` read-through), so a frozen snapshot here means a
        # proactive or reactive rotation never reaches it and it keeps
        # polling with the boot-time JWT forever (2026-07-16 fix).
        supervisor.register(McpFallbackSubscriber(config, session_ref or session, event_bus))

        # AttunementRefresher closes the steady-state gap: the MCP fallback
        # only carries attunement to the cache while the server is *down*, so
        # in normal operation (server connected) attunement never refreshes.
        # This component calls the ``alter_attunement`` tool on a slow cadence
        # REGARDLESS of server connection state and publishes an
        # ``attunement_transition`` identity.event that the CacheWriter
        # projects into ``identity.json``. It shares only the read-side MCP
        # wire contract with the fallback; it does NOT touch do_sse's
        # connect/auth/mint path. Disable via ALTER_RUNTIME_ATTUNEMENT_REFRESH=0.
        # Passed session_ref (not the frozen session) for the same
        # read-through reason as McpFallbackSubscriber above (2026-07-16 fix).
        if config.attunement_refresh_enabled:
            supervisor.register(AttunementRefresher(config, session_ref or session, event_bus))

        # DoctrineProjectionPoller maintains a local read-only JSONL projection
        # of the member's doctrine substrate per scope (personal/collective)
        # under ~/.local/share/alter/doctrine. Pull-mode: the backend emits no
        # event on a doctrine write, so it polls the cheap ``alter_doctrine``
        # ``summary`` verb each tick and only pulls the ``list`` delta when the
        # etag changes. Shares the read-side MCP wire contract (envelope +
        # endpoint + JWT) with the fallback / attunement pollers; it does NOT
        # touch do_sse's connect/auth/mint path. The projection file is a
        # rolling, rebuildable-from-substrate cache. Pass the session_ref holder
        # when available so the poller reads the live JWT after a proactive
        # rotation. Disable via ALTER_RUNTIME_DOCTRINE_PROJECTION=0.
        if config.doctrine_projection_enabled:
            supervisor.register(DoctrineProjectionPoller(config, session_ref or session))

        # SessionRefresher proactively shells ``alter creds refresh --force``
        # a configurable lead time before the access JWT expires.  After a
        # successful rotation it updates the shared ``session_ref`` holder so
        # all hot JWT consumers (DoSseSubscriber, McpFallback, CapCache, etc.)
        # immediately see the new token via ``.current.jwt`` read-through.
        # Without this component all subscribers hold the boot-time JWT forever
        # and 401-spiral at the 6 h access-token boundary.
        # Disable via ALTER_RUNTIME_SESSION_REFRESH=0.
        if config.session_refresh_enabled and session_ref is not None:
            supervisor.register(
                SessionRefresher(config, session_ref, refresh_trigger=refresh_trigger)
            )

        # InboxWriter is driven via the bus: its ``handle_raw_frame``
        # entrypoint is called by the bus rather than opening its own
        # socket. This preserves existing unit tests while hooking it
        # into the real network path.
        inbox = InboxWriter(config, session)
        supervisor.register(inbox)
        event_bus.subscribe("identity.frame", inbox.handle_raw_frame)

        # CeremonyEchoWriter sits next to InboxWriter on the same bus.
        # It filters the same frame stream for x-alter-recognition and
        # x-alter-ceremony content_types and persists a tiny "echo
        # state" file with a 72 h expiry. Shell-greeting consumers
        # (the `alter room` CLI surface, future menu greeting) read that
        # file and render the echo iff still within the window.
        ceremony = CeremonyEchoWriter(config, session)
        supervisor.register(ceremony)
        event_bus.subscribe("identity.frame", ceremony.handle_raw_frame)

        # --- Local fan-out surfaces ---------------------------------------
        # Import lazily so the top of the module stays cheap and so that
        # missing optional deps (dbus-next) only fail on Linux installs
        # that asked for them.
        from alter_runtime.sockets import UnixSocketServer
        from alter_runtime.sockets.dbus import DBusService

        # CacheWriter projects identity state into the shared shell cache
        # file (``$XDG_CACHE_HOME/alter/identity.json``) that the shell
        # identity cache already reads from. This glue lets existing shell
        # tools show live identity state - when the daemon is running,
        # existing shell tools transparently start showing live identity
        # state without any shell changes.
        supervisor.register(CacheWriter(event_bus))

        # DesktopNotifier renders inbound ``alter_message`` frames to a
        # freedesktop toast (``notify-send`` + the system message chime) the
        # instant they land on the bus. This is the arrival cue that makes
        # peer messages feel native: a sound + visual on receipt, like every
        # other messaging surface, rather than a counter you have to remember
        # to check. It self-subscribes to ``identity.event`` in its own
        # ``run()``; construction + registration is all the wiring it needs.
        # One-way render only: no read receipt, presence beacon, or
        # typing indicator goes back onto the bus. Disable with
        # ``ALTER_DESKTOP_NOTIFIER_DISABLED=1``.
        if config.desktop_notifier_enabled:
            from alter_runtime.notifiers import DesktopNotifier

            supervisor.register(DesktopNotifier(config, session, event_bus))

        # SessionPresenceWriter polls the presence endpoint on a cadence and
        # writes ~/.local/share/org-alter/state/sessions.json. External tooling
        # can merge that cache with same-host /dev/shm sibling files so every
        # session sees parallel sessions across hosts. The capability request
        # carries the alter_org.read scope; idle when
        # ``session_presence_enabled`` is false.
        # No bus coupling; the handoff is file-mediated. Passed session_ref
        # (not the frozen session) so a rotation propagates here too, plus
        # refresh_trigger so a capability request 401 wakes SessionRefresher out of
        # band instead of waiting for its schedule (2026-07-12 fix — this
        # subscriber previously held the boot-time JWT forever regardless of
        # SessionRefresher's own rotations).
        supervisor.register(
            SessionPresenceWriter(config, session_ref or session, refresh_trigger=refresh_trigger)
        )

        # Bus-driven JSONL writers under ``~/.local/share/alter-runtime/``.
        # See the bundled schema docs.
        supervisor.register(PresenceWriter(config, event_bus))

        # PresenceFeedWriter is the writer half of the ``alter room`` CLI
        # presence pane. It subscribes to the same ``identity.event`` bus
        # topic, filters peer ``presence_set`` frames (skipping the caller's
        # own self-echoes via ``session.handle``), and projects the CLI-shaped
        # subset into ``~/.local/share/alter-runtime/presence-feed.jsonl`` -
        # the file the ``alter room`` CLI surface reads. Without it the pane always
        # showed the "no peers active right now" placeholder. Gated by
        # ``ALTER_RUNTIME_PRESENCE_FEED_WRITER`` (default on).
        if config.presence_feed_writer_enabled:
            supervisor.register(PresenceFeedWriter(config, event_bus, own_handle=session.handle))

        supervisor.register(ActiveSessionsWriter(config, event_bus))
        # Periodic GC pass over the active-sessions JSONL. Reads under
        # LOCK_SH, emits session_heartbeat (idle) / session_ended (complete)
        # envelopes via the shared bus so the writer's dedup + rotation +
        # 0o600 invariants are preserved. PID-liveness probe gated on tool==cc.
        if config.active_sessions_gc_enabled:
            supervisor.register(ActiveSessionsGc(config, event_bus))
        supervisor.register(AdaptersWriter(config, event_bus))

        # Active-sessions server publisher. Tails the active-sessions JSONL
        # written by ActiveSessionsWriter and POSTs each new envelope to
        # ``{do_publish_url}/events/{handle}/sessions/ingest``. Passed
        # session_ref + refresh_trigger for the same reactive-rotation
        # reason as SessionPresenceWriter above (2026-07-12 fix).
        supervisor.register(
            ActiveSessionsDoPublisher(
                config, session_ref or session, refresh_trigger=refresh_trigger
            )
        )

        # Session-claims publisher. The sibling of the publisher above, on the
        # other session stream: it tails the session-claims JSONL the agent
        # hooks append to and forwards each payload to the backend, which mints
        # the capability and emits the frame. Two streams and two publishers is
        # the point. The claim records rode the active-sessions file until the
        # streams were split, where the sessions route's validator rejected
        # every one of them as an unknown shape and the publisher advanced past
        # each rejection, so the claim set was permanently empty and the only
        # trace was a warning in the journal.
        supervisor.register(
            SessionClaimsDoPublisher(
                config, session_ref or session, refresh_trigger=refresh_trigger
            )
        )

        # CronCreate emitter. Subscribes to ``cron.routine.started`` /
        # ``cron.routine.finished`` on the in-process bus and re-publishes
        # each as a ``tool: cron`` envelope on ``identity.event``. The
        # writer above projects those envelopes into the active-sessions
        # JSONL exactly like any other tool, so daemon-scheduled routines
        # participate in the cross-host session view without per-routine code.
        supervisor.register(ActiveSessionsCronEmitter(config, event_bus, session))

        # Agent-frame subscriber. Filters server SSE for
        # ``content_type=x-alter-agent``, projects to
        # ``~/.cache/alter/agent-frames.jsonl``, and re-publishes per-kind
        # bus topics (``alter.agent.frame.{kind}``). Also maintains an
        # in-memory instrument roster served via the ``agent/roster``
        # Unix-socket method without a server round-trip.
        agent_frames = AgentFrameSubscriber(event_bus)
        supervisor.register(agent_frames)

        # Loom-verdict thin-client mirror. Read-only projection of the
        # do_sse-delivered loom_verdict frame kind into a local mirror
        # store; see alter_runtime/subscribers/loom_verdict_subscriber.py
        # for the read-side trust gate and the explicit land-time-admission
        # non-scope. Default on (cheap, read-only, safe on every host,
        # mirroring AgentFrameSubscriber's always-on posture). Disable via
        # ALTER_RUNTIME_LOOM_VERDICT_SUBSCRIBER=0.
        if config.loom_verdict_subscriber_enabled:
            supervisor.register(LoomVerdictSubscriber(event_bus, config))

        # Loom-verdict desktop exporter. Opt-in (default off): only the
        # machine that IS the loom validator should tail its local verdict
        # store and re-emit rows cross-machine. See
        # alter_runtime/adapters/loom_verdict_exporter.py for the strict
        # four-field wire allowlist and the device-bound signing path.
        # Enable via ALTER_RUNTIME_LOOM_VERDICT_EXPORTER=1 on the
        # validator host only.
        if config.loom_verdict_exporter_enabled:
            from alter_runtime.adapters.loom_verdict_exporter import LoomVerdictExporter

            supervisor.register(LoomVerdictExporter(config, session_ref or session))

        supervisor.register(
            UnixSocketServer(
                config,
                event_bus,
                session,
                agent_frames_subscriber=agent_frames,
                floor_state=floor_state,
                # session_ref + refresh_trigger flow only into the lazily-
                # constructed DaemonCapCache (_ensure_cap_cache); `session`
                # keeps its existing frozen-snapshot meaning for `whoami`
                # and `send` unaffected (2026-07-12 fix).
                session_ref=session_ref,
                refresh_trigger=refresh_trigger,
                auth_health=auth_health,
            )
        )
        if config.enable_dbus:
            supervisor.register(DBusService(config, event_bus, session))

        # --- Ambient signal adapters --------------------------------------
        from alter_runtime.adapters import GitWatcher
        from alter_runtime.adapters.worktree_watcher import WorktreeWatcher

        supervisor.register(GitWatcher(config, event_bus))

        # WorktreeWatcher: working-tree filesystem watcher. Observes the
        # repo working tree and publishes local.signal kind=worktree_edit
        # on every file save, covering editors that lack a hook.
        supervisor.register(WorktreeWatcher(config, event_bus))

        # Claude Code JSONL token-usage watcher - opt-in via config flag.
        # Tails the Claude Code projects transcripts and posts token-usage events to
        # the ~alter backend audit endpoint. Disabled by default; enable via
        # ALTER_RUNTIME_CLAUDE_JSONL_WATCHER=1 or direct config mutation.
        if config.enable_claude_jsonl_watcher:
            from alter_runtime.adapters.claude_jsonl_watcher import ClaudeJsonlWatcher

            supervisor.register(ClaudeJsonlWatcher(config, event_bus))

        # --- External adapter plugins (entry-point discovery) -------------
        # Out-of-tree adapters register under the ``alter_runtime.adapters``
        # entry-point group and are discovered here rather than imported by
        # name. A plugin package that is not installed is simply absent; one
        # that fails to load is logged and skipped without affecting the
        # daemon. This is the public extension seam that lets gated or
        # separately-installed adapters live in their own installed package
        # and register themselves, so this module holds no import of an
        # adapter that lives outside the public tree.
        from alter_runtime.adapters.contract import (
            AdapterContext,
            discover_adapter_components,
        )

        adapter_context = AdapterContext(config=config, event_bus=event_bus, session=session)
        for component in discover_adapter_components(adapter_context):
            supervisor.register(component)

        # --- Kernel attestation -------------------------------------------
        # The eBPF subscriber spawns the kernel attestation loader and
        # republishes its exec stream onto ``kernel.attest.exec`` and
        # ``local.signal``. It silently disables itself on hosts where the
        # binary is missing or BPF LSM is unavailable, so it's safe to
        # always register on Linux. Other platforms skip the import - the
        # subscriber is Linux-only by construction.
        if sys.platform.startswith("linux"):
            from alter_runtime.subscribers import EbpfSubscriber

            supervisor.register(EbpfSubscriber(config, event_bus))

    await supervisor.run()


def _configure_logging(level: str) -> None:
    """Structured-ish logging for the daemon. Matches backend structlog intent
    but keeps the dependency surface small (stdlib logging only)."""
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )


def _getpid() -> int:
    try:
        import os

        return os.getpid()
    except Exception:
        return -1
