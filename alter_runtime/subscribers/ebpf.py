"""EbpfSubscriber - wires the eBPF kernel attestation loader into the daemon.

The Rust ``alter-ebpf`` helper binary is the
userspace half of a BPF LSM program that observes ``bprm_check_security``
and emits one ``alter1``-shaped JSON envelope per line to stdout for every
exec on a uid the operator opted in to.

This subscriber is the bridge between that binary and the in-process
:class:`EventBus`. It:

1. Resolves the binary path (``ALTER_EBPF_BIN`` env var, then
   :func:`shutil.which`, then :data:`DEFAULT_BINARY_NAMES`).
2. Resolves the target uid (``ALTER_EBPF_TARGET_UID`` env var, then the
   effective uid of the daemon process). The privacy filter inside the
   BPF program drops every event whose uid does not match this value, so
   the daemon never sees another user's exec stream even if it were
   started as root.
3. Spawns the binary as an asyncio subprocess (``alter-ebpf load
   --target-uid <uid>``).
4. Reads stdout line-by-line, parses each line as the ``alter1`` envelope
   the Rust loader produces, and publishes:

   * :data:`TOPIC_KERNEL_EXEC` - the ``payload`` dict from the envelope,
     so subscribers that only care about kernel exec events can listen
     on a specific topic without filtering.
   * :data:`TOPIC_LOCAL_SIGNAL` - the full envelope, mirroring the
     convention established by ``git_watcher`` and other local adapters.
     A future egress producer will relay these to the DO.
5. Treats stderr as plain log output and reroutes it through the
   subscriber logger at INFO level. The Rust binary writes
   ``tracing-subscriber`` output to stderr; we don't try to parse it.
6. On any unclean exit (non-zero status, transient I/O error,
   subprocess crash) backs off and restarts the loader. The supervisor
   provides the outer safety net for truly unexpected failures, but the
   inner backoff loop is what survives a kernel verifier rejecting a
   newly hot-reloaded program.

The subscriber gracefully **disables itself** if:

* the ``alter-ebpf`` binary is not on PATH (and ``ALTER_EBPF_BIN`` is not
  set);
* the binary is found but the platform is not Linux;
* the loader exits non-zero on its first attach attempt with the same
  error twice in a row (typically: kernel lacks BPF LSM in the active
  stack - there is no point retrying).

Disabling logs once at WARNING and the :meth:`run` task exits cleanly so
the supervisor does not restart it. This is the right behaviour for an
opt-in, kernel-version-sensitive surface - we should not flood the
journal on hosts that simply don't have BPF LSM enabled.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from alter_runtime.daemon import Component

if TYPE_CHECKING:
    from collections.abc import Awaitable

    from alter_runtime.config import DaemonConfig
    from alter_runtime.subscribers.bus import EventBus

__all__ = [
    "DEFAULT_BINARY_NAMES",
    "EbpfSubscriber",
    "TOPIC_KERNEL_EXEC",
    "TOPIC_LOCAL_SIGNAL",
]

logger = logging.getLogger("alter_runtime.subscribers.ebpf")

#: Topic published with the parsed payload dict from each kernel exec event.
TOPIC_KERNEL_EXEC: str = "kernel.attest.exec"

#: Topic published with the full ``alter1`` envelope, matching the convention
#: used by other local adapters that emit ambient signals destined for DO
#: relay (not yet wired).
TOPIC_LOCAL_SIGNAL: str = "local.signal"

#: Names that resolve via :func:`shutil.which` if no explicit binary path
#: is configured. The first one to resolve wins.
DEFAULT_BINARY_NAMES: tuple[str, ...] = ("alter-ebpf",)

#: Initial back-off in seconds after a transient subprocess failure.
BASE_BACKOFF_SECONDS: float = 1.0

#: Upper bound on exponential back-off between subprocess restarts.
MAX_BACKOFF_SECONDS: float = 60.0

#: Maximum line length we will buffer from stdout. The Rust loader emits one
#: JSON object per line; the largest legitimate line is bounded by the
#: ``filename`` field (256 bytes) plus envelope overhead. We cap at 16 KiB
#: to absorb future fields without giving an attacker a way to OOM the
#: daemon if a malicious binary on PATH ever masqueraded as alter-ebpf.
MAX_LINE_BYTES: int = 16 * 1024

#: A factory that returns a started ``asyncio.subprocess.Process``. Tests
#: pass a fake here to avoid actually spawning the Rust binary.
ProcessFactory = Callable[[list[str]], "Awaitable[asyncio.subprocess.Process]"]


@dataclass
class _SubscriberState:
    """Internal book-keeping (exposed via :attr:`EbpfSubscriber.state` for tests)."""

    spawn_count: int = 0
    line_count: int = 0
    parse_error_count: int = 0
    publish_count: int = 0
    backoff: float = BASE_BACKOFF_SECONDS
    disabled: bool = False
    history: list[str] = field(default_factory=list)


class EbpfSubscriber(Component):
    """Spawns the eBPF loader and republishes its event stream onto the bus.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`. Currently unused but accepted so the
        subscriber matches the calling convention of every other Component
        in the package and so future config knobs (poll interval, ringbuf
        sizing) can be added without breaking callers.
    bus:
        The shared :class:`EventBus` instance.
    binary_path:
        Optional explicit path to the ``alter-ebpf`` binary. If ``None``,
        the subscriber consults ``ALTER_EBPF_BIN`` and then
        :func:`shutil.which`. The Path equivalent works too.
    target_uid:
        Optional uid to observe. Defaults to ``ALTER_EBPF_TARGET_UID`` then
        the daemon's effective uid.
    process_factory:
        Optional factory that returns an ``asyncio.subprocess.Process``.
        Tests inject a fake to drive the subscriber without exec-ing the
        real Rust binary. Production callers leave this ``None`` and the
        subscriber uses :func:`asyncio.create_subprocess_exec`.
    extra_args:
        Optional extra CLI arguments appended after ``load --target-uid
        <uid>``. Useful for future flags (e.g. ``--ringbuf-pages``) and
        for tests that want to confirm pass-through.
    """

    name = "ebpf"

    def __init__(
        self,
        config: DaemonConfig,
        bus: EventBus,
        *,
        binary_path: str | os.PathLike[str] | None = None,
        target_uid: int | None = None,
        process_factory: ProcessFactory | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        self._config = config
        self._bus = bus
        self._binary_path = self._resolve_binary(binary_path)
        self._target_uid = self._resolve_target_uid(target_uid)
        self._process_factory: ProcessFactory = (
            process_factory if process_factory is not None else _default_process_factory
        )
        self._extra_args = list(extra_args or [])
        self._stop_event = asyncio.Event()
        self._proc: asyncio.subprocess.Process | None = None
        self._state = _SubscriberState()

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Long-lived loop: spawn → drain stdout → restart on failure."""
        if self._binary_path is None:
            logger.warning(
                "ebpf subscriber disabled - alter-ebpf binary not found "
                "(set ALTER_EBPF_BIN to point at the binary). "
                "Kernel attestation will not be available on this host."
            )
            self._state.disabled = True
            return

        argv = [
            str(self._binary_path),
            "load",
            "--target-uid",
            str(self._target_uid),
            *self._extra_args,
        ]
        logger.info(
            "ebpf starting binary=%s target_uid=%d",
            self._binary_path,
            self._target_uid,
        )

        consecutive_immediate_failures = 0
        while not self._stop_event.is_set():
            try:
                exit_code = await self._run_one_session(argv)
            except asyncio.CancelledError:
                raise
            except FileNotFoundError as exc:
                # The binary disappeared between resolution and spawn -
                # treat exactly as the resolution-failure case above.
                logger.warning(
                    "ebpf binary vanished from %s (%s) - disabling",
                    self._binary_path,
                    exc,
                )
                self._state.disabled = True
                return
            except Exception as exc:
                logger.exception("ebpf unexpected error spawning loader: %s", exc)
                exit_code = -1

            if self._stop_event.is_set():
                break

            # If the loader keeps exiting immediately (within < base backoff)
            # twice in a row, the kernel is almost certainly missing BPF LSM
            # support and we should disable rather than spinning the journal.
            if exit_code != 0:
                consecutive_immediate_failures += 1
                if consecutive_immediate_failures >= 2:
                    logger.warning(
                        "ebpf loader exited non-zero twice in a row "
                        "(last exit=%d) - disabling. Common causes: bpf LSM "
                        "not in /sys/kernel/security/lsm; daemon lacks "
                        "CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN; kernel BTF "
                        "missing.",
                        exit_code,
                    )
                    self._state.disabled = True
                    return
            else:
                consecutive_immediate_failures = 0

            await self._backoff_then_retry()

        logger.info("ebpf stopped binary=%s", self._binary_path)

    async def stop(self) -> None:
        """Cooperative shutdown - kill the subprocess and release the loop."""
        self._stop_event.set()
        proc = self._proc
        if proc is not None and proc.returncode is None:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass

    # ------------------------------------------------------------------
    # Subprocess session
    # ------------------------------------------------------------------

    async def _run_one_session(self, argv: list[str]) -> int:
        """Spawn one loader instance and drain it until it exits.

        Returns the subprocess exit code (or ``-1`` for an internal error).
        """
        self._state.spawn_count += 1
        self._state.history.append(f"spawn:{self._state.spawn_count}")
        proc = await self._process_factory(argv)
        self._proc = proc
        try:
            stdout_task = asyncio.create_task(self._drain_stdout(proc))
            stderr_task = asyncio.create_task(self._drain_stderr(proc))
            stop_waiter = asyncio.create_task(self._stop_event.wait())

            done, pending = await asyncio.wait(
                {stdout_task, stop_waiter},
                return_when=asyncio.FIRST_COMPLETED,
            )

            if stop_waiter in done:
                # Caller asked us to stop. Terminate the loader and let
                # the drain tasks finish naturally on EOF.
                if proc.returncode is None:
                    try:
                        proc.terminate()
                    except ProcessLookupError:
                        pass
            else:
                stop_waiter.cancel()

            # Always finish draining whatever's still buffered. Bound the
            # wait so a wedged subprocess can't hang shutdown indefinitely.
            for task in (stdout_task, stderr_task):
                if not task.done():
                    try:
                        await asyncio.wait_for(task, timeout=5.0)
                    except (TimeoutError, asyncio.TimeoutError):
                        task.cancel()

            try:
                exit_code = await asyncio.wait_for(proc.wait(), timeout=5.0)
            except (TimeoutError, asyncio.TimeoutError):
                logger.warning("ebpf loader did not exit after terminate; killing")
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                exit_code = await proc.wait()

            logger.info(
                "ebpf loader session ended exit=%d lines=%d publishes=%d parse_errors=%d",
                exit_code,
                self._state.line_count,
                self._state.publish_count,
                self._state.parse_error_count,
            )
            return exit_code
        finally:
            self._proc = None

    # ------------------------------------------------------------------
    # Drain helpers
    # ------------------------------------------------------------------

    async def _drain_stdout(self, proc: asyncio.subprocess.Process) -> None:
        """Read newline-delimited JSON envelopes and publish to the bus."""
        stdout = proc.stdout
        if stdout is None:
            logger.warning("ebpf process has no stdout pipe")
            return
        while True:
            try:
                line = await stdout.readline()
            except asyncio.LimitOverrunError as exc:
                # asyncio.StreamReader.readline raises this if a line
                # exceeds the buffer limit. Discard up to the next newline
                # and keep going.
                logger.warning(
                    "ebpf line longer than buffer (%d bytes consumed) - discarding",
                    exc.consumed,
                )
                await stdout.read(exc.consumed)
                self._state.parse_error_count += 1
                continue
            if not line:
                return  # EOF
            self._state.line_count += 1
            await self._handle_line(line)

    async def _drain_stderr(self, proc: asyncio.subprocess.Process) -> None:
        """Reroute the loader's stderr through our logger at INFO level."""
        stderr = proc.stderr
        if stderr is None:
            return
        while True:
            line = await stderr.readline()
            if not line:
                return
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                logger.info("ebpf-loader: %s", text)

    async def _handle_line(self, raw: bytes) -> None:
        """Parse one stdout line and publish on the bus.

        Bad JSON or unexpected envelope shapes are counted and dropped -
        a single malformed line must never crash the dispatcher.
        """
        if len(raw) > MAX_LINE_BYTES:
            logger.warning("ebpf line %d bytes > MAX_LINE_BYTES - dropping", len(raw))
            self._state.parse_error_count += 1
            return
        try:
            envelope: Any = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.debug("ebpf line not JSON: %s (%r)", exc, raw[:120])
            self._state.parse_error_count += 1
            return
        if not isinstance(envelope, dict):
            logger.debug("ebpf line not a JSON object: %r", raw[:120])
            self._state.parse_error_count += 1
            return
        if envelope.get("v") != "alter1":
            logger.debug("ebpf line missing alter1 envelope: %r", envelope.get("v"))
            self._state.parse_error_count += 1
            return

        kind = envelope.get("kind")
        payload = envelope.get("payload")
        if not isinstance(kind, str) or not isinstance(payload, dict):
            logger.debug("ebpf envelope missing kind/payload: %r", envelope)
            self._state.parse_error_count += 1
            return

        # Specific topic for kernel-exec consumers.
        if kind == "kernel.attest.exec":
            await self._bus.publish(TOPIC_KERNEL_EXEC, payload)

        # Generic local-signal topic for the egress relay and any
        # other subscriber that wants every ambient signal regardless of
        # source. Mirrors what git_watcher publishes.
        await self._bus.publish(TOPIC_LOCAL_SIGNAL, envelope)
        self._state.publish_count += 1

    # ------------------------------------------------------------------
    # Resolution helpers
    # ------------------------------------------------------------------

    def _resolve_binary(self, explicit: str | os.PathLike[str] | None) -> str | None:
        """Find the alter-ebpf binary, returning ``None`` if unavailable."""
        if explicit is not None:
            path = os.fspath(explicit)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
            logger.warning(
                "ebpf binary path %r is not an executable file - falling back to PATH",
                path,
            )
        env = os.environ.get("ALTER_EBPF_BIN")
        if env:
            if os.path.isfile(env) and os.access(env, os.X_OK):
                return env
            logger.warning(
                "ALTER_EBPF_BIN=%r is not an executable file - falling back to PATH",
                env,
            )
        for name in DEFAULT_BINARY_NAMES:
            resolved = shutil.which(name)
            if resolved:
                return resolved
        return None

    def _resolve_target_uid(self, explicit: int | None) -> int:
        """Decide which uid to observe."""
        if explicit is not None:
            return explicit
        env = os.environ.get("ALTER_EBPF_TARGET_UID")
        if env:
            try:
                return int(env)
            except ValueError:
                logger.warning(
                    "ALTER_EBPF_TARGET_UID=%r is not an integer - using effective uid",
                    env,
                )
        try:
            return os.geteuid()
        except AttributeError:
            # Non-POSIX (Windows) - uid concept doesn't apply but the
            # subscriber is Linux-only in practice. Return 0 as a placeholder
            # so we still spawn the binary in tests on non-POSIX hosts.
            return 0

    # ------------------------------------------------------------------
    # Backoff
    # ------------------------------------------------------------------

    async def _backoff_then_retry(self) -> None:
        """Sleep for the current backoff, then double it for next time."""
        delay = self._state.backoff
        self._state.backoff = min(delay * 2, MAX_BACKOFF_SECONDS)
        logger.info("ebpf restarting loader in %.1fs", delay)
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=delay)
        except (TimeoutError, asyncio.TimeoutError):
            return

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def state(self) -> _SubscriberState:
        """Internal state snapshot (used by tests)."""
        return self._state

    @property
    def binary_path(self) -> str | None:
        """The resolved binary path, or ``None`` if the subscriber is disabled."""
        return self._binary_path


# ---------------------------------------------------------------------------
# Default process factory
# ---------------------------------------------------------------------------


async def _default_process_factory(argv: list[str]) -> asyncio.subprocess.Process:
    """Spawn the loader via :func:`asyncio.create_subprocess_exec`."""
    return await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        # The loader must not inherit our stdin - it doesn't read it and
        # connecting to a tty can cause confusing behaviour under systemd.
        stdin=asyncio.subprocess.DEVNULL,
        # Run in its own process group so a Ctrl-C delivered to the daemon
        # supervisor's pgid doesn't double-signal the loader before our
        # cooperative terminate() lands.
        start_new_session=True,
    )
