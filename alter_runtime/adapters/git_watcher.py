"""GitWatcher - ambient signal adapter for git repository activity.

Observes one or more local git repositories and publishes ``local.signal``
events for commits and branch switches. Uses ``watchdog`` to tail the
per-branch ref files under ``.git/refs/heads/`` and the symbolic ``.git/HEAD``
pointer, because those change exactly when the user commits (``refs/heads/<br>``
is rewritten) or switches branches (``HEAD`` is rewritten).

Signals
-------

* ``kind = "git_commit"`` - a branch ref advanced. Payload::

      {
          "repo":     "/abs/path/to/repo",
          "branch":   "main",
          "sha":      "abc123...",
          "previous": "def456..." | None,
      }

* ``kind = "git_branch_switch"`` - the HEAD pointer moved to a different
  branch. Payload::

      {
          "repo":     "/abs/path/to/repo",
          "branch":   "feature/foo",
          "previous": "main",
      }

Both are published on the ``local.signal`` topic for the eventual egress
producer. The runtime itself does *not* post them back to the server - that
is the egress producer's job: it consumes these signals and forwards them.

Design notes
------------

* **One observer per repo.** Each configured repo gets a dedicated watchdog
  ``Observer`` so that a misbehaving filesystem event on one repo does not
  block another. For typical developer machines this is ~1-3 observers.
* **Debounce on ref changes.** Git writes refs atomically via rename, which
  fires both ``on_created`` and ``on_modified`` in rapid succession. We
  debounce by caching the last-seen SHA per ref and only publishing when it
  changes.
* **Thread boundary.** ``watchdog`` callbacks run on the observer's own
  thread. We marshal onto the asyncio loop via ``loop.call_soon_threadsafe``
  before publishing to the bus - the bus is *not* thread-safe.
* **Autodetect CWD.** When ``repo_paths`` is empty and the current working
  directory is a git repo, the adapter watches the CWD. This is the common
  case on a developer laptop where the user runs ``alter-runtime daemon``
  from inside their main workspace.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re as _re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from alter_runtime.config import DaemonConfig
from alter_runtime.daemon import Component
from alter_runtime.subscribers.bus import EventBus

__all__ = ["GitWatcher"]

logger = logging.getLogger("alter_runtime.adapters.git_watcher")

EGRESS_TOPIC: str = "local.signal"

#: Branch-name shape gate (hardening). Git itself imposes
#: tighter rules (see ``check-ref-format(1)``), but a watchdog-driven file
#: rename can land arbitrary bytes here if an attacker plants a malicious
#: file under ``.git/refs/heads/``. We accept the conservative subset that
#: covers every legitimate branch name we expect on disk and reject the
#: rest before they reach the bus and any downstream consumers (server ingest,
#: status-bar widgets, etc.).

_BRANCH_NAME_RE = _re.compile(r"^[A-Za-z0-9_./-]+$")


def _is_safe_branch_name(branch: str) -> bool:
    """Return True when ``branch`` matches the allowed branch shape.

    Additional gates beyond the regex (mirroring ``check-ref-format(1)``):
    reject any ``..`` sequence so a planted ref file can't traverse
    upward, reject leading ``/`` / ``-`` / ``.``, and reject trailing
    ``/`` / ``.``.
    """
    if not branch or len(branch) > 255:
        return False
    if not _BRANCH_NAME_RE.match(branch):
        return False
    if ".." in branch:
        return False
    if branch.startswith(("/", "-", ".")):
        return False
    if branch.endswith(("/", ".")):
        return False
    return True


@dataclass
class _WatchedRepo:
    """Bookkeeping for one watched repository."""

    path: Path
    git_dir: Path
    #: Last-seen SHAs keyed by branch name, for debouncing redundant fs events.
    branch_shas: dict[str, str] = field(default_factory=dict)
    #: Last-seen HEAD branch name, for detecting branch switches.
    head_branch: str | None = None
    observer: Any | None = None


class GitWatcher(Component):
    """Watches git repos and publishes commit / branch-switch signals.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig` (currently unused but kept for symmetry
        with the other components and future knobs like ``git_watch_paths``).
    bus:
        Shared :class:`EventBus` - signals are published on ``local.signal``.
    repo_paths:
        Explicit list of repository paths to watch. If empty, the adapter
        autodetects the current working directory when it's a git repo and
        falls back to no-op otherwise.
    """

    name = "git_watcher"

    def __init__(
        self,
        config: DaemonConfig,
        bus: EventBus,
        repo_paths: list[Path] | None = None,
    ) -> None:
        self._config = config
        self._bus = bus
        self._explicit_paths = repo_paths
        self._stop_event = asyncio.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._repos: list[_WatchedRepo] = []

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        self._loop = asyncio.get_running_loop()
        repos = self._resolve_repos()
        if not repos:
            logger.info("git_watcher no repositories to watch - idle")
            await self._stop_event.wait()
            return

        try:
            from watchdog.events import FileSystemEventHandler  # noqa: F401
            from watchdog.observers import Observer
        except ImportError:
            logger.warning("watchdog not installed - git_watcher disabled")
            await self._stop_event.wait()
            return

        for repo in repos:
            self._bootstrap_repo_state(repo)
            observer = Observer()
            handler = _GitRefHandler(self, repo)
            refs_dir = repo.git_dir / "refs" / "heads"
            if refs_dir.exists():
                observer.schedule(handler, str(refs_dir), recursive=True)
            head_file = repo.git_dir / "HEAD"
            if head_file.exists():
                observer.schedule(handler, str(repo.git_dir), recursive=False)
            observer.daemon = True
            observer.start()
            repo.observer = observer
            self._repos.append(repo)
            logger.info(
                "git_watcher observing repo=%s initial_branch=%s initial_shas=%s",
                repo.path,
                repo.head_branch,
                {k: v[:7] for k, v in repo.branch_shas.items()},
            )

        try:
            await self._stop_event.wait()
        finally:
            for repo in self._repos:
                if repo.observer is not None:
                    with contextlib.suppress(Exception):
                        repo.observer.stop()
                        repo.observer.join(timeout=2.0)
            logger.info("git_watcher stopped")

    async def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Repo discovery + initial state
    # ------------------------------------------------------------------

    def _resolve_repos(self) -> list[_WatchedRepo]:
        paths: list[Path] = []
        if self._explicit_paths:
            paths = [Path(p).expanduser().resolve() for p in self._explicit_paths]
        else:
            # Autodetect from CWD - resolve() so symlinked workspaces don't
            # confuse the symlink check below.
            cwd = Path.cwd().resolve()
            git_dir = cwd / ".git"
            if git_dir.is_dir():
                paths = [cwd]

        repos: list[_WatchedRepo] = []
        for path in paths:
            git_dir = path / ".git"
            # Hardening: refuse to register a watch when
            # ``.git`` is a symlink. Watchdog follows symlinks transparently,
            # which would let an attacker drop a symlinked .git into a CWD
            # the daemon scans and trick the watcher into observing - and
            # publishing signals from - a directory tree outside the
            # operator's repo set. Worktrees and gitlinks (file ``.git`` with
            # ``gitdir: <path>`` content) are handled separately by git
            # itself; refusing the symlink case is the conservative gate.
            if git_dir.is_symlink():
                logger.warning(
                    "git_watcher refusing symlinked .git path=%s -> %s",
                    git_dir,
                    git_dir.resolve(strict=False),
                )
                continue
            if not git_dir.is_dir():
                logger.warning("git_watcher skipping non-repo path=%s", path)
                continue
            repos.append(_WatchedRepo(path=path, git_dir=git_dir))
        return repos

    def _bootstrap_repo_state(self, repo: _WatchedRepo) -> None:
        """Prime ``branch_shas`` and ``head_branch`` from current refs.

        Without this, the first commit after startup would publish a
        ``git_commit`` for every existing ref because the ``branch_shas``
        cache starts empty.
        """
        refs_dir = repo.git_dir / "refs" / "heads"
        if refs_dir.is_dir():
            for ref_file in _iter_ref_files(refs_dir):
                branch = _branch_name_from_ref(refs_dir, ref_file)
                sha = _read_ref(ref_file)
                if sha:
                    repo.branch_shas[branch] = sha

        head_file = repo.git_dir / "HEAD"
        if head_file.exists():
            repo.head_branch = _read_head_branch(head_file)

    # ------------------------------------------------------------------
    # Watchdog callbacks (thread → asyncio bridge)
    # ------------------------------------------------------------------

    def _on_ref_change(self, repo: _WatchedRepo, event_path: str) -> None:
        """Called on the watchdog thread when a ref file changes."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        loop.call_soon_threadsafe(
            lambda: asyncio.create_task(self._handle_ref_change_async(repo, event_path))
        )

    async def _handle_ref_change_async(self, repo: _WatchedRepo, event_path: str) -> None:
        """Runs on the asyncio loop - inspect the ref and publish if changed."""
        path = Path(event_path)
        refs_dir = repo.git_dir / "refs" / "heads"
        head_file = repo.git_dir / "HEAD"

        try:
            if path == head_file or path.name == "HEAD":
                new_branch = _read_head_branch(head_file) if head_file.exists() else None
                if new_branch and new_branch != repo.head_branch:
                    # Hardening: branch names traverse the
                    # bus to the server ingest path. Reject anything that doesn't
                    # match the conservative shape gate before publishing -
                    # don't update head_branch on reject so the next valid
                    # change still fires.
                    if not _is_safe_branch_name(new_branch):
                        logger.warning(
                            "git_watcher rejecting unsafe HEAD branch name=%r repo=%s",
                            new_branch,
                            repo.path,
                        )
                        return
                    previous = repo.head_branch
                    repo.head_branch = new_branch
                    await self._publish(
                        "git_branch_switch",
                        {
                            "repo": str(repo.path),
                            "branch": new_branch,
                            "previous": previous,
                        },
                    )
                return

            # Ref file under .git/refs/heads/
            try:
                path.relative_to(refs_dir)
            except ValueError:
                return

            if not path.exists() or not path.is_file():
                return
            branch = _branch_name_from_ref(refs_dir, path)
            # Hardening: sanitise the branch name before it
            # reaches the bus. _branch_name_from_ref derives from the on-disk
            # ref filename which a same-UID attacker can plant arbitrarily.
            if not _is_safe_branch_name(branch):
                logger.warning(
                    "git_watcher rejecting unsafe ref branch name=%r repo=%s",
                    branch,
                    repo.path,
                )
                return
            sha = _read_ref(path)
            if not sha:
                return
            previous = repo.branch_shas.get(branch)
            if previous == sha:
                return  # debounce
            repo.branch_shas[branch] = sha
            await self._publish(
                "git_commit",
                {
                    "repo": str(repo.path),
                    "branch": branch,
                    "sha": sha,
                    "previous": previous,
                },
            )
        except Exception as exc:  # pragma: no cover
            logger.warning("git_watcher ref change handling failed: %s", exc)

    async def _publish(self, kind: str, payload: dict[str, Any]) -> None:
        logger.info(
            "git_watcher publishing kind=%s repo=%s branch=%s",
            kind,
            payload.get("repo"),
            payload.get("branch"),
        )
        await self._bus.publish(
            EGRESS_TOPIC,
            {"kind": kind, "payload": payload, "source": "git_watcher"},
        )

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def watched_repos(self) -> list[_WatchedRepo]:
        return list(self._repos)


# ---------------------------------------------------------------------------
# watchdog event handler - sits between the observer thread and the loop
# ---------------------------------------------------------------------------


class _GitRefHandler:
    """Tiny wrapper - watchdog's FileSystemEventHandler is imported lazily
    inside :meth:`GitWatcher.run` so that installs without watchdog can still
    import ``git_watcher``. This class shims the interface without subclassing
    so type checkers don't demand the import at module-load time.
    """

    def __init__(self, watcher: GitWatcher, repo: _WatchedRepo) -> None:
        self._watcher = watcher
        self._repo = repo
        # Cache the thread ID we were constructed on for debug logging.
        self._construct_thread = threading.get_ident()

    # watchdog calls these via duck typing; no base class required.
    def dispatch(self, event: Any) -> None:
        if getattr(event, "is_directory", False):
            return
        # Drop pure-read events. Modern watchdog versions (>=2.x with
        # IN_OPEN/IN_CLOSE_NOWRITE in the default mask) emit a
        # FileOpenedEvent + FileClosedNoWriteEvent for every open-and-read
        # of a watched file. ``.git/HEAD`` and the active branch ref are
        # opened thousands of times per second by ``git status`` callers
        # (IDE git plugins, statusline scripts, parallel editor/tooling sessions), and
        # without this filter every read scheduled an ``asyncio.create_task``
        # via ``_on_ref_change`` - flooding the loop with no-op handles
        # that grew RSS by ~10MB/s and tripped OOM in <5min on a busy repo.
        kind = type(event).__name__
        if kind in ("FileOpenedEvent", "FileClosedNoWriteEvent"):
            return
        src = getattr(event, "src_path", None)
        dest = getattr(event, "dest_path", None)
        # Fire on whichever path exists after the event (move target for
        # renames, src for create/modify).
        target = dest or src
        if not isinstance(target, str):
            return
        self._watcher._on_ref_change(self._repo, target)


# ---------------------------------------------------------------------------
# Ref file helpers
# ---------------------------------------------------------------------------


def _iter_ref_files(refs_dir: Path):
    """Yield every ref file under ``refs_dir`` recursively."""
    for root, _dirs, files in os.walk(refs_dir):
        for fname in files:
            yield Path(root) / fname


def _branch_name_from_ref(refs_dir: Path, ref_file: Path) -> str:
    """Return the branch name given a path under ``.git/refs/heads/``."""
    try:
        return str(ref_file.relative_to(refs_dir))
    except ValueError:
        return ref_file.name


def _read_ref(ref_file: Path) -> str | None:
    """Read a ref file and return the SHA, or None on read failure."""
    try:
        return ref_file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None


def _read_head_branch(head_file: Path) -> str | None:
    """Return the branch HEAD points at, or None if detached / unreadable.

    ``.git/HEAD`` is either ``ref: refs/heads/<branch>`` for an attached head
    or a bare SHA for a detached head.
    """
    try:
        content = head_file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None
    if content.startswith("ref:"):
        _, _, ref = content.partition("ref:")
        ref = ref.strip()
        if ref.startswith("refs/heads/"):
            return ref[len("refs/heads/") :]
    return None
