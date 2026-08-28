"""WorktreeWatcher - ambient working-tree file-watch adapter.

WorktreeWatcher observes one or more repo
working trees and publishes ``local.signal`` events of kind ``"worktree_edit"``
on every file save detected by watchdog. This covers editors (vim, vscode,
etc.) as a coarse-grained second producer for the working-tree write stream.

Signals
-------

* ``kind = "worktree_edit"`` - a working-tree file was saved. Payload::

      {
          "repo":      "/abs/path/to/repo",
          "file_path": "/abs/path/to/repo/src/foo.py",
          "rel_path":  "src/foo.py",
          "ts":        "2026-05-21T12:34:56.789012+00:00",
      }

Published on the ``local.signal`` topic for any downstream subscriber that
consumes working-tree save events.

Design notes
------------

* **Whole-tree watcher is MORE flood-exposed than GitWatcher.** The same
  read-event filter from ``git_watcher.py`` is mandatory here and is applied
  in every dispatch path, dropping ``FileOpenedEvent`` + ``FileClosedNoWriteEvent``
  before they ever reach the asyncio loop.
* **Debounce per path.** Within a 200 ms window, multiple watchdog events for
  the same file path emit only one bus event. Each repo tracks a ``dict[str, float]``
  of path → last-emit-time.
* **gitignore + symlink guards.** Reuses the same patterns from GitWatcher:
  refuse to watch a repo where ``.git`` is a symlink; skip symlinked files;
  honour ``.gitignore`` by filtering against a cached ignore spec on each event.
* **Thread boundary.** watchdog callbacks run on the observer's own thread.
  Marshalled onto the asyncio loop via ``loop.call_soon_threadsafe`` before
  publishing; the bus is not thread-safe.
* **Autodetect CWD.** When ``repo_paths`` is empty and the CWD is a git repo,
  the adapter watches the CWD. Same convention as GitWatcher.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from alter_runtime.config import DaemonConfig
from alter_runtime.daemon import Component
from alter_runtime.subscribers.bus import EventBus

__all__ = ["WorktreeWatcher"]

logger = logging.getLogger("alter_runtime.adapters.worktree_watcher")

EGRESS_TOPIC: str = "local.signal"

#: Debounce window in seconds; events within this window for the same path
#: are collapsed to one emission.
DEBOUNCE_SECONDS: float = 0.2

#: Maximum number of paths tracked in the per-repo debounce dict. When
#: exceeded, the oldest half is evicted to prevent unbounded growth on
#: very active repos with hundreds of simultaneous writes.
MAX_DEBOUNCE_PATHS: int = 2048


@dataclass
class _WatchedRepo:
    """Bookkeeping for one watched repository."""

    path: Path
    git_dir: Path
    observer: Any | None = None
    #: path string → last emit timestamp (monotonic)
    _debounce: dict[str, float] = field(default_factory=dict)
    #: Cached gitignore spec (pathspec.PathSpec | None). Populated lazily.
    _ignore_spec: Any | None = None
    _ignore_loaded: bool = False


class WorktreeWatcher(Component):
    """Watches working trees and publishes worktree_edit signals.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`.
    bus:
        Shared :class:`EventBus`; signals are published on ``local.signal``.
    repo_paths:
        Explicit list of repository roots to watch. If empty, autodetects
        from CWD (same convention as GitWatcher).
    debounce_seconds:
        Override the per-path debounce window (default 200 ms).
    """

    name = "worktree_watcher"

    def __init__(
        self,
        config: DaemonConfig,
        bus: EventBus,
        repo_paths: list[Path] | None = None,
        debounce_seconds: float = DEBOUNCE_SECONDS,
    ) -> None:
        self._config = config
        self._bus = bus
        self._explicit_paths = repo_paths
        self._debounce_seconds = debounce_seconds
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
            logger.info("worktree_watcher: no repositories to watch, idle")
            await self._stop_event.wait()
            return

        try:
            from watchdog.observers import Observer  # noqa: F401
        except ImportError:
            logger.warning("watchdog not installed, worktree_watcher disabled")
            await self._stop_event.wait()
            return

        from watchdog.observers import Observer

        for repo in repos:
            observer = Observer()
            handler = _WorktreeHandler(self, repo)
            # Schedule on the repo root (recursive). We watch the working
            # tree, NOT the .git dir; gitignore filter handles noise from
            # .git/ appearing if the observer root is above it.
            observer.schedule(handler, str(repo.path), recursive=True)
            observer.daemon = True
            observer.start()
            repo.observer = observer
            self._repos.append(repo)
            logger.info(
                "worktree_watcher observing repo=%s",
                repo.path,
            )

        try:
            await self._stop_event.wait()
        finally:
            for repo in self._repos:
                if repo.observer is not None:
                    with contextlib.suppress(Exception):
                        repo.observer.stop()
                        repo.observer.join(timeout=2.0)
            logger.info("worktree_watcher stopped")

    async def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Repo discovery
    # ------------------------------------------------------------------

    def _resolve_repos(self) -> list[_WatchedRepo]:
        paths: list[Path] = []
        if self._explicit_paths:
            paths = [Path(p).expanduser().resolve() for p in self._explicit_paths]
        else:
            cwd = Path.cwd().resolve()
            git_dir = cwd / ".git"
            if git_dir.is_dir() or git_dir.is_file():
                paths = [cwd]

        repos: list[_WatchedRepo] = []
        for path in paths:
            git_dir = path / ".git"
            # Mirror from git_watcher: refuse symlinked .git.
            if git_dir.is_symlink():
                logger.warning(
                    "worktree_watcher: refusing symlinked .git path=%s -> %s",
                    git_dir,
                    git_dir.resolve(strict=False),
                )
                continue
            if not git_dir.exists():
                logger.warning(
                    "worktree_watcher: skipping non-repo path=%s",
                    path,
                )
                continue
            repos.append(_WatchedRepo(path=path, git_dir=git_dir))
        return repos

    # ------------------------------------------------------------------
    # Watchdog callbacks (thread → asyncio bridge)
    # ------------------------------------------------------------------

    def _on_file_modified(self, repo: _WatchedRepo, abs_path: str) -> None:
        """Called on the watchdog observer thread when a file write is detected."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        loop.call_soon_threadsafe(
            lambda: asyncio.create_task(self._handle_file_modified_async(repo, abs_path))
        )

    async def _handle_file_modified_async(self, repo: _WatchedRepo, abs_path: str) -> None:
        """Runs on the asyncio loop: apply guards, debounce, and publish."""
        try:
            p = Path(abs_path)

            # Skip symlinks (pentest pattern from git_watcher)
            if p.is_symlink():
                return

            # Skip .git/ internals; we only care about working-tree files
            try:
                p.relative_to(repo.git_dir)
                return  # inside .git, skip
            except ValueError:
                pass

            # Skip gitignored paths
            if self._is_ignored(repo, p):
                return

            # Debounce: collapse rapid writes to the same path
            now = time.monotonic()
            last = repo._debounce.get(abs_path, 0.0)
            if now - last < self._debounce_seconds:
                return

            # Evict oldest if debounce dict is growing too large
            if len(repo._debounce) >= MAX_DEBOUNCE_PATHS:
                oldest_half = sorted(repo._debounce, key=lambda k: repo._debounce[k])[
                    : MAX_DEBOUNCE_PATHS // 2
                ]
                for k in oldest_half:
                    del repo._debounce[k]

            repo._debounce[abs_path] = now

            try:
                rel_path = str(p.relative_to(repo.path))
            except ValueError:
                rel_path = abs_path

            ts = datetime.now(timezone.utc).isoformat()
            await self._publish(
                repo,
                {
                    "repo": str(repo.path),
                    "file_path": abs_path,
                    "rel_path": rel_path,
                    "ts": ts,
                },
            )

        except Exception as exc:  # pragma: no cover
            logger.warning("worktree_watcher: file modified handling failed: %s", exc)

    async def _publish(self, repo: _WatchedRepo, payload: dict[str, Any]) -> None:
        logger.debug(
            "worktree_watcher publishing kind=worktree_edit repo=%s file=%s",
            payload.get("repo"),
            payload.get("rel_path"),
        )
        await self._bus.publish(
            EGRESS_TOPIC,
            {"kind": "worktree_edit", "payload": payload, "source": "worktree_watcher"},
        )

    # ------------------------------------------------------------------
    # gitignore filtering
    # ------------------------------------------------------------------

    def _is_ignored(self, repo: _WatchedRepo, path: Path) -> bool:
        """Return True if ``path`` is covered by the repo's .gitignore."""
        if not repo._ignore_loaded:
            repo._ignore_spec = _load_ignore_spec(repo.path)
            repo._ignore_loaded = True

        ignore_spec = repo._ignore_spec
        if ignore_spec is None:
            return False

        try:
            rel = path.relative_to(repo.path)
            return bool(ignore_spec.match_file(str(rel)))
        except (ValueError, Exception):
            return False

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def watched_repos(self) -> list[_WatchedRepo]:
        return list(self._repos)


# ---------------------------------------------------------------------------
# watchdog event handler
# ---------------------------------------------------------------------------


class _WorktreeHandler:
    """Shims watchdog's FileSystemEventHandler without subclassing it.

    Only write-class events (Modified, Created, Moved-dest) reach the watcher.
    Read events (FileOpenedEvent, FileClosedNoWriteEvent) are dropped at this
    level; the same filter documented in git_watcher.py that prevented the
    ~10MB/s RSS flood from open-and-read bursts.
    """

    def __init__(self, watcher: WorktreeWatcher, repo: _WatchedRepo) -> None:
        self._watcher = watcher
        self._repo = repo
        self._construct_thread = threading.get_ident()

    def dispatch(self, event: Any) -> None:
        if getattr(event, "is_directory", False):
            return

        # Read-event filter: critical for whole-tree watchers.
        kind = type(event).__name__
        if kind in ("FileOpenedEvent", "FileClosedNoWriteEvent"):
            return

        # For moves, use the destination path (the new file that now exists)
        src = getattr(event, "src_path", None)
        dest = getattr(event, "dest_path", None)
        target = dest if dest and kind in ("FileMovedEvent",) else src
        if not isinstance(target, str):
            return

        self._watcher._on_file_modified(self._repo, target)


# ---------------------------------------------------------------------------
# gitignore helpers
# ---------------------------------------------------------------------------


def _load_ignore_spec(repo_root: Path) -> Any | None:
    """Load a pathspec.PathSpec from the repo's .gitignore.

    Returns ``None`` if pathspec is not installed or the .gitignore does not
    exist; callers treat None as "nothing is ignored".
    """
    try:
        import pathspec  # type: ignore[import-untyped]
    except ImportError:
        return None

    gitignore = repo_root / ".gitignore"
    if not gitignore.exists():
        return None

    try:
        lines = gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
        return pathspec.PathSpec.from_lines("gitwildmatch", lines)
    except Exception as exc:
        logger.debug("worktree_watcher: failed to load .gitignore at %s: %s", gitignore, exc)
        return None
