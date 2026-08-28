"""ClaudeJsonlWatcher - ambient token-usage adapter for Claude Code transcripts.

Watches the per-project ``*.jsonl`` transcript files under Claude Code's
home projects directory with ``watchdog``.
On modification, reads new lines from the persisted byte offset, parses each
via the privacy-hard-stop ``parse_assistant_line`` function, and POSTs
batches to the ~alter backend token-usage audit endpoint.

Privacy guarantee
-----------------

``parse_assistant_line`` is the ONLY path from JSONL bytes to the wire.
It is a strict **whitelist** parser: it constructs the output dict key-by-key
from explicitly named fields and never spreads ``record``, ``message``, or
``usage``. A privacy regression test seeds every non-whitelisted field with a
CANARY sentinel and asserts that no sentinel reaches the serialised output.
Any change to the whitelist fails that test.

Allowed output keys (exact set, no extras):
- ``session_id``           - from top-level ``sessionId``
- ``message_id``           - from ``message.id``
- ``model``                - from ``message.model``
- ``input_tokens``         - from ``message.usage.input_tokens``
- ``output_tokens``        - from ``message.usage.output_tokens``
- ``cache_creation_tokens`` - from ``message.usage.cache_creation_input_tokens``
- ``cache_read_tokens``    - from ``message.usage.cache_read_input_tokens``
- ``ts``                   - from top-level ``timestamp``

Offset persistence
------------------

Per-file byte offsets are persisted atomically to
``~/.local/share/alter-runtime/cc-offsets.json`` so the adapter survives
daemon restarts without re-emitting already-posted events. The backend is
idempotent on ``message_id`` as a second line of defence.

On file rotation (on-disk size < persisted offset), the offset is reset to 0.

Backfill
--------

On first run, every existing ``*.jsonl`` under the Claude Code projects
directory is walked and assistant events within the last 30 days are emitted in batches of
at most 500. A 5-second sleep is inserted between batches to avoid flooding
the backend.

Threading
---------

``watchdog`` callbacks run on the observer's own thread. We marshal onto the
asyncio loop via ``loop.call_soon_threadsafe`` before doing any async work -
the bus and HTTP client are not thread-safe.

Configuration
-------------

The adapter is opt-in: register it only when ``config.enable_claude_jsonl_watcher``
is ``True`` (default ``False``).

Data handling
-------------

- The adapter collects only aggregate token-usage counts per model
  (input, output, and cache token totals) plus the message and session
  identifiers listed above. It never reads or transmits prompt text,
  response text, tool calls, or any message content. The data is local
  operational telemetry for the owning user's own visibility.
- HTTP auth: JWT sourced from ``load_session()`` at adapter start, then
  refreshed per-POST from ``ALTER_RUNTIME_SESSION_JWT`` env var as a
  fallback. See ``TokenUsageClient`` for details.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from alter_runtime.config import DaemonConfig, data_dir, load_session
from alter_runtime.daemon import Component
from alter_runtime.subscribers.bus import EventBus

__all__ = ["ClaudeJsonlWatcher", "parse_assistant_line"]

logger = logging.getLogger("alter_runtime.adapters.claude_jsonl_watcher")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Root directory containing per-project JSONL transcript directories.
CLAUDE_PROJECTS_DIR: Path = Path.home() / ".claude" / "projects"

#: Offset state file - written atomically with rename.
OFFSETS_FILENAME: str = "cc-offsets.json"

#: Maximum events per POST batch.
BATCH_SIZE: int = 500

#: Minimum seconds between successive POSTs (rate limit).
POST_RATE_LIMIT_SECONDS: float = 5.0

#: Backfill window in days.
BACKFILL_DAYS: int = 30

#: Sleep between backfill batches.
BACKFILL_BATCH_SLEEP_SECONDS: float = 5.0


# ---------------------------------------------------------------------------
# Privacy hard-stop - WHITELIST PARSER
# ---------------------------------------------------------------------------


def parse_assistant_line(record: dict) -> Optional[dict]:
    """Parse one JSONL record and return a token-usage dict, or None.

    This is the privacy hard-stop between Claude Code's local transcripts
    and ~alter's audit database. It is a strict whitelist: the output dict is
    constructed key-by-key from explicitly named fields. ``record``,
    ``message``, and ``usage`` are NEVER spread. No key beyond the whitelist
    can reach the output.

    Returns None when:
    - ``record`` is not a dict
    - ``record["type"]`` is not ``"assistant"``
    - ``record["message"]`` is missing or not a dict
    - ``record["message"]["usage"]`` is missing or not a dict
    - ``record["message"]["id"]`` is missing or not a str
    - ``record["message"]["usage"]["input_tokens"]`` or ``output_tokens`` is missing

    Malformed records return None rather than raising.
    """
    if not isinstance(record, dict):
        return None
    if record.get("type") != "assistant":
        return None
    msg = record.get("message")
    if not isinstance(msg, dict):
        return None
    usage = msg.get("usage")
    if not isinstance(usage, dict):
        return None
    msg_id = msg.get("id")
    if not isinstance(msg_id, str):
        return None
    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    if input_tokens is None or output_tokens is None:
        return None
    # Construct output dict key-by-key - no spread, no wildcard access.
    return {
        "session_id": str(record.get("sessionId", "")),
        "message_id": msg_id,
        "model": str(msg.get("model", "")),
        "input_tokens": int(input_tokens),
        "output_tokens": int(output_tokens),
        "cache_creation_tokens": int(usage.get("cache_creation_input_tokens") or 0),
        "cache_read_tokens": int(usage.get("cache_read_input_tokens") or 0),
        "ts": str(record.get("timestamp", "")),
    }


# ---------------------------------------------------------------------------
# Offset persistence helpers
# ---------------------------------------------------------------------------


def _offsets_path() -> Path:
    """Return the path to the per-file byte-offset state file."""
    return data_dir() / OFFSETS_FILENAME


def _load_offsets() -> dict[str, int]:
    """Load the offset state file, returning an empty dict on failure."""
    path = _offsets_path()
    if not path.exists():
        return {}
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, dict):
            return {str(k): int(v) for k, v in data.items() if isinstance(v, (int, float))}
    except (json.JSONDecodeError, OSError, ValueError):
        pass
    return {}


def _save_offsets(offsets: dict[str, int]) -> None:
    """Atomically write the offset state file (write → fsync → rename)."""
    path = _offsets_path()
    tmp = path.with_suffix(".tmp")
    try:
        content = json.dumps(offsets, indent=2)
        tmp.write_text(content, encoding="utf-8")
        # fsync the tmp file to ensure data reaches disk before rename.
        with tmp.open("rb") as f:
            os.fsync(f.fileno())
        tmp.rename(path)
    except OSError as exc:
        logger.warning("cc-offsets write failed: %s", exc)
        with contextlib.suppress(OSError):
            tmp.unlink()


# ---------------------------------------------------------------------------
# ClaudeJsonlWatcher
# ---------------------------------------------------------------------------


class ClaudeJsonlWatcher(Component):
    """Watches Claude Code JSONL transcripts and posts token-usage events.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`.
    bus:
        Shared :class:`EventBus` (not published to - present for Component
        symmetry and future local-signal emission).
    projects_dir:
        Override the Claude Code projects directory for testing.
    """

    name = "claude_jsonl_watcher"

    def __init__(
        self,
        config: DaemonConfig,
        bus: EventBus,
        projects_dir: Path | None = None,
        *,
        session_ref: object | None = None,
    ) -> None:
        self._config = config
        self._bus = bus
        self._session_ref = session_ref  # Optional SessionRef for live JWT read-through
        self._projects_dir = (projects_dir or CLAUDE_PROJECTS_DIR).expanduser().resolve()
        self._stop_event = asyncio.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._offsets: dict[str, int] = {}
        self._last_post_time: float = 0.0
        self._http_client: object | None = None  # TokenUsageClient, imported lazily
        self._pending_flush: asyncio.Task | None = None

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._offsets = _load_offsets()

        # Import HTTP client lazily so the module is importable without httpx.
        from alter_runtime.clients.token_usage_client import TokenUsageClient

        session = load_session()
        jwt: str | None = None
        if session is not None:
            jwt = session.jwt

        api_base = os.environ.get("ALTER_RUNTIME_API_BASE", "https://api.truealter.com")
        _ref = self._session_ref

        def _jwt_provider() -> str | None:
            # Prefer env-var override; then live SessionRef (proactive rotation);
            # fall back to the session JWT loaded at startup.
            env_jwt = os.environ.get("ALTER_RUNTIME_SESSION_JWT")
            if env_jwt:
                return env_jwt
            if _ref is not None:
                live = getattr(_ref, "current", None)
                if live is not None:
                    return getattr(live, "jwt", None)
            return jwt

        self._http_client = TokenUsageClient(base_url=api_base, jwt_provider=_jwt_provider)

        try:
            from watchdog.events import FileSystemEventHandler  # noqa: F401
            from watchdog.observers import Observer
        except ImportError:
            logger.warning("watchdog not installed - claude_jsonl_watcher disabled")
            await self._stop_event.wait()
            return

        if not self._projects_dir.exists():
            logger.info(
                "claude_jsonl_watcher: %s does not exist - skipping",
                self._projects_dir,
            )
            await self._stop_event.wait()
            return

        # First-run backfill
        await self._backfill_existing()

        # Set up watchdog observer
        observer = Observer()
        handler = _JsonlFileHandler(self)
        observer.schedule(handler, str(self._projects_dir), recursive=True)
        observer.daemon = True
        observer.start()

        logger.info(
            "claude_jsonl_watcher watching %s (offsets_file=%s)",
            self._projects_dir,
            _offsets_path(),
        )

        try:
            await self._stop_event.wait()
        finally:
            with contextlib.suppress(Exception):
                observer.stop()
                observer.join(timeout=2.0)
            logger.info("claude_jsonl_watcher stopped")

    async def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Backfill
    # ------------------------------------------------------------------

    async def _backfill_existing(self) -> None:
        """Walk every existing *.jsonl and emit the last 30 days' events."""
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=BACKFILL_DAYS)
        batch: list[dict] = []
        count = 0

        for jsonl_path in sorted(self._projects_dir.rglob("*.jsonl")):
            path_str = str(jsonl_path)
            if path_str in self._offsets:
                # Already partially consumed - skip full backfill for this file,
                # tail will catch new bytes.
                continue
            try:
                events = _read_events_from_file(jsonl_path, offset=0, cutoff=cutoff)
            except OSError as exc:
                logger.debug("backfill: skipping %s: %s", path_str, exc)
                continue
            # Record the end-of-file offset so future tails start correctly.
            try:
                size = jsonl_path.stat().st_size
            except OSError:
                size = 0
            self._offsets[path_str] = size

            for ev in events:
                slug = _slug_from_path(jsonl_path, self._projects_dir)
                ev["project_slug"] = slug
                batch.append(ev)
                if len(batch) >= BATCH_SIZE:
                    await self._flush_batch(batch)
                    batch = []
                    count += BATCH_SIZE
                    await asyncio.sleep(BACKFILL_BATCH_SLEEP_SECONDS)

        if batch:
            await self._flush_batch(batch)

        _save_offsets(self._offsets)
        logger.info("claude_jsonl_watcher backfill complete events_emitted=%d", count + len(batch))

    # ------------------------------------------------------------------
    # Watchdog callback (thread → asyncio bridge)
    # ------------------------------------------------------------------

    def _on_file_change(self, path_str: str) -> None:
        """Called on the watchdog observer thread when a JSONL file changes."""
        if not path_str.endswith(".jsonl"):
            return
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        loop.call_soon_threadsafe(lambda: asyncio.create_task(self._handle_file_change(path_str)))

    async def _handle_file_change(self, path_str: str) -> None:
        """Read new lines from the file and post events."""
        jsonl_path = Path(path_str)
        if not jsonl_path.is_file():
            return

        try:
            current_size = jsonl_path.stat().st_size
        except OSError:
            return

        persisted_offset = self._offsets.get(path_str, 0)

        # File rotation: on-disk size smaller than persisted offset.
        if current_size < persisted_offset:
            logger.info(
                "claude_jsonl_watcher: rotation detected %s (size=%d < offset=%d) - reset",
                path_str,
                current_size,
                persisted_offset,
            )
            persisted_offset = 0
            self._offsets[path_str] = 0

        if current_size == persisted_offset:
            return  # No new bytes

        try:
            events = _read_events_from_file(jsonl_path, offset=persisted_offset)
        except OSError as exc:
            logger.debug("claude_jsonl_watcher: read error %s: %s", path_str, exc)
            return

        slug = _slug_from_path(jsonl_path, self._projects_dir)
        batch = []
        for ev in events:
            ev["project_slug"] = slug
            batch.append(ev)

        if not batch:
            # Advance offset even when no parseable events (e.g. user-only lines).
            self._offsets[path_str] = current_size
            _save_offsets(self._offsets)
            return

        # Rate-limit: if we posted recently, wait.
        now = time.monotonic()
        since_last = now - self._last_post_time
        if since_last < POST_RATE_LIMIT_SECONDS:
            await asyncio.sleep(POST_RATE_LIMIT_SECONDS - since_last)

        success = await self._flush_batch(batch)
        if success:
            # Only advance offset after a successful POST - on failure the
            # next watchdog tick will re-attempt from the old offset.
            self._offsets[path_str] = current_size
            _save_offsets(self._offsets)

    # ------------------------------------------------------------------
    # HTTP posting
    # ------------------------------------------------------------------

    async def _flush_batch(self, events: list[dict]) -> bool:
        """POST a batch of events. Returns True on success, False on failure."""
        if not events or self._http_client is None:
            return True
        try:
            result = await self._http_client.post_events(events)  # type: ignore[attr-defined]
            self._last_post_time = time.monotonic()
            logger.info(
                "claude_jsonl_watcher posted events=%d result=%s",
                len(events),
                result,
            )
            return True
        except Exception as exc:
            logger.warning("claude_jsonl_watcher POST failed: %s - will retry on next tick", exc)
            return False


# ---------------------------------------------------------------------------
# File-reading helpers
# ---------------------------------------------------------------------------


def _read_events_from_file(
    path: Path,
    offset: int,
    cutoff: datetime | None = None,
) -> list[dict]:
    """Read and parse assistant events from a JSONL file starting at ``offset``.

    Only assistant lines with token usage are returned. Lines that don't
    parse or fail the date cutoff are silently skipped.
    """
    events: list[dict] = []
    try:
        with path.open("rb") as f:
            if offset > 0:
                f.seek(offset)
            for raw_line in f:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                parsed = parse_assistant_line(record)
                if parsed is None:
                    continue
                if cutoff is not None:
                    ts_str = parsed.get("ts", "")
                    if ts_str:
                        try:
                            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                            if ts < cutoff:
                                continue
                        except ValueError:
                            pass  # Unparseable timestamp - include it.
                events.append(parsed)
    except OSError:
        raise
    return events


def _slug_from_path(jsonl_path: Path, projects_dir: Path) -> str:
    """Derive the project slug from the JSONL file path.

    ``<projects-dir>/<slug>/<session>.jsonl`` → ``<slug>``
    """
    try:
        relative = jsonl_path.relative_to(projects_dir)
        return relative.parts[0] if relative.parts else str(jsonl_path.parent.name)
    except ValueError:
        return jsonl_path.parent.name


# ---------------------------------------------------------------------------
# watchdog event handler
# ---------------------------------------------------------------------------


class _JsonlFileHandler:
    """watchdog handler shim - dispatches JSONL file events to the watcher.

    Imported lazily (watchdog is optional). We shim the handler interface via
    duck typing rather than subclassing so that importing this module never
    demands watchdog at module load time.
    """

    def __init__(self, watcher: ClaudeJsonlWatcher) -> None:
        self._watcher = watcher
        self._thread = threading.get_ident()

    def dispatch(self, event: object) -> None:
        # Ignore directory events and pure-read events.
        if getattr(event, "is_directory", False):
            return
        kind = type(event).__name__
        if kind in ("FileOpenedEvent", "FileClosedNoWriteEvent"):
            return

        src = getattr(event, "src_path", None)
        dest = getattr(event, "dest_path", None)
        target = dest or src
        if not isinstance(target, str):
            return
        # New files (FileCreatedEvent) also trigger tail from offset=0.
        self._watcher._on_file_change(target)
