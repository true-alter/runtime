"""DoctrineProjectionPoller - maintains a local read-only JSONL projection of
the member's doctrine substrate, per scope.

Why this exists
---------------

The member's living-state doctrine (``alter_doctrine``: decisions, doctrine,
proposed-d, handovers, personal notes) lives server-side. Surfaces that want
to read "what is true now" offline - a hook, the CLI, a downstream reader -
need a local mirror they can grep without a network round-trip on every read.
This component is that mirror's writer.

Pull-mode, not an SSE subscriber
--------------------------------

Unlike :class:`InboxWriter` (which projects ``alter_message`` frames pushed
over the per-handle SSE stream), the backend emits **no event on a doctrine
write**. There is nothing to subscribe to. So this poller pulls on a fixed
cadence, but cheaply: each tick it calls the ``alter_doctrine`` ``summary``
verb (``{scope, max_created_at, count, etag}``) and only fetches the ``list``
delta when the etag has changed since the last checkpoint. A steady-state with
no doctrine writes is therefore one summary call per scope per tick and **zero**
writes - no list call, no JSONL append, no checkpoint rewrite.

Sync loop, per scope
--------------------

1. Call ``alter_doctrine`` ``summary`` for the scope -> ``{scope,
   max_created_at, count, etag}``.
2. Reconcile the checkpoint against the JSONL: if the file holds fewer rows than
   the checkpoint recorded projecting, it was truncated behind our back, so
   force a full re-pull (a delta cannot repair it - the missing rows are older
   than the cursor).
3. Otherwise, if ``etag`` is unchanged vs the cached checkpoint, SKIP (no
   further network, no write).
4. On change, call ``alter_doctrine`` ``list`` for the scope with
   ``since=<last_max_created_at>`` (delta only, or the full history when step 2
   forced it), cursor-paginating to completion.
5. Project each returned row to the local JSONL with the full StateEntry shape
   (verbatim - whatever the verb returns), append-only, deduped on ``id``.
6. Persist the new ``etag`` + ``max_created_at`` + the row count actually held
   to a per-scope checkpoint file via tmp-then-:func:`os.replace`, and only
   after a drain that reached the end of the list.

Retention
---------

Each projected row carries its SOURCE ``decay_class`` verbatim - the projection
NEVER invents one; constitutive kinds (decision / doctrine / proposed-d) stay
``exempt`` exactly as the substrate recorded them. The projection FILE itself is
a rolling, rebuildable-from-substrate cache: deleting it loses nothing the
substrate cannot re-serve, and the next tick re-pulls the full history.

That rebuild is not automatic, and assuming it was is what starved this
projection in the field. The file and the checkpoint are two pieces of state
that must agree, and deleting the file resets only one of them: the cursor
survives, still pointing at the server's newest row, so the etag gate reports
"nothing new" and the ``since`` delta asks only for rows written after the
cursor. Every server-side signal stays green while the projection holds
nothing. Step 2 below therefore reconciles the cursor against the file it
claims to describe BEFORE trusting it, which is what makes the rebuild real.

Wire contract
-------------

Shares the read-side MCP wire contract with
:class:`~alter_runtime.subscribers.mcp_fallback.McpFallbackSubscriber` and
:class:`~alter_runtime.subscribers.attunement_refresher.AttunementRefresher`:
the same JSON-RPC 2.0 ``tools/call`` envelope, the shared
``mcp_fallback_endpoint``, the Bearer-JWT auth, and the per-invocation ES256
signature header. One wire contract, not a fourth. The poller is resilient: any
transport error backs off exponentially (capped) and retries on the next tick;
the last-synced JSONL is left intact and the loop never raises out, so an
offline window cannot crash the daemon or corrupt the cache.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import fcntl
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from alter_runtime.config import DaemonConfig, doctrine_projection_dir
from alter_runtime.daemon import Component
from alter_runtime.http_auth import backend_default_headers
from alter_runtime.subscribers.do_sse import _build_tls_context

if TYPE_CHECKING:
    from alter_runtime.config import Session, SessionRef

__all__ = ["DoctrineProjectionPoller", "DOCTRINE_SCOPES"]

logger = logging.getLogger("alter_runtime.subscribers.doctrine_projection")

#: The scopes this poller projects. Each maps to its own ``<scope>.jsonl`` and
#: ``.<scope>.checkpoint.json`` under :func:`doctrine_projection_dir`.
DOCTRINE_SCOPES: tuple[str, ...] = ("personal", "collective")

#: Upper bound on the poller's own exponential backoff when the MCP endpoint
#: (or the doctrine tool) is failing. Matches the other pollers' cap.
MAX_POLL_BACKOFF_SECONDS: float = 60.0

#: Safety bound on cursor-pagination loops per ``list`` drain - a malformed
#: server cursor that never advances must not spin forever.
_MAX_PAGES: int = 10_000


class DoctrineProjectionPoller(Component):
    """Maintains a local read-only JSONL projection of doctrine, per scope.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`. Uses ``mcp_fallback_endpoint`` (the shared
        read-side MCP endpoint) and ``doctrine_projection_interval_seconds``.
    session:
        Authenticated CLI :class:`Session` (or a :class:`SessionRef` holder for
        live JWT read-through). Used for the Bearer JWT and the handle (logging).
    projection_dir:
        Override the projection directory. Tests pass a ``tmp_path`` so writes
        never touch the real ``~/.local/share/alter/doctrine``.
    http_client:
        Optional ``httpx.AsyncClient`` override for tests.
    interval_seconds:
        Override the poll cadence (tests pass a small value). Falls back to
        ``config.doctrine_projection_interval_seconds`` when ``None``.
    """

    name = "doctrine_projection"

    def __init__(
        self,
        config: DaemonConfig,
        session: "Session | SessionRef",
        *,
        projection_dir: Path | None = None,
        http_client: httpx.AsyncClient | None = None,
        interval_seconds: float | None = None,
    ) -> None:
        self._config = config
        from alter_runtime.config import SessionRef as _SessionRef

        if isinstance(session, _SessionRef):
            self._session_ref: "_SessionRef | None" = session
            self._session: "Session" = session.current
        else:
            self._session_ref = None
            self._session = session

        # Lazy-resolve the projection dir so a test that monkeypatches the XDG
        # env vars before construction gets the redirected directory. An
        # explicit override always wins.
        self._projection_dir_override = projection_dir
        self._http_client = http_client
        self._owns_client = http_client is None
        self._interval = (
            interval_seconds
            if interval_seconds is not None
            else config.doctrine_projection_interval_seconds
        )
        self._stop_event = asyncio.Event()
        self._request_id_counter = 0
        self._backoff: float = 0.0
        # Test introspection counters.
        self._summary_calls: int = 0
        self._list_calls: int = 0
        self._rows_written: int = 0
        self._skip_count: int = 0

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _dir(self) -> Path:
        """Resolve the projection directory (override or XDG default)."""
        if self._projection_dir_override is not None:
            self._projection_dir_override.mkdir(parents=True, exist_ok=True, mode=0o700)
            return self._projection_dir_override
        return doctrine_projection_dir()

    def jsonl_path(self, scope: str) -> Path:
        """Absolute path of the JSONL projection for ``scope``."""
        return self._dir() / f"{scope}.jsonl"

    def checkpoint_path(self, scope: str) -> Path:
        """Absolute path of the per-scope checkpoint file."""
        return self._dir() / f".{scope}.checkpoint.json"

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Tick on the configured interval, syncing every scope each tick."""
        logger.info(
            "doctrine_projection starting handle=%s endpoint=%s interval=%.0fs scopes=%s",
            self._session.handle,
            self._config.mcp_fallback_endpoint,
            self._interval,
            ",".join(DOCTRINE_SCOPES),
        )

        client = self._http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
            # Same strict TLS posture as the SSE / MCP fallback path:
            # CERT_REQUIRED, check_hostname=True, TLS 1.2 minimum.
            verify=_build_tls_context(),
            # Canonical client-identity headers; the per-request Bearer JWT and
            # invocation signature are attached on each call below.
            headers=backend_default_headers(),
        )

        try:
            while not self._stop_event.is_set():
                try:
                    await self._sync_all_scopes(client)
                except asyncio.CancelledError:
                    raise
                except (httpx.HTTPError, ValueError) as exc:
                    # Transport-level failure across the tick: back off and retry
                    # next tick. The last-synced JSONL is untouched.
                    await self._on_poll_error(exc)
                    await self._sleep_interruptible(self._backoff)
                    continue

                # A clean tick resets the backoff.
                self._backoff = 0.0
                await self._sleep_interruptible(self._interval)
        finally:
            if self._owns_client:
                try:
                    await client.aclose()
                except Exception:  # pragma: no cover
                    pass
            logger.info("doctrine_projection stopped handle=%s", self._session.handle)

    async def stop(self) -> None:
        """Cooperative shutdown - release the interval sleep."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Sync
    # ------------------------------------------------------------------

    async def _sync_all_scopes(self, client: httpx.AsyncClient) -> None:
        """Sync every scope in turn. A soft failure on one scope never aborts
        the others - each scope's sync swallows its own non-transport errors."""
        for scope in DOCTRINE_SCOPES:
            await self._sync_scope(client, scope)

    async def _sync_scope(self, client: httpx.AsyncClient, scope: str) -> None:
        """Run the summary -> (starvation reconcile) -> (etag gate) -> list-delta
        -> project loop for one scope.

        Transport errors (``httpx.HTTPError``) propagate so the caller's tick
        backoff engages; soft failures (JSON-RPC error, malformed payload) are
        logged and skipped without raising.
        """
        summary = await self._call_doctrine(client, {"action": "summary", "scope": scope})
        self._summary_calls += 1
        if summary is None:
            # Soft failure (JSON-RPC error / malformed) already logged.
            return

        etag = summary.get("etag")
        max_created_at = summary.get("max_created_at")
        server_count = summary.get("count")

        checkpoint = self._load_checkpoint(scope)

        # Reconcile the checkpoint against the FILE it claims to describe, BEFORE
        # the etag gate. The checkpoint is a cursor over the SERVER; on its own it
        # says nothing about what the local JSONL actually holds. If the file is
        # truncated or deleted out from under us, every server-side signal stays
        # correct and stale-free while the projection is empty, so both the etag
        # skip and the ``since`` delta silently preserve the loss forever.
        # Observing the file is what closes that gap.
        projected = self._existing_ids(self.jsonl_path(scope))
        starved = self._is_starved(
            scope,
            projected=len(projected),
            checkpoint=checkpoint,
            server_count=server_count,
        )

        if not starved and etag is not None and etag == checkpoint.get("etag"):
            self._skip_count += 1
            logger.debug("doctrine_projection scope=%s etag unchanged (%s) - skip", scope, etag)
            return

        # A starved projection cannot be repaired by a delta: the missing rows are
        # older than the cursor. Re-pull the full history instead.
        since = None if starved else checkpoint.get("max_created_at")
        drained = await self._drain_list(client, scope, since)
        if drained is None:
            # Soft failure during the list drain; leave the checkpoint as-is so
            # the next tick retries the same delta.
            return
        rows, complete = drained

        written = self._project_rows(scope, rows, seen=projected)
        self._rows_written += written
        total = len(projected)

        if not complete:
            # The drain stopped short of the end, so ``max_created_at`` from the
            # summary describes rows we never fetched. Advancing to it would skip
            # them permanently. Leave the checkpoint; the next tick retries.
            logger.warning(
                "doctrine_projection scope=%s drain incomplete (rows=%d) - checkpoint held",
                scope,
                written,
            )
            return

        # Advance the checkpoint only after a complete drain and a successful
        # project, and record what the projection actually HOLDS alongside the
        # server cursor, so a later truncation is detectable rather than silent.
        self._save_checkpoint(
            scope,
            etag=etag,
            max_created_at=max_created_at,
            projected_count=total,
        )
        logger.info(
            "doctrine_projection scope=%s synced rows=%d total=%d etag=%s max_created_at=%s",
            scope,
            written,
            total,
            etag,
            max_created_at,
        )

    def _is_starved(
        self,
        scope: str,
        *,
        projected: int,
        checkpoint: dict[str, Any],
        server_count: Any,
    ) -> bool:
        """Has the local JSONL lost rows the checkpoint claims are projected?

        Two signals, in order of authority:

        1. ``projected_count`` from our own last checkpoint. This is EXACT: we
           wrote that many rows and the file should never hold fewer. Strictly
           fewer means the file was truncated or deleted since we wrote it.
        2. On a legacy checkpoint written before ``projected_count`` existed, fall
           back to the server's ``count``. This is a conservative bootstrap only,
           and deliberately not the steady-state signal: the append-only JSONL
           keeps superseded rows the server's current-entry ``count`` excludes, so
           the two are not equal by construction and ``!=`` would loop forever.
           One full re-pull records a real ``projected_count`` and signal 1 takes
           over from the next tick.
        """
        last = checkpoint.get("projected_count")
        if isinstance(last, int):
            if projected >= last:
                return False
            logger.warning(
                "doctrine_projection scope=%s STARVED: projection holds %d row(s), "
                "checkpoint recorded %d - forcing a full re-pull",
                scope,
                projected,
                last,
            )
            return True

        if not checkpoint:
            # Cold start: no checkpoint at all, so ``since`` is already None and
            # the drain is a full pull by construction. Nothing to force.
            return False

        if isinstance(server_count, int) and projected < server_count:
            logger.warning(
                "doctrine_projection scope=%s STARVED: projection holds %d row(s), "
                "server declares %d and the checkpoint predates count-tracking - "
                "forcing a full re-pull",
                scope,
                projected,
                server_count,
            )
            return True
        return False

    async def _drain_list(
        self, client: httpx.AsyncClient, scope: str, since: str | None
    ) -> tuple[list[dict[str, Any]], bool] | None:
        """Cursor-paginate ``list`` to completion, returning ``(rows, complete)``.

        ``complete`` is False when the drain stopped at the page cap rather than
        at the true end of the list, which tells the caller its cursor would be
        advancing past rows it never fetched.

        Returns ``None`` on a soft failure (so the caller leaves the checkpoint
        untouched). ``since`` is the last-synced ``max_created_at`` (``None`` on
        a cold start, which pulls the full history).
        """
        rows: list[dict[str, Any]] = []
        cursor: str | None = None
        pages = 0
        complete = True
        while True:
            args: dict[str, Any] = {"action": "list", "scope": scope, "limit": 200}
            if since:
                args["since"] = since
            if cursor:
                args["cursor"] = cursor

            page = await self._call_doctrine(client, args)
            if page is None:
                return None  # soft failure mid-drain

            data = page.get("data")
            if isinstance(data, list):
                rows.extend(r for r in data if isinstance(r, dict))

            pagination = page.get("pagination") or {}
            cursor = pagination.get("next_cursor") if isinstance(pagination, dict) else None
            has_more = bool(pagination.get("has_more")) if isinstance(pagination, dict) else False

            pages += 1
            if not cursor or not has_more or pages >= _MAX_PAGES:
                if pages >= _MAX_PAGES and cursor and has_more:
                    logger.warning(
                        "doctrine_projection scope=%s hit page cap %d - stopping drain",
                        scope,
                        _MAX_PAGES,
                    )
                    complete = False
                break

        return rows, complete

    # ------------------------------------------------------------------
    # Projection (JSONL append, dedupe on id)
    # ------------------------------------------------------------------

    def _project_rows(
        self, scope: str, rows: list[dict[str, Any]], *, seen: set[str] | None = None
    ) -> int:
        """Append each new row to the scope JSONL, deduped on ``id``.

        Rows already present (by ``id``) are skipped. A row that supersedes an
        earlier one is simply appended; the chain-head resolution is a read-side
        concern (the newest non-superseded ``id`` wins), exactly as the backend
        ``get`` chain logic resolves it - the append-only JSONL preserves the
        full amendment history rather than rewriting in place.

        ``seen`` is the already-projected id set when the caller has read it
        (the sync loop reads it to reconcile starvation, so re-reading here
        would parse the whole file twice per tick). It is MUTATED to reflect
        what the file holds after this call, so the caller can record an
        accurate count. A row that fails to append is left out of it.

        Returns the count of rows newly written.
        """
        path = self.jsonl_path(scope)
        if seen is None:
            seen = self._existing_ids(path)
        if not rows:
            return 0

        written = 0
        for row in rows:
            row_id = row.get("id")
            if row_id is None:
                logger.warning("doctrine_projection scope=%s row missing id - dropping", scope)
                continue
            key = str(row_id)
            if key in seen:
                continue
            line = json.dumps(row, separators=(",", ":"), ensure_ascii=False, default=str)
            try:
                self._append_line(path, line)
            except OSError as exc:
                logger.warning(
                    "doctrine_projection scope=%s append failed: %s - dropping row %s",
                    scope,
                    exc,
                    key,
                )
                continue
            seen.add(key)
            written += 1
        return written

    @staticmethod
    def _existing_ids(path: Path) -> set[str]:
        """Read the set of already-projected row ids from the JSONL (empty if absent).

        A corrupt (non-JSON) line is skipped rather than aborting the read -
        the projection favours resilience; the substrate is the canonical
        record and a re-pull rebuilds anything dropped.
        """
        ids: set[str] = set()
        if not path.exists():
            return ids
        try:
            with open(path, encoding="utf-8") as fh:
                with contextlib.suppress(OSError):
                    fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
                try:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            raw = json.loads(line)
                        except (ValueError, json.JSONDecodeError):
                            continue
                        if isinstance(raw, dict) and raw.get("id") is not None:
                            ids.add(str(raw["id"]))
                finally:
                    with contextlib.suppress(OSError):
                        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            logger.warning("doctrine_projection: unable to read %s: %s", path, exc)
        return ids

    def _append_line(self, path: Path, line: str) -> None:
        """Atomically append ``line + '\\n'`` to ``path`` (mode 0o600).

        Uses ``O_APPEND`` semantics: the single small write is atomic against
        concurrent writers on POSIX,
        and an exclusive ``flock`` serialises against a second daemon instance.
        ``flock`` is guarded so an exotic filesystem that does not support it
        (``ENOTSUP`` / ``EINVAL``) degrades to the ``O_APPEND`` guarantee
        rather than crashing. ``fchmod`` is best-effort for the same reason.
        """
        self._ensure_parent(path)

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(path, flags, 0o600)
        try:
            # Re-tighten perms (umask may have widened the mode at create time).
            with contextlib.suppress(OSError):
                os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError as exc:  # pragma: no cover - exotic FS
                if exc.errno not in (errno.ENOTSUP, errno.EINVAL):
                    raise
            try:
                os.write(fd, line.encode("utf-8") + b"\n")
                os.fsync(fd)
            finally:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    @staticmethod
    def _ensure_parent(path: Path) -> None:
        """Create the parent directory with mode ``0o700`` if missing."""
        parent = path.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            os.chmod(parent, 0o700)

    # ------------------------------------------------------------------
    # Checkpoint persistence (tmp-then-os.replace, exactly the inbox idiom)
    # ------------------------------------------------------------------

    def _load_checkpoint(self, scope: str) -> dict[str, Any]:
        """Load ``{etag, max_created_at}`` for ``scope`` (empty dict if absent)."""
        path = self.checkpoint_path(scope)
        if not path.exists():
            return {}
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning(
                "doctrine_projection: unable to load checkpoint %s: %s - cold start",
                path,
                exc,
            )
            return {}
        if not isinstance(data, dict):
            return {}
        return data

    def _save_checkpoint(
        self,
        scope: str,
        *,
        etag: Any,
        max_created_at: Any,
        projected_count: int | None = None,
    ) -> None:
        """Atomically write the per-scope checkpoint via tmp + ``os.replace``.

        ``projected_count`` records how many rows the JSONL actually held when
        this cursor was written, so a later tick can tell a quiet truncation
        from a legitimately unchanged store.
        """
        path = self.checkpoint_path(scope)
        self._ensure_parent(path)
        payload = {
            "scope": scope,
            "etag": etag,
            "max_created_at": max_created_at,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        if projected_count is not None:
            payload["projected_count"] = projected_count
        tmp_path = path.with_suffix(path.suffix + ".tmp")

        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(tmp_path, flags, 0o600)
        try:
            with contextlib.suppress(OSError):
                os.fchmod(fd, 0o600)
            os.write(fd, json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

        os.replace(tmp_path, path)
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)

    # ------------------------------------------------------------------
    # MCP wire (JSON-RPC tools/call -> alter_doctrine)
    # ------------------------------------------------------------------

    async def _call_doctrine(
        self, client: httpx.AsyncClient, arguments: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Call ``alter_doctrine`` with ``arguments`` and return the parsed result.

        ``alter_doctrine`` returns an MCP text content-block whose single text
        item is a JSON string (the handler wraps its payload via ``_text``). We
        unwrap ``result.content[0].text`` and ``json.loads`` it back into the
        structured dict (``{scope,...}`` for summary, ``{data, pagination}`` for
        list).

        Raises on transport errors (``httpx.HTTPError``) so the caller's backoff
        path engages; returns ``None`` for a well-formed-but-empty,
        JSON-RPC-error, ``isError``, or no-credential response so a single soft
        failure does not abort the tick.

        Authentication: ``alter_doctrine`` is a member-self tool requiring
        ``member_self`` scope, which the 24h bearer JWT does NOT carry. It is
        authenticated with the long-lived ``member_api_key`` sent as
        ``X-ALTER-API-Key`` (exactly the bridge's contract for member-self
        tools) - the JWT and the per-invocation ES256 signature are NOT sent on
        this path. When the session carries no member key (legacy pre-cutover
        login) the call soft-fails: nothing is written, the next tick retries.
        """
        _live = self._session_ref.current if self._session_ref is not None else self._session
        member_api_key = getattr(_live, "member_api_key", None)
        if not member_api_key:
            logger.warning(
                "doctrine_projection: session carries no member_api_key - "
                "alter_doctrine needs member_self scope; skipping (re-run `alter login`)"
            )
            return None

        self._request_id_counter += 1
        body = {
            "jsonrpc": "2.0",
            "id": self._request_id_counter,
            "method": "tools/call",
            "params": {
                "name": "alter_doctrine",
                "arguments": arguments,
            },
        }
        if arguments.get("action") == "list":
            self._list_calls += 1

        headers = {
            "X-ALTER-API-Key": member_api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        response = await client.post(
            self._config.mcp_fallback_endpoint,
            json=body,
            headers=headers,
        )
        response.raise_for_status()

        try:
            rpc_response = response.json()
        except ValueError:
            logger.warning(
                "doctrine_projection non-JSON response action=%s", arguments.get("action")
            )
            return None

        if not isinstance(rpc_response, dict):
            return None
        if "error" in rpc_response and rpc_response.get("error"):
            err = rpc_response["error"]
            logger.warning(
                "doctrine_projection JSON-RPC error action=%s code=%s message=%s",
                arguments.get("action"),
                err.get("code") if isinstance(err, dict) else err,
                err.get("message") if isinstance(err, dict) else err,
            )
            return None

        result = rpc_response.get("result")
        if not isinstance(result, dict):
            return None
        if result.get("isError"):
            logger.warning(
                "doctrine_projection tool isError action=%s text=%s",
                arguments.get("action"),
                _first_text(result),
            )
            return None

        text = _first_text(result)
        if text is None:
            return None
        try:
            payload = json.loads(text)
        except (ValueError, json.JSONDecodeError):
            logger.warning(
                "doctrine_projection unparseable content action=%s", arguments.get("action")
            )
            return None
        if not isinstance(payload, dict):
            return None
        return payload

    async def _on_poll_error(self, exc: Exception) -> None:
        """Increase backoff and log. Never raises."""
        self._backoff = min(
            max(self._backoff * 2 if self._backoff else 2.0, 2.0),
            MAX_POLL_BACKOFF_SECONDS,
        )
        logger.warning(
            "doctrine_projection poll failed: %s - backoff %.1fs",
            exc,
            self._backoff,
        )

    async def _sleep_interruptible(self, seconds: float) -> None:
        """Wait ``seconds`` or until stopped, whichever comes first."""
        if seconds <= 0:
            return
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
        except (TimeoutError, asyncio.TimeoutError):
            return

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def summary_calls(self) -> int:
        """Number of ``summary`` calls issued (used by tests)."""
        return self._summary_calls

    @property
    def list_calls(self) -> int:
        """Number of ``list`` calls issued (used by tests)."""
        return self._list_calls

    @property
    def rows_written(self) -> int:
        """Total rows newly appended across the lifetime (used by tests)."""
        return self._rows_written

    @property
    def skip_count(self) -> int:
        """Number of etag-unchanged skips (used by tests)."""
        return self._skip_count

    @property
    def backoff(self) -> float:
        """Current backoff value (used by tests)."""
        return self._backoff


def _first_text(result: dict[str, Any]) -> str | None:
    """Return the text of the first ``text`` content-block, or ``None``.

    ``alter_doctrine`` returns ``{"content": [{"type": "text", "text": ...}],
    ...}``; this lifts the inner JSON string back out.
    """
    content = result.get("content")
    if not isinstance(content, list):
        return None
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            text = block.get("text")
            if isinstance(text, str):
                return text
    return None
