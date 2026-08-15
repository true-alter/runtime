"""ActiveSessionsDoPublisher - tails the JSONL and POSTs to the per-handle DO.

Companion publisher to :class:`ActiveSessionsWriter` (the local-disk
writer) and :class:`ActiveSessionsGc` (the idle/terminated sweeper).

The writer + GC pass already produce ``session_started`` /
``session_heartbeat`` / ``session_ended`` envelopes into
``~/.local/share/alter-runtime/active-sessions.jsonl``. This component
tails that file and republishes each new envelope to the per-``~handle``
Cloudflare Durable Object at
``${do_publish_url}/events/{handle}/sessions/ingest``, so that
cross-host visibility and cross-tool fan-out across supported clients
get a single canonical SSE stream
at ``/events/{handle}/sessions``.

Design contract:

* **Tail, don't re-read.** The publisher maintains a byte-offset
  checkpoint at ``${XDG_STATE_HOME}/alter-runtime/active-sessions-publisher.pos``
  so each tick only reads the bytes appended since the last successful
  POST. This matches the GC pass's file-position pattern at
  :class:`ActiveSessionsGc` (file-mediated, no bus coupling).
* **Filter contract: publish ALL envelopes.** ``session_started`` /
  ``session_heartbeat`` / ``session_ended`` ALL get POSTed. The DO is
  responsible for filtering ``session_ended`` out of live SSE - that's
  the server agent's contract. Do not filter on the publisher side.
* **Idempotent on failure.** A failed POST does NOT advance the
  offset; the next tick re-reads from the same start. Max 3 attempts
  per record (with exponential backoff between ticks); after 3
  failures the record is skipped with a structured log line and the
  offset advances past it, so a single poison-pill record cannot stall
  the entire tail.
* **Local-first.** The writer's append-only-on-disk path is the source
  of truth; the DO is downstream eventual consistency. The publisher
  never short-circuits the disk write - even when the DO is
  unreachable, envelopes still land on disk for the next tail attempt.

Auth flow per cycle mirrors :class:`SessionPresenceWriter` in shape
but uses the per-handle mint endpoint - the publisher
mints a cap-JWT scoped ``alter_events.sessions.ingest`` via
``POST {api}/api/v1/messaging/sessions-ingest-capability``
(Authorization: Bearer session.jwt; parameterless body), caches it
in-memory until 30s before its declared ``expires_at``, and attaches
it as ``Authorization: Bearer <cap>`` on the per-record ingest POST.

The endpoint is a parameterless self-directed mint; the resulting cap is
scoped to ``alter_events.sessions.ingest`` and is verified by the server
against the per-handle realm public key.

A 401 from the server drops the cached cap and triggers a single
re-mint+retry guard; a second 401 surfaces the error to the tick loop
without an infinite re-mint storm. When the CLI session is absent
the component idles silently - the writer + GC loops still produce a
fully usable local-disk record. The server-side scope match is the
``SESSIONS_INGEST_SCOPE`` constant.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import fcntl
import json
import logging
import os
import random
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from alter_runtime.config import DaemonConfig, data_dir, runtime_state_dir
from alter_runtime.daemon import Component
from alter_runtime.subscribers.active_sessions_writer import ACTIVE_SESSIONS_FILENAME
from alter_runtime.subscribers.do_sse import _build_tls_context

if TYPE_CHECKING:
    from alter_runtime.config import Session, SessionRef
    from alter_runtime.subscribers.session_refresher import RefreshTrigger

__all__ = [
    "ACTIVE_SESSIONS_PUBLISHER_POS_FILENAME",
    "BACKOFF_JITTER_RATIO",
    "BASE_BACKOFF_SECONDS",
    "BATCH_MAX_RECORDS",
    "BATCH_MAX_BYTES",
    "COOLDOWN_AFTER_CONSECUTIVE_FAILURES",
    "COOLDOWN_SECONDS",
    "INGEST_SCOPE",
    "MAX_POST_ATTEMPTS",
    "MAX_RETRY_AFTER_SECONDS",
    "ActiveSessionsDoPublisher",
]

logger = logging.getLogger("alter_runtime.subscribers.active_sessions_do_publisher")


#: Offset checkpoint filename (within ``runtime_state_dir()``).
ACTIVE_SESSIONS_PUBLISHER_POS_FILENAME: str = "active-sessions-publisher.pos"

#: Maximum POST attempts before the publisher gives up on a single record
#: and advances the offset past it. The skip is logged with the record's
#: ``id`` / ``version`` so an operator can manually replay if required.
MAX_POST_ATTEMPTS: int = 3

#: Upper bound on the inter-tick exponential backoff when the DO is
#: returning errors. Matches :class:`SessionPresenceWriter` for parity.
MAX_POLL_BACKOFF_SECONDS: float = 60.0

#: First-failure backoff. Doubles per consecutive failing tick up to
#: :data:`MAX_POLL_BACKOFF_SECONDS`, then escalates to the cool-down.
BASE_BACKOFF_SECONDS: float = 2.0

#: ± fraction of random jitter applied to every computed backoff so a
#: fleet of daemons recovering from a shared outage cannot re-synchronise
#: into a thundering herd, to avoid a synchronised retry storm against the
#: mint/ingest endpoints.
BACKOFF_JITTER_RATIO: float = 0.25

#: After this many CONSECUTIVE failing ticks the publisher stops
#: exponential growth and enters a flat cool-down cadence. With base 2s
#: doubling to the 60s cap, eight failures ≈ 3.5 minutes of escalation
#: before the cool-down engages.
COOLDOWN_AFTER_CONSECUTIVE_FAILURES: int = 8

#: Inter-tick sleep while in cool-down. A persistently failing/429ing
#: endpoint is probed once per five minutes instead of once per poll
#: interval - the daemon can never again hammer
#: ``/api/v1/messaging/sessions-ingest-capability`` at tick cadence. This
#: prevents tick-cadence hammering of the capability endpoint.
COOLDOWN_SECONDS: float = 300.0

#: Upper clamp on an honoured ``Retry-After`` response header, so a
#: malformed or hostile header cannot park the publisher for hours.
MAX_RETRY_AFTER_SECONDS: float = 900.0

#: Patchable jitter source - tests pin this to a constant for
#: deterministic backoff assertions. Production uses ``random.uniform``.
_uniform = random.uniform

#: Maximum line length we accept before treating the record as malformed
#: and skipping. Schema records are O(few hundred bytes); 64 KiB is a
#: generous upper bound that still bounds memory use under a runaway
#: writer.
MAX_LINE_BYTES: int = 64 * 1024

#: Maximum number of records per ingest-batch POST. Matches the server-side
#: limit for ``POST /events/{handle}/sessions/ingest-batch`` (413 over 100).
BATCH_MAX_RECORDS: int = 100

#: Maximum body size per ingest-batch POST in bytes. Matches the server-side
#: limit (413 over 256 KiB).
BATCH_MAX_BYTES: int = 256 * 1024

#: Cap scope required for ``/events/{handle}/sessions/ingest`` POSTs.
#: Matches the server-side ``SESSIONS_INGEST_SCOPE`` constant and the
#: ``SESSIONS_INGEST_CAPABILITY_SCOPE`` server-side. Re-export so
#: tests can pin against the cap claim returned by the mint endpoint.
INGEST_SCOPE: str = "alter_events.sessions.ingest"

#: Refresh leeway - re-mint when expiry is closer than this. Mirrors
#: :data:`alter_runtime.subscribers.session_presence.CAP_REFRESH_LEAD_SECONDS`.
CAP_REFRESH_LEAD_SECONDS: float = 30.0


# ---------------------------------------------------------------------------
# State (exposed for tests)
# ---------------------------------------------------------------------------


@dataclass
class _PublisherState:
    """Internal state - surfaced via ``state`` property for tests."""

    posted_count: int = 0
    skipped_count: int = 0
    failed_attempts: int = 0
    backoff: float = 0.0
    last_post_at: float = 0.0
    history: list[str] = field(default_factory=list)
    #: Count of consecutive ticks that ended in a transient failure
    #: (network error, 429/5xx, capability request refusal). Reset to 0 by any
    #: clean tick. Drives the exponential backoff + cool-down ladder.
    consecutive_failures: int = 0
    #: True once ``consecutive_failures`` crossed
    #: :data:`COOLDOWN_AFTER_CONSECUTIVE_FAILURES`. Cleared on recovery.
    in_cooldown: bool = False


@dataclass
class _CachedCap:
    """In-memory cap-JWT cache.

    Bounded multi-use caps are honoured the same way
    :class:`SessionPresenceWriter._CachedCap` honours them - but the
    publisher does not stripe ``X-Cap-Use-Index`` because the ingest
    server route does not require it. Each successful POST consumes one
    use; once exhausted (or stale) the next call re-mints.
    """

    capability: str
    expires_at_unix: float
    uses_available: int
    use_counter: int

    def is_fresh(self, now: float) -> bool:
        return self.expires_at_unix - now > CAP_REFRESH_LEAD_SECONDS

    def has_uses(self) -> bool:
        return self.use_counter < self.uses_available

    def take_use(self) -> None:
        self.use_counter += 1


# ---------------------------------------------------------------------------
# Internal exception types - kept private so callers cannot grep for
# them outside this module.
# ---------------------------------------------------------------------------


class _SessionMissing(Exception):
    """Raised when the CLI session is absent."""


class _CapabilityRequestError(Exception):
    """Raised when /api/v1/messaging/sessions-ingest-capability refuses
    or returns a malformed body."""


# ---------------------------------------------------------------------------
# Component
# ---------------------------------------------------------------------------


class ActiveSessionsDoPublisher(Component):
    """Tail ``active-sessions.jsonl`` and POST each envelope to the DO.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`. Reads ``do_publish_url``,
        ``do_publish_enabled``, ``do_publish_poll_interval_seconds``.
    session:
        Authenticated CLI :class:`Session`. Used for the bearer
        JWT when minting ``alter_events.sessions.ingest`` caps.
        Without a session the component idles silently and re-checks on
        every tick - the writer + GC continue producing local-disk
        envelopes regardless.
    sessions_path:
        Override the JSONL path. Tests redirect to ``tmp_path``.
    pos_path:
        Override the offset-checkpoint path. Tests redirect to ``tmp_path``.
    http_client:
        Optional ``httpx.AsyncClient`` override for tests.
    refresh_trigger:
        Optional shared :class:`~alter_runtime.subscribers.session_refresher.RefreshTrigger`.
        A capability request 401/403 (``session.jwt`` itself rejected) calls
        ``request_refresh()`` so ``SessionRefresher`` wakes and rotates out
        of band instead of waiting for its schedule (2026-07-12 fix).
        ``None`` preserves the prior pure-backoff behaviour.
    """

    name = "active_sessions_do_publisher"

    def __init__(
        self,
        config: DaemonConfig,
        session: "Session | SessionRef | None",
        *,
        sessions_path: Path | None = None,
        pos_path: Path | None = None,
        http_client: httpx.AsyncClient | None = None,
        refresh_trigger: "RefreshTrigger | None" = None,
    ) -> None:
        self._config = config
        from alter_runtime.config import SessionRef as _SessionRef

        if isinstance(session, _SessionRef):
            self._session_ref: "_SessionRef | None" = session
            self._session: "Session | None" = session.current
        else:
            self._session_ref = None
            self._session = session
        self._sessions_path: Path = (
            sessions_path if sessions_path is not None else data_dir() / ACTIVE_SESSIONS_FILENAME
        )
        self._pos_path: Path = (
            pos_path
            if pos_path is not None
            else runtime_state_dir() / ACTIVE_SESSIONS_PUBLISHER_POS_FILENAME
        )
        self._http_client = http_client
        self._owns_client = http_client is None
        self._refresh_trigger = refresh_trigger
        self._stop_event = asyncio.Event()
        self._state = _PublisherState()
        self._cap: _CachedCap | None = None
        # One-shot ``Retry-After`` hint captured from the most recent 429
        # response (capability request or ingest). Consumed - and cleared - by the
        # next ``_register_transient_failure`` so the server-instructed
        # wait becomes the backoff floor for exactly one cycle.
        self._retry_after_hint: float | None = None
        # In-memory attempt counter, keyed by (id, version). Persists
        # across ticks but not across daemon restarts - a restart resets
        # the counter and the record gets another MAX_POST_ATTEMPTS
        # attempts, which is the desired behaviour (a daemon restart is
        # an explicit operator intervention).
        self._attempts: dict[tuple[str, int], int] = {}

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        if not self._config.do_publish_enabled:
            logger.info("active_sessions_do_publisher disabled by config - idle")
            await self._stop_event.wait()
            return

        if self._session is None:
            # Fail-loud-once: log a single warning and idle silently.
            # The writer + GC continue producing local-disk envelopes
            # regardless; the DO mirror just stays empty until the
            # daemon next reloads with a populated session store.
            logger.warning(
                "active_sessions_do_publisher: no CLI session - "
                "DO publish disabled. Run `alter login` to mint cap "
                "credentials, or set ALTER_RUNTIME_DO_PUBLISH_ENABLED=0 "
                "to silence this warning."
            )
            await self._stop_event.wait()
            return

        logger.info(
            "active_sessions_do_publisher starting sessions=%s pos=%s "
            "interval=%.1fs publish_url=%s",
            self._sessions_path,
            self._pos_path,
            self._config.do_publish_poll_interval_seconds,
            self._config.do_publish_url,
        )

        # Client-default headers carry the X-Alter-Client-* identity bundle,
        # required for the server-side floor gate on every call. The
        # per-request Bearer JWT is attached on each call below.
        from alter_runtime.http_auth import backend_default_headers

        client = self._http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
            verify=_build_tls_context(),
            headers=backend_default_headers(self._config.do_publish_url),
        )

        try:
            while not self._stop_event.is_set():
                await self._tick_safe(client)
                await self._sleep_interruptible(self._config.do_publish_poll_interval_seconds)
        finally:
            if self._owns_client:
                with contextlib.suppress(Exception):
                    await client.aclose()
            logger.info("active_sessions_do_publisher stopped")

    async def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Tick
    # ------------------------------------------------------------------

    async def _tick_safe(self, client: httpx.AsyncClient) -> None:
        """Wrap ``_tick`` with backoff accounting + last-resort swallowing.

        Mirrors :class:`SessionPresenceWriter._poll_once_safe`. The
        supervisor restarts on bare exceptions, but we'd rather log and
        continue than tear down the component for a transient blip.

        Backoff contract: a tick that
        experiences a transient failure - whether it RAISES
        (``httpx.HTTPError`` / ``_CapabilityRequestError`` escaping ``_tick``) or
        returns ``False`` (a swallowed ``"transient"`` batch result or a
        failed per-record POST) - counts as one consecutive failure and
        grows the exponential backoff. The pre-fix bug: swallowed
        transient results returned normally, the unconditional
        ``backoff = 0.0`` reset fired, and a failing/429ing endpoint was
        re-hammered at full poll cadence forever.
        """
        try:
            clean = await self._tick(client)
        except asyncio.CancelledError:
            raise
        except _SessionMissing:
            # Session disappeared between run() and tick - idle until
            # the next cycle. No re-log: the run() entry already warned.
            self._state.backoff = max(self._state.backoff, 5.0)
            return
        except (httpx.HTTPError, _CapabilityRequestError) as exc:
            self._note_retry_after_exc(exc)
            self._register_transient_failure()
            logger.warning(
                "active_sessions_do_publisher tick failed: %s - backoff %.1fs (consecutive=%d%s)",
                exc,
                self._state.backoff,
                self._state.consecutive_failures,
                ", cool-down" if self._state.in_cooldown else "",
            )
            return
        except Exception as exc:  # noqa: BLE001 - last-resort safety net
            logger.exception("active_sessions_do_publisher unexpected: %s", exc)
            self._register_transient_failure()
            self._state.backoff = max(self._state.backoff, MAX_POLL_BACKOFF_SECONDS)
            return

        if clean:
            self._register_success()
        else:
            self._register_transient_failure()
            logger.warning(
                "active_sessions_do_publisher: transient failure this tick - "
                "backoff %.1fs (consecutive=%d%s)",
                self._state.backoff,
                self._state.consecutive_failures,
                ", cool-down" if self._state.in_cooldown else "",
            )

    # ------------------------------------------------------------------
    # Backoff ladder (exponential + jitter + cool-down)
    # ------------------------------------------------------------------

    def _register_success(self) -> None:
        """Reset the backoff ladder after a clean tick."""
        if self._state.in_cooldown:
            logger.info(
                "active_sessions_do_publisher: recovered - leaving cool-down "
                "after %d consecutive failing ticks",
                self._state.consecutive_failures,
            )
        self._state.consecutive_failures = 0
        self._state.in_cooldown = False
        self._state.backoff = 0.0
        self._retry_after_hint = None

    def _register_transient_failure(self) -> None:
        """Advance the backoff ladder by one consecutive failing tick.

        Exponential (``BASE * 2^(n-1)``, capped at
        :data:`MAX_POLL_BACKOFF_SECONDS`) with ±
        :data:`BACKOFF_JITTER_RATIO` random jitter; after
        :data:`COOLDOWN_AFTER_CONSECUTIVE_FAILURES` consecutive failures
        the ladder flattens onto :data:`COOLDOWN_SECONDS`. A pending
        ``Retry-After`` hint (captured from a 429) raises the floor and
        is consumed.
        """
        self._state.consecutive_failures += 1
        n = self._state.consecutive_failures
        if n >= COOLDOWN_AFTER_CONSECUTIVE_FAILURES:
            if not self._state.in_cooldown:
                self._state.in_cooldown = True
                logger.warning(
                    "active_sessions_do_publisher: %d consecutive failing ticks "
                    "- entering cool-down (one attempt per %.0fs until recovery)",
                    n,
                    COOLDOWN_SECONDS,
                )
            base = COOLDOWN_SECONDS
        else:
            base = min(BASE_BACKOFF_SECONDS * (2 ** (n - 1)), MAX_POLL_BACKOFF_SECONDS)
        backoff = base * (1.0 + _uniform(-BACKOFF_JITTER_RATIO, BACKOFF_JITTER_RATIO))
        hint = self._retry_after_hint
        self._retry_after_hint = None
        if hint is not None:
            backoff = max(backoff, hint)
        self._state.backoff = backoff

    def _note_retry_after(self, response: httpx.Response) -> None:
        """Capture a 429 response's ``Retry-After`` header as a backoff floor.

        Only the delta-seconds form is honoured (the HTTP-date form is
        rare on rate limiters and not worth a date parser here); values
        are clamped to [0, :data:`MAX_RETRY_AFTER_SECONDS`].
        """
        if response.status_code != 429:
            return
        raw = response.headers.get("Retry-After")
        if not raw:
            return
        try:
            seconds = float(raw.strip())
        except (TypeError, ValueError):
            return
        if seconds < 0:
            return
        seconds = min(seconds, MAX_RETRY_AFTER_SECONDS)
        if self._retry_after_hint is None or seconds > self._retry_after_hint:
            self._retry_after_hint = seconds

    def _note_retry_after_exc(self, exc: Exception) -> None:
        """Capture ``Retry-After`` from a raised ``httpx.HTTPStatusError``."""
        if isinstance(exc, httpx.HTTPStatusError):
            self._note_retry_after(exc.response)

    async def _tick(self, client: httpx.AsyncClient) -> bool:
        """One sweep: read new bytes since the last offset, POST as a batch.

        Attempts the new ``ingest-batch`` endpoint (one POST per tick for up
        to ``BATCH_MAX_RECORDS`` / ``BATCH_MAX_BYTES``). Falls back to the
        legacy per-record ``ingest`` path when the server returns 404 or 405
        (old server without the batch route).

        Backlog drain: when a single tick reads more than ``BATCH_MAX_RECORDS``
        records or ``BATCH_MAX_BYTES`` bytes (e.g. after a long sleep or log
        rotation), the tick emits multiple sequential sub-batch POSTs, advancing
        the offset after each successful sub-batch so the position checkpoint
        always reflects the last fully committed position.

        Returns ``True`` when the tick completed cleanly (including the
        nothing-to-do paths) and ``False`` when a transient failure was
        swallowed (a ``"transient"`` batch result or a failed per-record
        POST left for retry) - ``_tick_safe`` feeds that into the backoff
        ladder so swallowed failures still slow the loop down.
        """
        if not self._sessions_path.exists():
            return True

        offset = self._load_offset()
        new_bytes, new_offset = self._read_since(offset)
        if not new_bytes:
            # Defensive persist-on-shrink hardening. When
            # ``_read_since`` detects a shrink (rotation / truncation) it
            # resets its read base to 0 and returns ``new_offset`` reflecting
            # the *new* file size. If the new file is empty or unchanged we
            # get here with empty ``new_bytes`` - without persisting the
            # reset, the stale large offset stays on disk and EVERY
            # subsequent empty tick re-detects the shrink, re-logging the
            # rotation and keeping the wedge armed until fresh bytes arrive.
            # Persist the reset base now so a quiet post-rotation window
            # cannot keep re-triggering the replay path. Only writes when the
            # offset actually moved DOWN (shrink); the steady-state
            # caught-up tick (new_offset == offset) writes nothing, leaving
            # the success-path advancement untouched.
            if new_offset < offset:
                self._save_offset(new_offset)
            return True

        # Parse all lines from the newly read bytes into (raw_bytes, record?)
        # tuples. Malformed/oversized/blank lines are handled inline below and
        # are advanced past unconditionally.
        parsed_lines: list[tuple[bytes, dict[str, Any] | None]] = []
        for raw_line in new_bytes.splitlines(keepends=True):
            line_text = raw_line.decode("utf-8", errors="replace")
            stripped = line_text.strip()
            if not stripped:
                parsed_lines.append((raw_line, None))
                continue
            if len(stripped) > MAX_LINE_BYTES:
                logger.warning(
                    "active_sessions_do_publisher: oversize line (%d bytes) - skipping",
                    len(stripped),
                )
                parsed_lines.append((raw_line, None))
                continue
            try:
                record = json.loads(stripped)
            except (ValueError, json.JSONDecodeError):
                logger.warning("active_sessions_do_publisher: malformed JSON line - skipping")
                parsed_lines.append((raw_line, None))
                continue
            if not isinstance(record, dict):
                parsed_lines.append((raw_line, None))
                continue
            handle = record.get("handle")
            if not isinstance(handle, str) or not handle:
                logger.warning("active_sessions_do_publisher: missing handle - skipping")
                parsed_lines.append((raw_line, None))
                continue
            parsed_lines.append((raw_line, record))

        # Drain the parsed lines as sub-batches. Each sub-batch is at most
        # BATCH_MAX_RECORDS records and BATCH_MAX_BYTES of JSON body. We
        # attempt the batch endpoint first; on 404/405 we fall back to the
        # per-record path for the remainder of this tick.
        #
        # Seed ``consumed_offset`` from the read BASE, not the (possibly
        # stale) pre-rotation ``offset``. ``_read_since`` returns
        # ``new_offset == read_base + len(new_bytes)`` where ``read_base``
        # is 0 right after a rotation reset (offset > size) and == ``offset``
        # in steady state. ``new_offset - len(new_bytes)`` recovers that
        # base exactly. Using the stale ``offset`` here is the replay-loop
        # bug: after a rotation it persists ``stale_large +
        # line_lengths``, so the next tick re-detects the shrink and
        # re-POSTs the entire file forever.
        consumed_offset = new_offset - len(new_bytes)
        use_batch: bool = True  # Flipped to False on first 404/405 response.
        i = 0
        while i < len(parsed_lines):
            # Collect the next sub-batch: skip None (auto-advance) entries
            # and accumulate valid records up to the caps.
            sub_batch_lines: list[bytes] = []
            sub_batch_records: list[dict[str, Any]] = []
            sub_batch_byte_size: int = 0
            j = i
            # Advance past leading None lines (blank / malformed / no-handle).
            while j < len(parsed_lines) and parsed_lines[j][1] is None:
                raw_line, _ = parsed_lines[j]
                consumed_offset += len(raw_line)
                self._save_offset(consumed_offset)
                j += 1

            if j >= len(parsed_lines):
                break

            # Fill the sub-batch up to BATCH_MAX_RECORDS or BATCH_MAX_BYTES.
            k = j
            while k < len(parsed_lines):
                raw_line, record = parsed_lines[k]
                if record is None:
                    # Non-None lines follow valid records in the slice;
                    # a None after valid records terminates the sub-batch so
                    # it is handled in the NEXT iteration.
                    break
                encoded = json.dumps(record, separators=(",", ":")).encode("utf-8")
                # If adding this record would exceed either cap, close the
                # sub-batch (but only if we already have records - a single
                # oversized record still gets its own sub-batch attempt).
                if sub_batch_records and (
                    len(sub_batch_records) >= BATCH_MAX_RECORDS
                    or sub_batch_byte_size + len(encoded) > BATCH_MAX_BYTES
                ):
                    break
                sub_batch_lines.append(raw_line)
                sub_batch_records.append(record)
                sub_batch_byte_size += len(encoded)
                k += 1

            if not sub_batch_records:
                # All remaining entries are None - already advanced above.
                i = k
                continue

            if use_batch:
                # Attempt batch POST.
                batch_result = await self._post_batch(client, sub_batch_records)

                if batch_result == "fallback":
                    # 404/405 - old server. Switch to per-record for this tick.
                    use_batch = False
                    # Fall through to the single-record path below.
                elif batch_result == "transient":
                    # Network / 5xx / 429 - leave offset un-advanced and let
                    # the next tick retry the whole sub-batch (after backoff).
                    self._state.failed_attempts += 1
                    logger.info(
                        "active_sessions_do_publisher: batch POST transient failure "
                        "(%d records) - will retry next tick",
                        len(sub_batch_records),
                    )
                    return False
                elif isinstance(batch_result, list):
                    # Per-record results from the server. ``batch_result`` is a
                    # list of dicts: {index, ok, error?, status?}. Records whose
                    # result is ok:true (or idempotent duplicate) are accepted.
                    # Records whose result is ok:false are terminal (schema
                    # rejection) and are skipped, mirroring MAX_POST_ATTEMPTS
                    # skip. The batch is considered fully consumed when every
                    # record is either accepted or terminally skipped.
                    accepted = 0
                    skipped = 0
                    for res in batch_result:
                        idx = res.get("index", -1)
                        if res.get("ok"):
                            accepted += 1
                        else:
                            skipped += 1
                            logger.warning(
                                "active_sessions_do_publisher: batch record index=%d "
                                "terminal failure status=%s error=%r - skipping",
                                idx,
                                res.get("status"),
                                res.get("error"),
                            )

                    # All records accounted for - advance offset past the whole
                    # sub-batch.
                    for raw_line in sub_batch_lines:
                        consumed_offset += len(raw_line)
                    self._save_offset(consumed_offset)
                    self._state.posted_count += accepted
                    self._state.skipped_count += skipped
                    self._state.last_post_at = time.time()
                    i = k
                    continue
                else:
                    # batch_result == "success": every record accepted, no
                    # per-record results (simple 200 with accepted count only).
                    for raw_line in sub_batch_lines:
                        consumed_offset += len(raw_line)
                    self._save_offset(consumed_offset)
                    self._state.posted_count += len(sub_batch_records)
                    self._state.last_post_at = time.time()
                    i = k
                    continue

            # Per-record fallback path (use_batch is False). Process records
            # one at a time using the existing _post_record logic, which
            # preserves today's idempotent-on-failure contract exactly.
            all_consumed = True
            for idx2, (raw_line, record) in enumerate(zip(sub_batch_lines, sub_batch_records)):
                if record is None:
                    consumed_offset += len(raw_line)
                    self._save_offset(consumed_offset)
                    continue

                attempt_key = self._attempt_key(record)
                handle = record.get("handle", "")
                published = await self._post_record(client, handle, record)
                if published:
                    self._attempts.pop(attempt_key, None)
                    consumed_offset += len(raw_line)
                    self._save_offset(consumed_offset)
                    self._state.posted_count += 1
                    self._state.last_post_at = time.time()
                    continue

                self._attempts[attempt_key] = self._attempts.get(attempt_key, 0) + 1
                self._state.failed_attempts += 1
                if self._attempts[attempt_key] >= MAX_POST_ATTEMPTS:
                    logger.warning(
                        "active_sessions_do_publisher: giving up on record "
                        "id=%s version=%s after %d attempts - advancing offset",
                        record.get("id"),
                        record.get("version"),
                        self._attempts[attempt_key],
                    )
                    self._attempts.pop(attempt_key, None)
                    consumed_offset += len(raw_line)
                    self._save_offset(consumed_offset)
                    self._state.skipped_count += 1
                    continue

                logger.info(
                    "active_sessions_do_publisher: POST failed for id=%s "
                    "version=%s attempt=%d/%d - will retry next tick",
                    record.get("id"),
                    record.get("version"),
                    self._attempts[attempt_key],
                    MAX_POST_ATTEMPTS,
                )
                all_consumed = False
                return False  # Stop tick; next tick resumes from here.

            if not all_consumed:
                return False
            i = k

        return True

    # ------------------------------------------------------------------
    # Capability request
    # ------------------------------------------------------------------

    async def _get_cap(self, client: httpx.AsyncClient) -> str:
        """Return a fresh cap-JWT, minting one if cache is stale or used up.

        Mirrors :meth:`SessionPresenceWriter._get_cap` - single mint per
        cap window, in-memory cache, refresh on leeway, bounded
        multi-use caps honoured.
        """
        session = self._session_ref.current if self._session_ref is not None else self._session
        if session is None:
            raise _SessionMissing()

        now = time.time()
        cap = self._cap
        if cap is not None and cap.is_fresh(now) and cap.has_uses():
            cap.take_use()
            return cap.capability

        # Mint via the parameterless per-handle mint endpoint.
        # The collective-realm route is the wrong realm here;
        # see module docstring for the failure modes it triggers for
        # ``alter_events.sessions.ingest`` caps. TTL is server-configured
        # (``SESSIONS_INGEST_CAPABILITY_TTL_SECONDS``, clamped [30, 300],
        # default 60s); the per-handle 6/min rate limit means the cache +
        # leeway-refresh path is the steady-state pattern.
        url = f"{session.api.rstrip('/')}/api/v1/messaging/sessions-ingest-capability"
        headers = {
            "Authorization": f"Bearer {session.jwt}",
            "Accept": "application/json",
        }
        response = await client.post(url, headers=headers)
        if response.status_code in (401, 403):
            # The session JWT itself (not merely a cap) was rejected —
            # request an out-of-band SessionRefresher wake instead of
            # waiting for its scheduled lead time (2026-07-12 fix).
            if self._refresh_trigger is not None:
                self._refresh_trigger.request_refresh("capability_request_401")
            raise _CapabilityRequestError(
                f"capability request rejected (HTTP {response.status_code}): {response.text[:200]}"
            )
        response.raise_for_status()

        try:
            data = response.json()
        except ValueError as exc:
            raise _CapabilityRequestError("capability request returned non-JSON body") from exc

        if not isinstance(data, dict):
            raise _CapabilityRequestError("capability request returned non-object body")

        capability = data.get("capability")
        expires_at = data.get("expires_at")
        if not isinstance(capability, str) or not capability:
            raise _CapabilityRequestError("capability request response missing capability")
        if not isinstance(expires_at, str) or not expires_at:
            raise _CapabilityRequestError("capability request response missing expires_at")

        try:
            expires_at_unix = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
        except ValueError as exc:
            raise _CapabilityRequestError(
                f"capability request returned non-ISO expires_at: {expires_at}"
            ) from exc

        # The per-handle mint endpoint issues time-bounded JWTs -
        # the server's verifier checks scope + exp only and does no
        # per-use accounting, so the cap may be reused for any number
        # of POSTs within its TTL window. Cache refresh is governed by
        # the leeway gate (``CAP_REFRESH_LEAD_SECONDS``); the
        # server-side per-handle 6/min rate limit on the mint endpoint
        # bounds re-mint storms even under burst load.
        cap = _CachedCap(
            capability=capability,
            expires_at_unix=expires_at_unix,
            uses_available=sys.maxsize,
            use_counter=1,
        )
        self._cap = cap
        return capability

    # ------------------------------------------------------------------
    # Batch POST
    # ------------------------------------------------------------------

    async def _post_batch(
        self,
        client: httpx.AsyncClient,
        records: list[dict[str, Any]],
    ) -> str | list[dict[str, Any]]:
        """POST ``records`` as a JSON array to ``/events/{handle}/sessions/ingest-batch``.

        All records in a sub-batch share the same ``handle`` (the caller reads
        the first record's handle - mixed-handle batches are not supported by
        the server, but in practice all records in a single session log share
        one handle). Returns one of:

        ``"success"``
            HTTP 200 with ``accepted >= 1`` and no per-record failures; all
            records accepted.
        ``list[dict]``
            HTTP 200 with a ``results`` array containing at least one
            ``ok: false`` entry. The list contains the per-record result dicts
            so ``_tick`` can advance past terminal failures individually.
        ``"transient"``
            Network error, 5xx, or 429 - caller should leave offset
            un-advanced and retry next tick.
        ``"fallback"``
            HTTP 404 or 405 - server does not have the batch route. Caller
            should switch to the per-record path for this tick.
        """
        from urllib.parse import quote

        handle = records[0].get("handle", "")
        encoded_handle = quote(handle, safe="~")
        url = (
            f"{self._config.do_publish_url.rstrip('/')}"
            f"/events/{encoded_handle}/sessions/ingest-batch"
        )

        try:
            cap = await self._get_cap(client)
        except _SessionMissing:
            raise
        except (httpx.HTTPError, _CapabilityRequestError) as exc:
            self._note_retry_after_exc(exc)
            logger.warning(
                "active_sessions_do_publisher: capability request failed for batch: %s",
                exc,
            )
            return "transient"

        response = await self._do_batch_post(client, url, cap, records)
        if response is None:
            return "transient"

        if response.status_code in (404, 405):
            # server does not have the batch route yet.
            logger.info(
                "active_sessions_do_publisher: ingest-batch returned HTTP %d "
                "- falling back to per-record path for this tick",
                response.status_code,
            )
            return "fallback"

        if response.status_code in (401, 403):
            # Cap rejected - drop and re-mint once, then retry.
            logger.info(
                "active_sessions_do_publisher: ingest-batch auth rejected (HTTP %d) "
                "- re-minting cap and retrying once",
                response.status_code,
            )
            self._cap = None
            try:
                cap = await self._get_cap(client)
            except _SessionMissing:
                raise
            except (httpx.HTTPError, _CapabilityRequestError) as exc:
                self._note_retry_after_exc(exc)
                logger.warning(
                    "active_sessions_do_publisher: cap re-mint failed for batch: %s",
                    exc,
                )
                return "transient"
            response = await self._do_batch_post(client, url, cap, records)
            if response is None:
                return "transient"
            if response.status_code in (401, 403):
                # Second auth failure - surface as transient so the next tick
                # retries (no infinite re-mint loop).
                logger.warning(
                    "active_sessions_do_publisher: ingest-batch auth failed twice "
                    "(HTTP %d) - treating as transient",
                    response.status_code,
                )
                return "transient"

        if response.status_code in (429,) or response.status_code >= 500:
            self._note_retry_after(response)
            logger.warning(
                "active_sessions_do_publisher: ingest-batch transient HTTP %d - "
                "will retry next tick",
                response.status_code,
            )
            return "transient"

        if response.status_code == 413:
            # Over-limit. Should not happen given the BATCH_MAX_RECORDS /
            # BATCH_MAX_BYTES pre-send guards, but a single record that alone
            # exceeds the server's 256 KiB cap would 413 a sub-batch-of-one and,
            # if treated as transient, retry the identical body forever - a
            # poison-pill wedge that stalls all session egress for the handle.
            # Fall back to the per-record single-ingest path for this tick: an
            # oversized record gets the existing MAX_POST_ATTEMPTS terminal skip
            # and any well-sized records still post. Never infinite-retry a 413.
            logger.warning(
                "active_sessions_do_publisher: ingest-batch 413 (over server limit) "
                "- falling back to per-record path for this tick"
            )
            return "fallback"

        if response.status_code == 400:
            # Whole-body malformed (not a JSON array / unparseable). This is a
            # framing fault, not a transient condition - retrying the identical
            # body loops forever. Fall back to the per-record single-ingest path
            # for this tick, which serialises one record at a time and sidesteps
            # any array-framing fault. Should be rare - the publisher produces
            # well-formed JSON.
            try:
                body_preview = response.text[:200]
            except Exception:  # pragma: no cover
                body_preview = "<unreadable>"
            logger.warning(
                "active_sessions_do_publisher: ingest-batch 400 (malformed body) "
                "body=%r - falling back to per-record path for this tick",
                body_preview,
            )
            return "fallback"

        if 200 <= response.status_code < 300:
            try:
                data = response.json()
            except (ValueError, json.JSONDecodeError):
                # Non-JSON 2xx: accept all records (old server variant).
                return "success"

            if not isinstance(data, dict):
                return "success"

            results = data.get("results")
            if isinstance(results, list) and results:
                # Check whether any per-record result is ok:false.
                has_failures = any(isinstance(r, dict) and not r.get("ok", True) for r in results)
                if has_failures:
                    # Return the results list so _tick can skip individual
                    # terminal failures.
                    return [r for r in results if isinstance(r, dict)]
            return "success"

        # Unexpected status - treat as transient.
        try:
            body_preview = response.text[:200]
        except Exception:  # pragma: no cover
            body_preview = "<unreadable>"
        logger.warning(
            "active_sessions_do_publisher: ingest-batch unexpected HTTP %d "
            "body=%r - treating as transient",
            response.status_code,
            body_preview,
        )
        return "transient"

    async def _do_batch_post(
        self,
        client: httpx.AsyncClient,
        url: str,
        cap: str,
        records: list[dict[str, Any]],
    ) -> httpx.Response | None:
        """Single batch POST. Returns the Response or None on transport error."""
        headers = {
            "Authorization": f"Bearer {cap}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        try:
            return await client.post(url, json=records, headers=headers)
        except httpx.HTTPError as exc:
            logger.warning(
                "active_sessions_do_publisher: batch POST raised %s",
                exc,
            )
            return None

    # ------------------------------------------------------------------
    # POST
    # ------------------------------------------------------------------

    async def _post_record(
        self,
        client: httpx.AsyncClient,
        handle: str,
        record: dict[str, Any],
    ) -> bool:
        """POST one envelope. Returns True on 2xx, False otherwise.

        On 401/403 from the server the cached cap is dropped and a
        single re-mint+retry is attempted. A second 401 surfaces as a
        terminal failure for this record (counts against
        MAX_POST_ATTEMPTS) - the publisher never loops on auth.
        """
        # The DO route uses the URL-encoded handle, mirroring the server's
        # router which normalises + decodes again on receive.
        from urllib.parse import quote

        encoded_handle = quote(handle, safe="~")
        url = f"{self._config.do_publish_url.rstrip('/')}/events/{encoded_handle}/sessions/ingest"

        try:
            cap = await self._get_cap(client)
        except _SessionMissing:
            # Surface to _tick_safe so the standard idle path is taken
            # without per-record noise.
            raise
        except (httpx.HTTPError, _CapabilityRequestError) as exc:
            self._note_retry_after_exc(exc)
            logger.warning(
                "active_sessions_do_publisher: capability request failed: %s - id=%s",
                exc,
                record.get("id"),
            )
            return False

        response = await self._do_post(client, url, cap, record)
        if response is None:
            return False

        if 200 <= response.status_code < 300:
            return True

        if response.status_code in (401, 403):
            # Cap was rejected: drop it, re-mint, single retry. Guards
            # against an infinite re-mint loop by only retrying once
            # per record per tick.
            logger.info(
                "active_sessions_do_publisher: ingest auth rejected (HTTP %d) - "
                "re-minting cap and retrying once for id=%s",
                response.status_code,
                record.get("id"),
            )
            self._cap = None
            try:
                cap = await self._get_cap(client)
            except _SessionMissing:
                raise
            except (httpx.HTTPError, _CapabilityRequestError) as exc:
                logger.warning(
                    "active_sessions_do_publisher: cap re-mint failed: %s - id=%s",
                    exc,
                    record.get("id"),
                )
                return False

            retry = await self._do_post(client, url, cap, record)
            if retry is None:
                return False
            if 200 <= retry.status_code < 300:
                return True
            response = retry

        # 4xx/5xx (other than auth handled above): log + treat as
        # terminal failure for this record (counts against
        # MAX_POST_ATTEMPTS). The server is the authority and we honour
        # its rejection rather than retrying forever. A 429 still feeds
        # its Retry-After into the loop-level backoff floor.
        self._note_retry_after(response)
        try:
            body_preview = response.text[:200]
        except Exception:  # pragma: no cover - defensive
            body_preview = "<unreadable>"
        logger.warning(
            "active_sessions_do_publisher: POST rejected status=%d body=%r id=%s",
            response.status_code,
            body_preview,
            record.get("id"),
        )
        return False

    async def _do_post(
        self,
        client: httpx.AsyncClient,
        url: str,
        cap: str,
        record: dict[str, Any],
    ) -> httpx.Response | None:
        """Single POST. Returns the Response or None on transport error."""
        headers = {
            "Authorization": f"Bearer {cap}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        try:
            return await client.post(url, json=record, headers=headers)
        except httpx.HTTPError as exc:
            logger.warning(
                "active_sessions_do_publisher: POST raised %s - id=%s",
                exc,
                record.get("id"),
            )
            return None

    # ------------------------------------------------------------------
    # File reading / offset checkpoint
    # ------------------------------------------------------------------

    def _read_since(self, offset: int) -> tuple[bytes, int]:
        """Read all bytes from ``offset`` to EOF under a shared lock.

        Returns ``(bytes_read, new_offset)``. ``new_offset`` is the
        absolute file size after reading - i.e., the value we should
        persist once every line has been POSTed.

        Empty return on missing/unreadable file.
        """
        try:
            stat = self._sessions_path.stat()
        except FileNotFoundError:
            return b"", offset

        size = stat.st_size
        if offset > size:
            # File shrank (likely a rotation: writer moved jsonl ->
            # jsonl.1 and started fresh). Reset to 0 and re-read from
            # the top of the new file.
            logger.info(
                "active_sessions_do_publisher: jsonl shrank "
                "(offset=%d > size=%d) - resetting to 0 (rotation)",
                offset,
                size,
            )
            offset = 0

        if offset == size:
            return b"", offset

        flags = os.O_RDONLY
        try:
            fd = os.open(self._sessions_path, flags)
        except OSError as exc:
            logger.warning("active_sessions_do_publisher: open failed: %s", exc)
            return b"", offset

        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH)
            except OSError as exc:  # pragma: no cover - exotic FS
                if exc.errno not in (errno.ENOTSUP, errno.EINVAL):
                    logger.warning("active_sessions_do_publisher: LOCK_SH failed: %s", exc)
                    return b"", offset
            try:
                os.lseek(fd, offset, os.SEEK_SET)
                buf = b""
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    buf += chunk
            finally:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

        return buf, offset + len(buf)

    def _load_offset(self) -> int:
        """Read the last persisted offset. Returns 0 when absent/invalid."""
        if not self._pos_path.exists():
            return 0
        try:
            raw = self._pos_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            logger.warning(
                "active_sessions_do_publisher: cannot read pos file %s: %s",
                self._pos_path,
                exc,
            )
            return 0
        try:
            value = int(raw)
        except ValueError:
            logger.warning(
                "active_sessions_do_publisher: malformed pos file %s: %r - resetting to 0",
                self._pos_path,
                raw,
            )
            return 0
        return max(value, 0)

    def _save_offset(self, offset: int) -> None:
        """Atomically persist the current offset checkpoint."""
        self._ensure_parent(self._pos_path)
        tmp_path = self._pos_path.with_suffix(self._pos_path.suffix + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        try:
            fd = os.open(tmp_path, flags, 0o600)
        except OSError as exc:
            logger.warning(
                "active_sessions_do_publisher: cannot open pos tmp %s: %s",
                tmp_path,
                exc,
            )
            return
        try:
            with contextlib.suppress(OSError):
                os.fchmod(fd, 0o600)
            os.write(fd, str(offset).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.replace(tmp_path, self._pos_path)
        except OSError as exc:
            logger.warning(
                "active_sessions_do_publisher: cannot replace pos %s: %s",
                self._pos_path,
                exc,
            )
            return
        with contextlib.suppress(OSError):
            os.chmod(self._pos_path, 0o600)

    def _ensure_parent(self, path: Path) -> None:
        parent = path.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            os.chmod(parent, 0o700)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _attempt_key(record: dict[str, Any]) -> tuple[str, int]:
        """Stable in-memory attempt-counter key per record.

        Falls back to ``("", -1)`` when id/version are missing - those
        records get their own bucket so a single malformed line cannot
        evict a real one.
        """
        record_id = record.get("id")
        version = record.get("version")
        if not isinstance(record_id, str):
            record_id = ""
        if not isinstance(version, int):
            version = -1
        return record_id, version

    async def _sleep_interruptible(self, seconds: float) -> None:
        """Sleep ``seconds`` or until stop is set, whichever comes first."""
        effective = max(seconds, self._state.backoff)
        if effective <= 0:
            return
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=effective)
        except (TimeoutError, asyncio.TimeoutError):
            return

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def state(self) -> _PublisherState:
        return self._state

    @property
    def sessions_path(self) -> Path:
        return self._sessions_path

    @property
    def pos_path(self) -> Path:
        return self._pos_path

    @property
    def attempts(self) -> dict[tuple[str, int], int]:
        return dict(self._attempts)
