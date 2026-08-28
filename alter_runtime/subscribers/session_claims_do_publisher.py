"""SessionClaimsDoPublisher - forward ``session-claims.jsonl`` to the backend.

The claim stream's publisher. Agent instruments (the CC hooks, alter-cli
verbs, IDE plugins) append ``session_claim`` / ``session_release``
envelopes to ``$XDG_DATA_HOME/alter-runtime/session-claims.jsonl``; this
component tails that file and forwards each record's payload to the
backend, which mints the capability and emits the frame onto the
member's own per-handle DO.

Why the daemon and not the emitter
----------------------------------
Cap-JWT minting lives in the daemon rather than the instrument: a shell
hook must never hold a capability. The hook
appends a line and returns; reaching the DO is this component's problem,
and a hook that fires while the daemon is down loses nothing because the
line is already durable on disk.

The daemon does not mint either. It posts to
``/api/v1/companion/sessions/{claim,release}`` with the member session's
bearer JWT and the backend mints server-side, which is the same posture
the Android share sheet's ``external_drop`` settled on after an earlier
hand-rolled DO POST could never satisfy the route's capability and
signature requirements.

Why this is not the sessions publisher
--------------------------------------
:class:`ActiveSessionsDoPublisher` forwards ``active-sessions.jsonl``, a
different record class (flat, no payload) on a different route. The two
classes shared one file until the streams were split, and every claim was
rejected as an unknown field and dropped. They are separate streams with
separate publishers precisely so neither can be handed the other's
records again.

This class inherits that publisher's file cursor and backoff ladder,
which are record-class-agnostic and carry a rotation-replay fix worth
more than a second derivation of it. It overrides the route: no cap
cache, no batch endpoint, one POST per record.
"""

from __future__ import annotations

import contextlib
import json
import logging
from typing import TYPE_CHECKING, Any

import httpx

from alter_runtime.config import DaemonConfig, data_dir, runtime_state_dir
from alter_runtime.subscribers.active_sessions_do_publisher import (
    MAX_LINE_BYTES,
    MAX_POST_ATTEMPTS,
    ActiveSessionsDoPublisher,
    _SessionMissing,
)
from alter_runtime.subscribers.do_sse import _build_tls_context

if TYPE_CHECKING:
    from alter_runtime.config import Session, SessionRef
    from alter_runtime.subscribers.session_refresher import RefreshTrigger

__all__ = [
    "SESSION_CLAIMS_FILENAME",
    "SESSION_CLAIMS_PUBLISHER_POS_FILENAME",
    "CLAIM_ROUTES",
    "SessionClaimsDoPublisher",
]

logger = logging.getLogger("alter_runtime.subscribers.session_claims_do_publisher")


#: The claim stream. The writer's own configuration names this same file, and
#: the two must agree or the writer writes where nothing reads.
SESSION_CLAIMS_FILENAME: str = "session-claims.jsonl"

#: Offset checkpoint (within ``runtime_state_dir()``). Distinct from the
#: sessions publisher's checkpoint: two cursors over two files.
SESSION_CLAIMS_PUBLISHER_POS_FILENAME: str = "session-claims-publisher.pos"

#: Record kind to backend route. A record whose kind is absent from this
#: map is skipped rather than guessed at: this stream is single-purpose,
#: so an unknown kind means an emitter is writing to the wrong file, and
#: forwarding it would repeat the mistake the stream split exists to stop.
CLAIM_ROUTES: dict[str, str] = {
    "session_claim": "/api/v1/companion/sessions/claim",
    "session_release": "/api/v1/companion/sessions/release",
}


class SessionClaimsDoPublisher(ActiveSessionsDoPublisher):
    """Tail ``session-claims.jsonl`` and POST each payload to the backend.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`. Reads ``do_publish_enabled`` and
        ``do_publish_poll_interval_seconds``. It does NOT read
        ``do_publish_url``: that names the Worker origin, and this
        publisher talks to the backend API at ``session.api``.
    session:
        Authenticated CLI :class:`Session`, or a ``SessionRef``. Supplies
        the bearer JWT. Without one the component idles and re-checks
        each tick, exactly as the sessions publisher does.
    claims_path:
        Override the JSONL path. Tests redirect to ``tmp_path``.
    pos_path:
        Override the offset checkpoint. Tests redirect to ``tmp_path``.
    http_client:
        Optional ``httpx.AsyncClient`` override for tests.
    refresh_trigger:
        Optional shared ``RefreshTrigger``. A 401/403 on the member JWT
        requests an out-of-band session refresh instead of waiting out
        the backoff.
    """

    name = "session_claims_do_publisher"

    def __init__(
        self,
        config: DaemonConfig,
        session: "Session | SessionRef | None",
        *,
        claims_path: "Any" = None,
        pos_path: "Any" = None,
        http_client: httpx.AsyncClient | None = None,
        refresh_trigger: "RefreshTrigger | None" = None,
    ) -> None:
        super().__init__(
            config,
            session,
            sessions_path=(
                claims_path if claims_path is not None else data_dir() / SESSION_CLAIMS_FILENAME
            ),
            pos_path=(
                pos_path
                if pos_path is not None
                else runtime_state_dir() / SESSION_CLAIMS_PUBLISHER_POS_FILENAME
            ),
            http_client=http_client,
            refresh_trigger=refresh_trigger,
        )

    # ------------------------------------------------------------------
    # Convenience aliases - the inherited names say "sessions", which is
    # the other stream. Read-only; the parent's attributes stay the
    # single storage.
    # ------------------------------------------------------------------

    @property
    def claims_path(self):
        """Path to the claim stream this publisher tails."""
        return self._sessions_path

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        if not self._config.do_publish_enabled:
            logger.info("session_claims_do_publisher disabled by config - idle")
            await self._stop_event.wait()
            return

        if self._session is None and (
            self._session_ref is None or self._session_ref.current is None
        ):
            # Same fail-loud-once posture as the sessions publisher. The
            # hooks keep appending to disk; the claim set just stays empty
            # until a session exists. Nothing is lost, only delayed.
            logger.warning(
                "session_claims_do_publisher: no CLI session - claim publish "
                "disabled. Run `alter login`, or set "
                "ALTER_RUNTIME_DO_PUBLISH_ENABLED=0 to silence this warning."
            )
            await self._stop_event.wait()
            return

        logger.info(
            "session_claims_do_publisher starting claims=%s pos=%s interval=%.1fs",
            self._sessions_path,
            self._pos_path,
            self._config.do_publish_poll_interval_seconds,
        )

        from alter_runtime.http_auth import backend_default_headers

        api = self._api_base()
        client = self._http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
            verify=_build_tls_context(),
            headers=backend_default_headers(api),
        )

        try:
            while not self._stop_event.is_set():
                await self._tick_safe(client)
                await self._sleep_interruptible(self._config.do_publish_poll_interval_seconds)
        finally:
            if self._owns_client:
                with contextlib.suppress(Exception):
                    await client.aclose()
            logger.info("session_claims_do_publisher stopped")

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def _api_base(self) -> str:
        """Return the backend API origin from the live session."""
        session = self._session_ref.current if self._session_ref is not None else self._session
        if session is None:
            raise _SessionMissing()
        return session.api.rstrip("/")

    def _bearer(self) -> str:
        """Return the member JWT. No capability is minted client-side."""
        session = self._session_ref.current if self._session_ref is not None else self._session
        if session is None:
            raise _SessionMissing()
        return session.jwt

    async def _tick(self, client: httpx.AsyncClient) -> bool:
        """One sweep: read new bytes, POST each record, advance the cursor.

        No batching: the claim cadence is one record per session start,
        stop, or heartbeat, so a batch route would add a fallback path
        for a volume that does not exist.

        The offset advances after each record that is settled, whether it
        was accepted or is being abandoned. A record left for retry stops
        the sweep with the cursor still behind it, so ordering within the
        file is preserved: a release must never overtake the claim it
        retires.

        Returns ``True`` on a clean sweep and ``False`` when a transient
        failure was swallowed, which feeds the inherited backoff ladder.
        """
        if not self._sessions_path.exists():
            return True

        offset = self._load_offset()
        new_bytes, new_offset = self._read_since(offset)
        if not new_bytes:
            # Persist a rotation reset so a quiet post-rotation window
            # cannot re-detect the shrink on every tick. Same reasoning as
            # the parent; see its _tick for the full note.
            if new_offset < offset:
                self._save_offset(new_offset)
            return True

        consumed = new_offset - len(new_bytes)
        clean = True

        for raw_line in new_bytes.splitlines(keepends=True):
            record = self._parse_line(raw_line)
            if record is None:
                # Unusable line: advance past it. Retrying a malformed
                # record forever wedges every good record behind it.
                consumed += len(raw_line)
                self._save_offset(consumed)
                continue

            route = CLAIM_ROUTES[record["kind"]]
            settled = await self._post_claim(client, route, record)
            if settled is None:
                # Transient: stop the sweep with the cursor behind this
                # record so the next tick retries it in order.
                clean = False
                break

            consumed += len(raw_line)
            self._save_offset(consumed)
            if not settled:
                clean = False

        return clean

    def _parse_line(self, raw_line: bytes) -> dict[str, Any] | None:
        """Return a routable record, or ``None`` when the line is unusable."""
        stripped = raw_line.decode("utf-8", errors="replace").strip()
        if not stripped:
            return None
        if len(stripped) > MAX_LINE_BYTES:
            logger.warning(
                "session_claims_do_publisher: oversize line (%d bytes) - skipping",
                len(stripped),
            )
            return None
        try:
            record = json.loads(stripped)
        except (ValueError, json.JSONDecodeError):
            logger.warning("session_claims_do_publisher: malformed JSON line - skipping")
            return None
        if not isinstance(record, dict):
            return None

        kind = record.get("kind")
        if kind not in CLAIM_ROUTES:
            logger.warning(
                "session_claims_do_publisher: record kind %r is not a claim kind - "
                "skipping. An emitter is writing to the wrong stream.",
                kind,
            )
            return None
        payload = record.get("payload")
        if not isinstance(payload, dict) or not payload:
            logger.warning(
                "session_claims_do_publisher: %s record has no payload - skipping",
                kind,
            )
            return None
        return record

    async def _post_claim(
        self,
        client: httpx.AsyncClient,
        route: str,
        record: dict[str, Any],
    ) -> bool | None:
        """POST one record's payload.

        Returns ``True`` when the backend accepted it, ``False`` when the
        record is being abandoned after exhausting its attempts or being
        rejected outright, and ``None`` when the failure is transient and
        the record should be retried on the next tick.
        """
        kind = record.get("kind")
        key = self._attempt_key(record)

        try:
            url = f"{self._api_base()}{route}"
            bearer = self._bearer()
        except _SessionMissing:
            return None

        try:
            response = await client.post(
                url,
                json=record["payload"],
                headers={
                    "Authorization": f"Bearer {bearer}",
                    "Accept": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            logger.warning("session_claims_do_publisher: %s POST failed: %s", kind, exc)
            return self._count_attempt(key, kind)

        if response.status_code in (200, 201):
            self._attempts.pop(key, None)
            return True

        if response.status_code in (401, 403):
            # The member JWT itself is being refused, so retrying it on a
            # timer only repeats the rejection. Ask the refresher to
            # rotate out of band, then treat this as transient.
            logger.warning(
                "session_claims_do_publisher: %s rejected (HTTP %d) - requesting session refresh",
                kind,
                response.status_code,
            )
            if self._refresh_trigger is not None:
                with contextlib.suppress(Exception):
                    self._refresh_trigger.request_refresh("session_claims_401")
            return None

        if response.status_code == 429:
            self._note_retry_after(response)
            return None

        if 400 <= response.status_code < 500:
            # A shape the backend will refuse identically forever. Abandon
            # it loudly: a claim dropped in silence is the defect that put
            # this stream on its own route.
            logger.error(
                "session_claims_do_publisher: %s rejected (HTTP %d) - abandoning record id=%s: %s",
                kind,
                response.status_code,
                record.get("id"),
                response.text[:200],
            )
            self._attempts.pop(key, None)
            return False

        logger.warning(
            "session_claims_do_publisher: %s POST returned HTTP %d",
            kind,
            response.status_code,
        )
        return self._count_attempt(key, kind)

    def _count_attempt(self, key: tuple[str, int], kind: Any) -> bool | None:
        """Charge one attempt; abandon the record once they run out."""
        attempts = self._attempts.get(key, 0) + 1
        self._attempts[key] = attempts
        if attempts >= MAX_POST_ATTEMPTS:
            logger.error(
                "session_claims_do_publisher: %s id=%s version=%s failed %d attempts - abandoning",
                kind,
                key[0],
                key[1],
                attempts,
            )
            self._attempts.pop(key, None)
            return False
        return None
