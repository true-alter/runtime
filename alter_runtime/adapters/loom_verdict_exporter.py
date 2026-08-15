"""LoomVerdictExporter - desktop-only producer for the read-only
cross-machine loom-verdict feed.

Shape
-----

Only the single machine acting as the loom validator runs this component
(``DaemonConfig.loom_verdict_exporter_enabled``, default ``False``). It
tails the LOCAL verdict store the validator already writes (schema 2,
under ``~/.local/share/alter/verdicts/``: globally-scoped rows at the
root and worktree-scoped ones, which is every loom row, in a
per-worktree subdirectory one level down) and, for the newest row per
loom concern across that whole layout, POSTs a strict
four-field projection to
``POST /api/v1/identity-events/loom-verdict`` signed with the device's
registered ``AgentSigningKey`` (the same ES256 invocation-signing path
that already gates the daemon's MCP ``tools/call`` traffic - see
:mod:`alter_runtime.invocation_signing`).

This is the AMBIENT produce trigger only: the validator computes a
standing verdict on its own write-settle cadence and this component
relays it. A REMOTE-REQUEST trigger (a thin client asking this machine
to run a fresh validation against a coordinate it has never seen) and a
land-time admission gate that eventually *consumes* a mirrored verdict
are both explicitly OUT OF SCOPE here. This module only ever reads local
files and POSTs; it never runs a validator itself.

STRICT 5-FIELD WIRE ALLOWLIST
------------------------------

The local verdict-store row carries a free-text ``detail`` field plus
``basis`` / ``basis_inputs`` dicts (absolute worktree paths today, and
potentially other free-text reasoning of unknown sensitivity in future
revisions). :func:`row_to_wire_payload` is a strict allowlist
transform with two independent enforcement layers:

1. It reads ONLY ``row["verdict"]``, ``row["basis_digest"]`` (renamed to
   the wire's ``basis_hash``), ``row["observed_at"]``, and
   ``row["concern"]`` (which never reaches the wire in cleartext: it is
   read solely to derive the opaque ``concern_ref`` discriminator, see
   :func:`derive_concern_ref`). ``detail``, ``basis``, ``basis_inputs``,
   and any other row key are never read by this function - there is no
   code path for them to reach the wire.
2. Even if a future edit to this function accidentally read one of those
   keys, constructing :class:`LoomVerdictWirePayload` (``extra="forbid"``)
   by NAMING each field explicitly - never by splatting the row
   (``**row``) - means an unexpected extra key raises ``ValidationError``
   at construction time instead of silently forwarding.

See ``tests/test_loom_verdict_exporter.py`` for the leak-guard assertions.

Cross-platform
--------------

Pure ``pathlib`` + a portable poll loop (no ``inotify``/``watchdog``
dependency, no ``fcntl``): the verdict store changes at most once per
Loom-validate run, so a few seconds of poll latency is an acceptable
trade for identical behaviour on Linux, macOS, and Windows. Cursor state
is written via tempfile + ``os.replace`` (atomic rename on all three
platforms).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from alter_runtime.config import DaemonConfig, data_dir
from alter_runtime.daemon import Component
from alter_runtime.invocation_signing import build_invocation_signature_with_key

if TYPE_CHECKING:
    from collections.abc import Iterator

    from alter_runtime.config import Session, SessionRef
    from alter_runtime.validator_device_key import ValidatorKey

__all__ = [
    "CURSOR_FILENAME",
    "LOOM_CONCERN_PREFIX",
    "LoomVerdictExporter",
    "LoomVerdictWirePayload",
    "concern_ref_salt",
    "default_cursor_path",
    "derive_concern_ref",
    "iter_store_row_paths",
    "row_to_wire_payload",
    "verdict_store_dir",
]

logger = logging.getLogger("alter_runtime.adapters.loom_verdict_exporter")

#: Only verdict-store rows whose ``concern`` starts with this prefix are
#: eligible for cross-machine export. The local verdict store also carries
#: unrelated concerns under other prefixes, and those must never leave this
#: machine. Only concerns the loom validator itself writes belong on the wire.
LOOM_CONCERN_PREFIX = "loom:"

#: Cursor filename (within ``data_dir()``) tracking, per concern, the
#: ``observed_at`` of the last row successfully exported - survives
#: daemon restarts without re-emitting duplicates on every boot.
CURSOR_FILENAME = "loom-verdict-exporter-cursor.json"

#: Env var matching the upstream verdict store's own ``store_dir()``
#: resolution NAME exactly. That module is not an installable dependency
#: of alter-runtime, so its path resolution is intentionally replicated
#: (not imported) here. Any change to the upstream store path/env-var
#: must be mirrored in this constant.
_VERDICT_STORE_DIR_ENV = "ALTER_VERDICT_STORE_DIR"

#: Valid wire verdict values (matches the backend's
#: ``LoomVerdictIngestRequest.verdict`` Literal exactly).
_WIRE_VERDICTS = ("GREEN", "RED", "STALE", "UNKNOWN")

#: The DO's own literal rejection string for its per-content replay nonce
#: (``jsonError("nonce replay detected", 401)``). Matched exactly against
#: ``do_body["error"]`` - never inferred locally - so this exporter only
#: ever treats a rejection as "already accepted" when the DO itself said
#: so, and any other 401 (replay-window, bad signature) is left on the
#: existing warn-and-retry path untouched.
_DO_NONCE_REPLAY_ERROR = "nonce replay detected"

#: Env var supplying the shared salt for :func:`derive_concern_ref`.
#: SHARED DEPLOYMENT CONFIG, not a per-host secret - see that function's
#: docstring for why every producer must agree on this value.
_CONCERN_REF_SALT_ENV = "LOOM_CONCERN_REF_SALT"

#: Domain-separation prefix, versioned so the derivation can be rotated
#: later without silently re-pointing existing refs at new values.
_CONCERN_REF_DOMAIN = "loom-concern-ref:v1"

#: Length of the hex discriminator on the wire. Matches the backend
#: schema's ``min_length=16``/``max_length=64`` hex-only constraint.
_CONCERN_REF_HEX_LEN = 32


def concern_ref_salt() -> str:
    """Read the shared concern-ref salt from the environment (``""`` when unset)."""
    return os.environ.get(_CONCERN_REF_SALT_ENV, "")


def derive_concern_ref(concern: str, *, salt: str | None = None) -> str:
    """Derive the opaque per-concern discriminator carried on the wire.

    Two loom concerns can watch identical file globs and therefore compute
    an identical ``basis_hash``, and some do exactly that. Every downstream
    identity was previously built from ``basis_hash`` alone, so those two
    concerns collided: the backend's replay nonce collided, and the
    consumer's mirror filename collided. ``concern_ref`` restores the
    missing dimension.

    The discriminator is OPAQUE by design. The wire allowlist is a
    deliberate leak guard, and the internal gate name is exactly the kind
    of detail it exists to keep off the wire, so the concern is hashed
    rather than sent.

    Salt semantics
    --------------

    ``salt`` comes from the ``LOOM_CONCERN_REF_SALT`` environment
    variable and is SHARED DEPLOYMENT CONFIG, never per-host. Producers on
    different machines MUST be configured with the same salt: the whole
    point of the discriminator is that the same gate correlates to the
    same ref across every machine in the feed, and a per-host salt would
    silently break that correlation while still looking healthy locally.

    Be honest about what the salt does and does not buy. With an empty
    salt (the default) this value is OBFUSCATION, not secrecy: the space
    of loom concern names is small and enumerable, so anyone holding the
    feed can brute-force the preimage of a given ref. A non-empty shared
    salt raises that bar meaningfully. The COLLISION FIX holds either
    way, because it depends only on distinct concerns deriving distinct
    refs, which is true regardless of whether the salt is set.
    """
    effective_salt = concern_ref_salt() if salt is None else salt
    material = f"{_CONCERN_REF_DOMAIN}:{effective_salt}:{concern}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:_CONCERN_REF_HEX_LEN]


def verdict_store_dir() -> Path:
    """Resolve the local verdict-store directory the validator writes.

    Mirrors the upstream verdict store's own directory resolution
    byte-for-byte: ``pathlib.Path.home()``-based, portable across Linux,
    macOS, and Windows (this is the upstream producer's contract, not
    XDG-namespaced - not ours to change; alter-runtime's own
    :func:`alter_runtime.config.data_dir` is deliberately NOT reused here
    because it would resolve to a different directory than the one the
    validator actually writes to).
    """
    override = os.environ.get(_VERDICT_STORE_DIR_ENV)
    return Path(override) if override else Path.home() / ".local" / "share" / "alter" / "verdicts"


def iter_store_row_paths(store_dir: Path) -> "Iterator[Path]":
    """Yield every verdict-row path: the store root AND one level below it.

    The store is NOT flat. The upstream writer namespaces worktree-scoped
    concerns (``loom:``, ``frontend-verify:``) under a per-worktree
    subdirectory and leaves only globally-scoped rows at the root. A
    root-only ``glob("*.json")`` therefore stops seeing loom rows the
    moment the validator writes from a worktree, which is every skein.

    That is not hypothetical. A root-only glob held a handful of stale rows
    while thousands of current ones sat one level down, and nothing errored,
    because "no new rows" and "cannot see any rows" are the same silence.

    One level is the whole layout, not a guess: the upstream store creates
    exactly one namespace directory per worktree and never nests further,
    and the landing kernel's own verdict reader reconciles the same
    layout with the same one-level scan. Both readers must agree, so if
    the upstream ever nests deeper, both change together.
    """
    yield from sorted(store_dir.glob("*.json"))
    yield from sorted(store_dir.glob("*/*.json"))


class LoomVerdictWirePayload(BaseModel):
    """The exact five-field allowlist the backend's
    ``LoomVerdictIngestRequest`` accepts. ``extra="forbid"`` is the
    second, independent enforcement layer for the strict allowlist
    described in the module docstring - never construct this by splatting
    an upstream row (``**row``); name every field explicitly.

    ``concern_ref`` is the opaque per-concern discriminator
    (:func:`derive_concern_ref`), constrained here to match the backend
    schema exactly: lowercase hex, 16 to 64 characters, required. The
    RAW concern name is never a field on this model, so there is no code
    path by which it can reach the wire.
    """

    model_config = ConfigDict(extra="forbid")

    verdict: Literal["GREEN", "RED", "STALE", "UNKNOWN"]
    basis_hash: str
    observed_at: str
    producer_id: str
    concern_ref: str = Field(min_length=16, max_length=64, pattern=r"^[0-9a-f]+$")


def _decayed_verdict(row: dict[str, Any]) -> str | None:
    """Return the decay-honest lowercase verdict for a schema-2 row, or
    ``None`` if the row's verdict is missing/unrecognised.

    Mirrors the upstream store's own decay/TTL check (replicated, not
    imported - see module docstring): a
    ``green``/``red`` row whose ``decay.ttl_s`` has elapsed since
    ``observed_at`` degrades to ``"stale"`` here too, so the exporter
    never wires out a confidently green/red verdict that the LOCAL reader
    itself would already treat as stale. The stored file is never
    rewritten; this is read-time honesty only, exactly like the source
    module.
    """
    verdict = row.get("verdict")
    if verdict not in ("green", "red", "stale", "unknown"):
        return None
    if verdict not in ("green", "red"):
        return verdict
    ttl = (row.get("decay") or {}).get("ttl_s")
    if not ttl:
        return verdict
    observed_at = row.get("observed_at")
    if not isinstance(observed_at, str):
        return "stale"
    try:
        observed = datetime.fromisoformat(observed_at)
    except ValueError:
        return "stale"  # An unparseable timestamp can never prove freshness.
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    if (datetime.now(timezone.utc) - observed).total_seconds() > ttl:
        return "stale"
    return verdict


def row_to_wire_payload(row: dict[str, Any], *, producer_id: str) -> LoomVerdictWirePayload | None:
    """Strict allowlist transform: a verdict-store row -> the five-field
    wire payload, or ``None`` when the row is malformed or ineligible.

    ``producer_id`` is supplied by the CALLER (derived from the local
    device's own signing-key identity - see
    :meth:`LoomVerdictExporter._producer_id`); it is NEVER read from
    ``row``. See the module docstring for the two-layer allowlist this
    function implements.
    """
    if not isinstance(row, dict):
        return None
    if row.get("schema") != 2:
        return None
    concern = row.get("concern")
    if not isinstance(concern, str) or not concern.startswith(LOOM_CONCERN_PREFIX):
        return None

    decayed = _decayed_verdict(row)
    if decayed is None:
        return None
    wire_verdict = decayed.upper()
    if wire_verdict not in _WIRE_VERDICTS:
        return None

    basis_hash = row.get("basis_digest")
    observed_at = row.get("observed_at")
    if not isinstance(basis_hash, str) or not basis_hash:
        return None
    if not isinstance(observed_at, str) or not observed_at:
        return None

    try:
        return LoomVerdictWirePayload(
            verdict=wire_verdict,  # type: ignore[arg-type]
            basis_hash=basis_hash,
            observed_at=observed_at,
            producer_id=producer_id,
            # The RAW concern is hashed here and never carried in
            # cleartext: two concerns sharing a basis_hash need a
            # discriminator, but the gate name itself stays off the wire.
            concern_ref=derive_concern_ref(concern),
        )
    except ValidationError:
        # Fail-closed: an unexpected shape is dropped, never forwarded
        # partially. Should be unreachable given the checks above; kept as
        # the second enforcement layer described in the module docstring.
        logger.warning(
            "loom_verdict_exporter: row for concern=%r failed the wire-payload "
            "allowlist validation - dropping (never forwarding a partial row)",
            concern,
        )
        return None


# ---------------------------------------------------------------------------
# Cursor persistence (survives daemon restarts without re-emitting)
# ---------------------------------------------------------------------------


def default_cursor_path() -> Path:
    return data_dir() / CURSOR_FILENAME


def _load_cursor(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _save_cursor(path: Path, cursor: dict[str, str]) -> None:
    """Atomically write the cursor file (tempfile + fsync + os.replace).

    No ``fcntl`` - single-writer-at-a-time by construction (one exporter
    instance polls at a time) and this pattern is portable to Windows,
    unlike the ``flock``-based idiom used by the append-only JSONL writers
    elsewhere in this package.
    """
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(cursor, indent=2, sort_keys=True), encoding="utf-8")
        with tmp.open("rb") as f:
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        logger.warning("loom_verdict_exporter: cursor write failed: %s", exc)
        with contextlib.suppress(OSError):
            tmp.unlink()


# ---------------------------------------------------------------------------
# LoomVerdictExporter
# ---------------------------------------------------------------------------


class LoomVerdictExporter(Component):
    """Tails the local loom-concern verdict-store rows and re-emits each
    as a signed ``loom_verdict`` POST to the backend.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`. Uses ``loom_verdict_exporter_enabled``
        (checked by the daemon wiring, not this class),
        ``loom_verdict_exporter_poll_interval_seconds``, and
        ``loom_verdict_endpoint``.
    session:
        Authenticated CLI :class:`Session` or a live :class:`SessionRef`.
        Supplies the bearer JWT and the ES256 signing-key identity
        (``signing_kid`` / ``signing_key_fingerprint``) used to build the
        ``Mcp-Invocation-Signature`` header.
    http_client:
        Optional ``httpx.AsyncClient`` override for tests.
    store_dir:
        Override the verdict-store directory for tests (defaults to
        :func:`verdict_store_dir`).
    poll_interval_seconds:
        Override the poll cadence for tests.
    cursor_path:
        Override the cursor file path for tests (defaults to
        :func:`default_cursor_path`, i.e. ``data_dir()``). Tests MUST pass
        this (or redirect ``XDG_DATA_HOME``) - otherwise the exporter
        reads/writes the real ``~/.local/share/alter-runtime/`` cursor
        file, leaking cross-test-run state onto the developer's machine.
    """

    name = "loom_verdict_exporter"

    def __init__(
        self,
        config: DaemonConfig,
        session: "Session | SessionRef",
        *,
        http_client: httpx.AsyncClient | None = None,
        store_dir: Path | None = None,
        poll_interval_seconds: float | None = None,
        cursor_path: Path | None = None,
    ) -> None:
        self._config = config
        from alter_runtime.config import SessionRef as _SessionRef

        if isinstance(session, _SessionRef):
            self._session_ref: "_SessionRef | None" = session
            self._session: "Session" = session.current
        else:
            self._session_ref = None
            self._session = session  # type: ignore[assignment]

        self._http_client = http_client
        self._owns_client = http_client is None
        self._store_dir = store_dir if store_dir is not None else verdict_store_dir()
        self._poll_interval = (
            poll_interval_seconds
            if poll_interval_seconds is not None
            else config.loom_verdict_exporter_poll_interval_seconds
        )
        self._cursor_path = cursor_path if cursor_path is not None else default_cursor_path()
        self._stop_event = asyncio.Event()
        self._cursor: dict[str, str] = _load_cursor(self._cursor_path)

        # Test/observability introspection counters.
        self.export_count = 0
        self.skip_count = 0

        # Consecutive 401/403 refusals, and the monotonic deadline until
        # which polling is suspended. A refused kid cannot start working by
        # being retried, so retrying it every 5s is 12 futile posts a minute
        # against production. Worse, the previous arrangement logged each one
        # at WARNING and nothing surfaced, so the feed stayed dead for three
        # days without anything going red.
        self._refusal_streak = 0
        self._refusal_backoff_until = 0.0

        # Latch for the empty-scan warning, so an idle desktop reports the
        # condition once rather than every poll_interval.
        self._warned_empty_scan = False

    #: Consecutive refusals before the exporter escalates and backs off.
    REFUSAL_ESCALATE_AFTER = 3

    #: Seconds to suspend polling once a refusal is established.
    REFUSAL_BACKOFF_SECONDS = 300.0

    def _note_refusal(self, kid: str, status_code: int) -> None:
        """Record a 401/403 and, once established, escalate and back off.

        The first couple of refusals may be a deploy in flight. A third in a
        row means the kid is genuinely not accepted, which no amount of
        retrying fixes, so say so at ERROR with the exact remedy and stop
        hammering the endpoint until the backoff lapses.
        """
        self._refusal_streak += 1
        if self._refusal_streak < self.REFUSAL_ESCALATE_AFTER:
            return

        self._refusal_backoff_until = time.monotonic() + self.REFUSAL_BACKOFF_SECONDS
        logger.error(
            "loom_verdict_exporter: verdict export REFUSED %d times in a row "
            "(status=%d) for kid=%s. The cross-machine verdict feed is DOWN. "
            "Retrying cannot fix this: the kid has to be in the "
            "LOOM_VALIDATOR_KID allowlist on alter-api, which is an admin "
            "change. Suspending export for %.0fs.",
            self._refusal_streak,
            status_code,
            kid,
            self.REFUSAL_BACKOFF_SECONDS,
        )

    def _live_session(self) -> "Session":
        if self._session_ref is not None:
            return self._session_ref.current
        return self._session

    # ``_producer_id(session)`` used to derive this identifier from the
    # SESSION signing key. It is gone rather than retained: the whole point
    # of the validator device key is that the session key no longer speaks
    # for this device, and a helper that still reads it is an invitation to
    # wire the defect back in. ``producer_id`` is now derived in
    # :meth:`_poll_once` from the validator key that actually signs.
    #
    # For the record, unchanged: the backend derives ``producer_id``
    # server-side from the VERIFIED signing key and ignores any
    # caller-supplied value. We send our own key identity for schema
    # compatibility and forward honesty; the served value is authoritative
    # regardless.

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        client = self._http_client or httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        logger.info(
            "loom_verdict_exporter starting store_dir=%s endpoint=%s poll_interval=%.1fs",
            self._store_dir,
            self._config.loom_verdict_endpoint,
            self._poll_interval,
        )
        try:
            while not self._stop_event.is_set():
                try:
                    await self._poll_once(client)
                except Exception as exc:  # noqa: BLE001 - one bad poll must not kill the loop
                    logger.warning("loom_verdict_exporter: poll iteration failed: %s", exc)
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self._poll_interval)
                except (TimeoutError, asyncio.TimeoutError):
                    pass
        finally:
            if self._owns_client:
                with contextlib.suppress(Exception):
                    await client.aclose()
            logger.info("loom_verdict_exporter stopped")

    async def stop(self) -> None:
        """Cooperative shutdown - releases the poll loop."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Poll + emit
    # ------------------------------------------------------------------

    async def _poll_once(self, client: httpx.AsyncClient) -> None:
        """Scan the verdict-store directory once and emit any new rows."""
        if not self._store_dir.is_dir():
            return

        if time.monotonic() < self._refusal_backoff_until:
            return

        session = self._live_session()

        # Resolve the validator key ONCE per poll, not once per row. It also
        # supplies the producer_id, so the identifier we send names the key
        # that actually signs rather than whichever key the last login left
        # in the session.
        # Imported here rather than at module scope, because this dependency is
        # optional in some builds. A module-scope import would make its absence
        # break `import alter_runtime.adapters` outright, taking the whole
        # package down for a component that is off by default. Resolved per
        # poll, which is cheap next to the HTTP work in this method.
        try:
            from alter_runtime.validator_device_key import resolve_or_provision
        except ImportError:
            logger.warning(
                "loom_verdict_exporter: an optional dependency is unavailable "
                "in this build, so no device-bound loom_verdict can be emitted; "
                "disable loom_verdict_exporter_enabled to silence this"
            )
            return

        validator = await resolve_or_provision(session, client)
        if validator is None:
            logger.warning(
                "loom_verdict_exporter: no validator device key available - "
                "cannot emit a device-bound loom_verdict; skipping this poll"
            )
            return

        producer_id = f"es256-kid:{validator.kid}"

        newest = self._newest_row_per_concern(producer_id)

        # An empty scan is reported, never passed over in silence. The
        # root-only glob this replaced spent sixteen days finding nothing
        # and saying nothing, because a store it cannot read and a store
        # with no news are indistinguishable from inside the loop. They
        # are distinguishable from outside it: no eligible row ANYWHERE
        # under a store directory that exists means the reader and the
        # writer disagree about the layout, which is a defect, not a quiet
        # period. Latched so a genuinely idle desktop does not repeat it
        # every poll_interval.
        if not newest:
            if not self._warned_empty_scan:
                logger.warning(
                    "loom_verdict_exporter: no exportable %s rows found under %s "
                    "(scanned the root and one level below it) - the validator "
                    "writes no loom verdicts, or it writes them somewhere this "
                    "scan does not reach",
                    LOOM_CONCERN_PREFIX,
                    self._store_dir,
                )
                self._warned_empty_scan = True
            return
        self._warned_empty_scan = False

        for concern, payload in sorted(newest.items()):
            last_observed_at = self._cursor.get(concern)
            if last_observed_at is not None and payload.observed_at <= last_observed_at:
                continue  # Already exported this (or a newer) observation.

            ok = await self._emit(client, session, payload, validator)
            if ok:
                self._cursor[concern] = payload.observed_at
                _save_cursor(self._cursor_path, self._cursor)
                self.export_count += 1
            else:
                self.skip_count += 1

    def _newest_row_per_concern(self, producer_id: str) -> dict[str, LoomVerdictWirePayload]:
        """Reduce the whole store to the newest eligible row per concern.

        The rail carries what a concern's verdict IS, not every observation
        it has ever been, and the store keeps one row per (concern,
        worktree) pair. So a concern validated across several worktrees has
        several live rows whose only meaningful difference is age, and
        without this reduction the poll would emit each of them, ordered by
        a hex directory name, leaving whichever sorted last as the rail's
        answer. That is the same first-match-wins-over-duplicates defect the
        landing kernel had to fix in ``read_verdict_predicate``, arrived at
        from the write side.

        Newest ``observed_at`` wins, matching that kernel reduction: on
        identical content a later observation supersedes an earlier one.
        This deliberately does NOT mirror the kernel's red-dominates rule.
        The kernel is deciding whether to admit a landing and must fail
        closed; this is a reporting relay, and a stale red outranking a
        current green would misreport the concern's present state.
        """
        newest: dict[str, LoomVerdictWirePayload] = {}
        for path in iter_store_row_paths(self._store_dir):
            try:
                row = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue

            payload = row_to_wire_payload(row, producer_id=producer_id)
            if payload is None:
                continue

            concern = row["concern"]
            current = newest.get(concern)
            if current is None or payload.observed_at > current.observed_at:
                newest[concern] = payload
        return newest

    async def _emit(
        self,
        client: httpx.AsyncClient,
        session: "Session",
        payload: LoomVerdictWirePayload,
        validator: "ValidatorKey",
    ) -> bool:
        """POST one wire payload, signed. Returns True on confirmed success."""
        # tool_args MUST equal exactly what the server recomputes as
        # ``body.model_dump(exclude={"thread_id"})`` - since this payload
        # carries no thread_id field at all, model_dump() already matches
        # byte-for-byte (the canonicalisation itself is delegated entirely
        # to build_invocation_signature / the server's canonical_args_sha256,
        # both sort_keys=True + compact separators + ensure_ascii=False).
        tool_args = payload.model_dump()

        # Sign with this device's purpose-scoped validator key, NOT the
        # session key. The session key is re-minted by every `alter login`,
        # which silently moves the kid out of the backend's
        # LOOM_VALIDATOR_KID allowlist and kills the feed until someone
        # edits a production secret. The validator key never moves.
        jws = build_invocation_signature_with_key(
            pem=validator.pem,
            kid=validator.kid,
            handle=getattr(session, "handle", ""),
            tool_name="loom_verdict.emit",
            arguments=tool_args,
        )
        if jws is None:
            logger.warning(
                "loom_verdict_exporter: could not build Mcp-Invocation-Signature "
                "(validator key unusable) - skipping this export"
            )
            return False

        headers = {
            "Authorization": f"Bearer {session.jwt}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Mcp-Invocation-Signature": jws,
        }

        try:
            response = await client.post(
                self._config.loom_verdict_endpoint,
                json=tool_args,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            logger.warning("loom_verdict_exporter: POST transport error: %s", exc)
            return False

        if response.status_code >= 400:
            logger.warning(
                "loom_verdict_exporter: backend rejected loom_verdict status=%d body=%s",
                response.status_code,
                response.text[:256],
            )
            if response.status_code in (401, 403):
                self._note_refusal(validator.kid, response.status_code)
            return False

        self._refusal_streak = 0

        # The endpoint returns HTTP 200 with {"ok": false, ...} when the DO
        # itself rejects the envelope - a plain status check misses that.
        try:
            body = response.json()
        except ValueError:
            body = None
        if isinstance(body, dict) and body.get("ok") is False:
            do_body = body.get("do_body")
            do_reason = do_body.get("error") if isinstance(do_body, dict) else None

            if do_reason == _DO_NONCE_REPLAY_ERROR:
                # The DO's nonce is content-addressed
                # (`derive_nonce(handle, f"{concern_ref}:{basis_hash}:{verdict}",
                # ...)`, backend `producer.py`), so this specific rejection
                # means the DO already holds this exact (concern, basis_hash,
                # verdict) - a genuine retry of unchanged content, not a
                # refusal of anything new. The cursor only tracks
                # `observed_at`, so a later, content-identical row (e.g. an
                # unchanged worktree re-validated) would otherwise retry this
                # every poll forever, never advancing, and never tripping the
                # 401/403 backoff below (this path returns before that check
                # because the transport status is 200). Treating it as
                # confirmed-already-accepted for cursor purposes is honest,
                # not a rejection being papered over: the content IS on the
                # rail, just not from this call. Any OTHER do_body reason
                # (replay-window, bad signature) still falls through to the
                # WARNING + `False` below and is never silently absorbed.
                logger.info(
                    "loom_verdict_exporter: content already accepted (DO: %s) "
                    "for basis_hash=%s concern_ref=%s - advancing cursor, "
                    "nothing new to emit",
                    do_reason,
                    payload.basis_hash[:12],
                    payload.concern_ref[:12],
                )
                return True

            logger.warning(
                "loom_verdict_exporter: backend ok=false do_status=%s error=%s do_body=%s",
                body.get("do_status"),
                body.get("error"),
                do_body,
            )
            return False

        logger.info(
            "loom_verdict_exporter: emitted verdict=%s basis_hash=%s concern_ref=%s status=%d",
            payload.verdict,
            payload.basis_hash[:12],
            payload.concern_ref[:12],
            response.status_code,
        )
        return True

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def store_dir(self) -> Path:
        return self._store_dir

    @property
    def cursor(self) -> dict[str, str]:
        return self._cursor
