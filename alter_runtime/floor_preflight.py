"""Client-side floor preflight for the alter-runtime daemon.

Responsibilities of this module:

1.  Fetch the signed floor doc from ``${api}/v1/clients/min-version``.
2.  Verify the HMAC-SHA256 signature against a known-keys map keyed by
    ``key_id`` (first 8 hex chars of the signing key digest).
3.  Cache the doc to disk under the daemon's existing XDG config root, with
    the same JSON shape used by the CLI (so a single fresh-enough cache
    survives a CLI / daemon swap on the same host).
4.  Compare the daemon's running version against the floor for the
    ``alter-runtime`` client_id (channel ``binary``, with a fallback to the
    server-computed ``unknown`` row).
5.  Emit the canonical ``client_below_floor`` envelope when the daemon falls
    below floor. Consumed by ``FloorLoop`` and surfaced on every RPC reply
    through the Unix-socket gate.

The module is sync-friendly (uses ``httpx``'s async client behind a small
async wrapper) and free of any new runtime dependencies: ``httpx`` and
``hmac`` are already in the dep set.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from alter_runtime import __version__ as RUNTIME_VERSION
from alter_runtime.config import config_dir

__all__ = [
    "MIN_VERSION_ENDPOINT",
    "CLIENT_ID",
    "RUNTIME_CHANNEL",
    "ClientBelowFloorEnvelope",
    "FloorDocument",
    "FloorVerdict",
    "KNOWN_HMAC_KEYS",
    "build_envelope",
    "client_headers",
    "compare_semver",
    "disk_cache_path",
    "fetch_floor_doc",
    "load_known_keys",
    "preflight",
    "read_disk_cache",
    "verify_floor_signature",
    "write_disk_cache",
]


logger = logging.getLogger("alter_runtime.floor_preflight")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Floor endpoint suffix. The base lives on the same host as
#: ``DaemonConfig.mcp_fallback_endpoint`` / the backend; the leading ``/v1/``
#: prefix matches the FastAPI router mount.
MIN_VERSION_ENDPOINT: str = "/api/v1/clients/min-version"

#: Identifies the daemon to the server-side gate. The daemon ships as a
#: Python package via ``releases.truealter.com`` / ``alter update``, using
#: the ``binary`` distribution channel.
CLIENT_ID: str = "alter-runtime"
RUNTIME_CHANNEL: str = "binary"

#: 24h disk-cache freshness window. The
#: floor loop refresh cadence is also 24h, matching
#: ``UpdateLoop.poll_interval_seconds``.
DISK_FRESH_SECONDS: int = 24 * 60 * 60

#: 7d disk-cache permit-with-warn ceiling.
DISK_WARN_SECONDS: int = 7 * 24 * 60 * 60

#: Fetch budget. Floor fetch never blocks the daemon hot path; the loop
#: re-tries on the next 24h tick.
FETCH_TIMEOUT_SECONDS: float = 4.0


def _load_known_keys_from_env() -> dict[str, str]:
    """Read known HMAC keys from ``ALTER_FLOOR_HMAC_KEYS``.

    Format: comma-separated list of ``key_id:hex_key`` pairs, where ``key_id``
    is the first 8 hex chars of ``sha256(key)``. Missing or malformed entries
    are skipped silently; the verify path treats them as cache misses, never
    crashes.
    """
    raw = os.environ.get("ALTER_FLOOR_HMAC_KEYS", "")
    out: dict[str, str] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        kid, _, key = entry.partition(":")
        kid = kid.strip()
        key = key.strip()
        if not kid or not key:
            continue
        out[kid] = key
    return out


#: Known HMAC keys keyed by ``key_id``. Loaded from environment at module
#: import. May be empty in dev; verification then fails closed (cache miss)
#: verification then fails closed (cache miss). Operators provision via
#: ``ALTER_FLOOR_HMAC_KEYS=<key_id>:<hex_key>[,<key_id>:<hex_key>...]``.
KNOWN_HMAC_KEYS: dict[str, str] = _load_known_keys_from_env()


def load_known_keys() -> dict[str, str]:
    """Return the current known-keys map (re-read from env each call).

    Useful for tests that mutate the env between cases. Production code
    reads ``KNOWN_HMAC_KEYS`` directly.
    """
    return _load_known_keys_from_env()


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClientBelowFloorEnvelope:
    """Canonical client_below_floor envelope.

    Use :meth:`to_dict` for serialisation. Field order is fixed: ``code``,
    ``message``, ``client_version``, ``min_version``, ``upgrade_cmd``,
    ``channel``.
    """

    client_id: str
    client_version: str
    min_version: str
    upgrade_cmd: str
    channel: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": {
                "code": "client_below_floor",
                "message": (
                    f"Your {self.client_id} is below the minimum version. Upgrade required."
                ),
                "client_version": self.client_version,
                "min_version": self.min_version,
                "upgrade_cmd": self.upgrade_cmd,
                "channel": self.channel,
            }
        }


@dataclass
class FloorDocument:
    """In-memory view of the signed floor doc.

    Only the subset needed for daemon enforcement is materialised; the full
    ``floors`` map is retained as ``dict[str, Any]`` so future client_ids
    are not constrained.
    """

    floors: dict[str, Any]
    served_at: str
    cache_ttl_seconds: int
    signature: str
    key_id: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> FloorDocument:
        return cls(
            floors=dict(raw.get("floors", {})),
            served_at=str(raw.get("served_at", "")),
            cache_ttl_seconds=int(raw.get("cache_ttl_seconds", DISK_FRESH_SECONDS)),
            signature=str(raw.get("signature", "")),
            key_id=str(raw.get("key_id", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "floors": self.floors,
            "served_at": self.served_at,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "signature": self.signature,
            "key_id": self.key_id,
        }


@dataclass
class FloorVerdict:
    """Outcome of a preflight pass."""

    #: ``True`` when the daemon is at or above the floor (permitted).
    ok: bool
    envelope: ClientBelowFloorEnvelope | None = None
    #: Human-readable diagnostic; promoted to logs.
    diagnostic: str = ""
    #: Best-effort warning string (24h;7d stale-cache window). Operation still
    #: permitted when this is non-empty and ``ok`` is True.
    warn: str | None = None
    #: The document the verdict was derived from. ``None`` when no doc could
    #: be loaded (no cache + fetch failed). Useful for tests.
    doc: FloorDocument | None = None


# ---------------------------------------------------------------------------
# Semver
# ---------------------------------------------------------------------------


def _semver_tuple(version: str) -> tuple[int, ...]:
    """Strip pre-release / build suffix at the first non-numeric character.

    Lenient grammar: a daemon and CLI on the same host will always agree
    on whether the version is below floor.
    """
    parts: list[int] = []
    for raw in (version or "").split("."):
        digits = ""
        truncated = False
        for ch in raw:
            if ch.isdigit():
                digits += ch
            else:
                truncated = True
                break
        if not digits:
            return tuple(parts) if parts else (0,)
        parts.append(int(digits))
        if truncated:
            return tuple(parts)
    return tuple(parts) if parts else (0,)


def compare_semver(a: str, b: str) -> int:
    """Return -1 / 0 / +1 for ``a < b`` / ``a == b`` / ``a > b``."""
    ta = _semver_tuple(a)
    tb = _semver_tuple(b)
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


# ---------------------------------------------------------------------------
# HMAC verify ; client-side port of the server's floor-signing contract
# ---------------------------------------------------------------------------


def _canonical_json(obj: dict[str, Any]) -> bytes:
    """Sorted-key compact JSON encoding, matching the server-side implementation.

    The signature is computed over the canonical JSON of
    ``{"floors": ..., "served_at": ...}``. ``cache_ttl_seconds`` is advisory
    and deliberately outside the signature scope; ``signature`` and
    ``key_id`` are the verify outputs.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _key_id_for(signing_key: str) -> str:
    """Return the 8-char key_id for a signing key.

    The key_id is the first 8 hex chars of ``sha256(signing_key)``. The
    function is exposed in the test surface to derive expected key_ids in
    fixture data.
    """
    if not signing_key:
        return "00000000"
    digest = hashlib.sha256(signing_key.encode("utf-8")).hexdigest()
    return digest[:8]


def verify_floor_signature(
    doc: FloorDocument | dict[str, Any],
    known_keys: dict[str, str] | None = None,
) -> bool:
    """Constant-time verify of the floor doc HMAC.

    Returns ``True`` on a valid signature against any known key; ``False`` on
    unknown ``key_id``, mismatching ``key_id`` digest, or signature mismatch.
    Never raises; verification failure degrades to a cache miss in the
    caller.
    """
    if isinstance(doc, FloorDocument):
        payload = {"floors": doc.floors, "served_at": doc.served_at}
        signature = doc.signature
        doc_key_id = doc.key_id
    else:
        payload = {"floors": doc.get("floors"), "served_at": doc.get("served_at")}
        signature = doc.get("signature", "")
        doc_key_id = doc.get("key_id", "")

    if not signature or not doc_key_id:
        return False

    keys = known_keys if known_keys is not None else KNOWN_HMAC_KEYS
    if not keys:
        return False

    candidate = keys.get(doc_key_id)
    if not candidate:
        # ``key_id`` does not match any known key; verification fails. The
        # Server-side helper falls through other keys too; we mirror
        # that for robustness against rotation lag.
        for key_id, key in keys.items():
            if _key_id_for(key) != doc_key_id:
                continue
            candidate = key
            break
        if not candidate:
            return False

    canonical = _canonical_json(payload)
    expected = hmac.new(
        candidate.encode("utf-8"),
        canonical,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Envelope builder
# ---------------------------------------------------------------------------


def build_envelope(
    *,
    client_id: str,
    client_version: str,
    min_version: str,
    upgrade_cmd: str,
    channel: str,
) -> ClientBelowFloorEnvelope:
    return ClientBelowFloorEnvelope(
        client_id=client_id,
        client_version=client_version,
        min_version=min_version,
        upgrade_cmd=upgrade_cmd,
        channel=channel,
    )


# ---------------------------------------------------------------------------
# Header bundle
# ---------------------------------------------------------------------------


def client_headers() -> dict[str, str]:
    """Return the canonical ``X-Alter-Client-*`` header bundle.

    Attached to every outbound HTTP call from the daemon to the backend. The
    floor middleware reads ``X-Alter-Client-Id`` and ``X-Alter-Client-Version``
    before auth; missing values result in HTTP 426
    ``client_identification_required``, so these headers are always included.

    The ``X-Alter-Client-Channel`` value defaults to ``binary`` because the
    daemon ships via ``releases.truealter.com``. Operators may override via
    ``ALTER_RUNTIME_CHANNEL`` for distribution-packaged builds.
    """
    channel = os.environ.get("ALTER_RUNTIME_CHANNEL", "").strip() or RUNTIME_CHANNEL
    return {
        "X-Alter-Client-Id": CLIENT_ID,
        "X-Alter-Client-Version": RUNTIME_VERSION,
        "X-Alter-Client-Channel": channel,
    }


# ---------------------------------------------------------------------------
# Floor lookup
# ---------------------------------------------------------------------------


def _lookup_runtime_floor(doc: FloorDocument) -> dict[str, str] | None:
    """Return ``{min_version, upgrade_cmd}`` for the running daemon.

    Supports both a single floor entry and a per-channel map under
    ``alter-runtime``. The binary channel is consulted first, falling back to
    the server-computed unknown row.
    """
    entry = doc.floors.get(CLIENT_ID)
    if not entry:
        return None
    if isinstance(entry, dict) and "min_version" in entry and "upgrade_cmd" in entry:
        return {
            "min_version": str(entry["min_version"]),
            "upgrade_cmd": str(entry["upgrade_cmd"]),
        }
    # Per-channel map shape; CLI style.
    if isinstance(entry, dict):
        for channel in (RUNTIME_CHANNEL, "unknown"):
            sub = entry.get(channel)
            if isinstance(sub, dict) and "min_version" in sub and "upgrade_cmd" in sub:
                return {
                    "min_version": str(sub["min_version"]),
                    "upgrade_cmd": str(sub["upgrade_cmd"]),
                }
    return None


def _compare_to_floor(
    doc: FloorDocument,
    daemon_version: str,
) -> FloorVerdict:
    floor = _lookup_runtime_floor(doc)
    if floor is None:
        # No floor entry; neutral verdict, daemon proceeds.
        return FloorVerdict(ok=True, diagnostic="no-floor-defined", doc=doc)
    if compare_semver(daemon_version, floor["min_version"]) >= 0:
        return FloorVerdict(ok=True, diagnostic="above-floor", doc=doc)
    envelope = build_envelope(
        client_id=CLIENT_ID,
        client_version=daemon_version,
        min_version=floor["min_version"],
        upgrade_cmd=floor["upgrade_cmd"],
        channel=RUNTIME_CHANNEL,
    )
    return FloorVerdict(
        ok=False,
        envelope=envelope,
        diagnostic="below-floor",
        doc=doc,
    )


# ---------------------------------------------------------------------------
# Disk cache (ownership/mode + atomic write)
# ---------------------------------------------------------------------------


def disk_cache_path() -> Path:
    """Return the disk cache path. Shared with the CLI so a fresh cache
    survives a daemon / CLI swap on the same host.
    """
    return config_dir() / "floor-cache.json"


@dataclass
class _DiskCacheEntry:
    doc: FloorDocument
    fetched_at_ms: int = field(default=0)

    def to_dict(self) -> dict[str, Any]:
        return {"doc": self.doc.to_dict(), "fetched_at_ms": self.fetched_at_ms}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> _DiskCacheEntry:
        doc = FloorDocument.from_dict(raw.get("doc", {}))
        return cls(doc=doc, fetched_at_ms=int(raw.get("fetched_at_ms", 0)))


def read_disk_cache(
    path: Path | None = None,
    *,
    known_keys: dict[str, str] | None = None,
    require_mode_0600: bool = True,
    effective_uid: int | None = None,
) -> _DiskCacheEntry | None:
    """Read the disk cache after the ownership + mode-0600 check.

    Returns ``None`` on missing file, wrong UID, wrong mode, malformed JSON,
    or HMAC verification failure. Failure modes degrade to "no cache" ; the
    caller treats this identically to a fetch error.
    """
    target = path or disk_cache_path()
    try:
        stat = target.stat()
    except (FileNotFoundError, OSError):
        return None

    # POSIX ownership + mode check. ``effective_uid`` override is for
    # tests; production calls ``os.geteuid()``.
    if hasattr(os, "geteuid"):
        observed_uid = stat.st_uid
        wanted_uid = effective_uid if effective_uid is not None else os.geteuid()
        if observed_uid != wanted_uid:
            logger.warning(
                "floor_cache_owner_mismatch path=%s uid=%d expected=%d",
                target,
                observed_uid,
                wanted_uid,
            )
            return None
    if require_mode_0600:
        # Compare the file-permission bits exactly. Windows ACLs are out of
        # scope for v1; the Python daemon ships Linux+macOS first.
        if (stat.st_mode & 0o777) != 0o600:
            logger.warning(
                "floor_cache_mode_unexpected path=%s mode=%o",
                target,
                stat.st_mode & 0o777,
            )
            return None

    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(raw, dict):
        return None
    try:
        entry = _DiskCacheEntry.from_dict(raw)
    except (KeyError, ValueError, TypeError):
        return None

    # Re-verify signature on read; an attacker who swapped the file (without
    # changing ownership) still has to forge the HMAC.
    if not verify_floor_signature(entry.doc, known_keys):
        logger.warning("floor_cache_signature_invalid path=%s", target)
        return None

    return entry


def write_disk_cache(
    doc: FloorDocument,
    *,
    fetched_at_ms: int,
    path: Path | None = None,
) -> None:
    """Atomic write; temp file + rename (no advisory lock).

    The temp file is created at mode 0o600 so the ownership/mode check passes on the
    next read regardless of the inherited umask. Failure is swallowed at
    the supervisor level; the in-memory cache continues to work.
    """
    target = path or disk_cache_path()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    entry = _DiskCacheEntry(doc=doc, fetched_at_ms=fetched_at_ms)
    tmp = target.with_suffix(target.suffix + ".tmp")
    try:
        fd = os.open(
            str(tmp),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(entry.to_dict(), fh, separators=(",", ":"))
        except Exception:
            # fdopen closes fd on exit; ensure the tmp file is removed.
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            raise
        # Belt-and-braces: chmod after write in case of umask interference.
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    except OSError as exc:
        logger.warning("floor_cache_write_failed path=%s err=%s", target, exc)


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def _resolve_floor_url(api_base: str) -> str:
    if not api_base:
        api_base = "https://api.truealter.com"
    return api_base.rstrip("/") + MIN_VERSION_ENDPOINT


async def fetch_floor_doc(
    api_base: str,
    *,
    httpx_client: httpx.AsyncClient | None = None,
    known_keys: dict[str, str] | None = None,
) -> FloorDocument | None:
    """Fetch + verify the floor doc.

    Returns ``None`` on network failure, non-2xx response, malformed body,
    or signature-verification failure. Errors are logged at WARNING but
    never raised; the floor loop continues on the next tick.

    The outbound request carries the same canonical headers every other
    daemon HTTP call uses (see :func:`client_headers`) so the server can
    audit it consistently. The floor endpoint is exempt from the floor
    middleware.
    """
    url = _resolve_floor_url(api_base)
    headers: dict[str, str] = {
        "accept": "application/json",
        **client_headers(),
    }

    owns_client = httpx_client is None
    client = httpx_client or httpx.AsyncClient(timeout=FETCH_TIMEOUT_SECONDS)
    try:
        try:
            response = await client.get(url, headers=headers)
        except (httpx.HTTPError, OSError) as exc:
            logger.warning("floor_fetch_network_error url=%s err=%s", url, exc)
            return None
        if response.status_code != 200:
            logger.warning(
                "floor_fetch_non_200 url=%s status=%d",
                url,
                response.status_code,
            )
            return None
        try:
            body = response.json()
        except json.JSONDecodeError:
            logger.warning("floor_fetch_invalid_json url=%s", url)
            return None
        if not isinstance(body, dict):
            return None
        if "floors" not in body or "signature" not in body or "key_id" not in body:
            logger.warning("floor_fetch_malformed_doc url=%s", url)
            return None
        if not verify_floor_signature(body, known_keys):
            logger.warning("floor_fetch_signature_invalid url=%s", url)
            return None
        return FloorDocument.from_dict(body)
    finally:
        if owns_client:
            await client.aclose()


# ---------------------------------------------------------------------------
# Preflight; orchestrator
# ---------------------------------------------------------------------------


async def preflight(
    *,
    api_base: str,
    daemon_version: str = RUNTIME_VERSION,
    httpx_client: httpx.AsyncClient | None = None,
    known_keys: dict[str, str] | None = None,
    cache_path: Path | None = None,
    now_ms: int | None = None,
) -> FloorVerdict:
    """Run the connectivity ladder + return the FloorVerdict.

    Ladder:

    * Fetch fresh; on success → verify → compare. Write cache.
    * Fetch fails → fall back to disk cache.
    * Disk cache ≤24h → trust + compare.
    * Disk cache 24h;7d → permit-with-warn (when above floor); BLOCK on
      below floor (the only intentional offline lockout).
    * No cache + fetch fail → permit (server-side gate is authoritative).
    """
    if now_ms is None:
        now_ms = _now_ms()

    fetched = await fetch_floor_doc(
        api_base,
        httpx_client=httpx_client,
        known_keys=known_keys,
    )
    if fetched is not None:
        write_disk_cache(fetched, fetched_at_ms=now_ms, path=cache_path)
        verdict = _compare_to_floor(fetched, daemon_version)
        return verdict

    # Fall back to disk cache.
    entry = read_disk_cache(cache_path, known_keys=known_keys)
    if entry is None:
        return FloorVerdict(
            ok=True,
            diagnostic="no-cache-no-fetch-permit",
            warn="floor unreachable and no cached doc; proceeding",
        )

    age_seconds = max(0, (now_ms - entry.fetched_at_ms) // 1000)
    verdict = _compare_to_floor(entry.doc, daemon_version)

    if age_seconds > DISK_WARN_SECONDS:
        if not verdict.ok:
            return FloorVerdict(
                ok=False,
                envelope=verdict.envelope,
                diagnostic="below-floor-offline-stale-blocked",
                doc=verdict.doc,
            )
        return FloorVerdict(
            ok=True,
            diagnostic="stale-cache-permit-warn",
            warn="floor cache is >7d old and backend unreachable; permitting",
            doc=verdict.doc,
        )
    if age_seconds > DISK_FRESH_SECONDS:
        if not verdict.ok:
            return verdict
        return FloorVerdict(
            ok=True,
            diagnostic="warn-stale-permit",
            warn=(f"floor cache is {age_seconds // 3600}h old; refresh recommended"),
            doc=verdict.doc,
        )
    return verdict


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)
