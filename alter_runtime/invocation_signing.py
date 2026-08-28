"""Daemon-side MCP per-invocation ES256 signer.

The server requires an ``Mcp-Invocation-Signature`` header on every
authenticated ``tools/call``.  The local MCP bridge already signs;
this module gives the runtime daemon the same capability so the
MCP fallback subscriber and the attunement refresher stop failing
JSON-RPC error -32002 ("signature required").

The signing algorithm, wire format, and claim set are byte-identical to
the server-side contract.  The only
client-side implementation choice is how to sign: we use the
``cryptography`` package (already a base dependency for Ed25519
frame-signature verification) rather than PyJWT, which is not a
dependency and MUST NOT be added.

Compact JWS format
------------------

``<base64url(header_json)>.<base64url(payload_json)>.<base64url(sig)>``

Protected header::

    {"alg": "ES256", "kid": "<kid>"}

Payload claims (all required)::

    tool        : str   (exact MCP tool name)
    args_sha256 : str   (lowercase hex SHA-256 of canonical args JSON)
    nonce       : str   (base64url(>=16 random bytes), min 22 chars, no pad)
    iat         : int   (epoch seconds (int, not float))
    iss         : str   (caller ~handle (from session.handle))

Canonical args JSON
-------------------

``json.dumps(args or {}, sort_keys=True, separators=(",",":"),
ensure_ascii=False).encode("utf-8")``

Empty args map to ``{}`` not ``null``.  Non-ASCII passes through as
UTF-8, not \\uXXXX.

DER -> P1363 conversion
-----------------------

``cryptography``'s ECDSA sign returns DER-encoded r||s.  ES256 JWS
needs raw P1363 (two 32-byte big-endian ints).  The conversion uses
``decode_dss_signature`` from
``cryptography.hazmat.primitives.asymmetric.utils``.

Graceful degrade
----------------

When ``session.signing_kid`` is absent or no readable private key is
found, the signer emits a WARNING and returns ``None``.  Callers treat
``None`` as "omit the header" and let the existing behaviour stand
(the server will reject with -32002, but that is the pre-existing
baseline, but the daemon never crashes).

Key resolution order (mirrors the CLI signer + store fallback)
--------------------------------------------------------------

1. ``$ALTER_SIGNING_KEY_FILE`` if set
2. ``~/.config/alter/signing-keys/<kid>.pem``   (canonical per-kid)
3. ``~/.config/alter/signing-key-<suffix>.pem`` (session-suffix sibling)
4. ``~/.config/alter/signing-key.pem``          (legacy default)
5. OS native credential store: ``secret-tool lookup service alter-cli
   account signing-key`` (Linux/libsecret) or
   ``security find-generic-password -s alter-cli -a signing-key -w``
   (macOS). The value is either a bare PKCS8 PEM (legacy) or
   a versioned JSON envelope
   ``{"v":1,"kid":...,"private_key_pem":...,"public_key_fingerprint":...}``
   (current); both shapes are normalised to a usable PKCS8 PEM by
   :func:`_normalise_signing_key_store_value`.
6. Encrypted-file fallback: ``~/.config/alter/enc/signing-key.bin``
   decrypted with ``~/.config/alter/enc-keyfile`` (same AES-256-GCM
   ``[12B IV][16B auth tag][ciphertext]`` layout as the session blob).

Split-brain guard
-----------------

When ``session.signing_key_fingerprint`` is present (current login
format), the resolved private key's public-key fingerprint (SHA-256 of the
DER-encoded SPKI, base64url) is compared against it.  A mismatch means
the resolved key is NOT the one the session registered. Logging a
WARNING and returning ``None`` is safer than emitting a JWS the backend
will reject as ``handle_mismatch`` or ``unknown_kid``.

For PEM-file candidates (1-4) where the legacy split-brain warning
still applies: when the legacy ``signing-key.pem`` wins and a per-kid
file also exists, the daemon logs a warning (key may be from a previous
login) but proceeds. The server will reject with an appropriate error
if the key truly is wrong.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from alter_runtime.config import Session

# Lazy import guard: config.read_os_secret_store and config.read_enc_store are
# imported inside the key-resolution function so the module remains importable
# even if alter_runtime.config is not yet initialised (test isolation).  The
# functions themselves guard against missing DBUS / secret-tool / enc files.

__all__ = [
    "build_invocation_signature",
    "build_invocation_signature_with_key",
    "build_signed_mcp_headers",
    "_normalise_signing_key_store_value",
    "_public_key_fingerprint",
]

logger = logging.getLogger(__name__)

#: Minimum nonce length required by the server (22 base64url chars ≈ 16 random bytes).
_MIN_NONCE_LEN = 22


# ---------------------------------------------------------------------------
# base64url helpers (no padding)
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    """Return base64url-encoded string with NO padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Canonical args hash
# ---------------------------------------------------------------------------


def _canonical_args_sha256(args: dict[str, Any] | None) -> str:
    """Return the hex SHA-256 of the canonical JSON encoding of ``args``.

    Canonical form (byte-identical to the backend contract):
    ``json.dumps(args or {}, sort_keys=True, separators=(",",":"),
    ensure_ascii=False).encode("utf-8")``

    Empty / None args hash to ``"{}"``, not ``"null"``.
    """
    canonical_bytes = json.dumps(
        args or {},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Key resolution
# ---------------------------------------------------------------------------


def _config_dir() -> Path:
    """Return $XDG_CONFIG_HOME/alter (default ~/.config/alter)."""
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(xdg) / "alter"


def _normalise_signing_key_store_value(raw: str, expected_kid: str | None = None) -> str | None:
    """Normalise the OS secure store's ``signing-key`` account value to a PKCS8 PEM.

    A later ``alter login`` revision changed what is written under the
    ``signing-key`` account from a bare PKCS8 PEM string to a versioned JSON
    envelope::

        {"v": 1, "kid": "...", "private_key_pem": "...", "public_key_fingerprint": "..."}

    Both shapes are accepted:

    - **bare PEM** (legacy): returned unchanged.
    - **v1 envelope**: ``private_key_pem`` is extracted. When ``expected_kid``
      is supplied and the envelope carries a ``kid`` field, a mismatch returns
      ``None``. A stale envelope from a previous login must not shadow the
      current session's kid.

    Returns ``None`` for malformed JSON, unknown versions, or a kid mismatch.
    Mirrors the CLI's store-value normaliser. Never raises.
    """
    trimmed = raw.strip()
    if not trimmed.startswith("{"):
        # Bare PEM, the legacy shape.
        return raw
    try:
        parsed = json.loads(trimmed)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    if parsed.get("v") != 1:
        return None
    pem = parsed.get("private_key_pem")
    if not isinstance(pem, str):
        return None
    # Kid mismatch: a stale envelope from a previous login must not shadow
    # the current session's kid (same posture as the bridge's guard).
    if expected_kid and isinstance(parsed.get("kid"), str) and parsed["kid"] != expected_kid:
        return None
    return pem


def _public_key_fingerprint(pem: str) -> str | None:
    """Return the SHA-256 (base64url) of the DER-encoded SPKI of a private-key PEM.

    Mirrors the CLI's public-key fingerprint:
    SHA-256 hash of the DER-encoded SubjectPublicKeyInfo derived from the
    private key, encoded as base64url without padding.

    Returns ``None`` when the PEM does not parse as a private key. Never raises.
    """
    try:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
            load_pem_private_key,
        )

        priv = load_pem_private_key(pem.encode(), password=None)
        spki_der = priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        digest = hashlib.sha256(spki_der).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    except Exception:
        return None


def _fingerprint_to_bytes(fp: str | None) -> bytes | None:
    """Decode a key fingerprint to its raw 32 SHA-256 bytes, encoding-agnostic.

    The CLI writes ``session.signing_key_fingerprint`` as lowercase hex,
    while :func:`_public_key_fingerprint` returns base64url (no padding). Both are
    the SHA-256 of the same SPKI DER, so comparing the raw bytes is encoding-neutral
    and survives either side changing encoding. Returns ``None`` when ``fp`` does
    not decode to a 32-byte digest.
    """
    if not fp:
        return None
    s = fp.strip()
    if len(s) == 64:
        try:
            return bytes.fromhex(s)
        except ValueError:
            pass
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        if len(raw) == 32:
            return raw
    except Exception:
        pass
    return None


def _fingerprints_match(resolved_fp: str, session_fp: str) -> bool:
    """True when two key fingerprints denote the same SHA-256 digest.

    Encoding-agnostic: the CLI session field is hex, our computed fingerprint is
    base64url. Decodes both to raw bytes and compares; falls back to a literal
    string compare when either side cannot be decoded, so a genuinely different
    value still mismatches.
    """
    a = _fingerprint_to_bytes(resolved_fp)
    b = _fingerprint_to_bytes(session_fp)
    if a is not None and b is not None:
        return a == b
    return resolved_fp == session_fp


def _resolve_signing_key_pem(session: "Session") -> tuple[str | None, str | None]:
    """Return (pem_text, kid) for the session's signing key, or (None, None).

    Resolution order (mirrors the CLI signer plus store fallback):

    1. ``$ALTER_SIGNING_KEY_FILE``
    2. ``~/.config/alter/signing-keys/<kid>.pem``
    3. ``~/.config/alter/signing-key-<suffix>.pem``  (session-file sibling)
    4. ``~/.config/alter/signing-key.pem``           (legacy)
    5. OS native credential store (``secret-tool`` / macOS Keychain); value
       normalised from bare PEM or v1 JSON envelope via
       :func:`_normalise_signing_key_store_value`.
    6. Encrypted-file fallback ``~/.config/alter/enc/signing-key.bin``
       (AES-256-GCM, same layout as the session blob).

    After each candidate yields a parseable PEM, a split-brain guard is applied:
    when ``session.signing_key_fingerprint`` is present, the resolved key's SPKI
    fingerprint must match. On mismatch the candidate is skipped with a WARNING
    rather than used (a server rejection is avoidable here).

    Returns ``(None, None)`` when no readable, fingerprint-matching PEM is found.
    Never raises.
    """
    kid = getattr(session, "signing_kid", None)
    if not kid:
        return None, None

    session_fingerprint: str | None = getattr(session, "signing_key_fingerprint", None)

    cfg = _config_dir()

    # Build the PEM-file candidate list (candidates 1-4).
    file_candidates: list[Path] = []

    # 1. Explicit env override.
    env_path = os.environ.get("ALTER_SIGNING_KEY_FILE")
    if env_path:
        file_candidates.append(Path(env_path).expanduser())

    # 2. Per-kid canonical path.
    file_candidates.append(cfg / "signing-keys" / f"{kid}.pem")

    # 3. Session-file sibling (session-<suffix>.json -> signing-key-<suffix>.pem).
    import re

    session_file = os.environ.get("ALTER_SESSION_FILE") or str(cfg / "session.json")
    base = Path(session_file).name
    m = re.match(r"^session-(.+)\.json$", base)
    if m:
        file_candidates.append(Path(session_file).parent / f"signing-key-{m.group(1)}.pem")

    # 4. Legacy fallback.
    legacy_path = cfg / "signing-key.pem"
    file_candidates.append(legacy_path)

    for candidate in file_candidates:
        try:
            pem = candidate.read_text(encoding="utf-8")
        except OSError:
            continue

        # Verify it parses as an EC private key before using it.
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            load_pem_private_key(pem.encode(), password=None)
        except Exception:
            logger.debug(
                "invocation_signing: candidate key at %s failed to parse, skipping",
                candidate,
            )
            continue

        # Fingerprint split-brain guard (current login format).
        if session_fingerprint:
            resolved_fp = _public_key_fingerprint(pem)
            if resolved_fp is not None and not _fingerprints_match(
                resolved_fp, session_fingerprint
            ):
                logger.warning(
                    "invocation_signing: key at %s has fingerprint %s but session "
                    "expects %s for kid=%s; skipping to avoid signing with the "
                    "wrong key. Re-run `alter login` to re-pair the signing key.",
                    candidate,
                    resolved_fp,
                    session_fingerprint,
                    kid,
                )
                continue

        # Split-brain guard: if the winning candidate is the legacy file AND
        # a per-kid file also exists, warn. The legacy file may be from a
        # previous session whose key is no longer registered under this kid.
        if candidate == legacy_path:
            per_kid_path = cfg / "signing-keys" / f"{kid}.pem"
            if per_kid_path.exists():
                logger.warning(
                    "invocation_signing: using legacy signing-key.pem but per-kid "
                    "file %s also exists for kid=%s; the legacy file may be stale. "
                    "Re-run `alter login` to re-pair the signing key.",
                    per_kid_path,
                    kid,
                )

        return pem, kid

    # ---------------------------------------------------------------------------
    # Candidates 5 & 6: credential-store backends (store-first, enc-file fallback)
    # ---------------------------------------------------------------------------

    # Import the generalised readers from config. Done here (not at module level)
    # to keep the import graph clean and tests isolated.
    from alter_runtime.config import (
        SECURE_STORE_SIGNING_KEY_ACCOUNT,
        read_enc_store,
        read_os_secret_store,
    )

    # 5. OS native credential store.
    raw_store = read_os_secret_store(SECURE_STORE_SIGNING_KEY_ACCOUNT)
    if raw_store is not None:
        pem = _normalise_signing_key_store_value(raw_store, expected_kid=kid)
        if pem is not None:
            try:
                from cryptography.hazmat.primitives.serialization import load_pem_private_key

                load_pem_private_key(pem.encode(), password=None)
            except Exception:
                logger.debug(
                    "invocation_signing: OS secure store signing-key value failed to "
                    "parse as a private key, skipping"
                )
                pem = None
        if pem is not None:
            if session_fingerprint:
                resolved_fp = _public_key_fingerprint(pem)
                if resolved_fp is not None and not _fingerprints_match(
                    resolved_fp, session_fingerprint
                ):
                    logger.warning(
                        "invocation_signing: OS secure store signing key has fingerprint %s "
                        "but session expects %s for kid=%s; skipping. "
                        "Re-run `alter login` to re-pair the signing key.",
                        resolved_fp,
                        session_fingerprint,
                        kid,
                    )
                    pem = None
        if pem is not None:
            return pem, kid

    # 6. Encrypted-file fallback.
    raw_enc = read_enc_store("signing-key.bin")
    if raw_enc is not None:
        pem = _normalise_signing_key_store_value(raw_enc, expected_kid=kid)
        if pem is not None:
            try:
                from cryptography.hazmat.primitives.serialization import load_pem_private_key

                load_pem_private_key(pem.encode(), password=None)
            except Exception:
                logger.debug(
                    "invocation_signing: enc-file signing-key.bin value failed to "
                    "parse as a private key, skipping"
                )
                pem = None
        if pem is not None:
            if session_fingerprint:
                resolved_fp = _public_key_fingerprint(pem)
                if resolved_fp is not None and not _fingerprints_match(
                    resolved_fp, session_fingerprint
                ):
                    logger.warning(
                        "invocation_signing: enc-file signing key has fingerprint %s "
                        "but session expects %s for kid=%s; skipping. "
                        "Re-run `alter login` to re-pair the signing key.",
                        resolved_fp,
                        session_fingerprint,
                        kid,
                    )
                    pem = None
        if pem is not None:
            return pem, kid

    return None, None


# ---------------------------------------------------------------------------
# Compact JWS builder
# ---------------------------------------------------------------------------


def build_invocation_signature_with_key(
    pem: str,
    kid: str,
    handle: str,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
) -> str | None:
    """Build a compact ES256 JWS from an EXPLICIT key, bypassing the session.

    The session-driven :func:`build_invocation_signature` resolves whichever
    key ``alter login`` last minted, which is the right behaviour for member
    tool calls and the wrong behaviour for a purpose-scoped device key that
    must not move when someone logs in. Callers holding their own key pass
    it here.

    Returns ``None`` on any crypto failure, matching the sibling function's
    contract: ``None`` means "omit the header", never "send it unsigned".
    """
    try:
        return _sign_jws(
            pem=pem,
            kid=kid,
            tool_name=tool_name,
            arguments=arguments,
            handle=handle,
        )
    except Exception as exc:  # noqa: BLE001 - mirrors the sibling's contract
        logger.warning(
            "invocation_signing: explicit-key signing failed for tool=%s kid=%s: %s",
            tool_name,
            kid,
            exc,
        )
        return None


def build_invocation_signature(
    session: "Session",
    tool_name: str,
    arguments: dict[str, Any] | None = None,
) -> str | None:
    """Build a compact ES256 JWS for one MCP tool invocation.

    Returns the compact JWS string (``header.payload.signature``) or
    ``None`` when signing is not possible (missing kid, unreadable key).
    ``None`` means "omit the header"; the daemon degrades gracefully
    rather than crashing.

    Parameters
    ----------
    session:
        The authenticated CLI session.  ``session.signing_kid``
        and ``session.handle`` are required; missing either returns ``None``.
    tool_name:
        The MCP tool name exactly as it appears in the ``params.name``
        field of the ``tools/call`` body.
    arguments:
        The ``params.arguments`` dict.  ``None`` is treated as ``{}``.
    """
    # Use getattr for duck-typed compatibility with test stubs that predate
    # the signing_kid field (those stubs do not have the attribute).
    signing_kid = getattr(session, "signing_kid", None)
    if not signing_kid:
        logger.warning(
            "invocation_signing: session.signing_kid is absent; "
            "cannot sign MCP invocation for tool=%s. "
            "Re-run `alter login` to provision a signing key.",
            tool_name,
        )
        return None

    pem, kid = _resolve_signing_key_pem(session)
    if pem is None or kid is None:
        logger.warning(
            "invocation_signing: no readable signing key found for kid=%s; "
            "cannot sign MCP invocation for tool=%s. "
            "Check ~/.config/alter/signing-keys/%s.pem exists and is readable.",
            signing_kid,
            tool_name,
            signing_kid,
        )
        return None

    try:
        return _sign_jws(
            pem=pem,
            kid=kid,
            tool_name=tool_name,
            arguments=arguments,
            handle=getattr(session, "handle", ""),
        )
    except Exception as exc:
        logger.warning(
            "invocation_signing: signing failed for tool=%s kid=%s: %s",
            tool_name,
            kid,
            exc,
        )
        return None


def _sign_jws(
    pem: str,
    kid: str,
    tool_name: str,
    arguments: dict[str, Any] | None,
    handle: str,
) -> str:
    """Build the compact JWS.  Raises on crypto failure (caller wraps)."""
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    private_key = load_pem_private_key(pem.encode(), password=None)

    # Protected header (no ``typ``, exactly ``alg`` + ``kid``).
    header = {"alg": "ES256", "kid": kid}
    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))

    # Nonce: base64url(>=16 random bytes), min 22 chars, no padding.
    nonce_bytes = secrets.token_bytes(16)
    nonce = _b64url(nonce_bytes)
    # Pad to 22+ if somehow shorter (token_bytes(16) -> 22 chars after b64url, always fine).
    assert len(nonce) >= _MIN_NONCE_LEN, f"nonce too short: {len(nonce)} chars"

    payload = {
        "tool": tool_name,
        "args_sha256": _canonical_args_sha256(arguments),
        "nonce": nonce,
        "iat": int(time.time()),  # int, not float
        "iss": handle,
    }
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    # Sign: cryptography returns DER; ES256 JWS needs raw P1363 r||s.
    der_sig = private_key.sign(signing_input, ECDSA(SHA256()))

    # Convert DER -> P1363: extract r, s and concatenate as 32-byte big-endian.
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    sig_b64 = _b64url(raw_sig)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ---------------------------------------------------------------------------
# Shared header builder (the one chokepoint callers use)
# ---------------------------------------------------------------------------


def build_signed_mcp_headers(
    session: "Session",
    tool_name: str,
    arguments: dict[str, Any] | None,
    base_headers: dict[str, str],
) -> dict[str, str]:
    """Return a copy of ``base_headers`` with the invocation signature injected.

    This is the ONE chokepoint both MCP-calling subscribers must use so
    the ``Mcp-Invocation-Signature`` is added in exactly one place.

    When signing is not possible (missing kid, unreadable key), the
    original headers are returned unchanged and a WARNING is logged.
    The daemon degrades gracefully: the server will respond with -32002,
    but that is the pre-existing baseline, not a new crash.

    Parameters
    ----------
    session:
        The authenticated CLI session.
    tool_name:
        The MCP tool name, matching ``params.name`` on the wire.
    arguments:
        The ``params.arguments`` dict.  ``None`` is treated as ``{}``.
    base_headers:
        The headers dict to extend (e.g. Authorization + Content-Type).
        A shallow copy is returned; the original is not mutated.
    """
    jws = build_invocation_signature(session, tool_name, arguments)
    headers = dict(base_headers)
    if jws is not None:
        headers["Mcp-Invocation-Signature"] = jws
    return headers
