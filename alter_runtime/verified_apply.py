"""Verified download -> verify -> apply for alter-runtime self-update.

This module implements the FAIL-CLOSED apply step that the observation-only
:mod:`alter_runtime.update_loop` deliberately omits. The verification
primitive is the ``alter`` CLI's ``runtime verify`` subcommand, reached by
shell-out; this module never reimplements signature or digest checking.

Control flow (every path that does *not* end in an applied install is a
refusal that leaves the running version untouched, exactly as the
observe-only default does):

* unsupported platform                  -> refuse
* manifest has no applyable artefact    -> refuse
* download fails                        -> refuse, temp cleaned
* ``alter`` CLI absent / unexecutable   -> refuse, temp cleaned
* ``alter runtime verify`` exit != 0    -> refuse, temp cleaned
* verify stdout not a verified verdict  -> refuse, temp cleaned
* manifest sha256 disagrees with verdict-> refuse, temp cleaned
* verified                              -> install hook invoked on the bytes

The verify contract (owned by the CLI, trusted here):

    alter runtime verify --platform <key> --version <v> --file <path>
        [--releases-base <url>]

    exit 0  => stdout JSON {"ok": true, "status": "verified", "sha256": <hex>, ...}
              ONLY for sigstore-verified bytes whose digest matches the
              signature-bound manifest entry.
    exit !0 => stdout JSON {"ok": false, "status": "unavailable"|"rejected", ...}
              never exit 0 on unverified bytes.

The download is written to a private (0o700) ``mkdtemp`` directory with an
unpredictable name, so there is no symlink-race against a guessable
``/tmp`` path, and the directory is removed in a ``finally`` regardless of
outcome.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404 - trusted, fixed-shape argv; never shell=True
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from alter_runtime.update_loop import ManifestSnapshot, PlatformKey

__all__ = [
    "ApplyOutcome",
    "download_and_apply",
    "resolve_alter_bin",
]

logger = logging.getLogger("alter_runtime.verified_apply")

VERIFY_TIMEOUT_SECONDS: float = 120.0
DOWNLOAD_TIMEOUT_SECONDS: float = 300.0


@dataclass(frozen=True)
class ApplyOutcome:
    """Structured result of one verified-apply attempt.

    ``kind`` is one of:

    * ``"applied"``               -- verify passed, install hook invoked
    * ``"platform-unsupported"``  -- running platform has no manifest key
    * ``"no-artefact"``           -- manifest has no url for this slot
    * ``"download-failed"``       -- the tarball could not be fetched
    * ``"cli-absent"``            -- the ``alter`` CLI is not executable
    * ``"verify-rejected"``       -- verify exit != 0 / not a verified verdict
    * ``"digest-mismatch"``       -- verdict sha256 != manifest sha256
    * ``"install-failed"``        -- the install hook raised

    Only ``"applied"`` mutates the system; every other kind is a refusal that
    keeps the current version running.
    """

    kind: str
    version: str = ""
    reason: str = ""
    verified_sha256: str = ""
    staged_path: str = ""

    @property
    def applied(self) -> bool:
        return self.kind == "applied"


def resolve_alter_bin() -> str:
    """Return the ``alter`` CLI invocation target.

    Resolution order mirrors :mod:`alter_runtime.subscribers.session_refresher`
    so the two surfaces never disagree on which binary they call:

    1. ``ALTER_CLI_BIN`` env override.
    2. ``shutil.which("alter")`` (PATH).
    3. ``~/.local/bin/alter`` (default user-install location).
    4. The literal ``"alter"`` as a last resort -- if it is truly absent the
       subprocess spawn raises ``FileNotFoundError``, which the apply path
       catches and turns into a ``cli-absent`` refusal.
    """
    env_override = os.environ.get("ALTER_CLI_BIN")
    if env_override:
        return env_override
    on_path = shutil.which("alter")
    if on_path:
        return on_path
    local_bin = Path.home() / ".local" / "bin" / "alter"
    if local_bin.exists():
        return str(local_bin)
    return "alter"


def _default_client_factory() -> Any:  # pragma: no cover - thin wrapper
    import httpx

    return httpx.AsyncClient(http2=False, follow_redirects=True)


async def _download(url: str, dest: Path, client_factory: Callable[[], Any]) -> None:
    """Fetch ``url`` into ``dest``. Raises on any transport / HTTP error."""
    client_cm = client_factory()
    async with client_cm as client:
        response = await client.get(url, timeout=DOWNLOAD_TIMEOUT_SECONDS)
    response.raise_for_status()
    dest.write_bytes(response.content)


def _stage_verified_artefact(verified_file: Path, version: str) -> Path:
    """Default install hook: stage the verified bytes under the data dir.

    Conservative by design. The live in-place binary swap + supervisor
    handoff is the one genuinely dangerous step, so it is *not* performed
    here automatically; see the SWAP POINT note below. What this hook does
    perform is the safe, reversible half: it copies the cryptographically
    verified tarball into a per-version staging directory under
    ``data_dir()/updates/<version>/`` at mode 0o700, from which a separate,
    explicitly-invoked swap step (a future release, gated on the static
    binary build) can atomically replace the running install.

    Returns the staged path.
    """
    from alter_runtime.config import data_dir

    staging_root = data_dir() / "updates" / version
    staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    staged = staging_root / verified_file.name
    shutil.copy2(verified_file, staged)
    try:
        staged.chmod(0o600)
    except OSError:
        pass

    # --- SWAP POINT (intentionally not auto-performed) -------------------
    # The verified artefact is now staged at ``staged``. Replacing the live
    # running binary in place and restarting the supervisor is the only
    # irreversible step in the update; it requires the static-binary build
    # and a supervisor-aware handoff and is deliberately left to an explicit
    # apply step rather than fired from the daemon poll loop. Until that
    # lands, the daemon stays on the current version (identical safety to the
    # observe-only default) while still proving the full download->verify
    # path end to end against staged, verified bytes.
    # --------------------------------------------------------------------
    logger.info(
        "verified-apply: staged verified %s at %s (live swap deferred to explicit apply step)",
        version,
        staged,
    )
    return staged


async def download_and_apply(
    *,
    snapshot: ManifestSnapshot,
    channel: str,
    platform_key: PlatformKey | None,
    target_version: str,
    releases_base: str | None = None,
    http_client_factory: Callable[[], Any] | None = None,
    alter_bin: str | None = None,
    install_hook: Callable[[Path, str], Path] | None = None,
) -> ApplyOutcome:
    """Download, verify, and (only if verified) apply ``target_version``.

    FAIL-CLOSED: every non-verified path returns a refusal ``ApplyOutcome``
    and leaves the current version running. Never installs or execs
    unverified bytes. The temp directory holding the download is always
    removed before returning.
    """
    if platform_key is None:
        logger.debug("verified-apply: refusing, running platform unsupported by manifest")
        return ApplyOutcome("platform-unsupported", version=target_version)

    artefact = snapshot.artefact_for(channel, platform_key)
    if artefact is None or not artefact.url:
        logger.debug(
            "verified-apply: refusing, no applyable artefact for channel=%s platform=%s",
            channel,
            platform_key,
        )
        return ApplyOutcome(
            "no-artefact",
            version=target_version,
            reason=f"no url for channel={channel} platform={platform_key}",
        )

    client_factory = http_client_factory or _default_client_factory
    install = install_hook or _stage_verified_artefact
    bin_target = alter_bin or resolve_alter_bin()

    # Private 0o700 temp dir with an unpredictable name; cleaned in finally.
    tmp_dir = Path(tempfile.mkdtemp(prefix="alter-runtime-update-"))
    try:
        # Derive the download filename from the URL path; fall back to a fixed
        # name. Never trust the remote name beyond its basename.
        remote_name = Path(artefact.url.split("?", 1)[0]).name or "artefact.tar.gz"
        local_file = tmp_dir / remote_name

        # 1. Download -----------------------------------------------------
        try:
            await _download(artefact.url, local_file, client_factory)
        except Exception as exc:  # noqa: BLE001 - any transport error is a refusal
            logger.warning(
                "verified-apply: download failed for %s (%s); staying on current version",
                artefact.url,
                exc,
            )
            return ApplyOutcome("download-failed", version=target_version, reason=str(exc))

        # 2. Verify via the alter CLI shell-out ---------------------------
        argv = [
            bin_target,
            "runtime",
            "verify",
            "--platform",
            platform_key,
            "--version",
            target_version,
            "--file",
            str(local_file),
        ]
        if releases_base:
            argv += ["--releases-base", releases_base]

        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=VERIFY_TIMEOUT_SECONDS,
            )
        except FileNotFoundError:
            logger.warning(
                "verified-apply: `alter` CLI not found (tried %r); cannot verify, refusing",
                bin_target,
            )
            return ApplyOutcome(
                "cli-absent",
                version=target_version,
                reason=f"alter CLI not executable: {bin_target}",
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("verified-apply: verify invocation failed (%s); refusing", exc)
            return ApplyOutcome("cli-absent", version=target_version, reason=str(exc))

        verdict = _parse_verdict(completed.stdout)
        if completed.returncode != 0 or verdict is None or not _is_verified(verdict):
            logger.warning(
                "verified-apply: verify did NOT pass (exit=%s status=%s); refusing, no install",
                completed.returncode,
                (verdict or {}).get("status") if verdict else "unparseable",
            )
            return ApplyOutcome(
                "verify-rejected",
                version=target_version,
                reason=(verdict or {}).get("reason", "verify returned non-zero")
                if verdict
                else f"verify exit={completed.returncode}, unparseable stdout",
            )

        verified_sha = str(verdict.get("sha256", ""))

        # 3. Defence in depth: the manifest digest, when present, must agree
        #    with the signature-bound digest the verifier reports. A mismatch
        #    means the manifest and the signed artefact disagree -> refuse.
        if artefact.sha256 and verified_sha and artefact.sha256.lower() != verified_sha.lower():
            logger.warning(
                "verified-apply: manifest sha256 != verified sha256; refusing (manifest tamper?)",
            )
            return ApplyOutcome(
                "digest-mismatch",
                version=target_version,
                reason="manifest sha256 disagrees with verified digest",
                verified_sha256=verified_sha,
            )

        # 4. Verified -> install (only reached on exit 0 + verified verdict).
        try:
            staged = install(local_file, target_version)
        except Exception as exc:  # noqa: BLE001 - install failure is a refusal
            logger.error("verified-apply: install hook failed (%s); refusing", exc)
            return ApplyOutcome(
                "install-failed",
                version=target_version,
                reason=str(exc),
                verified_sha256=verified_sha,
            )

        logger.info("verified-apply: applied verified version %s", target_version)
        return ApplyOutcome(
            "applied",
            version=target_version,
            verified_sha256=verified_sha,
            staged_path=str(staged),
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _parse_verdict(stdout: str) -> dict[str, Any] | None:
    """Parse the verify stdout as JSON. Returns ``None`` on any parse error."""
    if not stdout or not stdout.strip():
        return None
    try:
        parsed = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _is_verified(verdict: dict[str, Any]) -> bool:
    """True only for an explicit ``{"ok": true, "status": "verified"}`` verdict."""
    return verdict.get("ok") is True and verdict.get("status") == "verified"
