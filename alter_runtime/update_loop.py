"""UpdateLoop: daemon-side auto-update observer for ~alter artefacts.

This component polls ``releases.truealter.com/manifest.json`` on a configurable
cadence, compares the advertised version against the running daemon's
``__version__``, and emits structured log events describing what it sees.

**Scope of this module (observation only).**

This component does *not*:

* download any artefact;
* verify any signature;
* replace any binary;
* restart the supervisor;
* emit backend signals.

Its purpose is to validate that the release host is reachable, the manifest
is parseable, and the daemon can detect when a newer version exists. Operators
read the structured log output (``journalctl --user -u alter-runtime``) to
verify the behaviour end-to-end.

**Poll cadence.**

* Immediate fire-and-forget poll on daemon start (does not block startup).
* Every ``poll_interval_seconds`` afterwards (default 24h with ±5 % jitter
  for timing-fingerprint defence).
* Server-pushed ``alter:update-now`` events are handled in a future release.

**Channel selection.**

* Daemon reads the same ``channel.json`` config file the CLI reads, with
  the same env override (``ALTER_CLI_CHANNEL``). An install resolves only
  published releases.

**Network failure mode.**

* Single missed poll: debug log + retry next tick.
* Seven consecutive misses: warning log noting the release host is unreachable.
  No retry storm; the supervisor continues running the current version
  indefinitely.

**Empty manifest tolerance.**

An empty manifest (``platforms: {}``, ``channels: {stable: null, beta: null}``)
reads as "no release advertised for this channel/platform" and is treated as a
no-op, producing a single debug line per poll.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import random
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from alter_runtime import __version__ as RUNTIME_VERSION
from alter_runtime.daemon import Component

__all__ = [
    "UpdateLoop",
    "PlatformKey",
    "PlatformArtefact",
    "PollOutcome",
    "detect_platform_key",
    "resolve_channel",
    "compare_semver",
    "parse_manifest",
    "ManifestSnapshot",
    "DEFAULT_MANIFEST_URL",
    "DEFAULT_POLL_INTERVAL_SECONDS",
]


# Sentinel used to distinguish "caller did not pass platform_key" from "caller
# explicitly passed None to mean unsupported". The constructor checks identity
# (``is _AUTO_DETECT``) so this value never accidentally collides with a real
# argument.
_AUTO_DETECT: object = object()


logger = logging.getLogger("alter_runtime.update_loop")


DEFAULT_MANIFEST_URL: str = "https://releases.truealter.com/manifest.json"
DEFAULT_POLL_INTERVAL_SECONDS: int = 24 * 60 * 60  # 24h
INITIAL_POLL_DELAY_SECONDS: float = 5.0  # fire after daemon settles, not at zero
JITTER_FRACTION: float = 0.05  # ±5 % timing-fingerprint defence
NETWORK_TIMEOUT_SECONDS: float = 10.0
UNREACHABLE_WARN_THRESHOLD: int = 7  # consecutive misses before WARN


# ---------------------------------------------------------------------------
# Type surfaces
# ---------------------------------------------------------------------------


PlatformKey = str
"""Platform identifier shared with the release manifest schema.

Possible values (mirrors the release manifest schema):
``linux-x64-tarball``, ``linux-arm64-tarball``, ``darwin-x64-tarball``,
``darwin-arm64-tarball``, ``windows-x64``, ``windows-arm64``.
"""


@dataclass(frozen=True)
class PlatformArtefact:
    """Full per-platform release entry, retained for the verified-apply path.

    The observation-only poll loop needs only ``version``; the verified
    download->verify->apply path additionally needs the download ``url``, the
    signature-bound ``sha256`` digest, and the ``sigstore_bundle_url`` so the
    bytes can be fetched and handed to the ``alter runtime verify`` primitive.
    Any field may be ``None`` when the manifest omits it; the apply path treats
    a missing ``url`` as "no applyable artefact" and refuses (fail-closed).
    """

    version: str
    url: str | None = None
    sha256: str | None = None
    sigstore_bundle_url: str | None = None


@dataclass(frozen=True)
class ManifestSnapshot:
    """Parsed view of the release manifest at a point in time."""

    schema_version: int
    channels: dict[str, str | None]
    platform_versions: dict[PlatformKey, str]
    updated_at: str
    platform_artefacts: dict[PlatformKey, PlatformArtefact] = field(default_factory=dict)

    def version_for(self, channel: str, platform_key: PlatformKey) -> str | None:
        """Resolve the version advertised for a (channel, platform) tuple.

        Returns ``None`` when the manifest is empty for that slot, when the
        channel is unknown, or when the channel pointer references a missing
        platform entry. Empty-manifest tolerance is essential: the
        manifest ships empty until the first release lands.
        """
        channel_pointer = self.channels.get(channel)
        if channel_pointer is None:
            return None
        # Manifest convention (per the release manifest schema): the `channels` map carries
        # the release tag, and the platform entry's `latest_version` carries the
        # per-platform version, which must agree with the channel pointer when
        # a release has been ingested. We surface the platform value because it
        # is the authoritative one for that platform; the channel pointer is the
        # advertisement target.
        platform_version = self.platform_versions.get(platform_key)
        if platform_version is None:
            return None
        return platform_version

    def artefact_for(self, channel: str, platform_key: PlatformKey) -> PlatformArtefact | None:
        """Resolve the full applyable artefact for a (channel, platform) tuple.

        Gated identically to :meth:`version_for`: the channel pointer must be
        set (channel-isolation invariant), otherwise ``None`` is returned even
        when a platform entry exists. This guarantees a stable-channel daemon
        can never download a beta-only artefact.
        """
        if self.channels.get(channel) is None:
            return None
        return self.platform_artefacts.get(platform_key)


# ---------------------------------------------------------------------------
# Platform + channel detection (pure)
# ---------------------------------------------------------------------------


def detect_platform_key() -> PlatformKey | None:
    """Map the running process's OS + arch to the manifest's platform key.

    Returns ``None`` on an unsupported platform. The daemon still runs; it
    just never matches a manifest entry, which is the correct degraded
    behaviour (an unsupported platform has no auto-update story by design).
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Normalise arch labels to the manifest's vocabulary.
    if machine in ("x86_64", "amd64"):
        arch = "x64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        return None

    if system == "linux":
        return f"linux-{arch}-tarball"
    if system == "darwin":
        return f"darwin-{arch}-tarball"
    if system == "windows":
        return f"windows-{arch}"
    return None


def resolve_channel(env: dict[str, str] | None = None) -> str:
    """Resolve the active channel using the same priority as the CLI.

    ``ALTER_CLI_CHANNEL`` env var > ``${XDG_CONFIG_HOME}/alter/channel.json``
    > default ``stable``. The default is ``stable`` (mapped to the public
    npm dist-tag ``latest`` by the CLI; the release manifest uses
    ``stable`` / ``beta`` channel names per the release manifest schema).
    """
    env_map = env if env is not None else os.environ
    from_env = env_map.get("ALTER_CLI_CHANNEL", "").strip()
    if from_env:
        return from_env

    xdg_config = env_map.get("XDG_CONFIG_HOME") or str(
        Path(env_map.get("HOME", str(Path.home()))) / ".config"
    )
    channel_file = Path(xdg_config) / "alter" / "channel.json"
    try:
        raw = channel_file.read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError, OSError):
        return "stable"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return "stable"
    if isinstance(parsed, dict):
        value = parsed.get("channel")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "stable"


# ---------------------------------------------------------------------------
# Semver comparison (pure)
# ---------------------------------------------------------------------------


_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.\-]+))?")


def compare_semver(a: str, b: str) -> int:
    """Compare two semver strings.

    Returns >0 when ``a > b``, <0 when ``a < b``, 0 when equal. Pre-release
    tags (``-rc.1``, ``-beta.2``) are ordered lower than the same version
    without a pre-release tag, matching the CLI's compareSemver semantics
    so the two surfaces never disagree on ordering.
    """
    a_match = _SEMVER_RE.match(a)
    b_match = _SEMVER_RE.match(b)
    if a_match is None and b_match is None:
        return 0
    if a_match is None:
        return -1
    if b_match is None:
        return 1
    a_major, a_minor, a_patch, a_pre = a_match.groups()
    b_major, b_minor, b_patch, b_pre = b_match.groups()
    a_ints = (int(a_major), int(a_minor), int(a_patch))
    b_ints = (int(b_major), int(b_minor), int(b_patch))
    if a_ints != b_ints:
        return -1 if a_ints < b_ints else 1
    # Equal numeric portion: pre-release tags decide.
    if a_pre is None and b_pre is None:
        return 0
    if a_pre is None:
        return 1  # `a` is the release, `b` is a pre-release of it
    if b_pre is None:
        return -1
    if a_pre == b_pre:
        return 0
    return -1 if a_pre < b_pre else 1


# ---------------------------------------------------------------------------
# Manifest parsing (pure)
# ---------------------------------------------------------------------------


def parse_manifest(body: Any) -> ManifestSnapshot | None:
    """Parse a manifest JSON body into a snapshot.

    Returns ``None`` if the shape doesn't match the schema. Designed to be
    paranoid, as the manifest is a public read surface, so any malformed
    response must be ignored rather than crashing the daemon.
    """
    if not isinstance(body, dict):
        return None
    schema_version = body.get("schema_version")
    if not isinstance(schema_version, int) or schema_version != 1:
        return None

    channels_raw = body.get("channels", {})
    channels: dict[str, str | None] = {}
    if isinstance(channels_raw, dict):
        for key, value in channels_raw.items():
            if not isinstance(key, str):
                continue
            if value is None or isinstance(value, str):
                channels[key] = value

    platforms_raw = body.get("platforms", {})
    platform_versions: dict[PlatformKey, str] = {}
    platform_artefacts: dict[PlatformKey, PlatformArtefact] = {}
    if isinstance(platforms_raw, dict):
        for key, value in platforms_raw.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                continue
            version = value.get("latest_version")
            if not (isinstance(version, str) and version.strip()):
                continue
            version = version.strip()
            platform_versions[key] = version

            # Retain the full applyable entry. Each field is optional and only
            # kept when it is a non-empty string; the apply path fails closed on
            # a missing url and defers all signature/digest checks to the
            # `alter runtime verify` primitive regardless of what is stored here.
            def _opt_str(field_value: Any) -> str | None:
                if isinstance(field_value, str) and field_value.strip():
                    return field_value.strip()
                return None

            platform_artefacts[key] = PlatformArtefact(
                version=version,
                url=_opt_str(value.get("url")),
                sha256=_opt_str(value.get("sha256")),
                sigstore_bundle_url=_opt_str(value.get("sigstore_bundle")),
            )

    updated_at_raw = body.get("updated_at")
    updated_at = updated_at_raw if isinstance(updated_at_raw, str) else ""

    return ManifestSnapshot(
        schema_version=schema_version,
        channels=channels,
        platform_versions=platform_versions,
        updated_at=updated_at,
        platform_artefacts=platform_artefacts,
    )


# ---------------------------------------------------------------------------
# UpdateLoop Component
# ---------------------------------------------------------------------------


class UpdateLoop(Component):
    """Polls the release host on cadence and logs what it sees.

    No download, no verify, no apply. Operators verify behaviour by reading
    the daemon's structured log output.

    The component is intentionally narrow:

    * One responsibility: poll, parse, compare, log.
    * No side effects on the filesystem, no signals out, no apply.
    * Defensive against every malformed-manifest shape the public endpoint
      could plausibly return.
    """

    name: str = "update-loop"

    def __init__(
        self,
        *,
        manifest_url: str = DEFAULT_MANIFEST_URL,
        poll_interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS,
        runtime_version: str = RUNTIME_VERSION,
        platform_key: Any = _AUTO_DETECT,
        channel: str | None = None,
        http_client_factory: Any = None,
        rng: random.Random | None = None,
        apply_enabled: bool = False,
        releases_base: str | None = None,
        apply_fn: Any = None,
    ) -> None:
        self._manifest_url = manifest_url
        self._poll_interval_seconds = poll_interval_seconds
        self._runtime_version = runtime_version
        # Sentinel handling: _AUTO_DETECT means use the live platform; an
        # explicit None means "the running platform is unsupported by the
        # manifest, and this loop should never resolve an advertised version
        # for it". Used by tests to pin the unsupported-platform path.
        if platform_key is _AUTO_DETECT:
            self._platform_key = detect_platform_key()
        else:
            self._platform_key = platform_key
        self._channel = channel if channel is not None else resolve_channel()
        self._http_client_factory = http_client_factory or _default_client_factory
        self._rng = rng or random.Random()
        self._consecutive_failures = 0
        self._stopping = asyncio.Event()
        # Verified-apply is OPT-IN. Default False keeps this loop strictly
        # observation-only (no download, no verify, no apply) -- identical to
        # the pre-apply behaviour. When enabled, a `newer-available` outcome
        # additionally drives the fail-closed verified download->verify->apply
        # path, which never installs unverified bytes.
        self._apply_enabled = apply_enabled
        self._releases_base = releases_base
        self._apply_fn = apply_fn

    async def stop(self) -> None:
        self._stopping.set()

    async def run(self) -> None:  # pragma: no cover - exercised by integration smoke
        """Long-running poll loop.

        Fires an initial poll after a small settle delay, then on the
        configured cadence with jitter. Cancellation-safe: ``stop()``
        unblocks the next sleep and the loop exits cleanly.
        """
        # Initial fire-and-forget settle delay so daemon startup is not
        # blocked by the first poll's network round-trip.
        try:
            await asyncio.wait_for(self._stopping.wait(), timeout=INITIAL_POLL_DELAY_SECONDS)
            return  # stopping requested during settle
        except (TimeoutError, asyncio.TimeoutError):
            pass

        while not self._stopping.is_set():
            await self.poll_once()

            sleep_for = self._poll_interval_seconds * (
                1.0 + self._rng.uniform(-JITTER_FRACTION, JITTER_FRACTION)
            )
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=sleep_for)
                return  # stopping requested during sleep
            except (TimeoutError, asyncio.TimeoutError):
                continue

    async def poll_once(self) -> "PollOutcome":
        """Run one poll cycle. Idempotent; never raises out."""
        if self._platform_key is None:
            logger.debug("update-loop: skipping poll, running platform is unsupported by manifest")
            return PollOutcome("platform-unsupported", current=self._runtime_version)

        try:
            manifest = await self._fetch_manifest()
        except Exception as exc:
            self._consecutive_failures += 1
            if self._consecutive_failures >= UNREACHABLE_WARN_THRESHOLD:
                logger.warning(
                    "update-loop: release host unreachable for %d consecutive polls, staying on %s",
                    self._consecutive_failures,
                    self._runtime_version,
                )
            else:
                logger.debug(
                    "update-loop: poll failed (%s), staying on %s, retry next tick",
                    exc,
                    self._runtime_version,
                )
            return PollOutcome(
                "fetch-failed",
                current=self._runtime_version,
                error=str(exc),
            )

        # Reset failure counter on a successful fetch.
        self._consecutive_failures = 0

        if manifest is None:
            logger.debug(
                "update-loop: manifest at %s is not parseable, ignoring",
                self._manifest_url,
            )
            return PollOutcome("manifest-malformed", current=self._runtime_version)

        advertised = manifest.version_for(self._channel, self._platform_key)
        if advertised is None:
            logger.debug(
                "update-loop: manifest has no release for channel=%s platform=%s;"
                " the first release may not be published yet",
                self._channel,
                self._platform_key,
            )
            return PollOutcome(
                "no-release-advertised",
                current=self._runtime_version,
                channel=self._channel,
                platform_key=self._platform_key,
            )

        cmp = compare_semver(advertised, self._runtime_version)
        if cmp > 0:
            if self._apply_enabled:
                logger.info(
                    "update-loop: newer release available: current=%s advertised=%s"
                    " channel=%s platform=%s (verified-apply enabled)",
                    self._runtime_version,
                    advertised,
                    self._channel,
                    self._platform_key,
                )
                await self._apply_newer(manifest, advertised)
            else:
                logger.info(
                    "update-loop: newer release available: current=%s advertised=%s"
                    " channel=%s platform=%s (observation only; no download or apply)",
                    self._runtime_version,
                    advertised,
                    self._channel,
                    self._platform_key,
                )
            return PollOutcome(
                "newer-available",
                current=self._runtime_version,
                advertised=advertised,
                channel=self._channel,
                platform_key=self._platform_key,
            )
        if cmp < 0:
            logger.warning(
                "update-loop: running ahead of manifest: current=%s advertised=%s channel=%s "
                "(pre-release or local-build path; safe to ignore unless unexpected)",
                self._runtime_version,
                advertised,
                self._channel,
            )
            return PollOutcome(
                "running-ahead",
                current=self._runtime_version,
                advertised=advertised,
                channel=self._channel,
                platform_key=self._platform_key,
            )

        logger.debug(
            "update-loop: already current, current=%s channel=%s platform=%s",
            self._runtime_version,
            self._channel,
            self._platform_key,
        )
        return PollOutcome(
            "already-current",
            current=self._runtime_version,
            advertised=advertised,
            channel=self._channel,
            platform_key=self._platform_key,
        )

    async def _apply_newer(self, manifest: ManifestSnapshot, advertised: str) -> None:
        """Drive the fail-closed verified apply for a newer advertised version.

        Never raises out: any apply failure is logged and the daemon stays on
        the current version (identical safety to the observe-only default).
        The verified-apply path itself refuses on every non-verified branch.
        """
        apply_fn = self._apply_fn
        if apply_fn is None:
            from alter_runtime.verified_apply import download_and_apply

            apply_fn = download_and_apply
        try:
            outcome = await apply_fn(
                snapshot=manifest,
                channel=self._channel,
                platform_key=self._platform_key,
                target_version=advertised,
                releases_base=self._releases_base,
            )
            logger.info("update-loop: verified-apply outcome=%s", getattr(outcome, "kind", outcome))
        except Exception as exc:  # noqa: BLE001 - apply must never crash the poll loop
            logger.error("update-loop: verified-apply raised (%s); staying on current version", exc)

    async def _fetch_manifest(self) -> ManifestSnapshot | None:
        client_cm = self._http_client_factory()  # type: ignore[operator]
        async with client_cm as client:
            response = await client.get(
                self._manifest_url,
                timeout=NETWORK_TIMEOUT_SECONDS,
            )
        response.raise_for_status()
        body = response.json()
        return parse_manifest(body)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PollOutcome:
    """Structured view of a single poll cycle. Returned for unit-testing."""

    kind: str
    current: str = ""
    advertised: str = ""
    channel: str = ""
    platform_key: str = ""
    error: str = ""


def _default_client_factory() -> "httpx.AsyncClient":  # pragma: no cover - thin wrapper
    return httpx.AsyncClient(http2=False, follow_redirects=True)
