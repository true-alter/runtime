"""LoomVerdictSubscriber - thin-client read-only mirror of the
cross-machine loom-verdict feed.

Shape
-----

Mirrors :class:`alter_runtime.subscribers.agent_frames.AgentFrameSubscriber`:
a long-lived :class:`~alter_runtime.daemon.Component` that subscribes to
the in-process :class:`EventBus` ``identity.event`` topic (the same
stream :class:`~alter_runtime.subscribers.do_sse.DoSseSubscriber` fans
out from the per-handle DO SSE connection), filters for the
``loom_verdict`` kind, dedups, and projects each into a local read-only
verdict-mirror file.

Mirror rows are keyed on the pair (``basis_hash``, ``concern_ref``), not
on ``basis_hash`` alone. Two loom concerns can watch identical file globs
and compute the same basis, so a basis-only key made them overwrite each
other in the mirror and collapse into one another in the dedup window.
See :func:`_mirror_filename` for the naming scheme and its migration
behaviour for pre-``concern_ref`` files.

READ-ONLY, ALWAYS. This component:

* NEVER runs a validator.
* NEVER writes into the validator's own verdict store
  (``~/.local/share/alter/verdicts/`` - the producer's namespace).
  Mirrored rows land in a SEPARATE directory
  (``loom-verdict-mirror/`` under :func:`alter_runtime.config.data_dir`)
  precisely so a mirrored verdict can never be confused with, or clobber,
  a locally-produced validator row - even on the validator's own machine,
  where both this subscriber and :class:`LoomVerdictExporter` may run
  side by side.
* NEVER admits anything to a trunk and NEVER emits a verdict of its own.

OUT OF SCOPE (explicitly, per design doc section 4's flagged open
boundary and section 9): the thin-client LAND-TIME ADMISSION action (a
"is there a cached PASS matching my current tree hash, else refuse to
push" git-hook check) is NOT built here. This subscriber only WRITES the
local mirror; something else, later, specified by whoever owns the
Unit-4 thin-client side, READS that mirror to gate a land. Do not wire
this subscriber's output into any admission/gating decision without that
separate design.

Read-side trust
----------------

The design's device-bound trust model lives entirely on the WRITE side
(the backend's ``verify_invocation`` gate on
``POST /api/v1/identity-events/loom-verdict`` - see
:mod:`alter_runtime.adapters.loom_verdict_exporter`). On the read side,
the existing Ed25519 signed-SSE-frame verifier in
:mod:`alter_runtime.subscribers.do_sse` already gates EVERY frame
published to the ``identity.event`` bus topic when
``DaemonConfig.require_frame_signature`` is ``True`` (the default):
``DoSseSubscriber._dispatch_frame`` verifies-then-publishes, so an
unsigned or wrong-key frame never reaches ``identity.event`` at all in
that mode. This subscriber reuses that guarantee rather than
re-implementing crypto verification (the "reuse, don't invent a second
mechanism" instruction in the design doc applies here too) - but it does
NOT blindly trust the bus. When ``require_frame_signature`` is ``False``
(enforcement disabled - a valid but unverified transitional/dev
configuration), ``DoSseSubscriber`` publishes EVERY frame, signed or not,
to ``identity.event``. A ``loom_verdict`` frame is a constitutive claim a
future land-time gate may rely on, so this subscriber refuses to mirror
ANY ``loom_verdict`` while enforcement is off, rather than silently
caching an unverifiable claim. See :meth:`LoomVerdictSubscriber.handle_event`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import tempfile
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from alter_runtime.config import DaemonConfig, data_dir
from alter_runtime.daemon import Component

if TYPE_CHECKING:
    from alter_runtime.subscribers.bus import EventBus

__all__ = [
    "LOOM_VERDICT_KIND",
    "MIRROR_DIRNAME",
    "MIRROR_SOURCE",
    "LoomVerdictSubscriber",
]

logger = logging.getLogger("alter_runtime.subscribers.loom_verdict_subscriber")

#: The identity-event ``kind`` this subscriber filters on. Matches the
#: backend's own ``KIND_LOOM_VERDICT`` constant.
LOOM_VERDICT_KIND = "loom_verdict"

#: Subdirectory (within ``data_dir()``) holding mirrored verdict rows.
#: Deliberately NOT the same directory the validator's own verdict store
#: writes to (``~/.local/share/alter/verdicts/``) - see the module
#: docstring.
MIRROR_DIRNAME = "loom-verdict-mirror"

#: The ``source`` tag stamped on every mirrored row, so a consumer can
#: never confuse a mirrored verdict with a locally-produced one.
MIRROR_SOURCE = "do-sse-mirror"

#: Bounded LRU dedup window. Sized to match the sibling bounded-dedup
#: idioms in this package (``do_sse.py`` / ``agent_frames.py``).
DEDUP_WINDOW: int = 256

_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]")


def _mirror_dir() -> Path:
    return data_dir() / MIRROR_DIRNAME


def _mirror_filename(basis_hash: str, concern_ref: str | None = None) -> str:
    """Build a safe, per-concern mirror filename.

    Two loom concerns can watch identical file globs and so compute an
    identical ``basis_hash``. Naming mirror files on ``basis_hash`` alone
    therefore made the two concerns overwrite each other silently, which
    is why ``concern_ref`` (the opaque per-concern discriminator derived
    by the producer) is part of the name: ``<basis_hash>-<concern_ref>.json``.

    MIGRATION: mirror files written before ``concern_ref`` existed are
    named ``<basis_hash>.json``. That legacy name is still produced here
    when a frame carries no ``concern_ref`` at all (an in-flight frame
    from a pre-upgrade producer), so old and new files coexist and no
    existing mirror file is ever orphaned by a rename or removed.
    """
    slug = _UNSAFE_FILENAME_CHARS.sub("-", basis_hash)[:200]
    if not slug:
        slug = "unknown-basis"
    if not concern_ref:
        return f"{slug}.json"
    ref_slug = _UNSAFE_FILENAME_CHARS.sub("-", concern_ref)[:64]
    return f"{slug}-{ref_slug}.json" if ref_slug else f"{slug}.json"


def _write_atomic_json(path: Path, payload: dict[str, Any]) -> None:
    """Write ``payload`` to ``path`` via tempfile + ``os.replace``.

    No ``fcntl`` - portable to Windows. Matches the atomic-rename idiom
    used by the upstream verdict store.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(prefix=path.stem + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


class LoomVerdictSubscriber(Component):
    """Projects ``loom_verdict`` deliveries to a local read-only mirror.

    Parameters
    ----------
    bus:
        The shared :class:`EventBus` instance.
    config:
        Loaded :class:`DaemonConfig`. Used to read
        ``require_frame_signature`` (the read-side trust gate - see the
        module docstring) and ``loom_verdict_subscriber_enabled`` is
        checked by the daemon wiring, not this class.
    mirror_dir:
        Override the mirror output directory. Tests redirect writes to a
        ``tmp_path`` fixture without touching ``~/.local/share/alter-runtime/``.
    """

    name = "loom_verdict_subscriber"

    def __init__(
        self,
        bus: "EventBus",
        config: DaemonConfig,
        *,
        mirror_dir: Path | None = None,
    ) -> None:
        self._bus = bus
        self._config = config
        self._mirror_dir: Path = mirror_dir if mirror_dir is not None else _mirror_dir()
        self._lock = asyncio.Lock()
        self._shutdown_event = asyncio.Event()
        # Bounded LRU dedup window keyed on a CONTENT-derived key
        # (basis_hash + observed_at + verdict). The loom_verdict envelope
        # (unlike agent_frame) carries no internal ``frame_id``, and
        # whether the outer DO SSE re-fan-out preserves the ingest-side
        # ``nonce`` at the top level is not confirmed against a live
        # capture (see agent_frames.py's own note on verifying wrapper
        # shapes against reality before trusting them). A content-derived
        # key is always available directly from the unwrapped payload
        # regardless of wrapper metadata, and gives the same
        # collapse-duplicate-projection behaviour dedup exists for.
        self._seen_keys: OrderedDict[str, None] = OrderedDict()

        # Test/observability introspection counters.
        self.mirrored_count = 0
        self.dropped_unverifiable_count = 0
        self.dropped_duplicate_count = 0

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        self._bus.subscribe("identity.event", self.handle_event)
        logger.info(
            "loom_verdict_subscriber started mirror_dir=%s require_frame_signature=%s",
            self._mirror_dir,
            self._config.require_frame_signature,
        )
        try:
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            raise
        finally:
            with contextlib.suppress(Exception):
                self._bus.unsubscribe("identity.event", self.handle_event)
            logger.info("loom_verdict_subscriber stopped")

    async def stop(self) -> None:
        """Cooperative shutdown - releases the run loop."""
        self._shutdown_event.set()

    # ------------------------------------------------------------------
    # Frame ingest - public surface for the bus and tests
    # ------------------------------------------------------------------

    async def handle_event(self, event: Any) -> None:
        """Project a single parsed identity-event dict if it is a
        ``loom_verdict``. Public test seam, mirroring
        :meth:`AgentFrameSubscriber.handle_event` - tests call this
        directly with synthesised dicts.
        """
        if not isinstance(event, dict):
            return

        # ---- 1. Discriminate + unwrap ------------------------------------
        # The DO identity-event wrapper shape (matching the git_commit /
        # agent_frame precedent captured live against the real stream):
        #   {"v": "alter1", "version": N, "handle": "~example",
        #    "kind": "loom_verdict", "timestamp": ...,
        #    "payload": {"verdict":..., "basis_hash":..., "observed_at":...,
        #                "producer_id":...}}
        # A bare unwrapped payload (kind at top level, no "payload" key) is
        # also accepted defensively, matching agent_frames.py's own
        # tolerance for more than one observed shape.
        if event.get("kind") == LOOM_VERDICT_KIND and isinstance(event.get("payload"), dict):
            payload = event["payload"]
        elif event.get("kind") == LOOM_VERDICT_KIND:
            payload = event
        else:
            return

        # ---- 2. READ-SIDE TRUST GATE --------------------------------------
        # See the module docstring: DoSseSubscriber only verifies-then-
        # publishes when require_frame_signature is True. When enforcement
        # is off, ANY frame - signed, unsigned, or forged - reaches
        # identity.event unfiltered. A loom_verdict is a constitutive claim
        # a future land-time gate may rely on, so this subscriber refuses
        # to mirror while that guarantee cannot be relied on, rather than
        # silently caching an unverifiable claim.
        if not self._config.require_frame_signature:
            self.dropped_unverifiable_count += 1
            logger.warning(
                "loom_verdict_subscriber: dropping loom_verdict - "
                "require_frame_signature is False, so this frame's "
                "authenticity cannot be relied on (see module docstring)"
            )
            return

        # ---- 3. Strict shape check (never mirror a malformed claim) ------
        verdict = payload.get("verdict")
        basis_hash = payload.get("basis_hash")
        observed_at = payload.get("observed_at")
        producer_id = payload.get("producer_id")
        # concern_ref is the opaque per-concern discriminator. It is
        # REQUIRED by the backend ingest schema, so every frame from a
        # current producer carries it. It is tolerated as absent here
        # only for an in-flight frame from a pre-upgrade producer, which
        # then keeps the legacy basis-only mirror name and dedup key
        # rather than being dropped mid-rollout.
        concern_ref_raw = payload.get("concern_ref")
        concern_ref = (
            concern_ref_raw if isinstance(concern_ref_raw, str) and concern_ref_raw else None
        )
        if (
            not isinstance(verdict, str)
            or verdict not in ("GREEN", "RED", "STALE", "UNKNOWN")
            or not isinstance(basis_hash, str)
            or not basis_hash
            or not isinstance(observed_at, str)
            or not observed_at
            or not isinstance(producer_id, str)
            or not producer_id
        ):
            logger.warning(
                "loom_verdict_subscriber: malformed loom_verdict payload - dropping: %r",
                {k: payload.get(k) for k in ("verdict", "basis_hash", "producer_id")},
            )
            return

        # ---- 4. Dedup on a content-derived key -----------------------------
        # concern_ref is part of the key: without it, two concerns sharing
        # a basis_hash and observed_at collapse into one, and the second
        # concern's verdict is silently dropped as a "duplicate".
        dedup_key = f"{concern_ref or '-'}:{basis_hash}:{observed_at}:{verdict}"
        async with self._lock:
            if dedup_key in self._seen_keys:
                self.dropped_duplicate_count += 1
                logger.debug(
                    "loom_verdict_subscriber: duplicate basis_hash=%s - dropping",
                    basis_hash[:12],
                )
                return
            self._seen_keys[dedup_key] = None
            if len(self._seen_keys) > DEDUP_WINDOW:
                self._seen_keys.popitem(last=False)

            # ---- 5. Project the read-only mirror row -----------------------
            record = {
                "verdict": verdict,
                "basis_hash": basis_hash,
                "observed_at": observed_at,
                "producer_id": producer_id,
                "source": MIRROR_SOURCE,
                "mirrored_at": datetime.now(timezone.utc).isoformat(),
            }
            # Persist the concern dimension into the row body too, so a
            # reader of the mirror can tell two same-basis concerns apart
            # from the content, not only from the filename.
            if concern_ref is not None:
                record["concern_ref"] = concern_ref
            mirror_path = self._mirror_dir / _mirror_filename(basis_hash, concern_ref)
            try:
                _write_atomic_json(mirror_path, record)
            except OSError as exc:
                logger.warning(
                    "loom_verdict_subscriber: mirror write failed for basis_hash=%s: %s",
                    basis_hash[:12],
                    exc,
                )
                return
            self.mirrored_count += 1

        logger.info(
            "loom_verdict_subscriber: mirrored verdict=%s basis_hash=%s -> %s",
            verdict,
            basis_hash[:12],
            mirror_path,
        )

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def mirror_dir(self) -> Path:
        return self._mirror_dir

    @property
    def seen_keys(self) -> OrderedDict[str, None]:
        return self._seen_keys
