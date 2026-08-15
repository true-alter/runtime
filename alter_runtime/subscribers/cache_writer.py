"""CacheWriter - projects identity state into the shared shell cache file.

This is the cache glue. Shell-side integrations (neofetch / waybar /
prompt indicators, and editor session-context injection) read live identity
state from a file at ``$XDG_CACHE_HOME/alter/identity.json``. Before this
component existed, those integrations hit the backend MCP endpoint directly
on every cache miss; that path is slow (HTTPS round-trip) and fails offline.

With CacheWriter registered in the daemon, every ``identity.event`` that
looks like a state snapshot (whether from the live SSE stream or the
cold-start MCP fallback) projects into the cache file with an atomic
``tmp → rename`` write. Any shell-side ``cache_is_fresh`` + ``read_cache``
flow therefore transparently picks up live state as soon as the daemon is
running, with no integration changes needed.

The cache schema matches the JSON written by the legacy identity-cache
API path:

::

    {
        "handle":     "ada",       - bare handle, no leading ~
        "level":      "3",         - bare numeric tier, no leading L
        "attunement": "0.42",      - decimal 0..1 or integer percentage
        "income":     "1.23"       - stringified USD earnings
    }

All fields are strings to match the shell script's ``jq -r`` consumers.
When a field is missing in the source event the output key is an empty
string (``""``) rather than omitted, so ``jq -r '.handle // ""'``
produces consistent behaviour across cache misses.

**Why strip the ``~`` and ``L`` prefixes?** The shell integration prepends
them at render time:

.. code-block:: bash

    display_handle="${handle:+~$handle}"
    display_level="${level:+L$level}"

If we stored ``"~example"`` / ``"L3"``, the script would render
``"~~example"`` / ``"LL3"``. The design is to feed the existing shell
scripts live data with **zero script changes**, so the CacheWriter
matches the raw shape the scripts already expect.

Design notes
------------

* The projection is *idempotent and lossy*. We keep only the four fields
  the shell script cares about; anything else from the source event is
  dropped. If a field is unchanged from the last write we still rewrite
  the file - atomic rename is cheap and the shell script uses file mtime
  as its TTL probe, so we want the mtime to bump on every refresh.
* The writer is tolerant of a variety of source shapes. State sync
  events from ``mcp_fallback`` wrap their payload under ``payload``;
  direct state frames put fields at the top level. The
  :func:`_extract_state` helper checks both.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from alter_runtime.config import cache_dir
from alter_runtime.daemon import Component

if TYPE_CHECKING:
    from alter_runtime.subscribers.bus import EventBus

__all__ = ["CacheWriter", "project_state_to_cache"]

logger = logging.getLogger("alter_runtime.subscribers.cache_writer")

#: Filename inside ``cache_dir()`` that the shell script reads.
CACHE_FILENAME: str = "identity.json"

#: Event kinds we recognise as carrying identity state.
STATE_KINDS: frozenset[str] = frozenset(
    {
        "state_sync",
        "alter_whoami",
        "attunement_transition",
        "identity_state",
    }
)


class CacheWriter(Component):
    """Writes identity state into ``$XDG_CACHE_HOME/alter/identity.json``.

    Parameters
    ----------
    bus:
        The shared :class:`EventBus`. Subscribes to ``identity.event``.
    cache_path:
        Override the cache file path. Tests inject a ``tmp_path`` value.
    """

    name = "cache_writer"

    def __init__(
        self,
        bus: EventBus,
        *,
        cache_path: Path | None = None,
    ) -> None:
        self._bus = bus
        self._cache_path: Path = (
            cache_path if cache_path is not None else cache_dir() / CACHE_FILENAME
        )
        self._stop_event = asyncio.Event()
        self._last_written: dict[str, str] | None = None

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        self._bus.subscribe("identity.event", self._on_event)
        logger.info("cache_writer started cache=%s", self._cache_path)
        try:
            await self._stop_event.wait()
        finally:
            self._bus.unsubscribe("identity.event", self._on_event)
            logger.info("cache_writer stopped")

    async def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Bus callback
    # ------------------------------------------------------------------

    async def _on_event(self, event: dict[str, Any]) -> None:
        """Project a bus event to the cache file (if it's a state snapshot)."""
        if not isinstance(event, dict):
            return
        kind = event.get("kind")
        if kind not in STATE_KINDS:
            return

        projected = project_state_to_cache(event)
        if not projected:
            logger.debug("cache_writer ignored event kind=%s - no extractable state", kind)
            return

        try:
            self._atomic_write(projected)
        except OSError as exc:
            logger.warning("cache_writer: write failed: %s - keeping previous cache", exc)
            return
        self._last_written = projected
        logger.info(
            "cache_writer wrote handle=%s level=%s attunement=%s",
            projected.get("handle"),
            projected.get("level"),
            projected.get("attunement"),
        )

    # ------------------------------------------------------------------
    # Atomic write
    # ------------------------------------------------------------------

    def _atomic_write(self, data: dict[str, str]) -> None:
        """Write ``data`` to the cache file via a tmp-and-rename sequence."""
        self._cache_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp_path = self._cache_path.with_suffix(self._cache_path.suffix + ".tmp")

        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(tmp_path, flags, 0o600)
        try:
            with contextlib.suppress(OSError):
                os.fchmod(fd, 0o600)
            payload = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
            os.write(fd, payload.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

        os.replace(tmp_path, self._cache_path)
        with contextlib.suppress(OSError):
            os.chmod(self._cache_path, 0o600)

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def cache_path(self) -> Path:
        return self._cache_path

    @property
    def last_written(self) -> dict[str, str] | None:
        return self._last_written


# ---------------------------------------------------------------------------
# Pure projection helper
# ---------------------------------------------------------------------------


def project_state_to_cache(event: dict[str, Any]) -> dict[str, str]:
    """Project a bus event dict into the shell-script cache schema.

    Returns an empty dict if the event doesn't carry any recognisable
    identity state. The result always contains the four fields the shell
    script reads (``handle``, ``level``, ``attunement``, ``income``) with
    empty strings filling any missing values - this keeps ``jq -r`` consumers
    happy across variant source shapes.

    The function is pure (no filesystem access, no bus calls) so it can be
    unit-tested independently of the component lifecycle.
    """

    # State can live at the top level (direct identity events from the
    # stream) or nested under ``payload`` (synthetic state_sync events from
    # the MCP fallback subscriber). Try both.
    sources: list[dict[str, Any]] = []
    payload = event.get("payload")
    if isinstance(payload, dict):
        sources.append(payload)
    sources.append(event)

    def pick(field: str) -> str:
        for src in sources:
            value = src.get(field)
            if value is not None and value != "":
                return _stringify(value)
        return ""

    handle = _strip_tilde(pick("handle"))
    # ``level`` - accept the string label "L3" or an integer engagement_level
    level = _normalise_level(pick("level"))
    if not level:
        engagement = ""
        for src in sources:
            engagement = src.get("engagement_level") or engagement
        if engagement:
            level = _normalise_level(engagement)
    if not level:
        tier = ""
        for src in sources:
            tier = src.get("consent_tier") or tier
        if tier:
            level = _normalise_level(tier)

    attunement = pick("attunement")
    if not attunement:
        for src in sources:
            value = src.get("attunement_score")
            if value is not None and value != "":
                attunement = _stringify(value)
                break

    income = pick("income")
    if not income:
        for src in sources:
            value = src.get("total_earnings") or src.get("identity_income")
            if value is not None and value != "":
                income = _stringify(value)
                break

    # Empty projection - nothing useful to cache.
    if not any((handle, level, attunement, income)):
        return {}

    return {
        "handle": handle,
        "level": level,
        "attunement": attunement,
        "income": income,
    }


def _stringify(value: Any) -> str:
    """Convert a Python value into the string form the shell script expects."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    # dicts / lists don't fit the shell schema - coerce to JSON and let the
    # shell script decide whether to render them.
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _normalise_level(value: Any) -> str:
    """Normalise any engagement-level representation to ``"1".."4"``.

    Accepts integers (``1``), strings (``"L3"`` or ``"3"``), or labels
    (``"augmented"``). Returns the bare numeric tier as a string so the
    cache matches the raw shape the shell integration already expects
    (the shell script prepends ``L`` at render time). Unknown inputs
    become an empty string.
    """
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        if 1 <= value <= 4:
            return str(value)
        return ""
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return ""
        # "L1".."L4"
        if len(stripped) == 2 and stripped[0] in ("L", "l") and stripped[1].isdigit():
            tier = int(stripped[1])
            if 1 <= tier <= 4:
                return str(tier)
        # Raw numeric "1".."4"
        try:
            tier = int(stripped)
        except ValueError:
            # Known label fallbacks - mirrors the canonical engagement-level labels.
            label_map = {
                "explorer": "1",
                "learner": "2",
                "augmented": "3",
                "deployed": "4",
            }
            return label_map.get(stripped.lower(), "")
        if 1 <= tier <= 4:
            return str(tier)
    return ""


def _strip_tilde(value: str) -> str:
    """Strip a single leading ``~`` from a handle, if present.

    The shell script prepends ``~`` at render time, so storing the bare
    handle keeps the shell integration rendering correctly without
    any shell changes (see the module docstring for the full rationale).
    """
    if value.startswith("~"):
        return value[1:]
    return value
