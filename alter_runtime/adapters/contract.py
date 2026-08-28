"""Adapter plugin contract, the public extension seam for runtime adapters.

Built-in adapters are registered directly in :mod:`alter_runtime.daemon`.
Out-of-tree adapters (for example gated or separately-installed adapters
kept in their own package) register under the ``alter_runtime.adapters``
entry-point group and are discovered at start-up. This keeps the daemon
free of any import of an adapter that lives outside the public tree: an
adapter the host has not installed is simply absent, and the public package
carries no reference to it.

A plugin entry-point resolves to a *factory*: a callable that accepts a
single :class:`AdapterContext` and returns one component, an iterable of
components, or ``None`` to decline registration (for example when the
adapter is disabled by config). A returned component is any object with an
async ``run`` method, matching :class:`alter_runtime.daemon.Component`.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from alter_runtime.daemon import Component

logger = logging.getLogger(__name__)

#: Entry-point group external adapter packages register under.
ADAPTER_ENTRY_POINT_GROUP = "alter_runtime.adapters"


@dataclass(frozen=True)
class AdapterContext:
    """Stable construction context handed to every adapter factory.

    Passing a context object rather than positional arguments keeps the
    factory signature stable as the runtime gains new wiring: new fields are
    added here without changing existing plugins.
    """

    config: Any
    event_bus: Any
    session: Any = None


#: A factory takes an AdapterContext and returns component(s) or None.
AdapterFactory = Callable[["AdapterContext"], "Component | Iterable[Component] | None"]


def discover_adapter_components(context: AdapterContext) -> Iterator[Component]:
    """Yield components contributed by installed adapter plugins.

    Each entry-point under :data:`ADAPTER_ENTRY_POINT_GROUP` is loaded and
    called with ``context``. Failures (import error, factory exception, a
    non-component return) are logged and skipped so a single bad plugin can
    never prevent the daemon from starting. When no plugin package is
    installed the generator is empty and the daemon runs exactly as a clean
    public build does.
    """
    try:
        discovered = entry_points(group=ADAPTER_ENTRY_POINT_GROUP)
    except Exception:  # pragma: no cover - importlib metadata edge cases
        logger.exception("failed to enumerate adapter entry-points")
        return

    for entry_point in discovered:
        try:
            factory = entry_point.load()
            result = factory(context)
        except Exception:
            logger.exception("adapter plugin %r failed to load; skipping", entry_point.name)
            continue
        if result is None:
            continue
        candidates = result if _is_iterable(result) else [result]
        for component in candidates:
            if _looks_like_component(component):
                logger.info("registered adapter plugin component: %s", entry_point.name)
                yield component
            else:
                logger.warning(
                    "adapter plugin %r returned a non-component (%s); skipping",
                    entry_point.name,
                    type(component).__name__,
                )


def _is_iterable(obj: object) -> bool:
    if isinstance(obj, (str, bytes)):
        return False
    try:
        iter(obj)  # type: ignore[call-overload]
    except TypeError:
        return False
    return True


def _looks_like_component(obj: object) -> bool:
    run = getattr(obj, "run", None)
    return callable(run)
