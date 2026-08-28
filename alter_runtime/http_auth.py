"""HTTP header helpers for upstream calls into the ~alter backend.

Every authenticated request carries an ``Authorization: Bearer <jwt>``
header set explicitly by the calling subscriber; that member bearer is
the whole auth story. This module supplies the constant
``X-Alter-Client-*`` identity bundle that the floor middleware expects
alongside the bearer on every outbound backend call.
"""

from __future__ import annotations

import logging

__all__ = [
    "backend_default_headers",
]

_logger = logging.getLogger(__name__)


def backend_default_headers(target_url: str | None = None) -> dict[str, str]:
    """Return headers attached to every outbound backend HTTP call.

    Returns the canonical ``X-Alter-Client-*`` identity bundle so the
    floor middleware sees a well-formed identification tuple on every
    request. The ``Authorization: Bearer`` header is set by the caller;
    this helper only supplies the constant identity headers.

    ``target_url`` is accepted for callsite compatibility and is not
    currently consulted.

    Defined here rather than in ``alter_runtime.floor_preflight`` so
    callers can adopt the helper without taking on the floor-preflight
    import surface. Both modules cross-import each other otherwise.
    """
    # Lazy import to avoid the http_auth -> floor_preflight -> http_auth cycle.
    from alter_runtime.floor_preflight import client_headers

    return dict(client_headers())
