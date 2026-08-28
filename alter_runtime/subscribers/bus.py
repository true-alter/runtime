"""In-process pub/sub event bus for the alter-runtime daemon.

The bus is the coupling point between the three halves of the runtime:

* **Ingress subscribers** (``do_sse``, ``mcp_fallback``) publish identity frames
  and connection-state transitions.
* **Local adapters** (``git_watcher`` and future client-hook / shell bridges) publish
  outbound ambient signals that the egress producer later relays to the DO.
* **Local fan-out surfaces** (the Unix socket server, the D-Bus service, the
  InboxWriter projection, cache writers) subscribe to whichever topics they
  care about.

Design goals
------------

1. **Tiny.** The bus is ~60 lines of Python. It owns no state beyond the
   subscriber map and a lock. No persistence, no ordering guarantees beyond
   "callbacks fire in registration order".
2. **Error-isolating.** A buggy subscriber must never kill the publisher's
   task. All exceptions raised inside a subscriber callback are caught and
   logged - the next subscriber still runs, and the publisher's `publish()`
   call returns normally.
3. **Async-first.** Both the publisher and subscribers run inside the daemon's
   single asyncio loop. Callbacks may be ``async`` coroutines or plain
   callables; both are supported.
4. **No topic taxonomy enforcement.** Topics are free-form strings. Conventions
   live in the daemon (currently: ``identity.frame``, ``identity.event``,
   ``identity.connected``, ``identity.disconnected``, ``local.signal``). Tests
   that want to assert on topic names can do so against these conventions.

Topic registry (agent channel)
------------------------------------------------------------------

``alter.agent.frame.{kind}``: published by :class:`AgentFrameSubscriber`
once per successfully projected ``agent_frame`` delivery whose
``content_type`` equals ``"x-alter-agent"``.  The ``{kind}`` suffix is the
15-kind catalogue value (see AgentFrameSubscriber for the full list,
``kind`` to a 15-member ``Literal``; the catalogue currently has 15 kinds), e.g.::

    alter.agent.frame.agent_handover
    alter.agent.frame.agent_advisory
    alter.agent.frame.agent_broadcast
    alter.agent.frame.agent_lock_request
    alter.agent.frame.agent_lock_release
    alter.agent.frame.agent_query
    alter.agent.frame.agent_response
    alter.agent.frame.agent_lease_extend
    alter.agent.frame.agent_binding_moment
    alter.agent.frame.agent_return_event
    alter.agent.frame.peer_diagnostic_request
    alter.agent.frame.peer_diagnostic_response
    alter.agent.frame.intent_declare
    alter.agent.frame.intent_withdraw
    alter.agent.frame.flush_executed

The payload published on each topic is the full deserialised ``agent_frame``
dict as received from the DO SSE stream.  Hook subscribers (client hooks,
adapters) can filter by subscribing to the specific kind topics they care
about rather than reading from the JSONL cache on every event.

The bus is deliberately not a drop-in replacement for a durable message broker.
If the daemon crashes or a subscriber is slow, events are lost. The durable
state lives server-side (replayable via ``Last-Event-ID``); the bus is a
transient coupling layer only.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Union

__all__ = ["EventBus", "Subscriber"]

logger = logging.getLogger("alter_runtime.subscribers.bus")

#: A subscriber callback may be sync or async. The bus awaits async callbacks
#: and calls sync callbacks inline.
Subscriber = Union[
    Callable[[Any], None],
    Callable[[Any], Awaitable[None]],
]


class EventBus:
    """Topic-keyed asyncio pub/sub.

    Thread-safety: all methods must be called from the same asyncio loop.
    The bus does not attempt to be thread-safe.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Subscriber]] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Subscribe / unsubscribe
    # ------------------------------------------------------------------

    def subscribe(self, topic: str, callback: Subscriber) -> None:
        """Register a callback to receive events published to ``topic``.

        Multiple callbacks may subscribe to the same topic; they fire in
        registration order. Calling ``subscribe`` for the same ``(topic,
        callback)`` pair twice registers it twice - the caller is expected
        to keep track of its own subscriptions and ``unsubscribe`` symmetrically.
        """
        self._subscribers.setdefault(topic, []).append(callback)
        logger.debug(
            "bus subscribe topic=%s callback=%r count=%d",
            topic,
            _describe_callback(callback),
            len(self._subscribers[topic]),
        )

    def unsubscribe(self, topic: str, callback: Subscriber) -> None:
        """Remove a previously registered callback.

        No-op if the callback is not registered or the topic has no
        subscribers - callers should not need to check first.
        """
        callbacks = self._subscribers.get(topic)
        if not callbacks:
            return
        try:
            callbacks.remove(callback)
        except ValueError:
            return
        if not callbacks:
            self._subscribers.pop(topic, None)

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    async def publish(self, topic: str, payload: Any) -> None:
        """Dispatch ``payload`` to every subscriber of ``topic``.

        Subscribers run sequentially in registration order. Exceptions raised
        by any one subscriber are caught and logged - the remainder still
        run, and ``publish`` returns normally once all have been invoked.
        """
        # Snapshot the subscriber list so that a subscriber mutating its own
        # subscription mid-publish doesn't corrupt the iteration.
        callbacks = list(self._subscribers.get(topic, ()))
        if not callbacks:
            return

        for callback in callbacks:
            try:
                result = callback(payload)
                if inspect.isawaitable(result):
                    await result
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "bus publish topic=%s subscriber=%r raised: %s - continuing",
                    topic,
                    _describe_callback(callback),
                    exc,
                )

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    def subscriber_count(self, topic: str) -> int:
        """Return the number of active subscribers on ``topic``."""
        return len(self._subscribers.get(topic, ()))

    def topics(self) -> list[str]:
        """Return the list of topics that currently have subscribers."""
        return list(self._subscribers.keys())


def _describe_callback(callback: Subscriber) -> str:
    """Best-effort human-readable name for a callback, for log lines."""
    try:
        name = getattr(callback, "__qualname__", None) or getattr(callback, "__name__", None)
        if name:
            return name
        return repr(callback)
    except Exception:  # pragma: no cover - defensive
        return "<callback>"
