"""Subscribers - long-lived components that consume the per-handle event stream.

Each subscriber is a :class:`alter_runtime.daemon.Component` that registers
with the daemon supervisor and is restarted with exponential backoff on
failure. Subscribers are the network-facing half of the runtime: they own the
SSE socket against ``https://mcp.truealter.com/events/{handle}/stream`` and
project events into local on-disk caches + the in-process :class:`EventBus`
that other ~alter surfaces (client hooks, the CLI, downstream adapters) read
from.

* Early releases shipped :class:`InboxWriter`, the shared :class:`SSEFrame` parser,
  and the skeleton supervisor.
* Subsequent releases added :class:`EventBus`, :class:`DoSseSubscriber`
  (the primary inbound subscriber), and :class:`McpFallbackSubscriber`
  (fallback via direct MCP polling).
* :class:`AgentFrameSubscriber` projects agent-frame envelopes from the SSE stream;
  projects ``agent_frame`` deliveries to ``~/.cache/alter/agent-frames.jsonl``
  and re-publishes per-kind bus topics.
"""

from alter_runtime.subscribers.active_sessions_cron_emitter import ActiveSessionsCronEmitter
from alter_runtime.subscribers.active_sessions_do_publisher import ActiveSessionsDoPublisher
from alter_runtime.subscribers.active_sessions_gc import ActiveSessionsGc
from alter_runtime.subscribers.active_sessions_writer import ActiveSessionsWriter
from alter_runtime.subscribers.adapters_writer import AdaptersWriter
from alter_runtime.subscribers.agent_frames import AgentFrameSubscriber
from alter_runtime.subscribers.attunement_refresher import AttunementRefresher
from alter_runtime.subscribers.bus import EventBus
from alter_runtime.subscribers.cache_writer import CacheWriter, project_state_to_cache
from alter_runtime.subscribers.ceremony_echo import CeremonyEchoWriter
from alter_runtime.subscribers.do_sse import DoSseSubscriber
from alter_runtime.subscribers.doctrine_projection import DoctrineProjectionPoller
from alter_runtime.subscribers.ebpf import EbpfSubscriber
from alter_runtime.subscribers.inbox_writer import InboxWriter
from alter_runtime.subscribers.loom_verdict_subscriber import LoomVerdictSubscriber
from alter_runtime.subscribers.mcp_fallback import McpFallbackSubscriber
from alter_runtime.subscribers.presence_feed_writer import PresenceFeedWriter
from alter_runtime.subscribers.presence_writer import PresenceWriter
from alter_runtime.subscribers.session_claims_do_publisher import SessionClaimsDoPublisher
from alter_runtime.subscribers.session_presence import SessionPresenceWriter
from alter_runtime.subscribers.session_refresher import SessionRefresher
from alter_runtime.subscribers.sse import SSEFrame, parse_sse_frames

__all__ = [
    "ActiveSessionsCronEmitter",
    "ActiveSessionsDoPublisher",
    "ActiveSessionsGc",
    "ActiveSessionsWriter",
    "AdaptersWriter",
    "AgentFrameSubscriber",
    "AttunementRefresher",
    "CacheWriter",
    "CeremonyEchoWriter",
    "DoSseSubscriber",
    "DoctrineProjectionPoller",
    "EbpfSubscriber",
    "EventBus",
    "InboxWriter",
    "LoomVerdictSubscriber",
    "McpFallbackSubscriber",
    "PresenceFeedWriter",
    "PresenceWriter",
    "SSEFrame",
    "SessionClaimsDoPublisher",
    "SessionPresenceWriter",
    "SessionRefresher",
    "parse_sse_frames",
    "project_state_to_cache",
]
