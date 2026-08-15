"""Local adapters - ambient-signal publishers.

Adapters are the runtime's *inputs from the device itself*: they observe
something local (git commits, editor-hook invocations, shell activity) and
publish a signal onto the ``local.signal`` topic. A separate egress producer
is responsible for POSTing those signals back to the per-handle Durable Object
``/ingest`` endpoint so they become part of the continuous identity field.

Adapters are deliberately kept simple: one file per signal source, no shared
state, no cross-adapter coordination. Each registers as a
:class:`alter_runtime.daemon.Component` and is supervised like any other
runtime component.
"""

from alter_runtime.adapters.claude_jsonl_watcher import ClaudeJsonlWatcher
from alter_runtime.adapters.git_watcher import GitWatcher
from alter_runtime.adapters.loom_verdict_exporter import LoomVerdictExporter
from alter_runtime.adapters.worktree_watcher import WorktreeWatcher

__all__ = [
    "ClaudeJsonlWatcher",
    "GitWatcher",
    "LoomVerdictExporter",
    "WorktreeWatcher",
]
