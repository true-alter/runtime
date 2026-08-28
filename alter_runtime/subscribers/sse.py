"""Minimal Server-Sent Events parser for the alter-runtime daemon.

This is a deliberately self-contained, stdlib-only port of the
server-side identity-events subscriber. The runtime daemon ships to user
devices and is self-contained and does not import the server module.

The parser is intentionally minimal: it understands ``event``, ``data`` and
``id`` fields per the SSE spec, joins multi-line ``data:`` payloads with
newlines, and silently drops keepalive comments (lines starting with ``:``).
Unknown fields (``retry``, etc.) are ignored. The wire contract is fixed
server-side and the only producer on the other side of the socket is the
identity field's own event stream, so we do not bother handling arbitrary
SSE producer quirks.

Usage::

    buffer = ""
    async for chunk in stream.aiter_text():
        buffer += chunk
        frames, buffer = parse_sse_frames(buffer)
        for frame in frames:
            ...

The returned ``remainder`` is the partial trailing frame (if any) and must be
prepended to the next chunk so that frames split across read boundaries are
reassembled correctly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

__all__ = ["SSEFrame", "parse_sse_frames"]


@dataclass
class SSEFrame:
    """A single parsed Server-Sent Events frame."""

    event: str
    """Value of the ``event:`` field, or ``"message"`` per the spec default."""

    data: str
    """Concatenated ``data:`` values (newline-joined)."""

    id: str | None = None
    """Value of the ``id:`` field, if supplied. Used as the SSE
    ``Last-Event-ID`` header on reconnect."""

    @property
    def json(self) -> dict:
        """Parse ``data`` as JSON. Raises ``ValueError`` if malformed."""
        return json.loads(self.data)


def parse_sse_frames(buffer: str) -> tuple[list[SSEFrame], str]:
    """Parse SSE frames out of a raw text buffer.

    Returns ``(frames, remainder)`` where ``remainder`` is the trailing
    partial frame (if any) that should be prepended to the next chunk.
    Comments (lines starting with ``:``) and blank-only buffers are
    tolerated and simply produce no frames.
    """

    frames: list[SSEFrame] = []

    # Frames are separated by a blank line. A trailing blank line may be
    # absent if the chunk ends mid-frame; that portion is returned as the
    # remainder.
    parts = buffer.split("\n\n")
    remainder = parts[-1]
    complete_parts = parts[:-1]

    for raw in complete_parts:
        frame = _parse_single_frame(raw)
        if frame is not None:
            frames.append(frame)

    return frames, remainder


def _parse_single_frame(raw: str) -> SSEFrame | None:
    """Parse a single (complete) SSE frame.

    Returns ``None`` if the frame is a pure comment or has no data.
    """

    event_name = "message"
    data_lines: list[str] = []
    event_id: str | None = None

    for line in raw.split("\n"):
        if not line:
            continue
        if line.startswith(":"):
            # Comment - silently ignored (keepalive).
            continue
        if ":" not in line:
            field_name = line
            value = ""
        else:
            field_name, _, value = line.partition(":")
            # Per SSE spec, a single leading space after ':' is ignored.
            if value.startswith(" "):
                value = value[1:]

        if field_name == "event":
            event_name = value
        elif field_name == "data":
            data_lines.append(value)
        elif field_name == "id":
            event_id = value
        # ``retry:`` and unknown fields are ignored.

    if not data_lines:
        return None

    return SSEFrame(
        event=event_name,
        data="\n".join(data_lines),
        id=event_id,
    )
