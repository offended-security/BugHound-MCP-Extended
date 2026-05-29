"""Server-Sent Events stream of job_manager state changes.

The webui's only "live" feature in Phase 1. Per-connection asyncio.Queue,
filter on workspace_id, heartbeat every 15s, guaranteed unsubscribe on
disconnect (so the JobManager's subscriber list never grows unbounded).

aiohttp's StreamResponse handles SSE just fine — no extra dependency.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog
from aiohttp import web

logger = structlog.get_logger("bughound.webui.events")


# Heartbeat cadence: matches typical SSE intermediary (nginx, CF) keepalive.
_HEARTBEAT_INTERVAL_S = 15.0

# Per-connection queue cap. If the client is slow to consume, oldest events
# get dropped first — preferable to growing memory unboundedly.
_QUEUE_MAX = 200


def _format_sse(event: str, data: Any) -> bytes:
    """Encode an SSE event frame. data is JSON-serialized."""
    payload = json.dumps(data, separators=(",", ":"))
    return f"event: {event}\ndata: {payload}\n\n".encode("utf-8")


async def stream_workspace_events(request: web.Request) -> web.StreamResponse:
    """SSE stream of JobRecord state changes for one workspace_id.

    Subscribes to the app's JobManager on connect, unsubscribes on disconnect.
    The route handler MUST own the unsubscribe lifecycle — no path through
    here may leave a subscriber stranded.
    """
    workspace_id = request.match_info["workspace_id"]
    jm = request.app["job_manager"]

    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_QUEUE_MAX)

    async def on_job_event(snapshot: dict[str, Any]) -> None:
        # Filter to this workspace only.
        if snapshot.get("workspace_id") != workspace_id:
            return
        try:
            queue.put_nowait(snapshot)
        except asyncio.QueueFull:
            # Drop oldest. SSE clients see eventual consistency via heartbeats.
            try:
                queue.get_nowait()
                queue.put_nowait(snapshot)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass

    jm.subscribe(on_job_event)

    response = web.StreamResponse(
        status=200,
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # disable proxy buffering for nginx
        },
    )
    await response.prepare(request)

    logger.info("sse.connect", workspace_id=workspace_id)

    try:
        # Initial frame so the client knows the channel is open.
        await response.write(_format_sse("ready", {"workspace_id": workspace_id}))

        while True:
            try:
                snapshot = await asyncio.wait_for(
                    queue.get(), timeout=_HEARTBEAT_INTERVAL_S
                )
            except asyncio.TimeoutError:
                # SSE comment-line heartbeat — keeps intermediaries happy and
                # lets the client detect dead connections.
                try:
                    await response.write(b": hb\n\n")
                except (ConnectionResetError, ConnectionError):
                    break
                continue

            try:
                await response.write(_format_sse("job", snapshot))
            except (ConnectionResetError, ConnectionError):
                break
    except asyncio.CancelledError:
        # Client disconnected or server is shutting down. Re-raise so aiohttp
        # cleans up correctly.
        raise
    finally:
        jm.unsubscribe(on_job_event)
        logger.info("sse.disconnect", workspace_id=workspace_id)

    return response
