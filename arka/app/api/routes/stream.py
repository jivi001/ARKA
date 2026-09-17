"""Real-time SSE event streaming endpoints."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from arka.app.api.stream_bus import format_sse, get_event_broadcaster

logger = logging.getLogger(__name__)

router = APIRouter(tags=["streaming"])


async def _sse_generator(engagement_id: str | None = None) -> AsyncIterator[str]:
    broadcaster = get_event_broadcaster()
    async for event in broadcaster.subscribe(engagement_id=engagement_id):
        yield format_sse(event)


@router.get("/stream")
async def global_event_stream() -> StreamingResponse:
    """Stream live real-time system events, tool proposals, and telemetry over SSE."""
    return StreamingResponse(
        _sse_generator(engagement_id=None),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/engagements/{engagement_id}/stream")
async def engagement_event_stream(engagement_id: str) -> StreamingResponse:
    """Stream live events, agent activities, and decisions for a specific engagement."""
    return StreamingResponse(
        _sse_generator(engagement_id=engagement_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
