"""Real-time event broadcaster for Server-Sent Events (SSE).

Provides decoupled, asynchronous pub/sub streaming between the ARKA control plane,
agents, workers, and connected operator web consoles.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class EventBroadcaster:
    """In-memory asyncio pub/sub broadcaster for SSE streams.

    Thread-safe and async-safe. Supports global streams and per-engagement filtering.
    """

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._lock = asyncio.Lock()
        self._background_tasks: set[asyncio.Task[Any]] = set()

    async def broadcast(
        self,
        event_type: str,
        data: dict[str, Any],
        engagement_id: str | None = None,
        event_id: str | None = None,
    ) -> None:
        """Broadcast an event to all active subscriber queues."""
        payload = {
            "id": event_id or f"evt_{int(datetime.now(UTC).timestamp() * 1000)}",
            "event": event_type,
            "engagement_id": engagement_id,
            "timestamp": utc_now_iso(),
            "data": data,
        }

        async with self._lock:
            dead_queues: set[asyncio.Queue[dict[str, Any]]] = set()
            for q in self._subscribers:
                try:
                    q.put_nowait(payload)
                except asyncio.QueueFull:
                    dead_queues.add(q)
                except Exception:
                    dead_queues.add(q)

            self._subscribers.difference_update(dead_queues)

    def broadcast_nowait(
        self,
        event_type: str,
        data: dict[str, Any],
        engagement_id: str | None = None,
        event_id: str | None = None,
    ) -> None:
        """Fire-and-forget sync helper for broadcasting from synchronous contexts."""
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(
                self.broadcast(
                    event_type=event_type,
                    data=data,
                    engagement_id=engagement_id,
                    event_id=event_id,
                )
            )
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
        except RuntimeError:
            pass

    async def subscribe(
        self, engagement_id: str | None = None, max_queue_size: int = 256
    ) -> AsyncIterator[dict[str, Any]]:
        """Subscribe to events with optional engagement_id filtering."""
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=max_queue_size)
        async with self._lock:
            self._subscribers.add(q)

        try:
            # Initial connection confirmation
            yield {
                "id": f"init_{int(datetime.now(UTC).timestamp() * 1000)}",
                "event": "connected",
                "engagement_id": engagement_id,
                "timestamp": utc_now_iso(),
                "data": {"status": "connected", "scope": engagement_id or "global"},
            }

            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15.0)
                    if engagement_id is None or event.get("engagement_id") in (
                        None,
                        engagement_id,
                        "",
                    ):
                        yield event
                except TimeoutError:
                    # Heartbeat keepalive
                    yield {
                        "id": f"ping_{int(datetime.now(UTC).timestamp() * 1000)}",
                        "event": "ping",
                        "engagement_id": engagement_id,
                        "timestamp": utc_now_iso(),
                        "data": {"ping": True},
                    }
        finally:
            async with self._lock:
                self._subscribers.discard(q)


# Singleton instance
_broadcaster: EventBroadcaster | None = None


def get_event_broadcaster() -> EventBroadcaster:
    """Get or create singleton EventBroadcaster."""
    global _broadcaster
    if _broadcaster is None:
        _broadcaster = EventBroadcaster()
    return _broadcaster


def format_sse(event: dict[str, Any]) -> str:
    """Format an event dictionary into SSE wire protocol."""
    event_id = event.get("id", "")
    event_name = event.get("event", "message")
    data_str = json.dumps(event)
    return f"id: {event_id}\nevent: {event_name}\ndata: {data_str}\n\n"
