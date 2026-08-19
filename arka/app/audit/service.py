"""Append-only audit trail service for ARKA.

This is NOT metrics — it's an authoritative security/compliance record.
Events are immutable once recorded.
"""
import inspect
from typing import Callable, Optional, Any

from arka.app.audit.schemas import AuditEvent, AuditEventType


class AuditService:
    """Append-only audit trail for compliance and security.

    This is NOT metrics — it's an authoritative security/compliance record.
    Events are immutable once recorded.
    """

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []  # In-memory for Phase 1, DB-backed later
        self._handlers: list[Callable] = []

    async def record(self, event: AuditEvent) -> None:
        """Record an audit event. Append-only — events cannot be modified or deleted."""
        self._events.append(event)
        for handler in self._handlers:
            if inspect.iscoroutinefunction(handler):
                await handler(event)
            else:
                handler(event)

    async def record_action(
        self,
        *,
        event_type: AuditEventType,
        actor: str,
        action: str,
        engagement_id: str | None = None,
        task_id: str | None = None,
        agent_id: str | None = None,
        target: str | None = None,
        tool_name: str | None = None,
        authorization_decision: str | None = None,
        parameters: dict[str, Any] | None = None,
        result_status: str | None = None,
        error: str | None = None,
        evidence_ref: str | None = None,
        correlation_id: str | None = None,
    ) -> AuditEvent:
        """Convenience method to record an audit event with individual fields."""
        event = AuditEvent(
            event_type=event_type,
            actor=actor,
            action=action,
            engagement_id=engagement_id,
            task_id=task_id,
            agent_id=agent_id,
            target=target,
            tool_name=tool_name,
            authorization_decision=authorization_decision,
            parameters=parameters or {},
            result_status=result_status,
            error=error,
            evidence_ref=evidence_ref,
            correlation_id=correlation_id,
        )
        await self.record(event)
        return event

    async def get_events(self, engagement_id: Optional[str] = None, 
                         task_id: Optional[str] = None,
                         event_type: Optional[AuditEventType] = None,
                         limit: int = 100, offset: int = 0) -> list[AuditEvent]:
        filtered = self._events
        if engagement_id:
            filtered = [e for e in filtered if e.engagement_id == engagement_id]
        if task_id:
            filtered = [e for e in filtered if e.task_id == task_id]
        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]
            
        return filtered[offset:offset+limit]

    def add_handler(self, handler: Callable) -> None:
        """Add a handler that's called for every audit event (e.g., for logging)."""
        self._handlers.append(handler)
