"""Append-only audit trail service for ARKA.

This is an authoritative security/compliance record, NOT metrics.
Events are strictly append-only and immutable once recorded.
No UPDATE or DELETE methods exist on this service.
"""

import inspect
from collections.abc import Callable
from copy import deepcopy
from typing import Any, ClassVar

from arka.app.audit.schemas import AuditEvent, AuditEventType


class AuditService:
    """Append-only audit trail for compliance and security.

    Events are immutable once recorded.
    Defensive copies are returned to prevent mutation of internal state.
    Sensitive parameters and secrets are automatically redacted.
    """

    SENSITIVE_KEYS: ClassVar[set[str]] = {
        "api_key",
        "apikey",
        "authorization",
        "auth_token",
        "token",
        "secret",
        "password",
        "vault_token",
        "private_key",
    }

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._handlers: list[Callable] = []

    def _redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively redact sensitive keys from dictionary data."""
        clean: dict[str, Any] = {}
        for k, v in data.items():
            if k.lower() in self.SENSITIVE_KEYS:
                clean[k] = "[REDACTED]"
            elif isinstance(v, dict):
                clean[k] = self._redact_dict(v)
            elif isinstance(v, list):
                clean[k] = [
                    self._redact_dict(item) if isinstance(item, dict) else item for item in v
                ]
            else:
                clean[k] = v
        return clean

    async def record(self, event: AuditEvent) -> None:
        """Record an audit event. Append-only — events cannot be modified or deleted."""
        # Sanitize parameters and metadata
        event_dict = event.model_dump()
        if "parameters" in event_dict and isinstance(event_dict["parameters"], dict):
            event_dict["parameters"] = self._redact_dict(event_dict["parameters"])
        if "metadata" in event_dict and isinstance(event_dict["metadata"], dict):
            event_dict["metadata"] = self._redact_dict(event_dict["metadata"])

        sanitized_event = AuditEvent(**event_dict)
        self._events.append(sanitized_event)

        for handler in self._handlers:
            try:
                if inspect.iscoroutinefunction(handler):
                    await handler(sanitized_event)
                else:
                    handler(sanitized_event)
            except Exception:
                pass

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
        sanitized_params = self._redact_dict(parameters) if parameters else {}
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
            parameters=sanitized_params,
            result_status=result_status,
            error=error,
            evidence_ref=evidence_ref,
            correlation_id=correlation_id,
        )
        await self.record(event)
        return deepcopy(event)

    async def get_events(
        self,
        engagement_id: str | None = None,
        task_id: str | None = None,
        event_type: AuditEventType | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        """Get defensive copies of recorded audit events."""
        filtered = self._events
        if engagement_id:
            filtered = [e for e in filtered if e.engagement_id == engagement_id]
        if task_id:
            filtered = [e for e in filtered if e.task_id == task_id]
        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]

        # Return deep copies so callers cannot mutate the internal list or models
        return [deepcopy(e) for e in filtered[offset : offset + limit]]

    def add_handler(self, handler: Callable) -> None:
        """Add a handler that's called for every audit event."""
        self._handlers.append(handler)
