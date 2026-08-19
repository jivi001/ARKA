import pytest
from arka.app.audit.schemas import AuditEvent, AuditEventType
from arka.app.audit.service import AuditService

class TestAuditService:
    @pytest.mark.asyncio
    async def test_record_event(self, audit_service: AuditService):
        event = AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTED,
            actor="system",
            action="executed",
            parameters={"tool": "echo_test"}
        )
        await audit_service.record(event)
        events = await audit_service.get_events()
        assert len(events) >= 1
        assert any(e.event_type == AuditEventType.TOOL_EXECUTED for e in events)

    @pytest.mark.asyncio
    async def test_record_action(self, audit_service: AuditService):
        await audit_service.record_action(
            event_type=AuditEventType.POLICY_DECISION,
            actor="system",
            action="evaluate",
            authorization_decision="allow"
        )
        events = await audit_service.get_events()
        assert any(e.event_type == AuditEventType.POLICY_DECISION for e in events)

    @pytest.mark.asyncio
    async def test_get_events_filter(self, audit_service: AuditService):
        await audit_service.record_action(
            event_type=AuditEventType.ENGAGEMENT_CREATED,
            actor="u1",
            action="create",
            engagement_id="1"
        )
        events = await audit_service.get_events(event_type=AuditEventType.ENGAGEMENT_CREATED)
        assert len(events) >= 1
        assert all(e.event_type == AuditEventType.ENGAGEMENT_CREATED for e in events)

    @pytest.mark.asyncio
    async def test_handler_called(self, audit_service: AuditService):
        handler_called = False
        async def mock_handler(event):
            nonlocal handler_called
            handler_called = True

        audit_service.add_handler(mock_handler)
        await audit_service.record_action(
            event_type=AuditEventType.TOOL_EXECUTED,
            actor="user",
            action="run"
        )
        assert handler_called is True

    @pytest.mark.asyncio
    async def test_events_immutable(self, audit_service: AuditService):
        await audit_service.record_action(
            event_type=AuditEventType.ENGAGEMENT_CREATED,
            actor="u1",
            action="create"
        )
        events = await audit_service.get_events()
        events.clear()
        events2 = await audit_service.get_events()
        assert len(events2) > 0
