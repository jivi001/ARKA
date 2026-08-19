"""Security tests proving audit trail immutability and secret safety.

Verifies:
- Append-only operations
- Absence of UPDATE and DELETE methods on AuditService
- Defensive copying (callers cannot mutate internal audit logs)
- Preservation of correlation IDs and metadata
- Automatic redaction of sensitive credentials (api_key, password, tokens, etc.)
"""

import pytest

from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService


class TestAuditImmutability:
    @pytest.mark.asyncio
    async def test_no_update_or_delete_methods(self):
        service = AuditService()
        assert not hasattr(service, "update")
        assert not hasattr(service, "delete")
        assert not hasattr(service, "remove")
        assert not hasattr(service, "clear")
        assert not hasattr(service, "modify")

    @pytest.mark.asyncio
    async def test_defensive_copies_prevent_external_tampering(self):
        service = AuditService()

        # Record initial event
        await service.record_action(
            event_type=AuditEventType.TOOL_EXECUTED,
            actor="test_actor",
            action="scan",
            engagement_id="eng-tamper-1",
            parameters={"target": "10.0.0.1"},
            result_status="success",
        )

        # Retrieve events
        events_1 = await service.get_events(engagement_id="eng-tamper-1")
        assert len(events_1) == 1

        # Attempt to tamper with retrieved event list
        events_1.clear()
        events_2 = await service.get_events(engagement_id="eng-tamper-1")
        assert len(events_2) == 1  # Internal list was unaffected

        # Attempt to tamper with event attributes
        events_2[0].actor = "malicious_actor"
        events_3 = await service.get_events(engagement_id="eng-tamper-1")
        assert events_3[0].actor == "test_actor"  # Internal event was unaffected

    @pytest.mark.asyncio
    async def test_correlation_id_preserved(self):
        service = AuditService()
        correlation_id = "corr-xyz-12345"

        await service.record_action(
            event_type=AuditEventType.POLICY_DECISION,
            actor="policy_engine",
            action="evaluate:echo",
            engagement_id="eng-corr-1",
            correlation_id=correlation_id,
        )

        events = await service.get_events(engagement_id="eng-corr-1")
        assert len(events) == 1
        assert events[0].correlation_id == correlation_id

    @pytest.mark.asyncio
    async def test_sensitive_secrets_are_redacted(self):
        service = AuditService()

        sensitive_params = {
            "target": "example.com",
            "api_key": "sk-super-secret-production-key",
            "password": "SuperSecretPassword123!",
            "auth_token": "bearer-token-abc",
            "nested_config": {
                "vault_token": "vault-root-token",
                "normal_setting": "enabled",
            },
            "list_config": [
                {"secret": "nested-secret-value"},
                "plain_string",
            ],
        }

        await service.record_action(
            event_type=AuditEventType.TOOL_REQUESTED,
            actor="user",
            action="scan",
            engagement_id="eng-secret-1",
            parameters=sensitive_params,
        )

        events = await service.get_events(engagement_id="eng-secret-1")
        assert len(events) == 1
        recorded_params = events[0].parameters

        # Verify sensitive values are redacted
        assert recorded_params["api_key"] == "[REDACTED]"
        assert recorded_params["password"] == "[REDACTED]"
        assert recorded_params["auth_token"] == "[REDACTED]"
        assert recorded_params["nested_config"]["vault_token"] == "[REDACTED]"
        assert recorded_params["nested_config"]["normal_setting"] == "enabled"
        assert recorded_params["list_config"][0]["secret"] == "[REDACTED]"
        assert recorded_params["list_config"][1] == "plain_string"

        # Verify raw secret strings are nowhere in the event dump
        dump_str = str(events[0].model_dump())
        assert "sk-super-secret-production-key" not in dump_str
        assert "SuperSecretPassword123!" not in dump_str
        assert "vault-root-token" not in dump_str
