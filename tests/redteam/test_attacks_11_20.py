"""
ARKA Red-Team Attack Suite — Attacks 11-20
Resource exhaustion, provider failover, evidence integrity,
privilege escalation, and fail-open behavior.
All tests use only in-memory fixtures. Zero real network calls.
"""

import asyncio
import hashlib
import json

import pytest

from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import (
    ApprovalStatus,
    RiskLevel,
    ScopeDefinition,
    ScopeTarget,
)
from arka.app.execution.evidence import EvidenceStore
from arka.app.execution.manager import ExecutionManager
from arka.app.execution.sandbox.local import LocalSafeRuntime
from arka.app.tools.mock.tools import (
    EchoToolExecutor,
    HighRiskMockToolExecutor,
    get_echo_tool_definition,
    get_high_risk_mock_tool_definition,
)
from arka.app.tools.registry.registry import ToolExecutor, ToolRegistry
from arka.app.tools.schemas.tool_schemas import (
    ToolDefinition,
    ToolRequest,
    ToolResult,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scope_def():
    return ScopeDefinition(
        engagement_id="rt-eng-2",
        includes=ScopeTarget(
            domains=["authorized.com"],
            ip_addresses=["10.0.0.5"],
            cidrs=["10.0.0.0/24"],
        ),
    )


@pytest.fixture
def guard(scope_def):
    return ScopeGuard(scope_def)


@pytest.fixture
def policy(guard):
    return PolicyEngine(guard)


@pytest.fixture
def audit():
    return AuditService()


@pytest.fixture
def approvals():
    return ApprovalManager()


@pytest.fixture
def registry(policy, audit, approvals):
    reg = ToolRegistry(
        policy_engine=policy,
        audit_service=audit,
        approval_manager=approvals,
        execution_manager=ExecutionManager(
            audit_service=audit,
            runtime=LocalSafeRuntime(),
        ),
    )
    reg.register(get_echo_tool_definition(), EchoToolExecutor())
    reg.register(get_high_risk_mock_tool_definition(), HighRiskMockToolExecutor())
    return reg


# ===========================================================================
# ATTACK 11 — Memory exhaustion via oversized argument string
# ===========================================================================
class TestAttack11_MemoryExhaustionOversizedArgument:
    """
    Attack: Pass a multi-megabyte string as an argument value.
    The schema validator only checks type (string), not length.
    The audit service stores the full parameters dict in memory.
    """

    @pytest.mark.asyncio
    async def test_oversized_string_argument_accepted(self, registry, audit):
        # 5 MB string — no length limit enforced by schema validator
        big_payload = "A" * (5 * 1024 * 1024)
        req = ToolRequest(
            engagement_id="rt-eng-2",
            task_id="task-1",
            agent_id="agent-rt",
            tool_name="echo_test",
            target="authorized.com",
            arguments={"message": big_payload},
            scope_validated=True,
            policy_approved=True,
        )
        result = await registry.execute(req)
        # The tool executes successfully — no size limit on arguments
        # The 5MB payload is stored in the audit trail
        events = await audit.get_events(engagement_id="rt-eng-2")
        # Check if the payload made it into audit storage
        found_in_audit = any(len(str(e.parameters)) > 1_000_000 for e in events)
        print(
            f"\n[ATTACK 11 FINDING] Oversized argument accepted. "
            f"result.success={result.success}. "
            f"Payload in audit storage: {found_in_audit}. "
            f"No string length limit enforced in _validate_arguments(). "
            f"Audit service stores full parameters in memory."
        )
        # This is a finding regardless of success/failure
        # No assertion failure — document the gap


# ===========================================================================
# ATTACK 12 — Concurrent execution without rate limiting
# ===========================================================================
class TestAttack12_ConcurrentExecutionNoRateLimit:
    """
    Attack: ToolDefinition has rate_limit_per_minute but ToolRegistry
    never enforces it. Launch many concurrent executions.
    """

    @pytest.mark.asyncio
    async def test_rate_limit_not_enforced(self, registry):
        """rate_limit_per_minute=60 on echo_test but no enforcement code exists."""
        tool_def = registry.get_tool("echo_test")
        assert tool_def is not None
        assert tool_def.rate_limit_per_minute == 60

        # Launch 100 concurrent requests — far exceeding the declared limit
        async def single_exec(i):
            req = ToolRequest(
                engagement_id="rt-eng-2",
                task_id=f"task-{i}",
                agent_id="agent-rt",
                tool_name="echo_test",
                target="authorized.com",
                arguments={"message": f"concurrent-{i}"},
                scope_validated=True,
                policy_approved=True,
            )
            return await registry.execute(req)

        results = await asyncio.gather(*[single_exec(i) for i in range(100)])
        success_count = sum(1 for r in results if r.success)

        # All 100 succeed — rate limit is declared but never enforced
        assert success_count == 100, (
            f"Unexpected: only {success_count}/100 succeeded. "
            "Rate limiting may be partially enforced."
        )
        print(
            "\n[ATTACK 12 FINDING] rate_limit_per_minute is declared on ToolDefinition "
            "but never enforced by ToolRegistry. All 100 concurrent requests succeeded. "
            "No token bucket, no counter, no rejection."
        )


# ===========================================================================
# ATTACK 13 — Evidence store: SHA-256 computed over mutable dict
# ===========================================================================
class TestAttack13_EvidenceIntegrityMutableContent:
    """
    Attack: EvidenceStore.record_evidence() accepts a dict, serializes it
    with json.dumps(sort_keys=True), and hashes the result. The raw blob
    stored is the serialized bytes. But the EvidenceReference.metadata dict
    is mutable — an attacker with access to the EvidenceStore object can
    modify metadata after recording without invalidating the hash.
    """

    def test_metadata_mutation_after_recording(self):
        store = EvidenceStore()
        content = {"scan_result": "open port 80", "target": "authorized.com"}
        ref = store.record_evidence(
            execution_id="exec-1",
            request_id="req-1",
            engagement_id="rt-eng-2",
            task_id="task-1",
            content=content,
            metadata={"tool": "nmap", "version": "7.95"},
        )

        # Mutate the metadata on the returned reference
        ref.metadata["injected"] = "malicious_data"
        ref.metadata["tool"] = "TAMPERED"

        # verify_integrity checks raw blob hash — metadata is NOT part of the blob
        integrity_ok = store.verify_integrity(ref.evidence_id)

        # Hash still matches because metadata is not hashed
        assert integrity_ok is True
        # But metadata has been tampered
        assert ref.metadata["tool"] == "TAMPERED"

        print(
            "\n[ATTACK 13 FINDING] EvidenceReference.metadata is mutable after recording. "
            "SHA-256 is computed over content only, not metadata. "
            "Metadata (tool name, version, target) can be tampered without "
            "invalidating the integrity check."
        )

    def test_evidence_reference_content_hash_covers_content_only(self):
        """Confirm the hash covers content, not the full EvidenceReference."""
        store = EvidenceStore()
        content = {"result": "vulnerable"}
        ref = store.record_evidence(
            execution_id="exec-2",
            request_id="req-2",
            engagement_id="rt-eng-2",
            task_id="task-1",
            content=content,
        )
        # Manually compute expected hash
        blob = json.dumps(content, sort_keys=True).encode("utf-8")
        expected = hashlib.sha256(blob).hexdigest()
        assert ref.sha256 == expected
        # The evidence_id, execution_id, engagement_id are NOT covered by the hash
        print(
            "\n[ATTACK 13 NOTE] SHA-256 covers content bytes only. "
            "Provenance fields (execution_id, engagement_id, task_id) are not hashed."
        )


# ===========================================================================
# ATTACK 14 — AuditService in-memory only: no persistence across restarts
# ===========================================================================
class TestAttack14_AuditServiceVolatileStorage:
    """
    Attack: AuditService stores events in self._events (a plain Python list).
    On process restart, all audit records are lost. There is no database
    persistence for audit events in Phase 1.
    """

    @pytest.mark.asyncio
    async def test_audit_events_lost_on_new_instance(self):
        svc1 = AuditService()
        from arka.app.audit.schemas import AuditEventType

        await svc1.record_action(
            event_type=AuditEventType.TOOL_EXECUTED,
            actor="agent",
            action="scan",
            engagement_id="rt-eng-2",
        )
        events_before = await svc1.get_events(engagement_id="rt-eng-2")
        assert len(events_before) == 1

        # Simulate restart: new instance has no events
        svc2 = AuditService()
        events_after = await svc2.get_events(engagement_id="rt-eng-2")
        assert len(events_after) == 0

        print(
            "\n[ATTACK 14 FINDING] AuditService is in-memory only. "
            "All audit records are lost on process restart. "
            "No database persistence for audit events in Phase 1. "
            "Compliance and forensic requirements cannot be met."
        )


# ===========================================================================
# ATTACK 15 — Bypass approval via find_matching_request REQUIRED status
# ===========================================================================
class TestAttack15_ApprovalBypassViaRequiredStatus:
    """
    Attack: find_matching_request() returns requests with status REQUIRED
    (not yet approved). The orchestrator uses this to find an existing
    approval request and reuses its approval_id. If the interrupt response
    claims 'approved' but the ApprovalManager.approve() call is wrapped in
    contextlib.suppress(ValueError), a failed approval silently continues.
    """

    def test_find_matching_request_returns_required_status(self, approvals):
        """find_matching_request returns REQUIRED (unapproved) requests."""
        req = approvals.create_request(
            engagement_id="rt-eng-2",
            task_id="task-1",
            agent_id="agent-rt",
            action="execute_tool:high_risk_mock",
            target="authorized.com",
            tool_name="high_risk_mock",
            risk_level=RiskLevel.HIGH,
        )
        # Status is REQUIRED — not yet approved
        assert req.status == ApprovalStatus.REQUIRED

        found = approvals.find_matching_request(
            engagement_id="rt-eng-2",
            task_id="task-1",
            tool_name="high_risk_mock",
            target="authorized.com",
        )
        assert found is not None
        assert found.status == ApprovalStatus.REQUIRED

        # The orchestrator reuses this approval_id even though it's REQUIRED
        # Then calls validate_approval_for_request which checks status == GRANTED
        # So this specific path is safe — but the suppress(ValueError) is the risk
        print(
            "\n[ATTACK 15 NOTE] find_matching_request returns REQUIRED requests. "
            "The orchestrator reuses the approval_id. validate_approval_for_request "
            "correctly requires GRANTED status. The suppress(ValueError) in "
            "tool_request_node means a failed approve() call is silently ignored, "
            "but the subsequent validate_approval_for_request still blocks execution."
        )

    def test_suppress_on_approve_failure_does_not_grant(self, approvals):
        """
        In tool_request_node, approve() is called inside contextlib.suppress(ValueError).
        If approve() raises (e.g., already rejected), the exception is swallowed.
        The subsequent validate_approval_for_request still checks GRANTED status.
        """
        import contextlib

        req = approvals.create_request(
            engagement_id="rt-eng-2",
            task_id="task-1",
            agent_id="agent-rt",
            action="execute_tool:high_risk_mock",
            target="authorized.com",
            tool_name="high_risk_mock",
            risk_level=RiskLevel.HIGH,
        )
        # Reject it first
        approvals.reject(req.approval_id, "human", "denied")

        # Now simulate what tool_request_node does: suppress ValueError from approve()
        with contextlib.suppress(ValueError):
            approvals.approve(req.approval_id, "human_operator")

        # Approval is still REJECTED — suppress did not grant it
        final = approvals.get_request(req.approval_id)
        assert final.status == ApprovalStatus.REJECTED

        # validate_approval_for_request will return False
        valid = approvals.validate_approval_for_request(
            approval_id=req.approval_id,
            engagement_id="rt-eng-2",
            task_id="task-1",
            tool_name="high_risk_mock",
            target="authorized.com",
        )
        assert valid is False
        print("\n[ATTACK 15 RESULT] suppress(ValueError) does not grant approval. Boundary holds.")


# ===========================================================================
# ATTACK 16 — Executor crash causes unhandled exception leak
# ===========================================================================
class TestAttack16_ExecutorCrashInformationLeak:
    """
    Attack: A crashing executor raises an exception with internal details.
    ExecutionManager catches it and puts str(e) into the error field of
    ToolResult, which is returned to the orchestrator and logged.
    Internal paths, stack details, or sensitive data in exception messages
    could leak through the error field.
    """

    @pytest.mark.asyncio
    async def test_executor_exception_message_in_tool_result(self, audit):
        class LeakingExecutor(ToolExecutor):
            async def execute(self, request, definition):
                raise RuntimeError(
                    f"DB connection failed: postgresql://arka:SECRET_PASSWORD@db:5432/arka "
                    f"for target {request.target}"
                )

        guard = ScopeGuard(
            ScopeDefinition(
                engagement_id="rt-eng-2",
                includes=ScopeTarget(domains=["authorized.com"]),
            )
        )
        pol = PolicyEngine(guard)
        reg = ToolRegistry(
            policy_engine=pol,
            audit_service=audit,
            execution_manager=ExecutionManager(audit_service=audit, runtime=LocalSafeRuntime()),
        )
        tool_def = ToolDefinition(
            name="leaking_tool",
            description="Leaks internal info on crash",
            input_schema={"type": "object", "properties": {}, "required": []},
            output_schema={"type": "object"},
            risk_level=RiskLevel.LOW,
        )
        reg.register(tool_def, LeakingExecutor())

        req = ToolRequest(
            engagement_id="rt-eng-2",
            task_id="task-1",
            agent_id="agent-rt",
            tool_name="leaking_tool",
            target="authorized.com",
            arguments={},
            scope_validated=True,
            policy_approved=True,
        )
        result = await reg.execute(req)
        assert result.success is False
        # The raw exception message is in result.error
        assert "SECRET_PASSWORD" in (result.error or ""), (
            "Exception message not propagated — check if sanitization was added."
        )
        print(
            f"\n[ATTACK 16 FINDING] Executor exception message propagated verbatim "
            f"to ToolResult.error. Sensitive data in exception messages leaks to "
            f"the orchestrator and audit trail. "
            f"error={result.error[:80] if result.error else None}"
        )


# ===========================================================================
# ATTACK 17 — Schema validation bypass: tool with empty input_schema
# ===========================================================================
class TestAttack17_EmptySchemaBypassesValidation:
    """
    Attack: A ToolDefinition with input_schema={} (empty dict, no 'properties')
    causes _validate_arguments to return None immediately (no validation).
    Any arguments, including injection payloads, pass through unchecked.
    """

    @pytest.mark.asyncio
    async def test_empty_schema_accepts_arbitrary_arguments(self, policy, audit):
        guard = ScopeGuard(
            ScopeDefinition(
                engagement_id="rt-eng-2",
                includes=ScopeTarget(domains=["authorized.com"]),
            )
        )
        pol = PolicyEngine(guard)
        reg = ToolRegistry(
            policy_engine=pol,
            audit_service=audit,
            execution_manager=ExecutionManager(audit_service=audit, runtime=LocalSafeRuntime()),
        )

        class PassthroughExecutor(ToolExecutor):
            async def execute(self, request, definition):
                return ToolResult(
                    request_id=request.request_id,
                    engagement_id=request.engagement_id,
                    task_id=request.task_id,
                    tool_name=request.tool_name,
                    success=True,
                    output={"received_args": request.arguments},
                )

        empty_schema_tool = ToolDefinition(
            name="empty_schema_tool",
            description="Tool with empty schema",
            input_schema={},  # ATTACK: empty schema — no validation
            output_schema={},
            risk_level=RiskLevel.LOW,
        )
        reg.register(empty_schema_tool, PassthroughExecutor())

        from arka.app.tools.schemas.tool_schemas import CandidateToolRequest

        candidate = CandidateToolRequest(
            tool_name="empty_schema_tool",
            target="authorized.com",
            arguments={
                "--script": "http-sql-injection",  # injection attempt
                "-oN": "/tmp/out.txt",
                "arbitrary_key": "arbitrary_value",
                "nested": {"deep": "injection"},
            },
        )
        _req, _dec, _err = reg.validate_candidate_request(
            candidate, "rt-eng-2", "task-1", "agent-rt"
        )
        assert _req is not None, (
            "ATTACK 17 SUCCEEDED: Empty input_schema allows arbitrary arguments "
            "including injection payloads to pass validation unchecked."
        )
        print(
            "\n[ATTACK 17 FINDING] ToolDefinition with empty input_schema={} bypasses "
            "_validate_arguments entirely. Any arguments pass through. "
            "Tools registered without a proper schema have no argument validation."
        )


# ===========================================================================
# ATTACK 18 — Nmap executor: target injected into simulated XML
# ===========================================================================
class TestAttack18_NmapTargetXmlInjection:
    """
    Attack: NmapToolExecutor formats the simulated XML with the target string:
        simulated_xml = _SIMULATED_NMAP_XML.format(target=request.target)
    If target contains XML special characters or format string sequences,
    this could corrupt the XML or cause a format error.
    """

    @pytest.mark.asyncio
    async def test_xml_special_chars_in_target(self):
        from arka.app.tools.nmap.definition import get_nmap_tool_definition
        from arka.app.tools.nmap.executor import NmapToolExecutor

        executor = NmapToolExecutor()
        defn = get_nmap_tool_definition()

        # Target with XML special characters
        malicious_target = '<script>alert(1)</script>&evil;"quoted"'
        req = ToolRequest(
            engagement_id="rt-eng-2",
            task_id="task-1",
            agent_id="agent-rt",
            tool_name="nmap",
            target=malicious_target,
            arguments={"ports": "80"},
            scope_validated=True,
            policy_approved=True,
        )
        try:
            result = await executor.execute(req, defn)
            # If it succeeds, the XML was malformed but defusedxml may have caught it
            print(
                f"\n[ATTACK 18 FINDING] XML special chars in target: "
                f"success={result.success}, error={result.error}"
            )
        except Exception as e:
            print(f"\n[ATTACK 18 FINDING] Unhandled exception with XML chars in target: {e}")

    @pytest.mark.asyncio
    async def test_format_string_braces_in_target(self):
        from arka.app.tools.nmap.definition import get_nmap_tool_definition
        from arka.app.tools.nmap.executor import NmapToolExecutor

        executor = NmapToolExecutor()
        defn = get_nmap_tool_definition()

        # Target with Python format string braces — could cause KeyError in .format()
        malicious_target = "10.0.0.1{evil_key}"
        req = ToolRequest(
            engagement_id="rt-eng-2",
            task_id="task-1",
            agent_id="agent-rt",
            tool_name="nmap",
            target=malicious_target,
            arguments={"ports": "80"},
            scope_validated=True,
            policy_approved=True,
        )
        try:
            result = await executor.execute(req, defn)
            print(
                f"\n[ATTACK 18 FINDING] Format string in target: "
                f"success={result.success}, error={result.error}"
            )
        except KeyError as e:
            pytest.fail(
                f"ATTACK 18 SUCCEEDED: Format string in target caused KeyError: {e}. "
                "The .format(target=...) call in NmapToolExecutor is vulnerable to "
                "KeyError when target contains brace sequences like {{evil_key}}."
            )


# ===========================================================================
# ATTACK 19 — Engagement store: global mutable dict shared across requests
# ===========================================================================
class TestAttack19_GlobalEngagementStoreMutation:
    """
    Attack: The engagement API uses a module-level dict `_engagements`.
    This is shared across all test clients and requests in the same process.
    An attacker who can create an engagement can overwrite another engagement's
    state by guessing or brute-forcing the UUID.
    More critically: the EngagementState object is mutated in-place by the
    start/pause/stop endpoints without any locking — race conditions possible.
    """

    def test_engagement_state_mutated_in_place(self):
        from fastapi.testclient import TestClient

        from arka.app.api import create_app

        app = create_app()
        client = TestClient(app)

        # Create engagement
        resp = client.post(
            "/engagements",
            json={
                "name": "RT Test",
                "scope": {"includes": {"domains": ["authorized.com"]}},
            },
        )
        assert resp.status_code == 201
        eng_id = resp.json()["engagement_id"]

        # Start it
        client.post(f"/engagements/{eng_id}/start")

        # The EngagementState object in _engagements is mutated directly
        # No copy-on-write, no versioning, no optimistic locking
        # Concurrent pause+stop could leave state inconsistent
        print(
            "\n[ATTACK 19 FINDING] _engagements is a module-level mutable dict. "
            "EngagementState is mutated in-place with no locking. "
            "Concurrent requests can cause race conditions. "
            "No database persistence — state lost on restart."
        )

    def test_engagement_store_not_isolated_between_test_runs(self):
        """Module-level _engagements persists across TestClient instances in same process."""
        from fastapi.testclient import TestClient

        from arka.app.api import create_app
        from arka.app.api.routes import engagements as eng_module

        initial_count = len(eng_module._engagements)

        app = create_app()
        client = TestClient(app)
        client.post("/engagements", json={"name": "Leak Test"})

        # The engagement was added to the module-level dict
        assert len(eng_module._engagements) > initial_count
        print(
            "\n[ATTACK 19 FINDING] Module-level _engagements leaks state between "
            "test runs and concurrent requests. No isolation between clients."
        )


# ===========================================================================
# ATTACK 20 — ExecutionManager flag bypass
# ===========================================================================
class TestAttack20_ExecutionManagerFlagBypass:
    @pytest.mark.asyncio
    async def test_execution_manager_requires_stamped_flags(self, audit, scope_def):
        """
        ToolRegistry.execute() stamps scope_validated=True and policy_approved=True
        BEFORE calling ExecutionManager.execute_tool().
        """
        guard = ScopeGuard(scope_def)
        policy = PolicyEngine(guard)
        approvals = ApprovalManager()
        registry = ToolRegistry(policy, audit, approvals)
        registry.register(get_echo_tool_definition(), EchoToolExecutor())

        # An unstamped ToolRequest
        req = ToolRequest(
            engagement_id="rt-eng-2",
            task_id="task-1",
            agent_id="agent-rt",
            tool_name="echo_test",
            target="authorized.com",
            arguments={"message": "test"},
            scope_validated=False,
            policy_approved=False,
        )

        assert req.scope_validated is False
        assert req.policy_approved is False

        _result = await registry.execute(req)

        assert req.scope_validated is True, (
            "Registry stamps scope_validated=True on the mutable ToolRequest object."
        )

    @pytest.mark.asyncio
    async def test_execution_manager_rejects_unstamped_request_directly(self, audit):
        """
        ExecutionManager.execute_tool() is the last line of defense.
        """
        from arka.app.execution.manager import ExecutionManager
        from arka.app.execution.sandbox.local import LocalSafeRuntime

        mgr = ExecutionManager(audit_service=audit, runtime=LocalSafeRuntime())
        tool_def = get_echo_tool_definition()
        executor = EchoToolExecutor()

        req = ToolRequest(
            engagement_id="rt-eng-2",
            task_id="task-1",
            agent_id="agent-rt",
            tool_name="echo_test",
            target="authorized.com",
            arguments={"message": "test"},
            scope_validated=False,
            policy_approved=False,
        )

        _exec_result, tool_result = await mgr.execute_tool(req, tool_def, executor)
        assert tool_result.success is False
        assert (
            "not scope-validated" in (tool_result.error or "").lower()
            or "scope" in (tool_result.error or "").lower()
        ), f"ExecutionManager should reject unstamped request. Got: {tool_result.error}"
        print(
            "\n[ATTACK 20 RESULT] ExecutionManager correctly rejects unstamped requests "
            "when called directly. The boolean flag check is a valid last-resort guard."
        )
