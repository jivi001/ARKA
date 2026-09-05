"""Integration test for full Phase 2 Autonomous Workflow (Phase 2.2.11 & 2.2.12).

Validates the complete autonomous reconnaissance and validation lifecycle:
1. Scope boundary configuration (ScopeGuard + PolicyEngine).
2. Passive enumeration via Amass (subdomains + IP discovery).
3. Port and service discovery via Nmap.
4. Web technology fingerprinting via WhatWeb.
5. Endpoint fuzzing and path discovery via ffuf.
6. Vulnerability scanning via Nuclei.
7. Multi-tool data aggregation and conflict resolution via CorrelationEngine.
8. Vulnerability triage and false-positive elimination via ValidationAgent.
9. Cryptographic provenance verification via EvidenceStore (SHA-256 hashes).
10. Invariant enforcement: DISCOVERED != AUTHORIZED.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from arka.app.agents.validation.agent import ValidationAgent
from arka.app.agents.validation.models import FindingValidationStatus
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.models import FindingStatus
from arka.app.core.assets.normalizer import AssetNormalizer
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.correlation import CorrelationEngine
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import PolicyDecisionType, ScopeDefinition, ScopeTarget, new_id
from arka.app.execution.evidence import EvidenceStore
from arka.app.execution.manager import ExecutionManager
from arka.app.execution.sandbox.local import LocalSafeRuntime
from arka.app.llm.gateway.gateway import LLMGateway
from arka.app.tools.amass.definition import register_amass_tool
from arka.app.tools.amass.parser import parse_amass_json
from arka.app.tools.ffuf.definition import register_ffuf_tool
from arka.app.tools.ffuf.parser import parse_ffuf_json
from arka.app.tools.nmap.definition import register_nmap_tool
from arka.app.tools.nmap.parser import parse_nmap_xml
from arka.app.tools.nuclei.definition import register_nuclei_tool
from arka.app.tools.nuclei.parser import parse_nuclei_json
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import CandidateToolRequest
from arka.app.tools.whatweb.definition import register_whatweb_tool
from arka.app.tools.whatweb.parser import parse_whatweb_json


@pytest.fixture
def phase2_e2e_scope() -> ScopeDefinition:
    return ScopeDefinition(
        engagement_id="eng-phase2-e2e",
        includes=ScopeTarget(
            domains=["example.corp", "app.example.corp"],
            ip_addresses=["192.168.1.100"],
            cidrs=["192.168.1.0/24"],
            ports=[80, 443, 8080],
        ),
        excludes=ScopeTarget(ip_addresses=["192.168.1.254"]),
    )


@pytest.fixture
def phase2_e2e_environment(phase2_e2e_scope: ScopeDefinition):
    guard = ScopeGuard(phase2_e2e_scope)
    policy = PolicyEngine(guard)
    audit = AuditService()
    approvals = ApprovalManager()
    evidence_store = EvidenceStore()
    runtime = LocalSafeRuntime()
    exec_manager = ExecutionManager(
        audit_service=audit,
        runtime=runtime,
        evidence_store=evidence_store,
    )
    registry = ToolRegistry(
        policy_engine=policy,
        audit_service=audit,
        approval_manager=approvals,
        execution_manager=exec_manager,
    )

    # Register all Phase 2 tools
    register_nmap_tool(registry)
    register_nuclei_tool(registry)
    register_ffuf_tool(registry)
    register_whatweb_tool(registry)
    register_amass_tool(registry)

    repo = InMemoryAssetRepository()
    normalizer = AssetNormalizer()
    llm = LLMGateway(audit_service=audit)

    validation_agent = ValidationAgent(
        llm_gateway=llm,
        tool_registry=registry,
        audit_service=audit,
        scope_guard=guard,
        policy_engine=policy,
        approval_manager=approvals,
        asset_repository=repo,
    )

    correlation_engine = CorrelationEngine()

    return SimpleNamespace(
        scope=phase2_e2e_scope,
        guard=guard,
        policy=policy,
        audit=audit,
        approvals=approvals,
        evidence_store=evidence_store,
        registry=registry,
        repo=repo,
        normalizer=normalizer,
        llm=llm,
        validation_agent=validation_agent,
        correlation_engine=correlation_engine,
    )


@pytest.mark.asyncio
async def test_phase2_full_workflow_lifecycle(phase2_e2e_environment) -> None:
    """Execute the full Phase 2 autonomous reconnaissance and validation pipeline."""
    env = phase2_e2e_environment
    engagement_id = env.scope.engagement_id

    # -------------------------------------------------------------------------
    # STEP 1: Passive Subdomain & IP Discovery (Amass)
    # -------------------------------------------------------------------------
    amass_output = (
        '{"name": "app.example.corp", "domain": "example.corp", '
        '"addresses": [{"ip": "192.168.1.100"}], "tag": "dns"}\n'
        '{"name": "partner.external.net", "domain": "external.net", '
        '"addresses": [{"ip": "10.50.0.1"}], "tag": "dns"}\n'
    )
    amass_result = parse_amass_json(amass_output, domain="example.corp")
    amass_bundle = env.normalizer.normalize_amass_result(
        result=amass_result,
        engagement_id=engagement_id,
        target="example.corp",
    )
    env.repo.save_bundle(amass_bundle)

    # Invariant check: Both saved as discovered
    all_assets = env.repo.get_assets_by_engagement(engagement_id)
    assert len(all_assets) >= 2
    in_scope_asset = next(a for a in all_assets if a.hostname == "app.example.corp")
    out_scope_asset = next(a for a in all_assets if a.hostname == "partner.external.net")
    assert in_scope_asset.status == "discovered"
    assert out_scope_asset.status == "discovered"

    # Out of scope invariant check: ScopeGuard rejects out-of-scope asset
    cand_out = CandidateToolRequest(
        tool_name="nuclei",
        target=out_scope_asset.hostname or "partner.external.net",
        arguments={},
        reason="Unauthorized scan attempt",
    )
    auth_req, decision, err = env.registry.validate_candidate_request(
        candidate=cand_out,
        engagement_id=engagement_id,
        task_id=new_id(),
        agent_id="recon-agent",
    )
    assert auth_req is None
    assert decision is not None
    assert decision.decision == PolicyDecisionType.DENY
    assert "out of scope" in (err or "").lower()

    # -------------------------------------------------------------------------
    # STEP 2: Active Port and Service Scan (Nmap) on authorized target
    # -------------------------------------------------------------------------
    nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" version="7.94">
      <host>
        <status state="up"/>
        <address addr="192.168.1.100" addrtype="ipv4"/>
        <hostnames><hostname name="app.example.corp" type="user"/></hostnames>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache httpd" version="2.4.49"/>
          </port>
          <port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https" product="Apache httpd" version="2.4.49"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    nmap_result = parse_nmap_xml(nmap_xml)
    nmap_bundle = env.normalizer.normalize_nmap_result(
        result=nmap_result,
        engagement_id=engagement_id,
        target="192.168.1.100",
    )
    env.repo.save_bundle(nmap_bundle)

    # -------------------------------------------------------------------------
    # STEP 3: Web Technology Fingerprinting (WhatWeb)
    # -------------------------------------------------------------------------
    whatweb_json = json.dumps(
        [
            {
                "target": "http://192.168.1.100",
                "http_status": 200,
                "plugins": {
                    "Apache": {"version": ["2.4.49"]},
                    "PHP": {"version": ["7.4.3"]},
                    "WordPress": {"version": ["5.8"]},
                    "HTTPServer": {"string": ["Apache/2.4.49 (Unix)"]},
                },
            }
        ]
    )
    whatweb_result = parse_whatweb_json(whatweb_json, target="http://192.168.1.100")
    whatweb_bundle = env.normalizer.normalize_whatweb_result(
        result=whatweb_result,
        engagement_id=engagement_id,
        target="http://192.168.1.100",
    )
    env.repo.save_bundle(whatweb_bundle)

    # -------------------------------------------------------------------------
    # STEP 4: Web Endpoint and Directory Discovery (ffuf)
    # -------------------------------------------------------------------------
    ffuf_json = json.dumps(
        {
            "results": [
                {
                    "input": {"FUZZ": "login"},
                    "status": 200,
                    "length": 1200,
                    "url": "http://192.168.1.100/login",
                },
                {
                    "input": {"FUZZ": "admin"},
                    "status": 403,
                    "length": 300,
                    "url": "http://192.168.1.100/admin",
                },
                {
                    "input": {"FUZZ": "api"},
                    "status": 200,
                    "length": 850,
                    "url": "http://192.168.1.100/api",
                },
            ]
        }
    )
    ffuf_result = parse_ffuf_json(ffuf_json, target_url="http://192.168.1.100")
    ffuf_bundle = env.normalizer.normalize_ffuf_result(
        result=ffuf_result,
        engagement_id=engagement_id,
        target="http://192.168.1.100",
    )
    env.repo.save_bundle(ffuf_bundle)

    # -------------------------------------------------------------------------
    # STEP 5: Vulnerability Scanning (Nuclei)
    # -------------------------------------------------------------------------
    nuclei_jsonl = (
        '{"template-id": "cve-2021-41773", "info": {"name": "Apache 2.4.49 Path Traversal", '
        '"severity": "high", "description": "Known path traversal"}, '
        '"matched-at": "http://192.168.1.100/cgi-bin/.%2e/%2e%2e/etc/passwd"}\n'
    )
    nuclei_result = parse_nuclei_json(nuclei_jsonl, target="http://192.168.1.100")
    nuclei_bundle = env.normalizer.normalize_nuclei_result(
        result=nuclei_result,
        engagement_id=engagement_id,
        target="http://192.168.1.100",
    )
    env.repo.save_bundle(nuclei_bundle)

    # -------------------------------------------------------------------------
    # STEP 6: Multi-Tool Correlation & Conflict Resolution
    # -------------------------------------------------------------------------
    correlation_report = env.correlation_engine.correlate_repository(
        repository=env.repo,
        engagement_id=engagement_id,
    )
    assert len(correlation_report.bundle.assets) >= 1

    correlated_target = next(
        a for a in correlation_report.bundle.assets if a.address == "192.168.1.100"
    )
    assert correlated_target.hostname == "app.example.corp"

    # Verify services aggregated across scans
    services = env.repo.get_services_by_asset(correlated_target.asset_id)
    ports = [s.port for s in services]
    assert 80 in ports
    assert 443 in ports

    # Verify technologies merged from WhatWeb
    techs = env.repo.get_technologies_by_asset(correlated_target.asset_id)
    tech_names = [t.name for t in techs]
    assert "Apache" in tech_names
    assert "PHP" in tech_names
    assert "WordPress" in tech_names

    # Verify endpoints merged from ffuf
    endpoints = env.repo.get_endpoints_by_asset(correlated_target.asset_id)
    paths = [e.path for e in endpoints]
    assert "/login" in paths
    assert "/admin" in paths
    assert "/api" in paths

    # Verify findings captured
    findings = env.repo.get_findings_by_engagement(engagement_id)
    assert len(findings) >= 1
    cve_finding = next(f for f in findings if f.template_id == "cve-2021-41773")
    assert cve_finding.status == FindingStatus.OBSERVED

    # -------------------------------------------------------------------------
    # STEP 7: Autonomous Vulnerability Validation (ValidationAgent)
    # -------------------------------------------------------------------------
    plan_json = json.dumps(
        {
            "finding_id": cve_finding.finding_id,
            "reasoning": "Probe path traversal endpoint directly with safe payload",
            "actions": [
                {
                    "tool_name": "nuclei",
                    "target": "192.168.1.100",
                    "arguments": {"templates": ["cve-2021-41773"]},
                    "rationale": "Verify path traversal payload responses",
                }
            ],
        }
    )
    assessment_json = json.dumps(
        {
            "finding_id": cve_finding.finding_id,
            "status": "validated",
            "confidence": 0.98,
            "reasoning": "Root file contents confirmed in HTTP body, finding is genuine.",
        }
    )

    with patch("litellm.acompletion") as mock_complete:
        mock_complete.side_effect = [
            SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=plan_json))],
                model="gpt-4o",
                usage=SimpleNamespace(prompt_tokens=15, completion_tokens=15, total_tokens=30),
            ),
            SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=assessment_json))],
                model="gpt-4o",
                usage=SimpleNamespace(prompt_tokens=15, completion_tokens=15, total_tokens=30),
            ),
        ]

        assessment = await env.validation_agent.validate_finding(
            finding=cve_finding,
            authorized_scope={},
        )

        assert assessment.status == FindingValidationStatus.VALIDATED
        assert assessment.confidence >= 0.95

        # Verify repository was updated to VALIDATED
        validated_finding = env.repo.get_finding_by_id(cve_finding.finding_id)
        assert validated_finding is not None
        assert validated_finding.status == FindingStatus.VALIDATED

    # -------------------------------------------------------------------------
    # STEP 8: Evidence Provenance & Cryptographic Integrity Verification
    # -------------------------------------------------------------------------
    # Store evidence records for the tool execution runs
    ev1 = env.evidence_store.record_evidence(
        execution_id=new_id(),
        request_id=new_id(),
        engagement_id=engagement_id,
        task_id=new_id(),
        content=amass_output,
        tool_name="amass",
        metadata={"command_argv": ["amass", "enum", "-passive", "-d", "example.corp"]},
    )
    ev2 = env.evidence_store.record_evidence(
        execution_id=new_id(),
        request_id=new_id(),
        engagement_id=engagement_id,
        task_id=new_id(),
        content=nuclei_jsonl,
        tool_name="nuclei",
        metadata={"command_argv": ["nuclei", "-target", "http://192.168.1.100", "-jsonl"]},
    )

    # Validate SHA-256 calculation and immutable retrieval
    assert len(ev1.sha256) == 64
    assert len(ev2.sha256) == 64
    record1 = env.evidence_store.get_evidence(ev1.evidence_id)
    assert record1 is not None
    assert record1.sha256 == ev1.sha256
    assert record1.tool_name == "amass"
