"""Security test verifying that ApprovalManager strictly binds approvals to argument hashes
(SEC-01 mitigation).
"""

from arka.app.core.approvals.manager import ApprovalManager, compute_arguments_hash
from arka.app.core.state.models import RiskLevel


def test_compute_arguments_hash_deterministic():
    """Verify that argument hash computation is deterministic regardless of key order."""
    args1 = {"target": "10.0.0.1", "ports": [80, 443], "fast": True}
    args2 = {"fast": True, "ports": [80, 443], "target": "10.0.0.1"}

    hash1 = compute_arguments_hash(args1)
    hash2 = compute_arguments_hash(args2)

    assert hash1 == hash2
    assert len(hash1) == 64


def test_approval_valid_with_exact_arguments():
    """Verify that an approval is accepted when the exact same arguments are provided."""
    mgr = ApprovalManager()
    args = {"target": "example.com", "scan_type": "syn"}

    req = mgr.create_request(
        engagement_id="eng-1",
        task_id="task-1",
        agent_id="recon",
        action="nmap_scan",
        target="example.com",
        tool_name="nmap",
        risk_level=RiskLevel.HIGH,
        arguments=args,
        scope_version=1,
    )

    # Grant approval
    mgr.approve(req.approval_id, approved_by="lead_operator")

    # Validate with exact same arguments
    valid = mgr.validate_approval_for_request(
        approval_id=req.approval_id,
        engagement_id="eng-1",
        task_id="task-1",
        tool_name="nmap",
        target="example.com",
        scope_version=1,
        arguments=args,
    )
    assert valid is True


def test_approval_rejected_when_arguments_tampered_sec01():
    """Verify SEC-01 mitigation: tampered arguments cause validate_approval_for_request
    to return False.
    """
    mgr = ApprovalManager()
    original_args = {"target": "example.com", "mode": "safe_probe"}
    tampered_args = {"target": "example.com", "mode": "exploit_rce", "payload": "destructive"}

    req = mgr.create_request(
        engagement_id="eng-1",
        task_id="task-1",
        agent_id="recon",
        action="nmap_scan",
        target="example.com",
        tool_name="nmap",
        risk_level=RiskLevel.HIGH,
        arguments=original_args,
        scope_version=1,
    )

    mgr.approve(req.approval_id, approved_by="lead_operator")

    # Tampered arguments must fail approval validation
    tampered_valid = mgr.validate_approval_for_request(
        approval_id=req.approval_id,
        engagement_id="eng-1",
        task_id="task-1",
        tool_name="nmap",
        target="example.com",
        scope_version=1,
        arguments=tampered_args,
    )
    assert tampered_valid is False
