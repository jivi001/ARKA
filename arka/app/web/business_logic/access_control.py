"""Access-Control and IDOR/BOLA Analysis Engine for ARKA Phase 3.8.3 & 3.8.4.

Enforces:
1. Horizontal access-control differences (IDOR/BOLA) between controlled test identities.
2. Vertical access-control differences (Privilege Escalation) between User and Admin roles.
3. Unauthenticated access detection on sensitive operations.
4. Strict bounds: max 2 probes, zero arbitrary ID mass-enumeration, fail-closed.
"""

from __future__ import annotations

from arka.app.core.state.models import RiskLevel
from arka.app.observability.logging import get_logger
from arka.app.web.analysis.models import (
    FindingValidationStatus,
    SecurityFinding,
)
from arka.app.web.business_logic.models import (
    AccessControlCheckType,
    TestIdentity,
)
from arka.app.web.client.client import ControlledHTTPClient
from arka.app.web.models.http import HTTPRequest

logger = get_logger(__name__)


class AccessControlAnalyzer:
    """Deterministic analyzer for IDOR, BOLA, and vertical privilege escalation."""

    def __init__(self, http_client: ControlledHTTPClient) -> None:
        self.http_client = http_client

    async def analyze_horizontal_bola(
        self,
        endpoint_template: str,
        primary_identity: TestIdentity,
        secondary_identity: TestIdentity,
        object_id_primary: str,
        object_id_secondary: str,
        engagement_id: str,
        task_id: str = "",
    ) -> SecurityFinding | None:
        """Section 3.8.4: IDOR/BOLA differential check between controlled identities."""
        target_url = endpoint_template.replace("{id}", object_id_primary)
        finding = await self.verify_horizontal_isolation(
            owner_identity=primary_identity,
            attacker_identity=secondary_identity,
            resource_url=target_url,
            task_id=task_id,
        )
        if finding:
            finding.check_type = AccessControlCheckType.HORIZONTAL_IDOR_BOLA
        return finding

    async def verify_horizontal_isolation(
        self,
        owner_identity: TestIdentity,
        attacker_identity: TestIdentity,
        resource_url: str,
        task_id: str = "",
    ) -> SecurityFinding | None:
        """Section 3.8.4: Verify if attacker_identity can access owner_identity's resource.

        Strictly bounded: only 1 probe against explicit owner resource. Zero mass-enumeration.
        """
        # 1. Establish that resource exists and is readable by the legitimate owner
        owner_req = HTTPRequest(url=resource_url)
        owner_tx = await self.http_client.execute(
            owner_req,
            engagement_id=owner_identity.engagement_id,
            task_id=task_id,
            session_context=owner_identity.session_context,
        )
        if not owner_tx.response or owner_tx.response.status_code != 200:
            logger.info(
                "IDOR baseline read by owner failed or unauthenticated",
                resource=resource_url,
                owner=owner_identity.name,
            )
            return None

        # 2. Attempt access using attacker_identity's credentials
        probe_req = HTTPRequest(url=resource_url)
        probe_tx = await self.http_client.execute(
            probe_req,
            engagement_id=attacker_identity.engagement_id,
            task_id=task_id,
            session_context=attacker_identity.session_context,
        )

        if not probe_tx.response:
            return None

        # 3. Deterministic evaluation: If attacker receives HTTP 200, BOLA/IDOR is verified
        if probe_tx.response.status_code == 200:
            finding = SecurityFinding(
                engagement_id=owner_identity.engagement_id,
                title=f"Broken Object Level Authorization (BOLA/IDOR) on '{resource_url}'",
                description=(
                    f"Test identity '{attacker_identity.name}' "
                    f"(ID: {attacker_identity.identity_id}) successfully accessed resource "
                    f"owned by '{owner_identity.name}' with HTTP 200."
                ),
                severity=RiskLevel.HIGH,
                evidence_confidence=1.0,
                target_url=resource_url,
                cwe_id="CWE-639",
                check_type=AccessControlCheckType.HORIZONTAL_IDOR_BOLA,
                status=FindingValidationStatus.VALIDATED,
                remediation=(
                    "Implement object-level access control verifying that the authenticated user "
                    "owns or has explicit permissions on the requested resource identifier."
                ),
            )
            if probe_tx.evidence_ref:
                finding.evidence_refs.append(probe_tx.evidence_ref)
            return finding

        return None

    async def verify_vertical_privilege_escalation(
        self,
        standard_user_identity: TestIdentity,
        admin_endpoint_url: str,
        task_id: str = "",
    ) -> SecurityFinding | None:
        """Section 3.8.3: Verify if a standard user can access an administrative endpoint."""
        probe_req = HTTPRequest(url=admin_endpoint_url)
        tx = await self.http_client.execute(
            probe_req,
            engagement_id=standard_user_identity.engagement_id,
            task_id=task_id,
            session_context=standard_user_identity.session_context,
        )

        if not tx.response:
            return None

        # If standard user receives 200 or 201 on an administrative function
        if tx.response.status_code in (200, 201):
            finding = SecurityFinding(
                engagement_id=standard_user_identity.engagement_id,
                title=f"Vertical Privilege Escalation on '{admin_endpoint_url}'",
                description=(
                    f"Standard user '{standard_user_identity.name}' with role "
                    f"'{standard_user_identity.role.value}' successfully accessed administrative "
                    f"endpoint '{admin_endpoint_url}' with HTTP {tx.response.status_code}."
                ),
                severity=RiskLevel.CRITICAL,
                evidence_confidence=1.0,
                target_url=admin_endpoint_url,
                cwe_id="CWE-269",
                check_type=AccessControlCheckType.VERTICAL_PRIVILEGE_ESCALATION,
                status=FindingValidationStatus.VALIDATED,
                remediation=(
                    "Enforce role-based access control (RBAC) at the route/gateway level "
                    "restricting administrative endpoints strictly to authorized admin roles."
                ),
            )
            if tx.evidence_ref:
                finding.evidence_refs.append(tx.evidence_ref)
            return finding

        return None

    async def verify_unauthenticated_access(
        self,
        protected_url: str,
        engagement_id: str,
        task_id: str = "",
    ) -> SecurityFinding | None:
        """Section 3.8.3: Verify if a sensitive endpoint is accessible without authentication."""
        probe_req = HTTPRequest(url=protected_url)
        # Execute with zero session / zero auth headers
        tx = await self.http_client.execute(
            probe_req,
            engagement_id=engagement_id,
            task_id=task_id,
            session_context=None,
        )

        if not tx.response:
            return None

        if tx.response.status_code in (200, 201):
            finding = SecurityFinding(
                engagement_id=engagement_id,
                title=f"Missing Authentication on Protected Endpoint '{protected_url}'",
                description=(
                    f"Endpoint '{protected_url}' returned HTTP {tx.response.status_code} "
                    "to completely unauthenticated/anonymous requests."
                ),
                severity=RiskLevel.HIGH,
                evidence_confidence=1.0,
                target_url=protected_url,
                cwe_id="CWE-306",
                check_type=AccessControlCheckType.UNAUTHENTICATED_ACCESS,
                status=FindingValidationStatus.VALIDATED,
                remediation="Ensure authentication middleware guards all sensitive routes.",
            )
            if tx.evidence_ref:
                finding.evidence_refs.append(tx.evidence_ref)
            return finding

        return None
