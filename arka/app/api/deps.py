"""FastAPI dependency injection for ARKA."""

from __future__ import annotations

from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.scope.repository import ScopeRepository
from arka.app.llm.gateway.gateway import LLMGateway

# Singleton instances for application lifetime
_audit_service: AuditService | None = None
_llm_gateway: LLMGateway | None = None
_scope_repository: ScopeRepository | None = None
_approval_manager: ApprovalManager | None = None


def get_audit_service() -> AuditService:
    """Get or create the singleton AuditService."""
    global _audit_service
    if _audit_service is None:
        _audit_service = AuditService()
    return _audit_service


def get_llm_gateway() -> LLMGateway:
    """Get or create the singleton LLMGateway."""
    global _llm_gateway
    if _llm_gateway is None:
        _llm_gateway = LLMGateway(audit_service=get_audit_service())
    return _llm_gateway


def get_scope_repository() -> ScopeRepository:
    """Get or create the singleton ScopeRepository."""
    global _scope_repository
    if _scope_repository is None:
        try:
            from arka.app.database.session import get_session_factory

            factory = get_session_factory()
            _scope_repository = ScopeRepository(session_factory=factory)
        except Exception:
            _scope_repository = ScopeRepository()
    return _scope_repository


def get_approval_manager() -> ApprovalManager:
    """Get or create the singleton ApprovalManager."""
    global _approval_manager
    if _approval_manager is None:
        try:
            from arka.app.database.session import get_session_factory

            factory = get_session_factory()
            _approval_manager = ApprovalManager(session_factory=factory)
        except Exception:
            _approval_manager = ApprovalManager()
    return _approval_manager


def reset_dependencies() -> None:
    """Reset all singleton instances. Used in testing."""
    global _audit_service, _llm_gateway, _scope_repository, _approval_manager
    _audit_service = None
    _llm_gateway = None
    _scope_repository = None
    _approval_manager = None
