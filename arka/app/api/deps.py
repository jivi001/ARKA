"""FastAPI dependency injection for ARKA."""
from functools import lru_cache

from arka.app.core.config import get_settings
from arka.app.audit.service import AuditService
from arka.app.llm.gateway.gateway import LLMGateway


# Singleton instances for application lifetime
_audit_service: AuditService | None = None
_llm_gateway: LLMGateway | None = None


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


def reset_dependencies() -> None:
    """Reset all singleton instances. Used in testing."""
    global _audit_service, _llm_gateway
    _audit_service = None
    _llm_gateway = None
