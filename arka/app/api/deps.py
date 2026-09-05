from __future__ import annotations

from arq.connections import ArqRedis

from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.scope.repository import ScopeRepository
from arka.app.core.tasks.repository import TaskRepository
from arka.app.execution.evidence import EvidenceStore
from arka.app.llm.gateway.gateway import LLMGateway
from arka.app.orchestration.recon_service import ReconOrchestrationService
from arka.app.workers.backend import ArqWorkerBackend, InProcessWorkerBackend, WorkerBackend

# Singleton instances for application lifetime
_audit_service: AuditService | None = None
_llm_gateway: LLMGateway | None = None
_scope_repository: ScopeRepository | None = None
_approval_manager: ApprovalManager | None = None
_task_repository: TaskRepository | None = None
_recon_orchestration_service: ReconOrchestrationService | None = None
_worker_backend: WorkerBackend | None = None
_arq_redis_pool: ArqRedis | None = None
_evidence_store: EvidenceStore | None = None


def set_arq_redis_pool(pool: ArqRedis | None) -> None:
    """Set the shared ArqRedis connection pool owned by the FastAPI lifespan."""
    global _arq_redis_pool
    _arq_redis_pool = pool
    if isinstance(_worker_backend, ArqWorkerBackend):
        _worker_backend.set_redis_pool(pool, owns_pool=False)


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


def get_task_repository() -> TaskRepository:
    """Get or create the singleton TaskRepository."""
    global _task_repository
    if _task_repository is None:
        from arka.app.database.session import get_session_factory

        factory = get_session_factory()
        _task_repository = TaskRepository(session_factory=factory)
    return _task_repository


def get_evidence_store() -> EvidenceStore:
    """Get or create the singleton EvidenceStore."""
    global _evidence_store
    if _evidence_store is None:
        _evidence_store = EvidenceStore()
    return _evidence_store


def get_recon_orchestration_service() -> ReconOrchestrationService:
    """Get or create the singleton ReconOrchestrationService."""
    global _recon_orchestration_service
    if _recon_orchestration_service is None:
        _recon_orchestration_service = ReconOrchestrationService(
            task_repository=get_task_repository(),
            scope_repository=get_scope_repository(),
            audit_service=get_audit_service(),
            llm_gateway=get_llm_gateway(),
            approval_manager=get_approval_manager(),
            evidence_store=get_evidence_store(),
        )
    return _recon_orchestration_service


def get_worker_backend() -> WorkerBackend:
    """Get or create the singleton WorkerBackend.

    Centralized resolution:
    - IN_PROCESS remains the default for local development and tests.
    - Production resolves to ARQ unless explicitly overridden.
    """
    global _worker_backend
    if _worker_backend is None:
        from arka.app.core.config import get_settings
        from arka.app.core.config.settings import WorkerBackendType

        settings = get_settings()
        if settings.resolved_worker_backend == WorkerBackendType.ARQ:
            _worker_backend = ArqWorkerBackend(redis_pool=_arq_redis_pool, owns_pool=False)
        else:
            _worker_backend = InProcessWorkerBackend(
                orchestrator=get_recon_orchestration_service(),
            )
    return _worker_backend


def reset_dependencies() -> None:
    """Reset all singleton instances. Used in testing."""
    global _audit_service, _llm_gateway, _scope_repository, _approval_manager
    global _task_repository, _recon_orchestration_service, _worker_backend, _arq_redis_pool
    global _evidence_store
    _audit_service = None
    _llm_gateway = None
    _scope_repository = None
    _approval_manager = None
    _task_repository = None
    _recon_orchestration_service = None
    _worker_backend = None
    _arq_redis_pool = None
    _evidence_store = None
