"""ARKA FastAPI application factory."""

import inspect
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from arka.app.api.deps import get_worker_backend, set_arq_redis_pool
from arka.app.api.errors import ArkaAPIError, arka_exception_handler, generic_exception_handler
from arka.app.api.routes.engagements import router as engagements_router
from arka.app.api.routes.evidence import router as evidence_router
from arka.app.api.routes.health import router as health_router
from arka.app.api.routes.llm import router as llm_router
from arka.app.core.config import get_settings
from arka.app.core.config.settings import WorkerBackendType
from arka.app.observability.logging import get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan manager.

    Explicitly owns the ARQ Redis connection pool lifecycle when ARQ is active,
    and ensures clean deterministic shutdown of worker backends.
    """
    settings = get_settings()
    arq_pool = None

    if settings.resolved_worker_backend == WorkerBackendType.ARQ:
        try:
            from arq import create_pool

            from arka.app.workers.arq_worker import get_redis_settings

            logger.info("Initializing ARQ Redis pool in application lifespan")
            arq_pool = await create_pool(get_redis_settings())
            set_arq_redis_pool(arq_pool)
        except Exception as e:
            logger.error(f"Failed to initialize ARQ Redis pool on startup: {e}")

    yield

    # Shutdown: Close ARQ Redis pool if active
    if arq_pool is not None:
        logger.info("Closing ARQ Redis pool in application lifespan")
        try:
            if hasattr(arq_pool, "aclose"):
                await arq_pool.aclose()
            elif hasattr(arq_pool, "close"):
                res = arq_pool.close()
                if inspect.isawaitable(res):
                    await res
        except Exception as e:
            logger.warning(f"Error closing ARQ Redis pool: {e}")
        set_arq_redis_pool(None)

    # Clean up worker backend
    try:
        backend = get_worker_backend()
        if backend:
            await backend.close()
    except Exception as e:
        logger.warning(f"Error closing worker backend on shutdown: {e}")


def create_app() -> FastAPI:
    """Create and configure the ARKA FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="ARKA — Autonomous Risk Knowledge & Assessment",
        description=(
            "AI-driven autonomous penetration-testing platform "
            "for authorized security assessments only."
        ),
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
    )

    # Exception handlers
    app.add_exception_handler(ArkaAPIError, arka_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, generic_exception_handler)  # type: ignore[arg-type]

    # Routers
    app.include_router(health_router)
    app.include_router(engagements_router)
    app.include_router(evidence_router)
    app.include_router(llm_router)

    return app


# Application instance for uvicorn
app = create_app()
