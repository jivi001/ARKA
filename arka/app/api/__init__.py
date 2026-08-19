"""ARKA FastAPI application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from arka.app.api.errors import ArkaAPIError, arka_exception_handler, generic_exception_handler
from arka.app.api.routes.engagements import router as engagements_router
from arka.app.api.routes.health import router as health_router
from arka.app.api.routes.llm import router as llm_router
from arka.app.core.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan manager.

    Handles startup and shutdown events for database connections,
    Redis connections, and worker initialization.
    """
    # Startup
    _ = get_settings()

    # Phase 1: Basic initialization
    # Future: Initialize database pool, Redis connection, Arq workers
    yield

    # Shutdown
    # Future: Close database pool, Redis connection, stop workers


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
    app.include_router(llm_router)

    return app


# Application instance for uvicorn
app = create_app()
