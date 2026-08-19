"""Health and readiness check endpoints."""
from datetime import datetime, timezone

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> dict:
    """Basic health check. Returns 200 if the API is running."""
    return {
        "status": "healthy",
        "service": "arka",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/ready")
async def readiness_check() -> dict:
    """Readiness check. Verifies that dependencies are available.

    Phase 1: Returns basic readiness status.
    Future: Will verify database, Redis, and LLM provider connectivity.
    """
    return {
        "status": "ready",
        "service": "arka",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {
            "api": "ok",
        },
    }
