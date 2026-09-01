"""Read-only evidence metadata API routes.

Exposes evidence metadata for inspection without exposing raw artifact blobs.
No evidence mutation, deletion, or raw content retrieval endpoints are provided.
"""

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from arka.app.execution.evidence import EvidenceStore

router = APIRouter(prefix="/evidence", tags=["evidence"])

# Module-level evidence store reference; set by application startup
_evidence_store: EvidenceStore | None = None


def set_evidence_store(store: EvidenceStore) -> None:
    """Configure the evidence store for API access."""
    global _evidence_store
    _evidence_store = store


def _get_store() -> EvidenceStore:
    if _evidence_store is None:
        raise HTTPException(
            status_code=503,
            detail="Evidence store not initialized",
        )
    return _evidence_store


@router.get("/{evidence_id}")
async def get_evidence_metadata(evidence_id: str) -> dict[str, Any]:
    """Retrieve evidence metadata by ID.

    Returns provenance information (engagement_id, task_id, execution_id,
    tool_name, sha256, evidence_type, timestamps) without exposing raw content.
    """
    store = _get_store()
    ref = store.get_evidence(evidence_id)
    if ref is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return ref.model_dump()


@router.get("")
async def list_evidence(
    engagement_id: str | None = Query(default=None),
    execution_id: str | None = Query(default=None),
) -> list[dict[str, Any]]:
    """List evidence metadata filtered by engagement or execution.

    At least one filter parameter is required to prevent unbounded queries.
    """
    store = _get_store()
    if engagement_id:
        refs = store.list_by_engagement(engagement_id)
    elif execution_id:
        refs = store.list_by_execution(execution_id)
    else:
        raise HTTPException(
            status_code=400,
            detail="At least one filter (engagement_id or execution_id) is required",
        )
    return [r.model_dump() for r in refs]
