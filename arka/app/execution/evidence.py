"""Evidence collection and cryptographic provenance for ARKA Phase 2.1."""

import hashlib
import json
from typing import Any

from arka.app.execution.schemas import EvidenceReference


class EvidenceStore:
    """Cryptographic evidence store for capturing execution artifacts and outputs.

    Ensures non-repudiation by computing SHA-256 checksums over all execution outputs.
    """

    def __init__(self) -> None:
        self._evidence: dict[str, EvidenceReference] = {}
        self._raw_blobs: dict[str, bytes] = {}

    def record_evidence(
        self,
        execution_id: str,
        request_id: str,
        engagement_id: str,
        task_id: str,
        content: str | bytes | dict[str, Any],
        evidence_type: str = "raw_tool_output",
        location: str = "in_memory",
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceReference:
        """Create and store a cryptographically hashed evidence record."""
        if isinstance(content, str):
            blob = content.encode("utf-8")
        elif isinstance(content, dict):
            blob = json.dumps(content, sort_keys=True).encode("utf-8")
        else:
            blob = content

        sha256 = hashlib.sha256(blob).hexdigest()
        size_bytes = len(blob)

        ref = EvidenceReference(
            execution_id=execution_id,
            request_id=request_id,
            engagement_id=engagement_id,
            task_id=task_id,
            evidence_type=evidence_type,
            location=location,
            sha256=sha256,
            size_bytes=size_bytes,
            metadata=metadata or {},
        )

        self._evidence[ref.evidence_id] = ref
        self._raw_blobs[ref.evidence_id] = blob
        return ref

    def get_evidence(self, evidence_id: str) -> EvidenceReference | None:
        """Retrieve evidence reference by ID."""
        return self._evidence.get(evidence_id)

    def get_raw_blob(self, evidence_id: str) -> bytes | None:
        """Retrieve raw content by evidence ID."""
        return self._raw_blobs.get(evidence_id)

    def verify_integrity(self, evidence_id: str) -> bool:
        """Verify that stored raw content matches its recorded SHA-256 digest."""
        ref = self._evidence.get(evidence_id)
        blob = self._raw_blobs.get(evidence_id)
        if not ref or blob is None:
            return False
        current_sha256 = hashlib.sha256(blob).hexdigest()
        return current_sha256 == ref.sha256
