"""Evidence collection and cryptographic provenance for ARKA.

Provides an append-only, content-addressed evidence store that:
- Computes SHA-256 integrity digests over all execution outputs
- Returns defensive copies to prevent mutation of internal state
- Deduplicates raw blob storage by SHA-256 (multiple references can share one blob)
- Supports listing by engagement, execution, or evidence type
- Never exposes delete or update operations for finalized evidence
"""

import hashlib
import json
import re
from copy import deepcopy
from typing import Any, ClassVar

from arka.app.execution.schemas import EvidenceReference, EvidenceType


class EvidenceStore:
    """Cryptographic evidence store for capturing execution artifacts and outputs.

    Ensures non-repudiation by computing SHA-256 checksums over all execution outputs.
    Evidence is append-only and immutable once recorded.
    Defensive copies prevent callers from mutating stored evidence.
    """

    # Patterns to redact from evidence metadata (NOT from raw content — that would
    # corrupt legitimate security evidence like certificates and protocol banners).
    _SECRET_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+"),
        re.compile(r"(?i)(bearer|authorization)\s+\S+"),
        re.compile(r"(?i)(password|passwd|secret|token)\s*[:=]\s*\S+"),
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),
        re.compile(r"(?i)(private[_-]?key)\s*[:=]\s*\S+"),
    ]

    _SENSITIVE_KEYS: ClassVar[set[str]] = {
        "api_key",
        "apikey",
        "authorization",
        "auth_token",
        "token",
        "secret",
        "password",
        "vault_token",
        "private_key",
        "bearer",
    }

    def __init__(self) -> None:
        self._evidence: dict[str, EvidenceReference] = {}
        self._raw_blobs: dict[str, bytes] = {}
        # Content-addressed index: sha256 -> evidence_id that holds the canonical blob
        self._sha256_to_blob_id: dict[str, str] = {}

    def record_evidence(
        self,
        execution_id: str,
        request_id: str,
        engagement_id: str,
        task_id: str,
        content: str | bytes | dict[str, Any],
        evidence_type: str = EvidenceType.STRUCTURED_RESULT.value,
        location: str = "in_memory",
        tool_name: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceReference:
        """Create and store a cryptographically hashed evidence record.

        Returns a defensive copy of the created EvidenceReference.
        The raw blob is stored content-addressed: if the same SHA-256 digest
        has been recorded before, the blob is reused but a new EvidenceReference
        is always created (preserving distinct execution provenance).
        """
        blob = self._serialize_content(content)
        sha256 = hashlib.sha256(blob).hexdigest()
        size_bytes = len(blob)

        # Redact sensitive keys from metadata only (never from raw content)
        clean_metadata = self._redact_metadata(metadata or {})

        ref = EvidenceReference(
            execution_id=execution_id,
            request_id=request_id,
            engagement_id=engagement_id,
            task_id=task_id,
            tool_name=tool_name,
            evidence_type=evidence_type,
            location=location,
            sha256=sha256,
            size_bytes=size_bytes,
            metadata=clean_metadata,
        )

        # Store reference (always — each execution gets its own provenance record)
        self._evidence[ref.evidence_id] = ref

        # Content-addressed blob storage: deduplicate by SHA-256
        if sha256 not in self._sha256_to_blob_id:
            self._raw_blobs[ref.evidence_id] = blob
            self._sha256_to_blob_id[sha256] = ref.evidence_id
        # If blob already exists, we don't store a duplicate copy;
        # the blob is retrievable via the canonical blob_id in _sha256_to_blob_id

        return ref.model_copy(deep=True)

    def get_evidence(self, evidence_id: str) -> EvidenceReference | None:
        """Retrieve a defensive copy of an evidence reference by ID.

        Returns None if the evidence_id is not found.
        The caller cannot mutate internal state through the returned copy.
        """
        ref = self._evidence.get(evidence_id)
        if ref is None:
            return None
        return ref.model_copy(deep=True)

    def get_raw_blob(self, evidence_id: str) -> bytes | None:
        """Retrieve raw content by evidence ID.

        Handles content-addressed deduplication: if this evidence_id's blob
        was deduplicated, retrieves from the canonical blob holder.
        Returns a copy of the bytes to prevent mutation.
        """
        # Direct lookup first
        blob = self._raw_blobs.get(evidence_id)
        if blob is not None:
            return bytes(blob)  # defensive copy

        # Content-addressed lookup: find the canonical blob via SHA-256
        ref = self._evidence.get(evidence_id)
        if ref is None:
            return None
        canonical_id = self._sha256_to_blob_id.get(ref.sha256)
        if canonical_id is None:
            return None
        blob = self._raw_blobs.get(canonical_id)
        if blob is not None:
            return bytes(blob)  # defensive copy
        return None

    def verify_integrity(self, evidence_id: str) -> bool:
        """Verify that stored raw content matches its recorded SHA-256 digest.

        This verifies INTEGRITY (content has not changed), not AUTHENTICITY
        (content came from a trusted source). Authenticity is established
        through the execution/request provenance chain.
        """
        ref = self._evidence.get(evidence_id)
        if not ref:
            return False
        blob = self.get_raw_blob(evidence_id)
        if blob is None:
            return False
        current_sha256 = hashlib.sha256(blob).hexdigest()
        return current_sha256 == ref.sha256

    def list_by_engagement(self, engagement_id: str) -> list[EvidenceReference]:
        """List all evidence references for an engagement (defensive copies)."""
        return [
            ref.model_copy(deep=True)
            for ref in self._evidence.values()
            if ref.engagement_id == engagement_id
        ]

    def list_by_execution(self, execution_id: str) -> list[EvidenceReference]:
        """List all evidence references for an execution (defensive copies)."""
        return [
            ref.model_copy(deep=True)
            for ref in self._evidence.values()
            if ref.execution_id == execution_id
        ]

    def list_all(self) -> list[EvidenceReference]:
        """List all evidence references (defensive copies). Use sparingly."""
        return [ref.model_copy(deep=True) for ref in self._evidence.values()]

    @property
    def count(self) -> int:
        """Number of evidence references stored."""
        return len(self._evidence)

    @property
    def blob_count(self) -> int:
        """Number of unique raw blobs stored (after deduplication)."""
        return len(self._raw_blobs)

    @staticmethod
    def _serialize_content(content: str | bytes | dict[str, Any]) -> bytes:
        """Serialize evidence content to bytes for hashing and storage."""
        if isinstance(content, str):
            return content.encode("utf-8")
        elif isinstance(content, dict):
            return json.dumps(content, sort_keys=True).encode("utf-8")
        else:
            return content

    def _redact_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        """Recursively redact sensitive keys from metadata dictionaries.

        This operates ONLY on metadata, never on raw evidence content.
        """
        clean: dict[str, Any] = {}
        for k, v in metadata.items():
            if k.lower() in self._SENSITIVE_KEYS:
                clean[k] = "[REDACTED]"
            elif isinstance(v, dict):
                clean[k] = self._redact_metadata(v)
            elif isinstance(v, str):
                clean[k] = self._redact_string(v)
            elif isinstance(v, list):
                clean[k] = [
                    self._redact_metadata(item) if isinstance(item, dict) else item for item in v
                ]
            else:
                clean[k] = deepcopy(v)
        return clean

    def _redact_string(self, value: str) -> str:
        """Redact known secret patterns from a metadata string value."""
        result = value
        for pattern in self._SECRET_PATTERNS:
            result = pattern.sub("[REDACTED]", result)
        return result
