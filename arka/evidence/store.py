"""
ARKA Evidence Store.

Implements:
- Content-addressed, tamper-evident immutable evidence repository
- Mission isolation and sensitivity-filtered queries
- Real-time cryptographic integrity verification
"""

import hashlib
import logging
import threading
from typing import Dict, List, Optional

from .exceptions import (
    EvidenceImmutabilityError,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
)
from .models import EvidenceRecord, SensitivityLevel
from .pipeline import DOMAIN_EVIDENCE

logger = logging.getLogger("arka.evidence.store")

SENSITIVITY_HIERARCHY = {
    SensitivityLevel.PUBLIC: 0,
    SensitivityLevel.INTERNAL: 1,
    SensitivityLevel.CONFIDENTIAL: 2,
    SensitivityLevel.SECRET: 3,
}


class EvidenceStore:
    """
    In-memory immutable evidence store.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # evidence_id -> EvidenceRecord
        self._records: Dict[str, EvidenceRecord] = {}
        # (mission_id, content_hash) -> evidence_id
        self._hash_index: Dict[tuple, str] = {}
        # mission_id -> List[evidence_id]
        self._mission_index: Dict[str, List[str]] = {}

    def put(self, record: EvidenceRecord) -> str:
        """
        Stores an evidence record immutably.
        Enforces content integrity and rejects mutations to existing records.
        """
        # Verify content hash integrity prior to storage
        hasher = hashlib.sha256()
        hasher.update(DOMAIN_EVIDENCE)
        hasher.update(record.raw_content)
        expected_hash = hasher.hexdigest()

        if record.content_hash != expected_hash:
            raise EvidenceIntegrityError(
                f"Evidence content hash mismatch! Declared: {record.content_hash}, calculated: {expected_hash}."
            )

        with self._lock:
            if record.evidence_id in self._records:
                existing = self._records[record.evidence_id]
                if existing.content_hash == record.content_hash:
                    return record.evidence_id  # Idempotent write
                raise EvidenceImmutabilityError(
                    f"Evidence record '{record.evidence_id}' already exists and cannot be mutated."
                )

            self._records[record.evidence_id] = record

            # Indexing
            mid = record.provenance.mission_id
            hash_key = (mid, record.content_hash)
            self._hash_index[hash_key] = record.evidence_id

            if mid not in self._mission_index:
                self._mission_index[mid] = []
            self._mission_index[mid].append(record.evidence_id)

        logger.debug(f"Stored immutable evidence '{record.evidence_id}' for mission '{mid}'.")
        return record.evidence_id

    def get(self, evidence_id: str, mission_id: Optional[str] = None) -> Optional[EvidenceRecord]:
        """
        Retrieves an evidence record by ID, enforcing mission isolation if mission_id is provided.
        """
        with self._lock:
            record = self._records.get(evidence_id)
            if not record:
                return None
            if mission_id and record.provenance.mission_id != mission_id:
                # Mission isolation barrier
                return None
            return record

    def get_by_hash(self, content_hash: str, mission_id: str) -> Optional[EvidenceRecord]:
        """Retrieves an evidence record by its content hash within a mission."""
        with self._lock:
            eid = self._hash_index.get((mission_id, content_hash))
            if not eid:
                return None
            return self._records.get(eid)

    def verify_integrity(self, evidence_id: str) -> bool:
        """
        Recomputes and verifies the cryptographic content hash of a stored record.
        """
        with self._lock:
            record = self._records.get(evidence_id)
            if not record:
                raise EvidenceNotFoundError(f"Evidence record '{evidence_id}' not found.")

            hasher = hashlib.sha256()
            hasher.update(DOMAIN_EVIDENCE)
            hasher.update(record.raw_content)
            computed_hash = hasher.hexdigest()

            return computed_hash == record.content_hash

    def list_for_mission(
        self,
        mission_id: str,
        sensitivity_ceiling: Optional[SensitivityLevel] = None,
    ) -> List[EvidenceRecord]:
        """
        Lists all evidence for a mission, optionally filtering by maximum allowable sensitivity.
        """
        with self._lock:
            eids = self._mission_index.get(mission_id, [])
            results: List[EvidenceRecord] = []
            max_lvl = SENSITIVITY_HIERARCHY.get(sensitivity_ceiling) if sensitivity_ceiling else None

            for eid in eids:
                record = self._records.get(eid)
                if record:
                    if max_lvl is not None:
                        record_lvl = SENSITIVITY_HIERARCHY.get(record.sensitivity, 99)
                        if record_lvl > max_lvl:
                            continue  # Exclude data exceeding sensitivity ceiling
                    results.append(record)

            return results
