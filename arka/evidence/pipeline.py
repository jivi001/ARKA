"""
ARKA Evidence Processing Pipeline.

Executes:
1. Ingress bounding and size enforcement
2. Quarantined sandboxed parsing (SafeParser)
3. Trust and sensitivity classification
4. Domain-separated cryptographic SHA-256 hashing (DOMAIN_EVIDENCE)
5. Immutable EvidenceRecord generation
"""

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional
import uuid

from .classifier import EvidenceClassifier
from .exceptions import EvidenceParserError, EvidenceProvenanceError, ParserBombError
from .models import (
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceType,
    SensitivityLevel,
    TrustLevel,
)
from .parsers import (
    HttpOutputParser,
    NmapXmlParser,
    SafeHtmlParser,
    SafeJsonParser,
    SafeParser,
    SafeXmlParser,
)

logger = logging.getLogger("arka.evidence.pipeline")

DOMAIN_EVIDENCE: bytes = b"ARKA-EVIDENCE-V1:"
DEFAULT_MAX_ARTIFACT_BYTES: int = 1024 * 1024  # 1 MB


class EvidencePipeline:
    """
    Authoritative ingestion and processing pipeline for untrusted evidence.
    """

    def __init__(self, max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES):
        self.max_artifact_bytes = max_artifact_bytes
        self.json_parser = SafeJsonParser()
        self.xml_parser = SafeXmlParser()
        self.nmap_parser = NmapXmlParser()
        self.html_parser = SafeHtmlParser()
        self.http_parser = HttpOutputParser()

    def _auto_detect_parser(self, raw_bytes: bytes, evidence_type: EvidenceType) -> Optional[SafeParser]:
        """Selects the safest appropriate parser based on type or content prefix."""
        if evidence_type == EvidenceType.PORT_SCAN:
            if b"<nmaprun" in raw_bytes:
                return self.nmap_parser
            return None
        if evidence_type == EvidenceType.HTTP_RESPONSE:
            return self.http_parser

        stripped = raw_bytes.strip()
        if stripped.startswith(b"{") or stripped.startswith(b"["):
            return self.json_parser
        if stripped.startswith(b"<?xml") or (stripped.startswith(b"<") and b"</" in stripped):
            if b"<nmaprun" in stripped:
                return self.nmap_parser
            if b"<html" in stripped.lower():
                return self.html_parser
            return self.xml_parser
        if b"HTTP/1." in stripped or b"HTTP/2" in stripped:
            return self.http_parser

        return None

    def quarantine_and_parse(
        self,
        raw_bytes: bytes,
        provenance: EvidenceProvenance,
        evidence_type: EvidenceType = EvidenceType.CUSTOM,
        parser_hint: Optional[str] = "auto",
        parent_refs: Optional[List[str]] = None,
    ) -> EvidenceRecord:
        """
        Quarantines, safely parses, classifies, and cryptographically seals raw evidence.
        """
        # 1. Provenance verification
        if not provenance.mission_id or not provenance.task_id:
            raise EvidenceProvenanceError("EvidenceProvenance must contain non-empty mission_id and task_id.")

        # 2. Ingress bounding
        if len(raw_bytes) > self.max_artifact_bytes:
            content_bytes = raw_bytes[: self.max_artifact_bytes]
            truncated = True
        else:
            content_bytes = raw_bytes
            truncated = False

        # 3. Quarantined safe parsing
        structured_data: Optional[Dict[str, Any]] = None
        parser: Optional[SafeParser] = None

        if parser_hint == "json":
            parser = self.json_parser
        elif parser_hint == "xml":
            parser = self.xml_parser
        elif parser_hint == "nmap":
            parser = self.nmap_parser
        elif parser_hint == "html":
            parser = self.html_parser
        elif parser_hint == "http":
            parser = self.http_parser
        elif parser_hint == "auto":
            parser = self._auto_detect_parser(content_bytes, evidence_type)

        if parser:
            try:
                structured_data = parser.parse(content_bytes, max_bytes=self.max_artifact_bytes)
            except ParserBombError:
                # Re-raise parser bombs immediately for security alerting
                raise
            except EvidenceParserError as e:
                logger.warning(f"Safe parser failed on untrusted evidence: {e}")
                structured_data = {"parse_error": str(e)}

        # 4. Trust classification
        trust = EvidenceClassifier.classify_trust(provenance, evidence_type)

        # 5. Sensitivity classification & DLP secret redaction
        sensitivity, redacted_content = EvidenceClassifier.classify_sensitivity(
            content_bytes,
            structured_data=structured_data,
            provenance=provenance,
        )

        # 6. Domain-separated SHA-256 cryptographic hashing
        hasher = hashlib.sha256()
        hasher.update(DOMAIN_EVIDENCE)
        hasher.update(content_bytes)
        content_hash = hasher.hexdigest()

        # 7. Immutable EvidenceRecord assembly
        evidence_id = f"evi-{uuid.uuid4().hex}"
        now = time.time()

        return EvidenceRecord(
            evidence_id=evidence_id,
            provenance=provenance,
            evidence_type=evidence_type,
            raw_content=content_bytes,
            content_hash=content_hash,
            size_bytes=len(content_bytes),
            created_at_unix=now,
            trust=trust,
            sensitivity=sensitivity,
            structured_data=structured_data,
            redacted_content=redacted_content,
            parent_refs=parent_refs or [],
            truncated=truncated,
        )
