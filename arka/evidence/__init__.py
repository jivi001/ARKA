"""
ARKA Evidence Analysis and Provenance Package (Module I).

Provides:
- Quarantined safe parsing for untrusted target content
- Automated trust and sensitivity classification
- Content-addressed tamper-evident storage under DOMAIN_EVIDENCE
"""

from .classifier import EvidenceClassifier
from .exceptions import (
    EvidenceError,
    EvidenceImmutabilityError,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    EvidenceParserError,
    EvidenceProvenanceError,
    EvidenceSizeLimitError,
    ParserBombError,
)
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
from .pipeline import DOMAIN_EVIDENCE, EvidencePipeline
from .store import EvidenceStore

__all__ = [
    "DOMAIN_EVIDENCE",
    "EvidenceClassifier",
    "EvidenceError",
    "EvidenceImmutabilityError",
    "EvidenceIntegrityError",
    "EvidenceNotFoundError",
    "EvidenceParserError",
    "EvidencePipeline",
    "EvidenceProvenance",
    "EvidenceProvenanceError",
    "EvidenceRecord",
    "EvidenceSizeLimitError",
    "EvidenceStore",
    "EvidenceType",
    "HttpOutputParser",
    "NmapXmlParser",
    "ParserBombError",
    "SafeHtmlParser",
    "SafeJsonParser",
    "SafeParser",
    "SafeXmlParser",
    "SensitivityLevel",
    "TrustLevel",
]
