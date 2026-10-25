"""
ARKA Evidence Pipeline Exceptions.

Enforces:
- Invariant INV-012: Evidence Provenance and Content-Addressable Integrity
- Invariant INV-016: Untrusted Output Invariant
- Safe parser containment preventing host compromise (THREAT-EVIDENCE-PARSER-COMPROMISE)
"""


class EvidenceError(Exception):
    """Base exception for all evidence pipeline operations."""

    pass


class EvidenceParserError(EvidenceError):
    """Base exception for parsing failures."""

    pass


class ParserBombError(EvidenceParserError):
    """Raised when an XML bomb, entity explosion, deep recursion, or parser attack is detected."""

    pass


class EvidenceSizeLimitError(EvidenceError):
    """Raised when evidence content exceeds the allowed size boundary."""

    pass


class EvidenceIntegrityError(EvidenceError):
    """Raised when an evidence artifact's cryptographic content hash does not match content bytes."""

    pass


class EvidenceProvenanceError(EvidenceError):
    """Raised when required provenance metadata (mission, task, source) is missing or invalid."""

    pass


class EvidenceNotFoundError(EvidenceError):
    """Raised when requested evidence artifact cannot be found in the store."""

    pass


class EvidenceImmutabilityError(EvidenceError):
    """Raised when an attempt is made to overwrite or mutate an existing immutable evidence record."""

    pass
