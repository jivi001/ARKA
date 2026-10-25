"""
ARKA Evidence Ingestion Classifier.

Implements:
- TRD Section 22: Trust and Sensitivity Classification at Ingestion
- PRD Section 18: Sensitive Data Handling & DLP Pre-Storage Redaction
- Invariant INV-016: Untrusted Output Invariant
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional, Pattern, Tuple

from .models import EvidenceProvenance, EvidenceType, SensitivityLevel, TrustLevel

# Regular expressions detecting sensitive credentials, tokens, and private keys
SECRET_PATTERNS: List[Tuple[str, Pattern]] = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("JWT_BEARER", re.compile(r"\b(Bearer\s+ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+(?:\.[A-Za-z0-9-_.+/=]*)?)\b", re.IGNORECASE)),
    ("GITHUB_TOKEN", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b")),
    ("SLACK_TOKEN", re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b")),
    ("GENERIC_PASSWORD", re.compile(r"(?i)\b(password|passwd|pwd|api_key|access_token|client_secret)\s*[:=]\s*['\"]?([^\s&'\"]{4,})")),
]

# Pattern matching RFC 1918 private IPv4 addresses
RFC1918_PATTERN = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")


class EvidenceClassifier:
    """
    Evaluates evidence artifacts for trust and sensitivity classifications,
    enforcing DLP secret redaction before storage and agent context consumption.
    """

    @classmethod
    def classify_trust(
        cls,
        provenance: EvidenceProvenance,
        evidence_type: EvidenceType,
    ) -> TrustLevel:
        """
        Determines the trust level of the evidence artifact.
        By default, all target, worker, and external network content is UNTRUSTED.
        """
        if provenance.collector in ("kernel", "security_kernel", "operator_audit"):
            return TrustLevel.TRUSTED
        return TrustLevel.UNTRUSTED

    @classmethod
    def redact_secrets(cls, text: str) -> Tuple[str, bool]:
        """
        Redacts high-entropy secrets and credentials, replacing them with [REDACTED_SECRET].
        Returns (redacted_text, secrets_detected_bool).
        """
        redacted = text
        detected = False

        for name, pattern in SECRET_PATTERNS:
            if pattern.search(redacted):
                detected = True
                if name == "GENERIC_PASSWORD":
                    # Redact only the value capture group
                    redacted = pattern.sub(r"\1=[REDACTED_SECRET]", redacted)
                else:
                    redacted = pattern.sub("[REDACTED_SECRET]", redacted)

        return redacted, detected

    @classmethod
    def classify_sensitivity(
        cls,
        raw_bytes: bytes,
        structured_data: Optional[Dict[str, Any]] = None,
        provenance: Optional[EvidenceProvenance] = None,
    ) -> Tuple[SensitivityLevel, Optional[str]]:
        """
        Classifies sensitivity and performs DLP pre-redaction.
        
        Returns:
            (SensitivityLevel, redacted_content_str)
        """
        text = raw_bytes.decode("utf-8", errors="replace")
        redacted_text, secrets_detected = cls.redact_secrets(text)

        if secrets_detected:
            return SensitivityLevel.SECRET, redacted_text

        # Check for vulnerability scan outputs or exploit payloads
        if provenance and provenance.capability_id in ("CONTROLLED_EXPLOITATION", "CREDENTIAL_VALIDATION"):
            return SensitivityLevel.CONFIDENTIAL, redacted_text

        # Check for internal RFC1918 addresses
        if RFC1918_PATTERN.search(text):
            return SensitivityLevel.INTERNAL, redacted_text

        # Default for external discovery
        return SensitivityLevel.PUBLIC, redacted_text
