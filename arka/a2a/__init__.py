"""
ARKA Agent-to-Agent (A2A) Protocol Package.

Provides cryptographically authenticated inter-agent messaging under KeyDomain::TokenSigning.
"""

from .bus import A2aMessageBus
from .exceptions import (
    A2aCapabilityForbiddenError,
    A2aError,
    A2aExpiredError,
    A2aMissionMismatchError,
    A2aPayloadTooLargeError,
    A2aRecipientMismatchError,
    A2aReplayError,
    A2aSchemaError,
    A2aSignatureError,
)
from .messenger import A2aMessenger
from .models import (
    A2aMessageEnvelope,
    A2aMessageType,
    A2aVerificationResult,
    Finding,
    TaskDelegation,
    TaskResult,
)
from .protocol import (
    A2aReplayCache,
    A2aSigner,
    A2aVerifier,
    build_signature_preimage,
    canonicalize_payload,
    compute_payload_hash,
)

__all__ = [
    "A2aCapabilityForbiddenError",
    "A2aError",
    "A2aExpiredError",
    "A2aMessageBus",
    "A2aMessageEnvelope",
    "A2aMessageType",
    "A2aMessenger",
    "A2aMissionMismatchError",
    "A2aPayloadTooLargeError",
    "A2aRecipientMismatchError",
    "A2aReplayCache",
    "A2aReplayError",
    "A2aSchemaError",
    "A2aSignatureError",
    "A2aSigner",
    "A2aVerificationResult",
    "A2aVerifier",
    "Finding",
    "TaskDelegation",
    "TaskResult",
    "build_signature_preimage",
    "canonicalize_payload",
    "compute_payload_hash",
]
