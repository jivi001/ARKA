"""
ARKA Agent-to-Agent (A2A) Protocol Exceptions.

Enforces:
- Section 1 of AGENTS.md: DISCOVERED != AUTHORIZED
- Zero direct execution authority
- Strict Ed25519 identity verification and replay protection
"""


class A2aError(Exception):
    """Base exception for all A2A messaging errors."""

    pass


class A2aSignatureError(A2aError):
    """Raised when an Ed25519 signature is invalid, forged, or sender key is missing/untrusted."""

    pass


class A2aReplayError(A2aError):
    """Raised when a replayed message ID or nonce is detected within the validity window."""

    pass


class A2aExpiredError(A2aError):
    """Raised when a message timestamp exceeds maximum allowable clock skew (TTL 60s) or is in the future."""

    pass


class A2aMissionMismatchError(A2aError):
    """Raised when an incoming message mission ID does not match receiver mission context."""

    pass


class A2aRecipientMismatchError(A2aError):
    """Raised when an incoming message is addressed to a different agent ID."""

    pass


class A2aSchemaError(A2aError):
    """Raised when a message envelope is malformed or uses an unsupported schema version."""

    pass


class A2aCapabilityForbiddenError(A2aError):
    """Raised when an A2A message attempts to transfer, issue, or forge capability tokens or execution authority."""

    pass


class A2aPayloadTooLargeError(A2aError):
    """Raised when serialized payload exceeds maximum permitted size (64 KB)."""

    pass
