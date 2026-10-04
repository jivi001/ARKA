"""
ARKA Cryptographic Core — Domain-Separated Key Management Contracts
Provides abstract KeyProvider interface and DevelopmentKeyProvider implementation.
"""

from .provider import (
    KeyProvider,
    DevelopmentKeyProvider,
    KeyDomain,
    KeyMetadata,
    SignatureResult,
    EncryptionResult,
    CryptoError,
    DomainSeparationViolationError,
    KeyNotFoundError,
    VerificationFailedError,
)

__all__ = [
    "KeyProvider",
    "DevelopmentKeyProvider",
    "KeyDomain",
    "KeyMetadata",
    "SignatureResult",
    "EncryptionResult",
    "CryptoError",
    "DomainSeparationViolationError",
    "KeyNotFoundError",
    "VerificationFailedError",
]
