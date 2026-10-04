"""
ARKA Core Cryptographic Provider Architecture
Defines the authoritative KeyProvider interface and DevelopmentKeyProvider implementation.
Adheres to ARKA Key Management Policy across 6 strictly separated key domains.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
import os
import time
import uuid
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization


class KeyDomain(str, Enum):
    ROOT_ANCHOR = "ROOT-ANCHOR"
    TOKEN_SIGNING = "TOKEN-SIGNING"
    AUDIT_SIGNING = "AUDIT-SIGNING"
    CREDENTIAL_KEK = "CREDENTIAL-KEK"
    MISSION_DATA_ENCRYPTION = "MISSION-DATA-ENCRYPTION"
    WORKER_IDENTITY = "WORKER-IDENTITY"


class CryptoError(Exception):
    """Base class for all ARKA cryptographic errors."""
    pass


class DomainSeparationViolationError(CryptoError):
    """Raised when an attempt is made to use a key across domain boundaries."""
    pass


class KeyNotFoundError(CryptoError):
    """Raised when a requested key ID does not exist."""
    pass


class VerificationFailedError(CryptoError):
    """Raised when signature verification fails."""
    pass


@dataclass(frozen=True)
class KeyMetadata:
    kid: str
    domain: KeyDomain
    algorithm: str
    version: int
    created_at: float
    active: bool


@dataclass(frozen=True)
class SignatureResult:
    signature: bytes
    kid: str
    algorithm: str
    timestamp: float


@dataclass(frozen=True)
class EncryptionResult:
    ciphertext: bytes
    nonce: bytes
    kid: str
    algorithm: str


class KeyProvider(ABC):
    """
    Authoritative Key Provider Interface.
    Enforces domain isolation, key lifecycle governance, and cryptographic operations.
    """

    @abstractmethod
    def sign(self, domain: KeyDomain, payload: bytes, kid: Optional[str] = None) -> SignatureResult:
        """Sign a payload using the active signing key for the specified domain."""
        pass

    @abstractmethod
    def verify(self, domain: KeyDomain, payload: bytes, signature: bytes, kid: str) -> bool:
        """Verify a payload signature using the specified domain key ID."""
        pass

    @abstractmethod
    def encrypt(
        self,
        domain: KeyDomain,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
        kid: Optional[str] = None,
    ) -> EncryptionResult:
        """Encrypt plaintext using the active symmetric key for the specified domain."""
        pass

    @abstractmethod
    def decrypt(
        self,
        domain: KeyDomain,
        ciphertext: bytes,
        nonce: bytes,
        kid: str,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt ciphertext using the specified domain key ID."""
        pass

    @abstractmethod
    def rotate_key(self, domain: KeyDomain) -> KeyMetadata:
        """Rotate key material for the given domain and return metadata for the new active key."""
        pass

    @abstractmethod
    def get_key_metadata(self, domain: KeyDomain, kid: Optional[str] = None) -> KeyMetadata:
        """Retrieve metadata for a key without exposing raw key bytes."""
        pass


class DevelopmentKeyProvider(KeyProvider):
    """
    Ephemeral in-memory KeyProvider implementation for local development and unit tests.

    CRITICAL SECURITY NOTICE:
    -------------------------
    THIS IMPLEMENTATION IS FOR LOCAL DEVELOPMENT AND TESTING PURPOSES ONLY.
    IT IS NOT PRODUCTION-SAFE AND MUST NOT BE USED IN PRODUCTION ENVIRONMENTS.
    PRODUCTION ARKA ENVIRONMENTS MUST USE HARDWARE SECURITY MODULES (HSM)
    OR CLOUD KMS PROVIDERS WITH SECURE KEY ENCLAVES.
    """

    IS_DEVELOPMENT_ONLY = True

    SIGNING_DOMAINS = {
        KeyDomain.ROOT_ANCHOR,
        KeyDomain.TOKEN_SIGNING,
        KeyDomain.AUDIT_SIGNING,
        KeyDomain.WORKER_IDENTITY,
    }

    ENCRYPTION_DOMAINS = {
        KeyDomain.CREDENTIAL_KEK,
        KeyDomain.MISSION_DATA_ENCRYPTION,
    }

    def __init__(self):
        # Disallow production execution
        if os.getenv("ARKA_ENVIRONMENT", "").lower() in ("production", "prod"):
            raise CryptoError(
                "CRITICAL: DevelopmentKeyProvider is strictly forbidden in production environments!"
            )

        # Internal in-memory storage: domain -> {kid -> (metadata, key_object)}
        self._keys: Dict[KeyDomain, Dict[str, Tuple[KeyMetadata, object]]] = {
            domain: {} for domain in KeyDomain
        }
        self._active_kid: Dict[KeyDomain, Optional[str]] = {
            domain: None for domain in KeyDomain
        }
        self._version_counter: Dict[KeyDomain, int] = {
            domain: 0 for domain in KeyDomain
        }

        # Initialize one active key for each domain
        for domain in KeyDomain:
            self._generate_key(domain)

    def _generate_key(self, domain: KeyDomain) -> KeyMetadata:
        self._version_counter[domain] += 1
        ver = self._version_counter[domain]
        kid = f"{domain.value}-v{ver}-{uuid.uuid4().hex[:8]}"

        if domain in self.SIGNING_DOMAINS:
            # Ed25519 signing key
            private_key = ed25519.Ed25519PrivateKey.generate()
            algorithm = "Ed25519"
            key_obj = private_key
        elif domain in self.ENCRYPTION_DOMAINS:
            # AES-256-GCM symmetric key (32 bytes)
            aes_key = AESGCM.generate_key(bit_length=256)
            algorithm = "AES-256-GCM"
            key_obj = aes_key
        else:
            raise CryptoError(f"Unsupported key domain: {domain}")

        metadata = KeyMetadata(
            kid=kid,
            domain=domain,
            algorithm=algorithm,
            version=ver,
            created_at=time.time(),
            active=True,
        )

        # Mark previous active key as inactive
        prev_kid = self._active_kid[domain]
        if prev_kid and prev_kid in self._keys[domain]:
            old_meta, old_obj = self._keys[domain][prev_kid]
            updated_old_meta = KeyMetadata(
                kid=old_meta.kid,
                domain=old_meta.domain,
                algorithm=old_meta.algorithm,
                version=old_meta.version,
                created_at=old_meta.created_at,
                active=False,
            )
            self._keys[domain][prev_kid] = (updated_old_meta, old_obj)

        self._keys[domain][kid] = (metadata, key_obj)
        self._active_kid[domain] = kid
        return metadata

    def sign(self, domain: KeyDomain, payload: bytes, kid: Optional[str] = None) -> SignatureResult:
        if domain not in self.SIGNING_DOMAINS:
            raise DomainSeparationViolationError(
                f"Domain '{domain.value}' is an encryption domain, not a signing domain."
            )

        target_kid = kid or self._active_kid[domain]
        if not target_kid or target_kid not in self._keys[domain]:
            raise KeyNotFoundError(f"Key '{target_kid}' not found in domain '{domain.value}'")

        metadata, key_obj = self._keys[domain][target_kid]
        if not isinstance(key_obj, ed25519.Ed25519PrivateKey):
            raise DomainSeparationViolationError("Key object is not an Ed25519 private key.")

        signature = key_obj.sign(payload)
        return SignatureResult(
            signature=signature,
            kid=target_kid,
            algorithm=metadata.algorithm,
            timestamp=time.time(),
        )

    def verify(self, domain: KeyDomain, payload: bytes, signature: bytes, kid: str) -> bool:
        if domain not in self.SIGNING_DOMAINS:
            raise DomainSeparationViolationError(
                f"Domain '{domain.value}' is an encryption domain, not a signing domain."
            )

        if kid not in self._keys[domain]:
            raise KeyNotFoundError(f"Key '{kid}' not found in domain '{domain.value}'")

        metadata, key_obj = self._keys[domain][kid]
        if not isinstance(key_obj, ed25519.Ed25519PrivateKey):
            raise DomainSeparationViolationError("Key object is not an Ed25519 private key.")

        public_key = key_obj.public_key()
        try:
            public_key.verify(signature, payload)
            return True
        except Exception:
            return False

    def encrypt(
        self,
        domain: KeyDomain,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
        kid: Optional[str] = None,
    ) -> EncryptionResult:
        if domain not in self.ENCRYPTION_DOMAINS:
            raise DomainSeparationViolationError(
                f"Domain '{domain.value}' is a signing domain, not an encryption domain."
            )

        target_kid = kid or self._active_kid[domain]
        if not target_kid or target_kid not in self._keys[domain]:
            raise KeyNotFoundError(f"Key '{target_kid}' not found in domain '{domain.value}'")

        metadata, key_bytes = self._keys[domain][target_kid]
        if not isinstance(key_bytes, bytes):
            raise DomainSeparationViolationError("Key object is not a symmetric key bytes instance.")

        nonce = os.urandom(12)  # 96-bit nonce standard for AES-GCM
        aesgcm = AESGCM(key_bytes)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

        return EncryptionResult(
            ciphertext=ciphertext,
            nonce=nonce,
            kid=target_kid,
            algorithm=metadata.algorithm,
        )

    def decrypt(
        self,
        domain: KeyDomain,
        ciphertext: bytes,
        nonce: bytes,
        kid: str,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        if domain not in self.ENCRYPTION_DOMAINS:
            raise DomainSeparationViolationError(
                f"Domain '{domain.value}' is a signing domain, not an encryption domain."
            )

        if kid not in self._keys[domain]:
            raise KeyNotFoundError(f"Key '{kid}' not found in domain '{domain.value}'")

        metadata, key_bytes = self._keys[domain][kid]
        if not isinstance(key_bytes, bytes):
            raise DomainSeparationViolationError("Key object is not a symmetric key bytes instance.")

        aesgcm = AESGCM(key_bytes)
        try:
            return aesgcm.decrypt(nonce, ciphertext, associated_data)
        except Exception as e:
            raise CryptoError(f"Decryption failed or authentication tag mismatch: {e}") from e

    def rotate_key(self, domain: KeyDomain) -> KeyMetadata:
        return self._generate_key(domain)

    def get_key_metadata(self, domain: KeyDomain, kid: Optional[str] = None) -> KeyMetadata:
        target_kid = kid or self._active_kid[domain]
        if not target_kid or target_kid not in self._keys[domain]:
            raise KeyNotFoundError(f"Key '{target_kid}' not found in domain '{domain.value}'")
        return self._keys[domain][target_kid][0]
