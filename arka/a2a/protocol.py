"""
ARKA Agent-to-Agent (A2A) Protocol Implementation.

Enforces:
- Ed25519 cryptographic authentication under KeyDomain::TokenSigning (INV-002, INV-004)
- Replay resistance via monotonic nonces and message IDs
- Clock skew / TTL bounded freshness (60s window)
- Zero capability delegation authority across agents
- Ingress payload bounds (<= 64KB) and RFC 8785 canonical serialization
"""

import base64
import hashlib
import json
import logging
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from arka.core.crypto.provider import (
    DevelopmentKeyProvider,
    KeyDomain,
    KeyNotFoundError,
    KeyProvider,
)

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
from .models import A2aMessageEnvelope, A2aMessageType, A2aVerificationResult

logger = logging.getLogger("arka.a2a")

# Non-negotiable limits
MAX_PAYLOAD_BYTES: int = 65536  # 64 KB
MAX_CLOCK_SKEW_SECONDS: float = 60.0  # 60s TTL window
SUPPORTED_SCHEMA_VERSIONS: Set[str] = {"1.0.0"}

# Forbidden capability-granting keys in A2A payloads
FORBIDDEN_CAPABILITY_KEYS: Set[str] = {
    "capability_token",
    "token",
    "jwt",
    "authorization_token",
    "kernel_receipt",
    "bearer_token",
    "action_token",
    "execution_ticket",
}


def canonicalize_payload(payload: Any) -> bytes:
    """
    Produces deterministic canonical JSON bytes conforming to RFC 8785 (JCS).
    Lexicographically sorts keys, eliminates extraneous whitespace, enforces UTF-8.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_payload_hash(payload: Any) -> str:
    """Computes SHA-256 hex digest of canonicalized payload bytes."""
    payload_bytes = canonicalize_payload(payload)
    return hashlib.sha256(payload_bytes).hexdigest()


def build_signature_preimage(envelope: A2aMessageEnvelope) -> bytes:
    """
    Constructs the authoritative preimage for Ed25519 signing.
    Includes all core message metadata fields and the payload hash.
    """
    signed_fields = {
        "message_id": envelope.message_id,
        "message_type": (
            envelope.message_type.value
            if isinstance(envelope.message_type, A2aMessageType)
            else str(envelope.message_type)
        ),
        "mission_id": envelope.mission_id,
        "nonce": envelope.nonce,
        "parent_task_id": envelope.parent_task_id,
        "payload_hash": envelope.payload_hash,
        "recipient_id": envelope.recipient_id,
        "schema_version": envelope.schema_version,
        "sender_id": envelope.sender_id,
        "timestamp": envelope.timestamp,
    }
    return canonicalize_payload(signed_fields)


class A2aReplayCache:
    """
    Thread-safe in-memory cache tracking observed message IDs and (sender_id, nonce) tuples.
    Evicts entries older than ttl_seconds (default 120s to cover 60s clock skew window).
    """

    def __init__(self, ttl_seconds: float = 120.0):
        self._ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        # sender_id:nonce -> expire_at
        self._nonce_cache: Dict[str, float] = {}
        # message_id -> expire_at
        self._msg_id_cache: Dict[str, float] = {}

    def _purge_expired(self, now: float) -> None:
        """Purges entries past their expiration timestamp."""
        expired_nonces = [k for k, exp in self._nonce_cache.items() if exp <= now]
        for k in expired_nonces:
            del self._nonce_cache[k]

        expired_msgs = [k for k, exp in self._msg_id_cache.items() if exp <= now]
        for k in expired_msgs:
            del self._msg_id_cache[k]

    def check_and_record(
        self,
        sender_id: str,
        nonce: str,
        message_id: str,
        timestamp: float,
        current_time: Optional[float] = None,
    ) -> bool:
        """
        Atomically checks if (sender_id, nonce) or message_id was previously recorded.
        If fresh, records both and returns True. If replayed, returns False.
        """
        now = current_time if current_time is not None else time.time()
        expire_at = now + self._ttl_seconds
        nonce_key = f"{sender_id}:{nonce}"

        with self._lock:
            self._purge_expired(now)

            if nonce_key in self._nonce_cache:
                return False
            if message_id in self._msg_id_cache:
                return False

            self._nonce_cache[nonce_key] = expire_at
            self._msg_id_cache[message_id] = expire_at
            return True


class A2aSigner:
    """
    Signs outbound A2A message envelopes using Ed25519 under KeyDomain::TokenSigning.
    """

    def __init__(
        self,
        key_provider: Optional[KeyProvider] = None,
        kid: Optional[str] = None,
        private_key: Optional[ed25519.Ed25519PrivateKey] = None,
    ):
        if not key_provider and not private_key:
            raise ValueError("A2aSigner requires either a KeyProvider or an Ed25519PrivateKey.")

        self._key_provider = key_provider
        self._kid = kid
        self._private_key = private_key

    @property
    def kid(self) -> str:
        if self._kid:
            return self._kid
        if self._key_provider:
            meta = self._key_provider.get_key_metadata(KeyDomain.TOKEN_SIGNING)
            return meta.kid
        return "ed25519-custom-key"

    def sign_envelope(
        self,
        mission_id: str,
        sender_id: str,
        recipient_id: str,
        message_type: A2aMessageType,
        payload: Dict[str, Any],
        parent_task_id: Optional[str] = None,
        timestamp: Optional[float] = None,
        nonce: Optional[str] = None,
    ) -> A2aMessageEnvelope:
        """
        Constructs and signs a canonical A2aMessageEnvelope.
        """
        # Validate payload size
        payload_bytes = canonicalize_payload(payload)
        if len(payload_bytes) > MAX_PAYLOAD_BYTES:
            raise A2aPayloadTooLargeError(
                f"Payload size {len(payload_bytes)} bytes exceeds maximum {MAX_PAYLOAD_BYTES} bytes."
            )

        # Authority boundary check: agents cannot issue capability tokens
        for forbidden in FORBIDDEN_CAPABILITY_KEYS:
            if forbidden in payload:
                raise A2aCapabilityForbiddenError(
                    f"Forbidden authorization field '{forbidden}' detected in A2A payload. "
                    f"Agents have zero capability issuance authority."
                )

        now = timestamp if timestamp is not None else time.time()
        assigned_nonce = nonce if nonce is not None else secrets.token_hex(16)
        msg_id = f"msg-{secrets.token_hex(16)}"
        payload_hash = compute_payload_hash(payload)

        # Build partial envelope to generate signature preimage
        envelope = A2aMessageEnvelope(
            message_id=msg_id,
            mission_id=mission_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            parent_task_id=parent_task_id,
            message_type=message_type,
            schema_version="1.0.0",
            timestamp=now,
            nonce=assigned_nonce,
            payload=payload,
            payload_hash=payload_hash,
            signature="",
            kid=self.kid,
        )

        preimage = build_signature_preimage(envelope)

        # Perform Ed25519 signature
        if self._key_provider:
            sig_result = self._key_provider.sign(
                KeyDomain.TOKEN_SIGNING,
                payload=preimage,
                kid=self._kid,
            )
            sig_bytes = sig_result.signature
            envelope.kid = sig_result.kid
        elif self._private_key:
            sig_bytes = self._private_key.sign(preimage)
        else:
            raise A2aSignatureError("No active signing key configured.")

        envelope.signature = base64.b64encode(sig_bytes).decode("ascii")
        return envelope


class A2aVerifier:
    """
    Authoritative verifier for inbound A2A message envelopes.
    
    Verifies:
    1. Maximum payload size (<= 64 KB)
    2. Schema version compatibility
    3. Absence of forbidden capability tokens / execution grants
    4. Mission ID binding
    5. Recipient ID binding
    6. Timestamp freshness (within 60s TTL)
    7. Replay resistance (nonce and message_id)
    8. Payload SHA-256 hash integrity
    9. Ed25519 signature verification against sender key
    """

    def __init__(
        self,
        key_provider: Optional[KeyProvider] = None,
        public_keys: Optional[Dict[str, ed25519.Ed25519PublicKey]] = None,
        replay_cache: Optional[A2aReplayCache] = None,
        max_clock_skew: float = MAX_CLOCK_SKEW_SECONDS,
    ):
        self._key_provider = key_provider
        self._public_keys = public_keys or {}
        self._replay_cache = replay_cache or A2aReplayCache()
        self._max_clock_skew = max_clock_skew

    def register_public_key(self, kid_or_sender: str, public_key: ed25519.Ed25519PublicKey) -> None:
        """Registers a public key for a given sender ID or key ID."""
        self._public_keys[kid_or_sender] = public_key

    def verify_envelope(
        self,
        envelope: A2aMessageEnvelope,
        expected_mission_id: Optional[str] = None,
        expected_recipient_id: Optional[str] = None,
        current_time: Optional[float] = None,
    ) -> A2aVerificationResult:
        """
        Executes strict 9-stage verification.
        Raises specific A2aError subclasses on failure, or returns A2aVerificationResult.
        """
        now = current_time if current_time is not None else time.time()

        # 1. Payload size check
        payload_bytes = canonicalize_payload(envelope.payload)
        if len(payload_bytes) > MAX_PAYLOAD_BYTES:
            raise A2aPayloadTooLargeError(
                f"Payload size {len(payload_bytes)} bytes exceeds maximum {MAX_PAYLOAD_BYTES} bytes."
            )

        # 2. Schema version check
        if envelope.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            raise A2aSchemaError(
                f"Unsupported A2A schema version: {envelope.schema_version}. Supported: {SUPPORTED_SCHEMA_VERSIONS}"
            )

        # 3. Authority boundary check: verify no capability tokens in payload
        for forbidden in FORBIDDEN_CAPABILITY_KEYS:
            if forbidden in envelope.payload:
                raise A2aCapabilityForbiddenError(
                    f"Forbidden authorization field '{forbidden}' detected in A2A message payload. "
                    f"Agents cannot issue or delegate capability tokens."
                )

        # 4. Mission isolation check
        if expected_mission_id and envelope.mission_id != expected_mission_id:
            raise A2aMissionMismatchError(
                f"Cross-mission message rejected: envelope mission '{envelope.mission_id}' "
                f"does not match expected mission '{expected_mission_id}'."
            )

        # 5. Recipient check
        if expected_recipient_id:
            if envelope.recipient_id != expected_recipient_id and envelope.recipient_id != "BROADCAST":
                raise A2aRecipientMismatchError(
                    f"Message addressed to '{envelope.recipient_id}' but received by '{expected_recipient_id}'."
                )

        # 6. Timestamp freshness (60s TTL window)
        time_diff = now - envelope.timestamp
        if abs(time_diff) > self._max_clock_skew:
            reason = "expired" if time_diff > 0 else "from the future"
            raise A2aExpiredError(
                f"Message timestamp {envelope.timestamp} is {reason} (skew: {time_diff:.2f}s > {self._max_clock_skew}s)."
            )

        # 7. Replay filter check
        if not self._replay_cache.check_and_record(
            sender_id=envelope.sender_id,
            nonce=envelope.nonce,
            message_id=envelope.message_id,
            timestamp=envelope.timestamp,
            current_time=now,
        ):
            raise A2aReplayError(
                f"Replayed message detected: sender '{envelope.sender_id}', nonce '{envelope.nonce}', "
                f"msg_id '{envelope.message_id}'."
            )

        # 8. Payload hash integrity
        computed_hash = compute_payload_hash(envelope.payload)
        if computed_hash != envelope.payload_hash:
            raise A2aSignatureError(
                f"Payload hash mismatch! Computed: {computed_hash}, envelope claims: {envelope.payload_hash}."
            )

        # 9. Ed25519 signature verification
        preimage = build_signature_preimage(envelope)
        try:
            sig_bytes = base64.b64decode(envelope.signature)
        except Exception as e:
            raise A2aSignatureError(f"Malformed base64 signature in envelope: {e}") from e

        # Resolve public key
        verified = False
        # Try direct public key lookup by sender_id or kid
        pubkey = self._public_keys.get(envelope.kid) or self._public_keys.get(envelope.sender_id)
        if pubkey:
            try:
                pubkey.verify(sig_bytes, preimage)
                verified = True
            except Exception:
                verified = False
        elif self._key_provider:
            try:
                verified = self._key_provider.verify(
                    KeyDomain.TOKEN_SIGNING,
                    payload=preimage,
                    signature=sig_bytes,
                    kid=envelope.kid,
                )
            except KeyNotFoundError:
                raise A2aSignatureError(
                    f"Signing key '{envelope.kid}' not registered in KeyProvider."
                )
            except Exception as e:
                raise A2aSignatureError(f"Cryptographic verification error: {e}") from e
        else:
            raise A2aSignatureError(
                f"No verification key found for kid '{envelope.kid}' or sender '{envelope.sender_id}'."
            )

        if not verified:
            raise A2aSignatureError(
                f"Signature verification failed for sender '{envelope.sender_id}' using kid '{envelope.kid}'."
            )

        return A2aVerificationResult(
            is_valid=True,
            envelope=envelope,
        )
