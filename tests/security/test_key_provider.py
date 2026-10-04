"""
Unit tests for ARKA KeyProvider interface and DevelopmentKeyProvider implementation.
Verifies cryptographic domain separation, signature verification, authenticated encryption,
key rotation, and production safeguards.
Compatible with both pytest and python standard unittest.
"""

import os
import unittest
from arka.core.crypto.provider import (
    DevelopmentKeyProvider,
    KeyDomain,
    DomainSeparationViolationError,
    CryptoError,
    KeyNotFoundError,
)


class TestKeyProvider(unittest.TestCase):
    def setUp(self):
        # Ensure clean environment
        if "ARKA_ENVIRONMENT" in os.environ:
            del os.environ["ARKA_ENVIRONMENT"]

    def test_development_key_provider_initialization(self):
        provider = DevelopmentKeyProvider()
        self.assertTrue(provider.IS_DEVELOPMENT_ONLY)

        # Verify all 6 key domains are initialized
        for domain in KeyDomain:
            meta = provider.get_key_metadata(domain)
            self.assertEqual(meta.domain, domain)
            self.assertTrue(meta.active)
            self.assertEqual(meta.version, 1)
            self.assertTrue(meta.kid.startswith(domain.value))

    def test_token_signing_and_verification(self):
        provider = DevelopmentKeyProvider()
        payload = b"INV-002:capability:scan:target=10.0.0.1"

        result = provider.sign(KeyDomain.TOKEN_SIGNING, payload)
        self.assertIsNotNone(result.signature)
        self.assertEqual(len(result.signature), 64)  # Ed25519 signature length
        self.assertEqual(result.algorithm, "Ed25519")

        # Verify valid signature
        is_valid = provider.verify(KeyDomain.TOKEN_SIGNING, payload, result.signature, result.kid)
        self.assertTrue(is_valid)

        # Verify invalid payload fails
        is_invalid = provider.verify(
            KeyDomain.TOKEN_SIGNING, b"tampered_payload", result.signature, result.kid
        )
        self.assertFalse(is_invalid)

    def test_domain_separation_enforcement(self):
        provider = DevelopmentKeyProvider()
        payload = b"sensitive_data"

        # Attempting to sign using an encryption domain must fail
        with self.assertRaises(DomainSeparationViolationError):
            provider.sign(KeyDomain.CREDENTIAL_KEK, payload)

        with self.assertRaises(DomainSeparationViolationError):
            provider.sign(KeyDomain.MISSION_DATA_ENCRYPTION, payload)

        # Attempting to encrypt using a signing domain must fail
        with self.assertRaises(DomainSeparationViolationError):
            provider.encrypt(KeyDomain.TOKEN_SIGNING, payload)

        with self.assertRaises(DomainSeparationViolationError):
            provider.encrypt(KeyDomain.AUDIT_SIGNING, payload)

        with self.assertRaises(DomainSeparationViolationError):
            provider.encrypt(KeyDomain.ROOT_ANCHOR, payload)

        with self.assertRaises(DomainSeparationViolationError):
            provider.encrypt(KeyDomain.WORKER_IDENTITY, payload)

    def test_authenticated_encryption_and_decryption(self):
        provider = DevelopmentKeyProvider()
        secret = b"target_db_password_super_secret_123"
        aad = b"mission_id:mis-98765"

        enc_result = provider.encrypt(
            KeyDomain.CREDENTIAL_KEK,
            plaintext=secret,
            associated_data=aad,
        )
        self.assertNotEqual(enc_result.ciphertext, secret)
        self.assertEqual(len(enc_result.nonce), 12)
        self.assertEqual(enc_result.algorithm, "AES-256-GCM")

        # Decrypt with correct parameters
        decrypted = provider.decrypt(
            KeyDomain.CREDENTIAL_KEK,
            ciphertext=enc_result.ciphertext,
            nonce=enc_result.nonce,
            kid=enc_result.kid,
            associated_data=aad,
        )
        self.assertEqual(decrypted, secret)

        # Tampered ciphertext must fail decryption
        tampered_ciphertext = bytearray(enc_result.ciphertext)
        tampered_ciphertext[0] ^= 0xFF
        with self.assertRaises(CryptoError):
            provider.decrypt(
                KeyDomain.CREDENTIAL_KEK,
                ciphertext=bytes(tampered_ciphertext),
                nonce=enc_result.nonce,
                kid=enc_result.kid,
                associated_data=aad,
            )

        # Wrong AAD must fail decryption
        with self.assertRaises(CryptoError):
            provider.decrypt(
                KeyDomain.CREDENTIAL_KEK,
                ciphertext=enc_result.ciphertext,
                nonce=enc_result.nonce,
                kid=enc_result.kid,
                associated_data=b"wrong_mission_id",
            )

    def test_key_rotation(self):
        provider = DevelopmentKeyProvider()
        initial_meta = provider.get_key_metadata(KeyDomain.AUDIT_SIGNING)
        self.assertEqual(initial_meta.version, 1)

        new_meta = provider.rotate_key(KeyDomain.AUDIT_SIGNING)
        self.assertEqual(new_meta.version, 2)
        self.assertNotEqual(new_meta.kid, initial_meta.kid)
        self.assertTrue(new_meta.active)

        # Active key should now be version 2
        active_meta = provider.get_key_metadata(KeyDomain.AUDIT_SIGNING)
        self.assertEqual(active_meta.kid, new_meta.kid)

        # Old key is still accessible for verification by explicit kid
        old_meta = provider.get_key_metadata(KeyDomain.AUDIT_SIGNING, kid=initial_meta.kid)
        self.assertFalse(old_meta.active)

    def test_production_safety_guard(self):
        os.environ["ARKA_ENVIRONMENT"] = "production"
        try:
            with self.assertRaises(CryptoError) as exc_info:
                DevelopmentKeyProvider()
            self.assertIn("strictly forbidden in production", str(exc_info.exception))
        finally:
            del os.environ["ARKA_ENVIRONMENT"]


if __name__ == "__main__":
    unittest.main()
