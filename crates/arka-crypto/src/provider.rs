//! Cryptographic Key Provider Interface and In-Memory Development Provider.
//!
//! Enforces:
//! - INV-011: Strict cryptographic domain separation across all 6 key domains.
//! - Ed25519 signing and verification.
//! - Non-exportable key material.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;
use thiserror::Error;

/// The six independent security domains defined by ARKA Cryptographic Policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyDomain {
    RootAnchor,
    TokenSigning,
    AuditSigning,
    CredentialKek,
    MissionDataEncryption,
    WorkerIdentity,
}

impl KeyDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyDomain::RootAnchor => "ROOT-ANCHOR",
            KeyDomain::TokenSigning => "TOKEN-SIGNING",
            KeyDomain::AuditSigning => "AUDIT-SIGNING",
            KeyDomain::CredentialKek => "CREDENTIAL-KEK",
            KeyDomain::MissionDataEncryption => "MISSION-DATA-ENCRYPTION",
            KeyDomain::WorkerIdentity => "WORKER-IDENTITY",
        }
    }
}

impl fmt::Display for KeyDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMetadata {
    pub kid: String,
    pub domain: KeyDomain,
    pub algorithm: String,
    pub version: u32,
    pub created_at_unix: u64,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct SignatureResult {
    pub signature: Vec<u8>,
    pub kid: String,
    pub algorithm: String,
    pub timestamp_unix: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Domain separation violation: {0}")]
    DomainSeparationViolation(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Key is revoked: {0}")]
    KeyRevoked(String),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

pub trait KeyProvider: Send + Sync {
    fn sign(
        &self,
        domain: KeyDomain,
        kid: &str,
        data: &[u8],
    ) -> Result<SignatureResult, CryptoError>;
    fn verify(
        &self,
        domain: KeyDomain,
        kid: &str,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError>;
    fn get_metadata(&self, kid: &str) -> Result<KeyMetadata, CryptoError>;
    fn is_revoked(&self, kid: &str) -> bool;
}

struct KeyEntry {
    signing_key: SigningKey,
    metadata: KeyMetadata,
}

/// Development in-memory key provider generating ephemeral Ed25519 keys for testing.
pub struct DevKeyProvider {
    keys: RwLock<HashMap<String, KeyEntry>>,
    revoked_kids: RwLock<HashMap<String, bool>>,
}

impl DevKeyProvider {
    pub fn new() -> Self {
        let provider = Self {
            keys: RwLock::new(HashMap::new()),
            revoked_kids: RwLock::new(HashMap::new()),
        };

        // Initialize default development keys for the signing domains
        provider.init_default_key(KeyDomain::TokenSigning, "TOKEN-SIGNING-dev-01");
        provider.init_default_key(KeyDomain::AuditSigning, "AUDIT-SIGNING-dev-01");
        provider.init_default_key(KeyDomain::RootAnchor, "ROOT-ANCHOR-dev-01");
        provider.init_default_key(KeyDomain::WorkerIdentity, "WORKER-IDENTITY-dev-01");

        provider
    }

    fn init_default_key(&self, domain: KeyDomain, kid: &str) {
        use rand_core::OsRng;
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let metadata = KeyMetadata {
            kid: kid.to_string(),
            domain,
            algorithm: "Ed25519".to_string(),
            version: 1,
            created_at_unix: 1700000000,
            active: true,
        };

        self.keys.write().unwrap().insert(
            kid.to_string(),
            KeyEntry {
                signing_key,
                metadata,
            },
        );
    }

    pub fn revoke_key(&self, kid: &str) {
        self.revoked_kids
            .write()
            .unwrap()
            .insert(kid.to_string(), true);
    }
}

impl Default for DevKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for DevKeyProvider {
    fn sign(
        &self,
        domain: KeyDomain,
        kid: &str,
        data: &[u8],
    ) -> Result<SignatureResult, CryptoError> {
        let keys = self.keys.read().unwrap();
        let entry = keys
            .get(kid)
            .ok_or_else(|| CryptoError::KeyNotFound(kid.to_string()))?;

        // INV-011: Enforce strict domain separation
        if entry.metadata.domain != domain {
            return Err(CryptoError::DomainSeparationViolation(format!(
                "Key {} belongs to domain {}, cannot be used for domain {}",
                kid, entry.metadata.domain, domain
            )));
        }

        if self.is_revoked(kid) {
            return Err(CryptoError::KeyRevoked(kid.to_string()));
        }

        let signature: Signature = entry.signing_key.sign(data);
        Ok(SignatureResult {
            signature: signature.to_vec(),
            kid: kid.to_string(),
            algorithm: "Ed25519".to_string(),
            timestamp_unix: 1700000000,
        })
    }

    fn verify(
        &self,
        domain: KeyDomain,
        kid: &str,
        data: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, CryptoError> {
        let keys = self.keys.read().unwrap();
        let entry = keys
            .get(kid)
            .ok_or_else(|| CryptoError::KeyNotFound(kid.to_string()))?;

        // INV-011: Domain separation
        if entry.metadata.domain != domain {
            return Err(CryptoError::DomainSeparationViolation(format!(
                "Key {} belongs to domain {}, cannot verify in domain {}",
                kid, entry.metadata.domain, domain
            )));
        }

        if self.is_revoked(kid) {
            return Err(CryptoError::KeyRevoked(kid.to_string()));
        }

        let signature = Signature::from_slice(signature_bytes)
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;

        let verifying_key: VerifyingKey = entry.signing_key.verifying_key();
        Ok(verifying_key.verify(data, &signature).is_ok())
    }

    fn get_metadata(&self, kid: &str) -> Result<KeyMetadata, CryptoError> {
        let keys = self.keys.read().unwrap();
        let entry = keys
            .get(kid)
            .ok_or_else(|| CryptoError::KeyNotFound(kid.to_string()))?;
        Ok(entry.metadata.clone())
    }

    fn is_revoked(&self, kid: &str) -> bool {
        self.revoked_kids
            .read()
            .unwrap()
            .get(kid)
            .copied()
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_success() {
        let provider = DevKeyProvider::new();
        let payload = b"critical_authorization_token_data";
        let res = provider
            .sign(KeyDomain::TokenSigning, "TOKEN-SIGNING-dev-01", payload)
            .unwrap();

        assert_eq!(res.signature.len(), 64);
        let valid = provider
            .verify(
                KeyDomain::TokenSigning,
                "TOKEN-SIGNING-dev-01",
                payload,
                &res.signature,
            )
            .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_domain_separation_enforcement() {
        let provider = DevKeyProvider::new();
        let payload = b"audit_event_block";

        // Attempting to sign using AuditSigning domain with a TokenSigning key must fail
        let res = provider.sign(KeyDomain::AuditSigning, "TOKEN-SIGNING-dev-01", payload);
        assert!(matches!(
            res,
            Err(CryptoError::DomainSeparationViolation(_))
        ));
    }

    #[test]
    fn test_revoked_key_rejected() {
        let provider = DevKeyProvider::new();
        let kid = "TOKEN-SIGNING-dev-01";
        provider.revoke_key(kid);

        let res = provider.sign(KeyDomain::TokenSigning, kid, b"data");
        assert!(matches!(res, Err(CryptoError::KeyRevoked(_))));
    }
}
