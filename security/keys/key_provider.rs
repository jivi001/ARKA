//! ARKA Cryptographic Key Provider Contract (Phase 1 Kernel Trait Specification)
//!
//! Enforces compile-time and runtime key-domain separation across the 6 independent
//! cryptographic domains defined in `security/keys/key-management-policy.yaml`.
//!
//! Security Invariant: INV-011 (Cryptographic Domain Separation)
//! "Keys from domain X cannot be used in domain Y under any circumstances."

use std::error::Error;
use std::fmt;

/// The six independent security domains defined by ARKA Cryptographic Policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyDomain {
    /// Long-term master signing anchor for issuing subsystem certificates.
    RootAnchor,
    /// Ed25519 signing key for deterministic capability and authorization tokens.
    TokenSigning,
    /// Ed25519 signing key for immutable audit log chain signatures.
    AuditSigning,
    /// AES-256-GCM Key Encryption Key for securing credential store secrets.
    CredentialKek,
    /// AES-256-GCM Data Encryption Key for per-mission / per-evidence storage.
    MissionDataEncryption,
    /// Ed25519 keypair for mTLS and internal worker process authentication.
    WorkerIdentity,
}

impl fmt::Display for KeyDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyDomain::RootAnchor => write!(f, "ROOT-ANCHOR"),
            KeyDomain::TokenSigning => write!(f, "TOKEN-SIGNING"),
            KeyDomain::AuditSigning => write!(f, "AUDIT-SIGNING"),
            KeyDomain::CredentialKek => write!(f, "CREDENTIAL-KEK"),
            KeyDomain::MissionDataEncryption => write!(f, "MISSION-DATA-ENCRYPTION"),
            KeyDomain::WorkerIdentity => write!(f, "WORKER-IDENTITY"),
        }
    }
}

/// Metadata identifying a key without exposing raw key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMetadata {
    pub kid: String,
    pub domain: KeyDomain,
    pub algorithm: String,
    pub version: u32,
    pub created_at_unix: u64,
    pub active: bool,
}

/// Cryptographic signature result containing signature bytes and verification metadata.
#[derive(Debug, Clone)]
pub struct SignatureResult {
    pub signature: Vec<u8>,
    pub kid: String,
    pub algorithm: String,
    pub timestamp_unix: u64,
}

/// Authenticated ciphertext result containing ciphertext, nonce, and key ID.
#[derive(Debug, Clone)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub kid: String,
    pub algorithm: String,
}

/// Cryptographic error states.
#[derive(Debug)]
pub enum CryptoError {
    DomainSeparationViolation(String),
    KeyNotFound(String),
    SigningFailed(String),
    VerificationFailed(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    KeyRotationForbidden(String),
    HardwareEnclaveUnavailable(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::DomainSeparationViolation(msg) => write!(f, "Domain separation violation: {}", msg),
            CryptoError::KeyNotFound(msg) => write!(f, "Key not found: {}", msg),
            CryptoError::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            CryptoError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            CryptoError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            CryptoError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            CryptoError::KeyRotationForbidden(msg) => write!(f, "Key rotation forbidden: {}", msg),
            CryptoError::HardwareEnclaveUnavailable(msg) => write!(f, "Hardware enclave unavailable: {}", msg),
        }
    }
}

impl Error for CryptoError {}

/// Authoritative KeyProvider trait for the Rust Security Kernel.
///
/// Implemented by Hardware Security Module (HSM) connectors, KMS drivers,
/// or development mocking providers.
pub trait KeyProvider: Send + Sync {
    /// Sign a payload using the domain's active signing key.
    ///
    /// Fails with `DomainSeparationViolation` if invoked on an encryption domain.
    fn sign(&self, domain: KeyDomain, payload: &[u8], kid: Option<&str>) -> Result<SignatureResult, CryptoError>;

    /// Verify a digital signature against the payload and key ID.
    fn verify(&self, domain: KeyDomain, payload: &[u8], signature: &[u8], kid: &str) -> Result<bool, CryptoError>;

    /// Encrypt plaintext using authenticated encryption (e.g. AES-256-GCM).
    ///
    /// Fails with `DomainSeparationViolation` if invoked on a signing domain.
    fn encrypt(
        &self,
        domain: KeyDomain,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
        kid: Option<&str>,
    ) -> Result<EncryptionResult, CryptoError>;

    /// Decrypt authenticated ciphertext using the specified key ID and nonce.
    fn decrypt(
        &self,
        domain: KeyDomain,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        kid: &str,
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Rotate active key material for a domain.
    fn rotate_key(&self, domain: KeyDomain) -> Result<KeyMetadata, CryptoError>;

    /// Retrieve public key or key metadata without exposing private key bytes.
    fn get_key_metadata(&self, domain: KeyDomain, kid: Option<&str>) -> Result<KeyMetadata, CryptoError>;
}
