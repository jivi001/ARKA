//! ARKA Cryptographic & Canonicalization Engine.
//!
//! Provides RFC 8785 JCS canonicalization, domain-separated SHA-256 hashing,
//! Phase 0 KeyProvider integration, and deterministic token signing/verification.

#![forbid(unsafe_code)]

pub mod canonical;
pub mod hashing;
pub mod provider;
pub mod token;

pub use canonical::{canonicalize_json, canonicalize_json_bytes};
pub use hashing::{
    sha256_digest, sha256_hex, DOMAIN_ACTION, DOMAIN_APPROVAL, DOMAIN_AUDIT, DOMAIN_PARAM,
    DOMAIN_REPLAY, DOMAIN_TOKEN,
};
pub use provider::{
    CryptoError, DevKeyProvider, KeyDomain, KeyMetadata, KeyProvider, SignatureResult,
};
pub use token::{SignedToken, TokenClaims};
