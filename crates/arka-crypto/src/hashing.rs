//! Domain-separated SHA-256 cryptographic hashing.
//!
//! Enforces:
//! - Section 4.6: Explicit domain separation for all security-relevant hashes.
//! - SHA-256 standard hashing algorithm.

use sha2::{Digest, Sha256};

pub const DOMAIN_TOKEN: &str = "ARKA-TOKEN-V1:";
pub const DOMAIN_ACTION: &str = "ARKA-ACTION-V1:";
pub const DOMAIN_PARAM: &str = "ARKA-PARAM-V1:";
pub const DOMAIN_AUDIT: &str = "ARKA-AUDIT-V1:";
pub const DOMAIN_APPROVAL: &str = "ARKA-APPROVAL-V1:";
pub const DOMAIN_REPLAY: &str = "ARKA-REPLAY-V1:";

/// Computes SHA-256 with explicit domain separation prefix:
/// SHA-256(domain_prefix || data)
pub fn sha256_digest(domain: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes SHA-256 with explicit domain separation prefix and returns a lowercase hex string.
pub fn sha256_hex(domain: &str, data: &[u8]) -> String {
    hex::encode(sha256_digest(domain, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_separation_produces_distinct_hashes() {
        let payload = b"action_payload_123";
        let h1 = sha256_digest(DOMAIN_ACTION, payload);
        let h2 = sha256_digest(DOMAIN_PARAM, payload);

        assert_ne!(
            h1, h2,
            "Different domains must produce different digests for identical payload"
        );
    }

    #[test]
    fn test_sha256_hex_length() {
        let h = sha256_hex(DOMAIN_TOKEN, b"claims");
        assert_eq!(h.len(), 64);
    }
}
