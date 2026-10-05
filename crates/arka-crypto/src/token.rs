//! Deterministic JCS Signed Token issuance and verification.
//!
//! Enforces:
//! - INV-004: Identity comes strictly from verified token claims.
//! - RFC 8785 canonical serialization with domain separation `ARKA-TOKEN-V1:`.
//! - Clock-abstracted expiration and revocation validation.

use crate::canonical::canonicalize_json;
use crate::hashing::DOMAIN_TOKEN;
use crate::provider::{KeyDomain, KeyProvider};
use arka_core_types::clock::Clock;
use arka_core_types::errors::KernelSecurityError;
use arka_core_types::id::{CapabilityId, MissionId, TaskId, TokenId};
use arka_core_types::subject::{AuthenticatedContext, Subject};
use serde::{Deserialize, Serialize};

/// Cryptographically sealed claims payload of an ARKA Identity/Capability Token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenClaims {
    pub token_id: TokenId,
    pub subject: Subject,
    pub mission_id: MissionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_task_id: Option<TaskId>,
    pub capabilities: Vec<CapabilityId>,
    pub scope_ref: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_token_id: Option<TokenId>,
}

/// The wire envelope for a signed security token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedToken {
    pub kid: String,
    pub alg: String,
    pub claims: TokenClaims,
    pub signature: String, // 64-byte Ed25519 signature in hex
}

impl SignedToken {
    /// Issues a signed token using RFC 8785 canonical bytes and DOMAIN_TOKEN domain separation.
    pub fn issue(
        claims: TokenClaims,
        kid: &str,
        provider: &dyn KeyProvider,
    ) -> Result<Self, KernelSecurityError> {
        let claims_value = serde_json::to_value(&claims)
            .map_err(|e| KernelSecurityError::InternalFailure(e.to_string()))?;
        let canon_str = canonicalize_json(&claims_value)
            .map_err(|e| KernelSecurityError::InternalFailure(e.to_string()))?;

        let mut signed_data = Vec::with_capacity(DOMAIN_TOKEN.len() + canon_str.len());
        signed_data.extend_from_slice(DOMAIN_TOKEN.as_bytes());
        signed_data.extend_from_slice(canon_str.as_bytes());

        let sig_res = provider
            .sign(KeyDomain::TokenSigning, kid, &signed_data)
            .map_err(|e| KernelSecurityError::AuthenticationFailed(e.to_string()))?;

        Ok(Self {
            kid: kid.to_string(),
            alg: "Ed25519".to_string(),
            claims,
            signature: hex::encode(sig_res.signature),
        })
    }

    /// Verifies the token envelope and claims against the KeyProvider, revocation state, and Clock.
    pub fn verify(
        &self,
        provider: &dyn KeyProvider,
        clock: &dyn Clock,
    ) -> Result<AuthenticatedContext, KernelSecurityError> {
        // 1. Verify algorithm
        if self.alg != "Ed25519" {
            return Err(KernelSecurityError::AuthenticationFailed(format!(
                "Unsupported algorithm '{}', expected Ed25519",
                self.alg
            )));
        }

        // 2. Check key revocation state
        if provider.is_revoked(&self.kid) {
            return Err(KernelSecurityError::TokenRevoked(format!(
                "Signing key {} has been revoked",
                self.kid
            )));
        }

        // 3. Decode signature bytes
        let sig_bytes = hex::decode(&self.signature).map_err(|_| {
            KernelSecurityError::InvalidSignature("Signature is not valid hexadecimal".to_string())
        })?;
        if sig_bytes.len() != 64 {
            return Err(KernelSecurityError::InvalidSignature(format!(
                "Invalid signature length {} (expected 64)",
                sig_bytes.len()
            )));
        }

        // 4. Re-canonicalize claims payload using RFC 8785
        let claims_value = serde_json::to_value(&self.claims)
            .map_err(|e| KernelSecurityError::InternalFailure(e.to_string()))?;
        let canon_str = canonicalize_json(&claims_value)
            .map_err(|e| KernelSecurityError::InternalFailure(e.to_string()))?;

        let mut signed_data = Vec::with_capacity(DOMAIN_TOKEN.len() + canon_str.len());
        signed_data.extend_from_slice(DOMAIN_TOKEN.as_bytes());
        signed_data.extend_from_slice(canon_str.as_bytes());

        // 5. Verify Ed25519 signature under TokenSigning domain
        let valid = provider
            .verify(KeyDomain::TokenSigning, &self.kid, &signed_data, &sig_bytes)
            .map_err(|e| KernelSecurityError::InvalidSignature(e.to_string()))?;

        if !valid {
            return Err(KernelSecurityError::InvalidSignature(
                "Ed25519 signature verification failed".to_string(),
            ));
        }

        // 6. Verify expiration
        let now = clock.now_unix();
        if now >= self.claims.expires_at_unix {
            return Err(KernelSecurityError::TokenExpired {
                expired_at: self.claims.expires_at_unix,
                current_time: now,
            });
        }

        // 7. Construct trusted AuthenticatedContext
        Ok(AuthenticatedContext {
            token_id: self.claims.token_id.clone(),
            subject: self.claims.subject.clone(),
            mission_id: self.claims.mission_id.clone(),
            parent_task_id: self.claims.parent_task_id.clone(),
            capabilities: self.claims.capabilities.clone(),
            scope_ref: self.claims.scope_ref.clone(),
            issued_at_unix: self.claims.issued_at_unix,
            expires_at_unix: self.claims.expires_at_unix,
            parent_token_id: self.claims.parent_token_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::DevKeyProvider;
    use arka_core_types::clock::MockClock;
    use arka_core_types::id::{AgentId, CapabilityId, MissionId, OperatorId, TokenId};

    fn sample_claims(now: u64, ttl: u64) -> TokenClaims {
        TokenClaims {
            token_id: TokenId::new("tok-sample-01").unwrap(),
            subject: Subject::Operator(OperatorId::new("opr-analyst").unwrap()),
            mission_id: MissionId::new("mis-redteam-01").unwrap(),
            parent_task_id: None,
            capabilities: vec![CapabilityId::new("PORT_SCAN").unwrap()],
            scope_ref: "scope-main-01".to_string(),
            issued_at_unix: now,
            expires_at_unix: now + ttl,
            parent_token_id: None,
        }
    }

    #[test]
    fn test_issue_and_verify_token_success() {
        let provider = DevKeyProvider::new();
        let clock = MockClock::new(1000);
        let claims = sample_claims(1000, 900); // 15 min TTL

        let token = SignedToken::issue(claims, "TOKEN-SIGNING-dev-01", &provider).unwrap();
        let auth_ctx = token.verify(&provider, &clock).unwrap();

        assert_eq!(auth_ctx.mission_id.as_str(), "mis-redteam-01");
        assert!(auth_ctx.subject.is_operator());
        assert_eq!(auth_ctx.capabilities.len(), 1);
    }

    #[test]
    fn test_tampered_token_rejected() {
        let provider = DevKeyProvider::new();
        let clock = MockClock::new(1000);
        let claims = sample_claims(1000, 900);

        let mut token = SignedToken::issue(claims, "TOKEN-SIGNING-dev-01", &provider).unwrap();
        // Tamper with subject identity
        token.claims.subject = Subject::Agent(AgentId::new("agt-injected").unwrap());

        let res = token.verify(&provider, &clock);
        assert!(matches!(res, Err(KernelSecurityError::InvalidSignature(_))));
    }

    #[test]
    fn test_expired_token_rejected() {
        let provider = DevKeyProvider::new();
        let clock = MockClock::new(1000);
        let claims = sample_claims(1000, 300); // Expires at 1300

        let token = SignedToken::issue(claims, "TOKEN-SIGNING-dev-01", &provider).unwrap();

        // Advance clock past expiration
        clock.set_now(1301);
        let res = token.verify(&provider, &clock);
        assert!(matches!(res, Err(KernelSecurityError::TokenExpired { .. })));
    }

    #[test]
    fn test_revoked_key_token_rejected() {
        let provider = DevKeyProvider::new();
        let clock = MockClock::new(1000);
        let claims = sample_claims(1000, 900);

        let token = SignedToken::issue(claims, "TOKEN-SIGNING-dev-01", &provider).unwrap();

        provider.revoke_key("TOKEN-SIGNING-dev-01");
        let res = token.verify(&provider, &clock);
        assert!(matches!(res, Err(KernelSecurityError::TokenRevoked(_))));
    }
}
