//! Kernel Authentication and Security Context Engine.
//!
//! Enforces:
//! - INV-004: All requester identities originate from cryptographically verified tokens.
//! - Rejection of expired, revoked, or forged tokens.

use arka_core_types::clock::Clock;
use arka_core_types::errors::KernelSecurityError;
use arka_core_types::subject::AuthenticatedContext;
use arka_crypto::provider::KeyProvider;
use arka_crypto::token::SignedToken;
use std::sync::Arc;

pub struct AuthenticationService {
    key_provider: Arc<dyn KeyProvider>,
    clock: Arc<dyn Clock>,
}

impl AuthenticationService {
    pub fn new(key_provider: Arc<dyn KeyProvider>, clock: Arc<dyn Clock>) -> Self {
        Self {
            key_provider,
            clock,
        }
    }

    /// Authenticates a signed token envelope and constructs an authoritative AuthenticatedContext.
    pub fn authenticate(
        &self,
        token: &SignedToken,
    ) -> Result<AuthenticatedContext, KernelSecurityError> {
        token.verify(self.key_provider.as_ref(), self.clock.as_ref())
    }
}
