//! Authority Delegation Model.
//!
//! Enforces:
//! - INV-003: Child authority cannot exceed parent authority.
//! - Strict monotonic subset validation: scope, capabilities, risk, budget, expiry, depth.

use crate::capabilities::RiskClass;
use crate::errors::KernelSecurityError;
use crate::id::CapabilityId;
use crate::scope::ScopeDefinition;
use serde::{Deserialize, Serialize};

/// Authoritative delegation permissions structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authority {
    pub scope: ScopeDefinition,
    pub capabilities: Vec<CapabilityId>,
    pub max_risk: RiskClass,
    pub budget_cents: u64,
    pub expires_at_unix: u64,
    pub delegation_depth: u32,
    pub max_delegation_depth: u32,
}

impl Authority {
    /// Validates that a child authority is strictly a non-expanding subset of parent authority (INV-003).
    pub fn validate_child_delegation(&self, child: &Authority) -> Result<(), KernelSecurityError> {
        // 1. Delegation depth check
        if child.delegation_depth <= self.delegation_depth {
            return Err(KernelSecurityError::AuthenticationFailed(
                "Child delegation depth must be strictly greater than parent depth".to_string(),
            ));
        }
        if child.delegation_depth > self.max_delegation_depth {
            return Err(KernelSecurityError::AuthenticationFailed(format!(
                "Child delegation depth {} exceeds maximum allowed depth {}",
                child.delegation_depth, self.max_delegation_depth
            )));
        }

        // 2. Risk check: child.risk <= parent.risk
        if child.max_risk > self.max_risk {
            return Err(KernelSecurityError::AuthenticationFailed(format!(
                "Child risk '{}' exceeds parent maximum risk '{}'",
                child.max_risk, self.max_risk
            )));
        }

        // 3. Budget check: child.budget <= parent.budget
        if child.budget_cents > self.budget_cents {
            return Err(KernelSecurityError::AuthenticationFailed(format!(
                "Child budget {} exceeds parent budget {}",
                child.budget_cents, self.budget_cents
            )));
        }

        // 4. Expiry check: child.expiry <= parent.expiry
        if child.expires_at_unix > self.expires_at_unix {
            return Err(KernelSecurityError::AuthenticationFailed(format!(
                "Child expiration {} exceeds parent expiration {}",
                child.expires_at_unix, self.expires_at_unix
            )));
        }

        // 5. Capability check: child.capabilities ⊆ parent.capabilities
        for cap in &child.capabilities {
            if !self.capabilities.contains(cap) {
                return Err(KernelSecurityError::AuthenticationFailed(format!(
                    "Child capability '{}' is not granted in parent authority",
                    cap
                )));
            }
        }

        // 6. Scope check: child scope cannot allow private ranges if parent disallows it
        if child.scope.allow_private_ranges && !self.scope.allow_private_ranges {
            return Err(KernelSecurityError::AuthenticationFailed(
                "Child cannot enable private ranges when parent disallows it".to_string(),
            ));
        }

        // 7. Exclusions check: parent exclusions MUST be present in child exclusions
        for parent_ex in &self.scope.exclusions {
            if !child.scope.exclusions.contains(parent_ex) {
                return Err(KernelSecurityError::AuthenticationFailed(
                    "Child scope fails to inherit mandatory parent exclusion rule".to_string(),
                ));
            }
        }

        Ok(())
    }
}
