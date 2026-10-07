//! Scope Evaluation Engine.
//!
//! Enforces:
//! - INV-003: Discovered != Authorized
//! - Section 11: Scope Invariants (Exclusions override Inclusions, Default-Deny).
//! - SSRF and cloud metadata access prevention.

use arka_core_types::errors::KernelSecurityError;
use arka_core_types::scope::{CanonicalTarget, ScopeDecision, ScopeDefinition};

pub struct ScopeEngine;

impl ScopeEngine {
    /// Evaluates a canonical target against a mission's scope definition.
    ///
    /// Precedence:
    /// 1. Exclusions: If matched, immediately DENY.
    /// 2. Restricted Addresses: If loopback/RFC1918/metadata and not explicitly allowed, DENY.
    /// 3. Inclusions: If matched, ALLOW.
    /// 4. Default: DENY.
    pub fn evaluate(
        scope: &ScopeDefinition,
        target: &CanonicalTarget,
    ) -> Result<(), KernelSecurityError> {
        match Self::evaluate_decision(scope, target) {
            ScopeDecision::Allowed => Ok(()),
            ScopeDecision::Denied(reason) => {
                Err(KernelSecurityError::ScopeDenied(reason.to_string()))
            }
        }
    }

    pub fn evaluate_decision(scope: &ScopeDefinition, target: &CanonicalTarget) -> ScopeDecision {
        // 1. Exclusions override inclusions unconditionally
        for exclusion in &scope.exclusions {
            if exclusion.matches(target) {
                return ScopeDecision::Denied("Target matches an explicit scope exclusion rule");
            }
        }

        // 2. Restricted address checks (SSRF / Cloud Metadata prevention)
        if !scope.allow_private_ranges && target.is_restricted_address() {
            return ScopeDecision::Denied(
                "Target is a restricted internal, loopback, or cloud metadata address",
            );
        }

        // 3. Inclusions check
        for inclusion in &scope.inclusions {
            if inclusion.matches(target) {
                return ScopeDecision::Allowed;
            }
        }

        // 4. Default-deny
        ScopeDecision::Denied("Target does not match any authorized scope inclusion rule")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arka_core_types::scope::{CidrBlock, ScopeRule};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_exclusions_override_inclusions() {
        let net = CidrBlock::new_v4(Ipv4Addr::new(10, 0, 0, 0), 16).unwrap();
        let target_allowed = CanonicalTarget::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5)));
        let target_excluded = CanonicalTarget::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 99, 99)));

        let scope = ScopeDefinition {
            inclusions: vec![ScopeRule::IpRange(net)],
            exclusions: vec![ScopeRule::IpExact(IpAddr::V4(Ipv4Addr::new(10, 0, 99, 99)))],
            allow_private_ranges: true, // test private range
        };

        // Included IP is allowed
        assert!(ScopeEngine::evaluate(&scope, &target_allowed).is_ok());

        // Excluded IP inside the included CIDR is denied!
        let res = ScopeEngine::evaluate(&scope, &target_excluded);
        assert!(matches!(res, Err(KernelSecurityError::ScopeDenied(_))));
    }

    #[test]
    fn test_default_deny() {
        let scope = ScopeDefinition {
            inclusions: vec![ScopeRule::DomainExact("authorized.example.com".to_string())],
            exclusions: vec![],
            allow_private_ranges: false,
        };

        let outside_target = CanonicalTarget::Domain {
            domain: "unauthorized.example.com".to_string(),
            port: None,
        };

        let res = ScopeEngine::evaluate(&scope, &outside_target);
        assert!(matches!(res, Err(KernelSecurityError::ScopeDenied(_))));
    }

    #[test]
    fn test_cloud_metadata_blocked() {
        let scope = ScopeDefinition {
            inclusions: vec![ScopeRule::IpRange(
                CidrBlock::new_v4(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap(),
            )],
            exclusions: vec![],
            allow_private_ranges: false, // Default deny private/metadata
        };

        let metadata_target = CanonicalTarget::Ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)));
        let res = ScopeEngine::evaluate(&scope, &metadata_target);
        assert!(matches!(res, Err(KernelSecurityError::ScopeDenied(_))));
    }
}
