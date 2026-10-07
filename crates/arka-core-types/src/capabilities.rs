//! Capability Metadata and Risk Classification Model.
//!
//! Enforces:
//! - INV-005: Risk is derived from the Capability Registry, not self-declared.
//! - Typed permission primitives and approval policy definitions.

use crate::id::CapabilityId;
use crate::scope::CanonicalTarget;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Deterministic Risk Classification defined by TRD Section 9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskClass {
    Observation = 1,
    Low = 2,
    Moderate = 3,
    High = 4,
    Critical = 5,
}

impl RiskClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskClass::Observation => "OBSERVATION",
            RiskClass::Low => "LOW",
            RiskClass::Moderate => "MODERATE",
            RiskClass::High => "HIGH",
            RiskClass::Critical => "CRITICAL",
        }
    }
}

impl fmt::Display for RiskClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Allowed target types for a given capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TargetClass {
    Ip,
    Cidr,
    Domain,
    Url,
}

impl TargetClass {
    pub fn matches_target(&self, target: &CanonicalTarget) -> bool {
        matches!(
            (self, target),
            (TargetClass::Ip, CanonicalTarget::Ip(_))
                | (TargetClass::Ip, CanonicalTarget::IpPort { .. })
                | (TargetClass::Cidr, CanonicalTarget::Cidr(_))
                | (TargetClass::Domain, CanonicalTarget::Domain { .. })
                | (TargetClass::Url, CanonicalTarget::UrlOrigin { .. })
        )
    }
}

/// Authoritative metadata defining capability execution policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityMetadata {
    pub id: CapabilityId,
    pub name: String,
    pub description: String,
    pub risk_class: RiskClass,
    pub requires_approval: bool,
    pub allowed_target_classes: Vec<TargetClass>,
    pub network_required: bool,
    pub timeout_seconds: u32,
    pub sandbox_profile: String,
}

impl CapabilityMetadata {
    pub fn allows_target(&self, target: &CanonicalTarget) -> bool {
        self.allowed_target_classes
            .iter()
            .any(|tc| tc.matches_target(target))
    }
}
