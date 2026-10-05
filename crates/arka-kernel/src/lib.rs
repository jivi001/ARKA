//! ARKA Security Kernel.
//!
//! Authoritative deterministic security boundary between untrusted inputs / LLMs
//! and downstream execution brokers.

#![forbid(unsafe_code)]

pub mod actions;
pub mod audit;
pub mod auth;
pub mod capabilities;
pub mod emergency_stop;
pub mod missions;
pub mod policy;
pub mod scope;
pub mod storage;

pub use actions::{ActionNormalizer, CURRENT_POLICY_VERSION};
pub use audit::AuditChainEngine;
pub use auth::AuthenticationService;
pub use capabilities::{CapabilityRegistry, StandardCapabilityRegistry};
pub use emergency_stop::EmergencyStopService;
pub use missions::MissionService;
pub use policy::{AuthorizationDecision, AuthorizationEngine};
pub use scope::{ScopeEngine, TargetParser};
pub use storage::{Storage, StorageTransaction};
