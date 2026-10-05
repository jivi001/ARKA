//! ARKA Security Kernel.
//!
//! Authoritative deterministic security boundary between untrusted inputs / LLMs
//! and downstream execution brokers.

#![forbid(unsafe_code)]

pub mod auth;
pub mod missions;
pub mod scope;
pub mod storage;

pub use auth::AuthenticationService;
pub use missions::MissionService;
pub use scope::{ScopeEngine, TargetParser};
pub use storage::{Storage, StorageTransaction};
