//! Policy & Authorization Module.
//!
//! Provides the authorization decision engine (ALLOW, DENY, REQUIRE_APPROVAL).

pub mod engine;

pub use engine::{AuthorizationDecision, AuthorizationEngine};
