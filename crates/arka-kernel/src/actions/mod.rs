//! Actions Module.
//!
//! Provides the canonical normalization boundary from untrusted proposals to CanonicalActions.

pub mod normalizer;

pub use normalizer::{ActionNormalizer, CURRENT_POLICY_VERSION};
