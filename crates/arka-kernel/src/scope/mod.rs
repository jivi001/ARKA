//! Scope Module.
//!
//! Provides the target parser with bypass defense and the scope evaluation engine.

pub mod evaluator;
pub mod parser;

pub use evaluator::ScopeEngine;
pub use parser::TargetParser;
