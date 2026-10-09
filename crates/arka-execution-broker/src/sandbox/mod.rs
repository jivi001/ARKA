//! Rootless container sandbox and supervisor module.
//!
//! Provides process isolation, namespace partitioning, dropped capabilities,
//! bounded outputs, and deterministic teardown via Bubblewrap.

pub mod config;
pub mod dispatcher;
pub mod supervisor;

pub use config::SandboxConfig;
pub use dispatcher::SandboxWorkerDispatcher;
pub use supervisor::{SandboxSupervisor, SandboxedExecutionResult};
