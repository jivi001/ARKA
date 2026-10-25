//! ARKA Security Kernel Daemon Library.
//!
//! Exposes protocol models, typed errors, and the UDS service server.

#![forbid(unsafe_code)]

pub mod errors;
pub mod protocol;
pub mod server;

pub use errors::KernelServiceError;
pub use protocol::{
    KernelErrorPayload, KernelExecutionResult, KernelRequest, KernelResponse,
    DEFAULT_MAX_FRAME_SIZE, DEFAULT_TIMEOUT_MS,
};
pub use server::{KernelServer, KernelServerConfig};
