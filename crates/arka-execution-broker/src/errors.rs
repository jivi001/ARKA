//! Error types for the ARKA Execution Broker.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BrokerError {
    #[error("Action authorization failed or missing: {0}")]
    ActionNotAuthorized(String),

    #[error("Action hash mismatch: expected {expected}, computed {actual}")]
    ActionHashMismatch { expected: String, actual: String },

    #[error("Approval required but missing, expired, or invalid: {0}")]
    ApprovalMissingOrInvalid(String),

    #[error("Emergency stop is active for mission or platform: {0}")]
    EmergencyStopActive(String),

    #[error("Action deadline expired: deadline {deadline}, current time {now}")]
    ActionExpired { deadline: u64, now: u64 },

    #[error(
        "Duplicate dispatch detected for action {action_id} (attempt {attempt}). Replay denied."
    )]
    DuplicateDispatch { action_id: String, attempt: u32 },

    #[error("Illegal execution state transition from {from} to {to}")]
    IllegalStateTransition { from: String, to: String },

    #[error("Concurrency limit exceeded: {current} active dispatches (maximum {max})")]
    ConcurrencyLimitReached { current: usize, max: usize },

    #[error("Worker supervisor or sandbox communication failure: {0}")]
    WorkerCommunicationFailure(String),

    #[error("Worker execution failed: {0}")]
    WorkerExecutionFailure(String),

    #[error("Execution unit timed out after {timeout_ms}ms")]
    TimeoutExceeded { timeout_ms: u64 },

    #[error("Execution unit was cancelled: {0}")]
    Cancelled(String),

    #[error("Storage transaction or persistence error: {0}")]
    StorageError(String),

    #[error("Worker protocol error: {0}")]
    ProtocolError(String),

    #[error("Sandbox runtime initialization failed: {0}")]
    SandboxInitializationFailure(String),

    #[error("Sandbox execution failed or exited with error: {0}")]
    SandboxExecutionError(String),
}
