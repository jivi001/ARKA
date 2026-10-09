//! Worker dispatch abstraction and NoOpWorker test implementation.
//!
//! Enforces:
//! - Non-side-effecting integration testing path
//! - Strict isolation: broker dispatches through typed trait interface

use crate::errors::BrokerError;
use crate::record::{ExecutionRecord, ExecutionResultEnvelope};
use crate::state::ExecutionState;
use async_trait::async_trait;

#[async_trait]
pub trait WorkerDispatcher: Send + Sync {
    async fn dispatch(
        &self,
        record: &ExecutionRecord,
    ) -> Result<ExecutionResultEnvelope, BrokerError>;
}

/// Safe, non-side-effecting worker implementation for verification and integration tests.
pub struct NoOpWorker {
    pub simulated_status: ExecutionState,
    pub simulated_delay_ms: u64,
}

impl Default for NoOpWorker {
    fn default() -> Self {
        Self::new()
    }
}

impl NoOpWorker {
    pub fn new() -> Self {
        Self {
            simulated_status: ExecutionState::Completed,
            simulated_delay_ms: 0,
        }
    }

    pub fn with_status(status: ExecutionState) -> Self {
        Self {
            simulated_status: status,
            simulated_delay_ms: 0,
        }
    }

    pub fn with_delay(delay_ms: u64) -> Self {
        Self {
            simulated_status: ExecutionState::Completed,
            simulated_delay_ms: delay_ms,
        }
    }
}

#[async_trait]
impl WorkerDispatcher for NoOpWorker {
    async fn dispatch(
        &self,
        record: &ExecutionRecord,
    ) -> Result<ExecutionResultEnvelope, BrokerError> {
        if self.simulated_delay_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(self.simulated_delay_ms)).await;
        }

        let completed_at = record.created_at_unix + (self.simulated_delay_ms / 1000);

        match self.simulated_status {
            ExecutionState::Completed => Ok(ExecutionResultEnvelope {
                execution_id: record.execution_id.clone(),
                action_id: record.action_id.clone(),
                action_hash: record.action_hash.clone(),
                state: ExecutionState::Completed,
                exit_code: Some(0),
                stdout_truncated: Some("NoOpWorker: execution simulated successfully".to_string()),
                stderr_truncated: None,
                structured_output: serde_json::json!({
                    "simulated": true,
                    "target": record.target,
                    "capability": record.capability_id.to_string(),
                }),
                evidence_hashes: vec!["sha256-noop-evidence-placeholder".to_string()],
                completed_at_unix: completed_at,
            }),
            ExecutionState::Failed => Ok(ExecutionResultEnvelope {
                execution_id: record.execution_id.clone(),
                action_id: record.action_id.clone(),
                action_hash: record.action_hash.clone(),
                state: ExecutionState::Failed,
                exit_code: Some(1),
                stdout_truncated: None,
                stderr_truncated: Some("NoOpWorker: simulated worker failure".to_string()),
                structured_output: serde_json::json!({"error": "simulated_failure"}),
                evidence_hashes: vec![],
                completed_at_unix: completed_at,
            }),
            ExecutionState::TimedOut => Err(BrokerError::TimeoutExceeded {
                timeout_ms: self.simulated_delay_ms,
            }),
            ExecutionState::Cancelled => Err(BrokerError::Cancelled(
                "NoOpWorker: execution cancelled".to_string(),
            )),
            _ => Err(BrokerError::WorkerExecutionFailure(format!(
                "Invalid simulated state: {:?}",
                self.simulated_status
            ))),
        }
    }
}
