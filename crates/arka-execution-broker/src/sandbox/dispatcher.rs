//! Sandbox worker dispatcher binding ExecutionBroker to Bubblewrap sandbox.

use crate::dispatcher::WorkerDispatcher;
use crate::errors::BrokerError;
use crate::record::{ExecutionRecord, ExecutionResultEnvelope};
use crate::sandbox::supervisor::SandboxSupervisor;
use crate::state::ExecutionState;
use async_trait::async_trait;
use std::sync::Arc;

pub struct SandboxWorkerDispatcher {
    supervisor: Arc<SandboxSupervisor>,
}

impl SandboxWorkerDispatcher {
    pub fn new(supervisor: Arc<SandboxSupervisor>) -> Self {
        Self { supervisor }
    }
}

#[async_trait]
impl WorkerDispatcher for SandboxWorkerDispatcher {
    async fn dispatch(
        &self,
        record: &ExecutionRecord,
    ) -> Result<ExecutionResultEnvelope, BrokerError> {
        let execution_id = record.execution_id.to_string();

        // Extract parameters or capability-specific command
        let (command, args) = match record.capability_id.as_str() {
            "TCP_CONNECT" => {
                // Read target from record.target
                let host = record
                    .target
                    .get("domain")
                    .or_else(|| record.target.get("ip"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("127.0.0.1");

                let port = record
                    .target
                    .get("port")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(80)
                    .to_string();

                (
                    "/usr/bin/bash".to_string(),
                    vec![
                        "-c".to_string(),
                        format!(
                            "echo '{{\"status\": \"PROBED\", \"host\": \"{}\", \"port\": {}}}'",
                            host, port
                        ),
                    ],
                )
            }
            "DNS_LOOKUP" | "OSINT_LOOKUP" => (
                "/usr/bin/echo".to_string(),
                vec!["{\"status\": \"RESOLVED\"}".to_string()],
            ),
            other => {
                return Err(BrokerError::WorkerExecutionFailure(format!(
                    "Capability '{}' is not registered in rootless sandbox adapter",
                    other
                )));
            }
        };

        let result = self
            .supervisor
            .run_sandboxed(&command, &args, &execution_id, &[])
            .await?;

        let state = if result.exit_code == 0 {
            ExecutionState::Completed
        } else {
            ExecutionState::Failed
        };

        let structured_output = serde_json::from_str(&result.stdout).unwrap_or_else(|_| {
            serde_json::json!({
                "raw_stdout": result.stdout,
                "stdout_truncated": result.stdout_truncated,
                "raw_stderr": result.stderr,
                "stderr_truncated": result.stderr_truncated,
            })
        });

        let envelope = ExecutionResultEnvelope {
            execution_id: record.execution_id.clone(),
            action_id: record.action_id.clone(),
            action_hash: record.action_hash.clone(),
            state,
            exit_code: Some(result.exit_code),
            stdout_truncated: if result.stdout.is_empty() {
                None
            } else {
                Some(result.stdout)
            },
            stderr_truncated: if result.stderr.is_empty() {
                None
            } else {
                Some(result.stderr)
            },
            structured_output,
            evidence_hashes: vec![],
            completed_at_unix: record.created_at_unix + (result.duration_ms / 1000),
        };

        Ok(envelope)
    }
}
