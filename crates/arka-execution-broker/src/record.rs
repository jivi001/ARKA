//! Execution records and result envelopes for the Execution Broker.

use crate::state::ExecutionState;
use arka_core_types::id::{ActionId, CapabilityId, ExecutionId, MissionId, ProposalId};
use serde::{Deserialize, Serialize};

/// Immutable execution result envelope produced by a worker or supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResultEnvelope {
    pub execution_id: ExecutionId,
    pub action_id: ActionId,
    pub action_hash: String,
    pub state: ExecutionState,
    pub exit_code: Option<i32>,
    pub stdout_truncated: Option<String>,
    pub stderr_truncated: Option<String>,
    pub structured_output: serde_json::Value,
    pub evidence_hashes: Vec<String>,
    pub completed_at_unix: u64,
}

/// Durable execution tracking entity stored by the Execution Broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub execution_id: ExecutionId,
    pub action_id: ActionId,
    pub proposal_id: ProposalId,
    pub mission_id: MissionId,
    pub capability_id: CapabilityId,
    pub action_hash: String,
    pub target: serde_json::Value,
    pub parameters: serde_json::Value,
    pub state: ExecutionState,
    pub dispatch_attempt: u32,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub deadline_unix: u64,
    pub result: Option<ExecutionResultEnvelope>,
    pub error_reason: Option<String>,
}

impl ExecutionRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution_id: ExecutionId,
        action_id: ActionId,
        proposal_id: ProposalId,
        mission_id: MissionId,
        capability_id: CapabilityId,
        action_hash: String,
        target: serde_json::Value,
        parameters: serde_json::Value,
        created_at_unix: u64,
        deadline_unix: u64,
    ) -> Self {
        Self {
            execution_id,
            action_id,
            proposal_id,
            mission_id,
            capability_id,
            action_hash,
            target,
            parameters,
            state: ExecutionState::Authorized,
            dispatch_attempt: 1,
            created_at_unix,
            updated_at_unix: created_at_unix,
            deadline_unix,
            result: None,
            error_reason: None,
        }
    }
}
