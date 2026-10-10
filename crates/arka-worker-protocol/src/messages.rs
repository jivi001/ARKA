//! Strongly-typed, versioned, bounded protocol message schemas for Worker-Broker communication.
//!
//! Enforces:
//! - Strict schema deserialization with deny_unknown_fields on all message payloads
//! - Protocol version pinning (PROTOCOL_VERSION = 1)
//! - Hard upper limits on payload bytes (64 KB) and text buffer truncation (16 KB)
//! - Invariants INV-001, INV-002, INV-004, INV-010

use arka_core_types::id::{ActionId, CapabilityId, ExecutionId, MissionId, WorkerId};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_MESSAGE_BYTES: usize = 65536; // 64 KB
pub const MAX_STDOUT_BYTES: usize = 16384; // 16 KB
pub const MAX_STDERR_BYTES: usize = 16384; // 16 KB
pub const MAX_FIELD_STRING_BYTES: usize = 1024;
pub const MAX_NONCE_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskExitStatus {
    Success,
    Failed,
    Denied,
    TimedOut,
    Cancelled,
}

/// Initial identity presentation sent from worker upon establishing mTLS connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerHello {
    pub protocol_version: u32,
    pub worker_id: WorkerId,
    pub execution_id: ExecutionId,
    pub mission_id: MissionId,
    pub capability_id: CapabilityId,
    pub nonce: String,
}

/// Broker's acknowledgment of worker identity before dispatching instructions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerHandshakeResponse {
    pub protocol_version: u32,
    pub accepted: bool,
    pub execution_id: ExecutionId,
    pub deadline_unix_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

/// Task dispatch payload from broker to worker containing kernel-authorized canonical parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteTaskRequest {
    pub execution_id: ExecutionId,
    pub action_id: ActionId,
    pub action_hash: String,
    pub capability_id: CapabilityId,
    pub target: serde_json::Value,
    pub parameters: serde_json::Value,
    pub deadline_unix_ms: u64,
}

/// Structured task execution result returned from worker to broker.
/// Untrusted output is strictly bounded to prevent memory amplification or broker crash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteTaskResponse {
    pub execution_id: ExecutionId,
    pub action_id: ActionId,
    pub action_hash: String,
    pub status: TaskExitStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_truncated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_truncated: Option<String>,
    pub structured_output: serde_json::Value,
    pub evidence_hashes: Vec<String>,
    pub completed_at_unix_ms: u64,
}

/// Asynchronous cancellation order sent from broker upon emergency stop or timeout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelTaskRequest {
    pub execution_id: ExecutionId,
    pub reason: String,
}

/// Heartbeat message exchanged to verify connection health and detect worker hangs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub ping_unix_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pong_unix_ms: Option<u64>,
}

/// Authoritative union envelope for all Broker-Worker communication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum WorkerMessage {
    WorkerHello(WorkerHello),
    BrokerHandshake(BrokerHandshakeResponse),
    ExecuteTask(ExecuteTaskRequest),
    TaskResponse(ExecuteTaskResponse),
    CancelTask(CancelTaskRequest),
    Heartbeat(Heartbeat),
}
