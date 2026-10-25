//! Wire protocol models for ARKA Kernel IPC.
//!
//! Enforces:
//! - ADR-007 Section 4.2 & 4.3 wire schemas
//! - Strict deserialization denying unknown fields
//! - Length-prefixed framing <= 64 KB

use arka_core_types::actions::RawActionProposal;
use serde::{Deserialize, Serialize};

pub const DEFAULT_MAX_FRAME_SIZE: usize = 65_536; // 64 KB
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000; // 30 seconds

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelRequest {
    pub request_id: String,
    pub client_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    pub operation: String,
    pub proposal: RawActionProposal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelExecutionResult {
    pub state: String,
    pub evidence_hashes: Vec<String>,
    pub execution_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelErrorPayload {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelResponse {
    pub request_id: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_result: Option<KernelExecutionResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<KernelErrorPayload>,
}

impl KernelResponse {
    pub fn allow(
        request_id: String,
        action_id: String,
        action_hash: String,
        execution_result: Option<KernelExecutionResult>,
    ) -> Self {
        Self {
            request_id,
            decision: "ALLOW".to_string(),
            action_id: Some(action_id),
            action_hash: Some(action_hash),
            execution_result,
            error: None,
        }
    }

    pub fn require_approval(request_id: String, action_id: String, action_hash: String) -> Self {
        Self {
            request_id,
            decision: "REQUIRE_APPROVAL".to_string(),
            action_id: Some(action_id),
            action_hash: Some(action_hash),
            execution_result: None,
            error: None,
        }
    }

    pub fn deny(
        request_id: String,
        code: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            request_id,
            decision: "DENY".to_string(),
            action_id: None,
            action_hash: None,
            execution_result: None,
            error: Some(KernelErrorPayload {
                code: code.into(),
                message: message.into(),
                retryable,
            }),
        }
    }
}
