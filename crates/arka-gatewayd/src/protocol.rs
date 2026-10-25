//! Wire protocol models for ARKA LLM Gateway IPC.

use serde::{Deserialize, Serialize};

pub const DEFAULT_MAX_FRAME_SIZE: usize = 65_536; // 64 KB
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000; // 30 seconds

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SensitivityClass {
    #[default]
    Public,
    Internal,
    Confidential,
    Secret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayMessage {
    pub role: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayInferenceRequest {
    pub request_id: String,
    pub mission_id: String,
    pub caller_agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    pub provider: String,
    pub model: String,
    pub messages: Vec<GatewayMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(default)]
    pub sensitivity: SensitivityClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelOutput {
    pub content: String,
    pub finish_reason: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayErrorPayload {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayInferenceResponse {
    pub request_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<ModelOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<GatewayErrorPayload>,
    pub sanitized: bool,
}

impl GatewayInferenceResponse {
    pub fn success(request_id: String, output: ModelOutput, sanitized: bool) -> Self {
        Self {
            request_id,
            status: "SUCCESS".to_string(),
            output: Some(output),
            error: None,
            sanitized,
        }
    }

    pub fn error(request_id: String, code: String, message: String, retryable: bool) -> Self {
        Self {
            request_id,
            status: "ERROR".to_string(),
            output: None,
            error: Some(GatewayErrorPayload {
                code,
                message,
                retryable,
            }),
            sanitized: false,
        }
    }
}
