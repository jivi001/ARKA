//! Anthropic Messages API Adapter.

use super::ProviderAdapter;
use crate::errors::GatewayError;
use crate::protocol::{GatewayInferenceRequest, ModelOutput};
use crate::transport::HttpTransport;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use zeroize::Zeroizing;

pub const DEFAULT_ANTHROPIC_ENDPOINT: &str = "https://api.anthropic.com/v1/messages";

const SUPPORTED_MODELS: &[&str] = &[
    "claude-3-5-sonnet-20241022",
    "claude-3-5-haiku-20241022",
    "claude-3-haiku-20240307",
    "claude-3-opus-20240229",
    "claude-sonnet",
    "claude-haiku",
];

pub struct AnthropicAdapter {
    endpoint: String,
    transport: Arc<dyn HttpTransport>,
}

impl AnthropicAdapter {
    pub fn new(transport: Arc<dyn HttpTransport>) -> Self {
        Self {
            endpoint: DEFAULT_ANTHROPIC_ENDPOINT.to_string(),
            transport,
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }
}

#[derive(Debug, Deserialize)]
struct AnthropicMessageResponse {
    content: Vec<AnthropicContentBlock>,
    stop_reason: Option<String>,
    usage: Option<AnthropicUsage>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type")]
    block_type: String,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicUsage {
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct AnthropicErrorResponse {
    error: Option<AnthropicErrorDetail>,
}

#[derive(Debug, Deserialize)]
struct AnthropicErrorDetail {
    message: Option<String>,
}

#[async_trait]
impl ProviderAdapter for AnthropicAdapter {
    fn provider_name(&self) -> &str {
        "anthropic"
    }

    fn supported_models(&self) -> &[&str] {
        SUPPORTED_MODELS
    }

    async fn complete(
        &self,
        req: &GatewayInferenceRequest,
        key: Option<&Zeroizing<String>>,
    ) -> Result<ModelOutput, GatewayError> {
        let raw_key = match key {
            Some(k) => k.as_str(),
            None => {
                return Err(GatewayError::ProviderUnavailable(
                    "No active credential configured for provider 'anthropic'".to_string(),
                ));
            }
        };

        // Separate system messages from user/assistant messages
        let mut system_prompts = Vec::new();
        let mut conversational_messages = Vec::new();

        for m in &req.messages {
            if m.role.eq_ignore_ascii_case("system") {
                system_prompts.push(m.content.as_str());
            } else {
                conversational_messages.push(json!({
                    "role": m.role,
                    "content": m.content,
                }));
            }
        }

        // Anthropic requires max_tokens to be set
        let max_tokens = req.max_tokens.unwrap_or(4096);

        let mut body_map = json!({
            "model": req.model,
            "messages": conversational_messages,
            "max_tokens": max_tokens,
        });

        if !system_prompts.is_empty() {
            body_map["system"] = json!(system_prompts.join("\n\n"));
        }

        if let Some(temp) = req.temperature {
            body_map["temperature"] = json!(temp);
        }

        let body_bytes = serde_json::to_vec(&body_map).map_err(|e| {
            GatewayError::InvalidJson(format!("Anthropic request encode failed: {}", e))
        })?;

        let headers = [
            ("content-type", "application/json"),
            ("x-api-key", raw_key),
            ("anthropic-version", "2023-06-01"),
        ];

        let response = self
            .transport
            .send("POST", &self.endpoint, &headers, &body_bytes)
            .await?;

        match response.status {
            200 => {
                let parsed: AnthropicMessageResponse = serde_json::from_slice(&response.body)
                    .map_err(|e| {
                        GatewayError::InvalidJson(format!(
                            "Anthropic response decode failed: {}",
                            e
                        ))
                    })?;

                let content_text = parsed
                    .content
                    .into_iter()
                    .filter(|b| b.block_type == "text")
                    .filter_map(|b| b.text)
                    .collect::<Vec<String>>()
                    .join("\n");

                let finish_reason = match parsed.stop_reason.as_deref() {
                    Some("end_turn") | Some("stop_sequence") => "stop".to_string(),
                    Some("max_tokens") => "length".to_string(),
                    Some(other) => other.to_string(),
                    None => "stop".to_string(),
                };

                let (prompt_tokens, completion_tokens) = match parsed.usage {
                    Some(u) => (u.input_tokens.unwrap_or(0), u.output_tokens.unwrap_or(0)),
                    None => (0, 0),
                };

                Ok(ModelOutput {
                    content: content_text,
                    finish_reason,
                    prompt_tokens,
                    completion_tokens,
                })
            }
            401 | 403 => Err(GatewayError::PeerAuthFailed(
                "Anthropic rejected provider authentication credentials (HTTP 401/403)".to_string(),
            )),
            429 => {
                let err_detail = serde_json::from_slice::<AnthropicErrorResponse>(&response.body)
                    .ok()
                    .and_then(|r| r.error)
                    .and_then(|e| e.message)
                    .unwrap_or_else(|| "Rate limit exceeded".to_string());
                Err(GatewayError::RateLimited(err_detail))
            }
            status => {
                let err_detail = serde_json::from_slice::<AnthropicErrorResponse>(&response.body)
                    .ok()
                    .and_then(|r| r.error)
                    .and_then(|e| e.message)
                    .unwrap_or_else(|| {
                        String::from_utf8_lossy(&response.body)
                            .chars()
                            .take(200)
                            .collect()
                    });
                Err(GatewayError::ProviderUnavailable(format!(
                    "Anthropic returned HTTP {}: {}",
                    status, err_detail
                )))
            }
        }
    }
}
