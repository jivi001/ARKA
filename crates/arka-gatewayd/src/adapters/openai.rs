//! OpenAI Chat Completions API Adapter.

use super::ProviderAdapter;
use crate::errors::GatewayError;
use crate::protocol::{GatewayInferenceRequest, ModelOutput};
use crate::transport::HttpTransport;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use zeroize::Zeroizing;

pub const DEFAULT_OPENAI_ENDPOINT: &str = "https://api.openai.com/v1/chat/completions";

const SUPPORTED_MODELS: &[&str] = &[
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",
    "gpt-3.5-turbo",
    "o1-preview",
    "o1-mini",
];

pub struct OpenAiAdapter {
    endpoint: String,
    transport: Arc<dyn HttpTransport>,
}

impl OpenAiAdapter {
    pub fn new(transport: Arc<dyn HttpTransport>) -> Self {
        Self {
            endpoint: DEFAULT_OPENAI_ENDPOINT.to_string(),
            transport,
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }
}

#[derive(Debug, Deserialize)]
struct OpenAiChatResponse {
    choices: Vec<OpenAiChoice>,
    usage: Option<OpenAiUsage>,
}

#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessage,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAiMessage {
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAiUsage {
    prompt_tokens: Option<u32>,
    completion_tokens: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct OpenAiErrorResponse {
    error: Option<OpenAiErrorDetail>,
}

#[derive(Debug, Deserialize)]
struct OpenAiErrorDetail {
    message: Option<String>,
}

#[async_trait]
impl ProviderAdapter for OpenAiAdapter {
    fn provider_name(&self) -> &str {
        "openai"
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
                    "No active credential configured for provider 'openai'".to_string(),
                ));
            }
        };

        // Format OpenAI JSON payload
        let messages_payload: Vec<serde_json::Value> = req
            .messages
            .iter()
            .map(|m| {
                json!({
                    "role": m.role,
                    "content": m.content,
                })
            })
            .collect();

        let mut body_map = json!({
            "model": req.model,
            "messages": messages_payload,
        });

        if let Some(temp) = req.temperature {
            body_map["temperature"] = json!(temp);
        }
        if let Some(max_tokens) = req.max_tokens {
            body_map["max_tokens"] = json!(max_tokens);
        }

        let body_bytes = serde_json::to_vec(&body_map).map_err(|e| {
            GatewayError::InvalidJson(format!("OpenAI request encode failed: {}", e))
        })?;

        let auth_header_val = format!("Bearer {}", raw_key);
        let headers = [
            ("content-type", "application/json"),
            ("authorization", auth_header_val.as_str()),
        ];

        let response = self
            .transport
            .send("POST", &self.endpoint, &headers, &body_bytes)
            .await?;

        match response.status {
            200 => {
                let parsed: OpenAiChatResponse =
                    serde_json::from_slice(&response.body).map_err(|e| {
                        GatewayError::InvalidJson(format!("OpenAI response decode failed: {}", e))
                    })?;

                let choice = parsed.choices.into_iter().next().ok_or_else(|| {
                    GatewayError::InvalidJson("OpenAI returned empty choices array".to_string())
                })?;

                let content = choice.message.content.unwrap_or_default();
                let finish_reason = choice.finish_reason.unwrap_or_else(|| "stop".to_string());

                let (prompt_tokens, completion_tokens) = match parsed.usage {
                    Some(u) => (
                        u.prompt_tokens.unwrap_or(0),
                        u.completion_tokens.unwrap_or(0),
                    ),
                    None => (0, 0),
                };

                Ok(ModelOutput {
                    content,
                    finish_reason,
                    prompt_tokens,
                    completion_tokens,
                })
            }
            401 | 403 => Err(GatewayError::PeerAuthFailed(
                "OpenAI rejected provider authentication credentials (HTTP 401/403)".to_string(),
            )),
            429 => {
                let err_detail = serde_json::from_slice::<OpenAiErrorResponse>(&response.body)
                    .ok()
                    .and_then(|r| r.error)
                    .and_then(|e| e.message)
                    .unwrap_or_else(|| "Rate limit exceeded".to_string());
                Err(GatewayError::RateLimited(err_detail))
            }
            status => {
                let err_detail = serde_json::from_slice::<OpenAiErrorResponse>(&response.body)
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
                    "OpenAI returned HTTP {}: {}",
                    status, err_detail
                )))
            }
        }
    }
}
