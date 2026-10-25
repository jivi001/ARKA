//! Ollama Local Inference API Adapter.

use super::ProviderAdapter;
use crate::errors::GatewayError;
use crate::protocol::{GatewayInferenceRequest, ModelOutput};
use crate::transport::HttpTransport;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use zeroize::Zeroizing;

pub const DEFAULT_OLLAMA_ENDPOINT: &str = "http://localhost:11434/api/chat";

const SUPPORTED_MODELS: &[&str] = &["llama3", "llama3.1", "deepseek-r1", "mistral", "phi3"];

pub struct OllamaAdapter {
    endpoint: String,
    transport: Arc<dyn HttpTransport>,
}

impl OllamaAdapter {
    pub fn new(transport: Arc<dyn HttpTransport>) -> Self {
        Self {
            endpoint: DEFAULT_OLLAMA_ENDPOINT.to_string(),
            transport,
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }
}

#[derive(Debug, Deserialize)]
struct OllamaChatResponse {
    message: Option<OllamaMessage>,
    done_reason: Option<String>,
    prompt_eval_count: Option<u32>,
    eval_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct OllamaMessage {
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OllamaErrorResponse {
    error: Option<String>,
}

#[async_trait]
impl ProviderAdapter for OllamaAdapter {
    fn provider_name(&self) -> &str {
        "ollama"
    }

    fn supported_models(&self) -> &[&str] {
        SUPPORTED_MODELS
    }

    async fn complete(
        &self,
        req: &GatewayInferenceRequest,
        _key: Option<&Zeroizing<String>>,
    ) -> Result<ModelOutput, GatewayError> {
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

        let mut options = serde_json::Map::new();
        if let Some(t) = req.temperature {
            options.insert("temperature".to_string(), json!(t));
        }
        if let Some(m) = req.max_tokens {
            options.insert("num_predict".to_string(), json!(m));
        }

        let body_map = json!({
            "model": req.model,
            "messages": messages_payload,
            "stream": false,
            "options": options,
        });

        let body_bytes = serde_json::to_vec(&body_map).map_err(|e| {
            GatewayError::InvalidJson(format!("Ollama request encode failed: {}", e))
        })?;

        let headers = [("content-type", "application/json")];

        let response = self
            .transport
            .send("POST", &self.endpoint, &headers, &body_bytes)
            .await?;

        match response.status {
            200 => {
                let parsed: OllamaChatResponse =
                    serde_json::from_slice(&response.body).map_err(|e| {
                        GatewayError::InvalidJson(format!("Ollama response decode failed: {}", e))
                    })?;

                let content = parsed.message.and_then(|m| m.content).unwrap_or_default();

                let finish_reason = parsed.done_reason.unwrap_or_else(|| "stop".to_string());
                let prompt_tokens = parsed.prompt_eval_count.unwrap_or(0);
                let completion_tokens = parsed.eval_count.unwrap_or(0);

                Ok(ModelOutput {
                    content,
                    finish_reason,
                    prompt_tokens,
                    completion_tokens,
                })
            }
            status => {
                let err_msg = serde_json::from_slice::<OllamaErrorResponse>(&response.body)
                    .ok()
                    .and_then(|r| r.error)
                    .unwrap_or_else(|| {
                        String::from_utf8_lossy(&response.body)
                            .chars()
                            .take(200)
                            .collect()
                    });
                Err(GatewayError::ProviderUnavailable(format!(
                    "Ollama returned HTTP {}: {}",
                    status, err_msg
                )))
            }
        }
    }
}
