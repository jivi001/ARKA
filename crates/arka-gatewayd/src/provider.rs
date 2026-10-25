//! LLM Provider Interface and Mock Engine for Gateway Core.

use crate::errors::GatewayError;
use crate::protocol::{GatewayInferenceRequest, ModelOutput};
use async_trait::async_trait;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(&self, req: &GatewayInferenceRequest) -> Result<ModelOutput, GatewayError>;
}

/// In-memory mock provider for testing Gateway core behaviors, framing, timeouts, and DLP.
#[derive(Debug, Clone)]
pub struct MockProvider {
    completion_text: String,
    simulated_delay_ms: u64,
    should_fail: bool,
    failure_message: String,
    request_count: Arc<AtomicU32>,
}

impl Default for MockProvider {
    fn default() -> Self {
        Self {
            completion_text: "Deterministic mock LLM completion from arka-gatewayd.".to_string(),
            simulated_delay_ms: 0,
            should_fail: false,
            failure_message: "Simulated upstream provider outage".to_string(),
            request_count: Arc::new(AtomicU32::new(0)),
        }
    }
}

impl MockProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_response(mut self, text: impl Into<String>) -> Self {
        self.completion_text = text.into();
        self
    }

    pub fn with_delay(mut self, delay_ms: u64) -> Self {
        self.simulated_delay_ms = delay_ms;
        self
    }

    pub fn with_failure(mut self, message: impl Into<String>) -> Self {
        self.should_fail = true;
        self.failure_message = message.into();
        self
    }

    pub fn request_count(&self) -> u32 {
        self.request_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl LlmProvider for MockProvider {
    async fn complete(&self, req: &GatewayInferenceRequest) -> Result<ModelOutput, GatewayError> {
        self.request_count.fetch_add(1, Ordering::SeqCst);

        if self.simulated_delay_ms > 0 {
            sleep(Duration::from_millis(self.simulated_delay_ms)).await;
        }

        if self.should_fail {
            return Err(GatewayError::ProviderUnavailable(
                self.failure_message.clone(),
            ));
        }

        let prompt_tokens = req
            .messages
            .iter()
            .map(|m| m.content.split_whitespace().count() as u32)
            .sum::<u32>()
            + 10;

        let completion_tokens = self.completion_text.split_whitespace().count() as u32;

        Ok(ModelOutput {
            content: self.completion_text.clone(),
            finish_reason: "stop".to_string(),
            prompt_tokens,
            completion_tokens,
        })
    }
}
