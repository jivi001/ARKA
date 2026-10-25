//! Provider adapter implementations for standard LLM APIs.

pub mod anthropic;
pub mod ollama;
pub mod openai;

pub use anthropic::AnthropicAdapter;
pub use ollama::OllamaAdapter;
pub use openai::OpenAiAdapter;

use crate::errors::GatewayError;
use crate::protocol::{GatewayInferenceRequest, ModelOutput};
use async_trait::async_trait;
use zeroize::Zeroizing;

#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    /// Return the canonical name of the provider (e.g. "openai", "anthropic", "ollama").
    fn provider_name(&self) -> &str;

    /// Supported models for this provider adapter.
    fn supported_models(&self) -> &[&str];

    /// Translates the standard ARKA inference request, executes outbound HTTP,
    /// and parses the response into standardized ModelOutput.
    async fn complete(
        &self,
        req: &GatewayInferenceRequest,
        key: Option<&Zeroizing<String>>,
    ) -> Result<ModelOutput, GatewayError>;
}
