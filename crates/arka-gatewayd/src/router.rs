//! Model and Provider Routing Engine.
//!
//! Enforces:
//! - Deterministic dispatch to registered provider adapters
//! - Strict model allowlisting per provider (anti-downgrade & anti-tampering)
//! - Provider disablement / revocation checks
//! - Credential resolution and zeroized header injection
//! - Fail-closed error handling

use crate::adapters::{AnthropicAdapter, OllamaAdapter, OpenAiAdapter, ProviderAdapter};
use crate::credentials::CredentialStore;
use crate::errors::GatewayError;
use crate::protocol::{GatewayInferenceRequest, ModelOutput};
use crate::provider::{LlmProvider, MockProvider};
use crate::transport::HttpTransport;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

/// Adapts the in-memory `MockProvider` to the `ProviderAdapter` interface.
pub struct MockAdapter {
    inner: MockProvider,
}

impl MockAdapter {
    pub fn new(inner: MockProvider) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl ProviderAdapter for MockAdapter {
    fn provider_name(&self) -> &str {
        "mock"
    }

    fn supported_models(&self) -> &[&str] {
        &["mock-model", "mock-default", "mock-agent", "mock-reasoning"]
    }

    async fn complete(
        &self,
        req: &GatewayInferenceRequest,
        _key: Option<&Zeroizing<String>>,
    ) -> Result<ModelOutput, GatewayError> {
        self.inner.complete(req).await
    }
}

pub struct ModelRouter {
    cred_store: Arc<CredentialStore>,
    adapters: Arc<RwLock<HashMap<String, Arc<dyn ProviderAdapter>>>>,
    allowed_models: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    strict_model_check: bool,
}

impl ModelRouter {
    pub fn new(cred_store: Arc<CredentialStore>) -> Self {
        Self {
            cred_store,
            adapters: Arc::new(RwLock::new(HashMap::new())),
            allowed_models: Arc::new(RwLock::new(HashMap::new())),
            strict_model_check: true,
        }
    }

    /// Sets whether unknown or unregistered models are rejected (defaults to true).
    pub fn with_strict_model_check(mut self, strict: bool) -> Self {
        self.strict_model_check = strict;
        self
    }

    /// Register a provider adapter and automatically register its supported models.
    pub async fn register_adapter(&self, adapter: Arc<dyn ProviderAdapter>) {
        let name = adapter.provider_name().to_string();
        let mut models = HashSet::new();
        for m in adapter.supported_models() {
            models.insert(m.to_string());
        }

        let mut adapters_lock = self.adapters.write().await;
        adapters_lock.insert(name.clone(), adapter);

        let mut models_lock = self.allowed_models.write().await;
        models_lock.insert(name, models);
    }

    /// Manually authorize an additional model name for a provider.
    pub async fn allow_model(&self, provider: &str, model: &str) {
        let mut models_lock = self.allowed_models.write().await;
        models_lock
            .entry(provider.to_string())
            .or_default()
            .insert(model.to_string());
    }

    /// Factory method initializing the standard suite of adapters (OpenAI, Anthropic, Ollama, Mock)
    /// backed by the provided HTTP transport.
    pub async fn with_standard_adapters(
        cred_store: Arc<CredentialStore>,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        let router = Self::new(cred_store);

        let openai = Arc::new(OpenAiAdapter::new(transport.clone()));
        router.register_adapter(openai).await;

        let anthropic = Arc::new(AnthropicAdapter::new(transport.clone()));
        router.register_adapter(anthropic).await;

        let ollama = Arc::new(OllamaAdapter::new(transport));
        router.register_adapter(ollama).await;

        let mock = Arc::new(MockAdapter::new(MockProvider::new()));
        router.register_adapter(mock).await;

        router
    }
}

#[async_trait]
impl LlmProvider for ModelRouter {
    async fn complete(&self, req: &GatewayInferenceRequest) -> Result<ModelOutput, GatewayError> {
        // 1. Verify provider is not disabled by operator policy
        if self.cred_store.is_disabled(&req.provider).await {
            return Err(GatewayError::ProviderUnavailable(format!(
                "Provider '{}' is disabled by security policy.",
                req.provider
            )));
        }

        // 2. Locate provider adapter
        let adapter = {
            let adapters_lock = self.adapters.read().await;
            adapters_lock.get(&req.provider).cloned().ok_or_else(|| {
                GatewayError::ProviderUnavailable(format!(
                    "Unsupported or unregistered provider '{}'",
                    req.provider
                ))
            })?
        };

        // 3. Validate requested model against the allowed model registry (Anti-Downgrade / Tampering)
        if self.strict_model_check {
            let models_lock = self.allowed_models.read().await;
            if let Some(allowed) = models_lock.get(&req.provider) {
                if !allowed.contains(&req.model) {
                    return Err(GatewayError::InvalidModel(req.model.clone()));
                }
            } else {
                return Err(GatewayError::InvalidModel(req.model.clone()));
            }
        }

        // 4. Resolve provider credential if required
        let provider_key =
            if req.provider == "mock" || req.provider == "ollama" || req.provider == "local" {
                None
            } else {
                let key = self.cred_store.get_key(&req.provider).await?;
                Some(key)
            };

        // 5. Delegate inference execution to the adapter
        adapter.complete(req, provider_key.as_ref()).await
    }
}
