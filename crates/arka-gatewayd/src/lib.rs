//! ARKA LLM Gateway Daemon Library.
//!
//! Provides the standalone OS daemon, UDS server, length-prefixed framing,
//! DLP content filtering, and provider abstractions.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod credentials;
pub mod dlp;
pub mod errors;
pub mod protocol;
pub mod provider;
pub mod router;
pub mod server;
pub mod transport;

pub use adapters::{AnthropicAdapter, OllamaAdapter, OpenAiAdapter, ProviderAdapter};
pub use credentials::{CredentialSourceType, CredentialStore, ProviderKey};
pub use dlp::DlpFilter;
pub use errors::GatewayError;
pub use protocol::{
    GatewayErrorPayload, GatewayInferenceRequest, GatewayInferenceResponse, GatewayMessage,
    ModelOutput, SensitivityClass, DEFAULT_MAX_FRAME_SIZE, DEFAULT_TIMEOUT_MS,
};
pub use provider::{LlmProvider, MockProvider};
pub use router::{MockAdapter, ModelRouter};
pub use server::{GatewayServer, GatewayServerConfig};
pub use transport::{HttpResponse, HttpTransport, MockHttpTransport, RecordedHttpRequest};
