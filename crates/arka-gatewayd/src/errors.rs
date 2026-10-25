//! ARKA LLM Gateway Error Types.

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Payload frame too large: {0} bytes (max: {1} bytes)")]
    FrameTooLarge(usize, usize),

    #[error("Invalid JSON payload: {0}")]
    InvalidJson(String),

    #[error("Peer authentication failed: {0}")]
    PeerAuthFailed(String),

    #[error("Data Loss Prevention policy violation: {0}")]
    DlpViolation(String),

    #[error("Request timed out after {0} ms")]
    Timeout(u64),

    #[error("Provider unavailable: {0}")]
    ProviderUnavailable(String),

    #[error("Invalid model: {0}")]
    InvalidModel(String),

    #[error("Endpoint blocked by policy: {0}")]
    EndpointBlocked(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimited(String),

    #[error("Internal gateway error: {0}")]
    Internal(String),
}

impl GatewayError {
    pub fn sanitized_code(&self) -> &'static str {
        match self {
            GatewayError::IoError(_) => "ERR_GATEWAY_IO",
            GatewayError::FrameTooLarge(_, _) => "ERR_FRAME_TOO_LARGE",
            GatewayError::InvalidJson(_) => "ERR_INVALID_PAYLOAD",
            GatewayError::PeerAuthFailed(_) => "ERR_PEER_AUTH_FAILED",
            GatewayError::DlpViolation(_) => "ERR_DLP_VIOLATION",
            GatewayError::Timeout(_) => "ERR_GATEWAY_TIMEOUT",
            GatewayError::ProviderUnavailable(_) => "ERR_PROVIDER_UNAVAILABLE",
            GatewayError::InvalidModel(_) => "ERR_INVALID_MODEL",
            GatewayError::EndpointBlocked(_) => "ERR_ENDPOINT_BLOCKED",
            GatewayError::RateLimited(_) => "ERR_RATE_LIMITED",
            GatewayError::Internal(_) => "ERR_GATEWAY_INTERNAL",
        }
    }

    pub fn sanitized_message(&self) -> String {
        match self {
            GatewayError::FrameTooLarge(actual, max) => {
                format!(
                    "Request payload of {} bytes exceeds maximum allowed limit of {} bytes.",
                    actual, max
                )
            }
            GatewayError::DlpViolation(reason) => {
                format!(
                    "Request blocked by Data Loss Prevention policy: {}.",
                    reason
                )
            }
            GatewayError::Timeout(ms) => {
                format!("Inference request timed out after {} ms.", ms)
            }
            GatewayError::PeerAuthFailed(_) => {
                "Peer credentials could not be verified.".to_string()
            }
            GatewayError::InvalidJson(_) => {
                "Malformed request payload or strict JSON parsing rules violated.".to_string()
            }
            GatewayError::InvalidModel(model) => {
                format!(
                    "The requested model '{}' is not registered or authorized for this provider.",
                    model
                )
            }
            GatewayError::EndpointBlocked(ep) => {
                format!(
                    "Connection to outbound endpoint '{}' is denied by security policy.",
                    ep
                )
            }
            GatewayError::RateLimited(reason) => {
                format!("Upstream provider rate limit exceeded: {}", reason)
            }
            GatewayError::ProviderUnavailable(reason) => {
                format!(
                    "The requested model provider is currently unreachable or disabled: {}",
                    reason
                )
            }
            GatewayError::IoError(_) | GatewayError::Internal(_) => {
                "An internal error occurred in the LLM Gateway.".to_string()
            }
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            GatewayError::Timeout(_)
                | GatewayError::ProviderUnavailable(_)
                | GatewayError::RateLimited(_)
        )
    }
}
