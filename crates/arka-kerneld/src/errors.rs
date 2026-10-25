//! ARKA Kernel Daemon Error Types.

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum KernelServiceError {
    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Payload frame too large: {0} bytes (max: {1} bytes)")]
    FrameTooLarge(usize, usize),

    #[error("Invalid JSON payload: {0}")]
    InvalidJson(String),

    #[error("Peer authentication failed: {0}")]
    PeerAuthFailed(String),

    #[error("Token verification failed: {0}")]
    TokenVerificationFailed(String),

    #[error("Action normalization failed: {0}")]
    NormalizationFailed(String),

    #[error("Replay detected: {0}")]
    ReplayDetected(String),

    #[error("Emergency stop is active: {0}")]
    EmergencyStopActive(String),

    #[error("Broker execution failed: {0}")]
    BrokerExecutionFailed(String),

    #[error("Internal kernel error: {0}")]
    Internal(String),
}

impl KernelServiceError {
    pub fn sanitized_code(&self) -> &'static str {
        match self {
            KernelServiceError::IoError(_) => "ERR_KERNEL_IO",
            KernelServiceError::FrameTooLarge(_, _) => "ERR_FRAME_TOO_LARGE",
            KernelServiceError::InvalidJson(_) => "ERR_INVALID_PAYLOAD",
            KernelServiceError::PeerAuthFailed(_) => "ERR_PEER_AUTH_FAILED",
            KernelServiceError::TokenVerificationFailed(_) => "ERR_UNAUTHORIZED_TOKEN",
            KernelServiceError::NormalizationFailed(_) => "ERR_NORMALIZATION_FAILED",
            KernelServiceError::ReplayDetected(_) => "ERR_REPLAY_DETECTED",
            KernelServiceError::EmergencyStopActive(_) => "ERR_EMERGENCY_STOP_ACTIVE",
            KernelServiceError::BrokerExecutionFailed(_) => "ERR_BROKER_EXECUTION",
            KernelServiceError::Internal(_) => "ERR_KERNEL_INTERNAL",
        }
    }

    pub fn sanitized_message(&self) -> String {
        match self {
            KernelServiceError::FrameTooLarge(actual, max) => {
                format!(
                    "Request payload of {} bytes exceeds maximum allowed limit of {} bytes.",
                    actual, max
                )
            }
            KernelServiceError::PeerAuthFailed(_) => {
                "Caller process failed OS peer credential verification.".to_string()
            }
            KernelServiceError::TokenVerificationFailed(_) => {
                "Caller authentication token is invalid, expired, or untrusted.".to_string()
            }
            KernelServiceError::NormalizationFailed(msg) => {
                format!("Action proposal normalization rejected: {}", msg)
            }
            KernelServiceError::ReplayDetected(_) => {
                "Action proposal nonce collision or replay detected.".to_string()
            }
            KernelServiceError::EmergencyStopActive(msg) => {
                format!("Emergency stop active: {}", msg)
            }
            KernelServiceError::BrokerExecutionFailed(msg) => {
                format!("Execution broker failed to dispatch action: {}", msg)
            }
            KernelServiceError::InvalidJson(_) => {
                "Malformed request payload or strict JSON parsing rules violated.".to_string()
            }
            KernelServiceError::IoError(_) | KernelServiceError::Internal(_) => {
                "An internal error occurred in the ARKA Security Kernel.".to_string()
            }
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self, KernelServiceError::IoError(_))
    }
}
