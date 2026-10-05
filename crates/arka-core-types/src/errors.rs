//! Security Error Model.
//!
//! Enforces:
//! - INV-010: Fail-closed error handling
//! - Section 17: Error Oracle Defense (internal detailed telemetry vs sanitized external denial)

use crate::id::MissionId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Internal detailed security errors for kernel tracing, structured telemetry, and audit logging.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KernelSecurityError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Token expired at {expired_at}, current time is {current_time}")]
    TokenExpired { expired_at: u64, current_time: u64 },

    #[error("Token has been revoked: {0}")]
    TokenRevoked(String),

    #[error("Cryptographic signature verification failed: {0}")]
    InvalidSignature(String),

    #[error("Key domain separation violation: {0}")]
    KeyDomainViolation(String),

    #[error("Identity mismatch: {0}")]
    IdentityMismatch(String),

    #[error("Mission {0} not found")]
    MissionNotFound(MissionId),

    #[error("Invalid mission state transition from '{current}' to '{target}'")]
    MissionStateInvalid { current: String, target: String },

    #[error("Cross-mission access denied: requester {requester_mission} attempted to access {target_mission}")]
    CrossMissionAccessDenied {
        requester_mission: MissionId,
        target_mission: MissionId,
    },

    #[error("Emergency stop is active: {0}")]
    EmergencyStopActive(String),

    #[error("Destination or asset is out of authorized scope: {0}")]
    ScopeDenied(String),

    #[error("Capability not found or unauthorized: {0}")]
    CapabilityNotFound(String),

    #[error(
        "Risk class override forbidden: untrusted proposal risk does not match capability registry"
    )]
    RiskOverrideForbidden,

    #[error("Action proposal replay detected: {0}")]
    ReplayDetected(String),

    #[error("High-risk action requires independent operator approval: {0}")]
    ApprovalRequired(String),

    #[error("Approval is invalid or expired: {0}")]
    ApprovalInvalid(String),

    #[error("Self-approval forbidden: requester and approver cannot be the same identity")]
    SelfApprovalForbidden,

    #[error("Storage failure during security transaction: {0}")]
    StorageFailure(String),

    #[error("Internal kernel failure: {0}")]
    InternalFailure(String),
}

/// Sanitized external error contract returned to untrusted callers / API clients.
/// Strictly masks internal state, secret existence, and foreign mission existence (Section 17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalSecurityError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub retryable: bool,
}

impl ExternalSecurityError {
    pub fn new(code: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            request_id: None,
            retryable,
        }
    }
}

impl From<KernelSecurityError> for ExternalSecurityError {
    fn from(err: KernelSecurityError) -> Self {
        match err {
            KernelSecurityError::ApprovalRequired(action_hash) => Self {
                code: "REQUIRE_APPROVAL".to_string(),
                message: format!(
                    "Action requires independent operator approval. Action hash: {}",
                    action_hash
                ),
                request_id: None,
                retryable: false,
            },
            KernelSecurityError::TokenExpired { .. } => Self {
                code: "TOKEN_EXPIRED".to_string(),
                message: "Authentication token has expired. Re-authentication required."
                    .to_string(),
                request_id: None,
                retryable: false,
            },
            KernelSecurityError::EmergencyStopActive(_) => Self {
                code: "EMERGENCY_STOP_ACTIVE".to_string(),
                message: "Platform emergency stop is active. All operations halted.".to_string(),
                request_id: None,
                retryable: false,
            },
            KernelSecurityError::ScopeDenied(_) => Self {
                code: "SCOPE_DENIED".to_string(),
                message: "Requested target is outside authorized mission scope.".to_string(),
                request_id: None,
                retryable: false,
            },
            // Oracle defense: Mask cross-mission, non-existent mission, replay, and internal errors into generic rejection
            KernelSecurityError::CrossMissionAccessDenied { .. }
            | KernelSecurityError::MissionNotFound(_)
            | KernelSecurityError::AuthenticationFailed(_)
            | KernelSecurityError::TokenRevoked(_)
            | KernelSecurityError::InvalidSignature(_)
            | KernelSecurityError::KeyDomainViolation(_)
            | KernelSecurityError::IdentityMismatch(_)
            | KernelSecurityError::MissionStateInvalid { .. }
            | KernelSecurityError::CapabilityNotFound(_)
            | KernelSecurityError::RiskOverrideForbidden
            | KernelSecurityError::ReplayDetected(_)
            | KernelSecurityError::ApprovalInvalid(_)
            | KernelSecurityError::SelfApprovalForbidden => Self {
                code: "AUTHORIZATION_DENIED".to_string(),
                message: "Action proposal authorization denied by security policy.".to_string(),
                request_id: None,
                retryable: false,
            },
            KernelSecurityError::StorageFailure(_) | KernelSecurityError::InternalFailure(_) => {
                Self {
                    code: "INTERNAL_SECURITY_ERROR".to_string(),
                    message: "Kernel failed closed due to an internal execution error.".to_string(),
                    request_id: None,
                    retryable: false,
                }
            }
        }
    }
}
