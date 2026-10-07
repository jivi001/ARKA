//! Human Approval Model & TOCTOU Binding.
//!
//! Enforces:
//! - INV-007: Approval is bound to the exact canonical action hash.
//! - Section 19: Self-approval forbidden (requester != approver).
//! - Section 43: Operator approval expiration and single consumption.

use crate::actions::CanonicalAction;
use crate::errors::KernelSecurityError;
use crate::id::{ApprovalId, MissionId, OperatorId};
use crate::subject::Subject;
use serde::{Deserialize, Serialize};

/// An authoritative cryptographic or logged operator approval seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub approval_id: ApprovalId,
    pub mission_id: MissionId,
    pub action_hash: String,
    pub approver: OperatorId,
    pub status: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed_at_unix: Option<u64>,
}

impl Approval {
    pub fn new(
        approval_id: ApprovalId,
        mission_id: MissionId,
        action_hash: impl Into<String>,
        approver: OperatorId,
        issued_at_unix: u64,
        expires_at_unix: u64,
    ) -> Self {
        Self {
            approval_id,
            mission_id,
            action_hash: action_hash.into(),
            approver,
            status: "APPROVED".to_string(),
            issued_at_unix,
            expires_at_unix,
            consumed_at_unix: None,
        }
    }

    /// Verifies approval binding against canonical action, requester identity, and clock.
    pub fn validate_for_action(
        &self,
        action: &CanonicalAction,
        requester: &Subject,
        now_unix: u64,
    ) -> Result<(), KernelSecurityError> {
        // 1. Check approval status
        if self.status == "CONSUMED" {
            return Err(KernelSecurityError::ApprovalInvalid(
                "Approval has already been consumed".to_string(),
            ));
        }
        if self.status != "APPROVED" {
            return Err(KernelSecurityError::ApprovalInvalid(format!(
                "Approval status '{}' is not valid for execution",
                self.status
            )));
        }

        // 2. Action hash match (TOCTOU parameter binding protection)
        if self.action_hash != action.action_hash {
            return Err(KernelSecurityError::ApprovalInvalid(format!(
                "Action hash mismatch: approval is bound to '{}', action hash is '{}'",
                self.action_hash, action.action_hash
            )));
        }

        // 3. Mission isolation
        if self.mission_id != action.mission_id {
            return Err(KernelSecurityError::CrossMissionAccessDenied {
                requester_mission: action.mission_id.clone(),
                target_mission: self.mission_id.clone(),
            });
        }

        // 4. Expiration check
        if now_unix > self.expires_at_unix {
            return Err(KernelSecurityError::ApprovalInvalid(format!(
                "Approval expired at {}, current time is {}",
                self.expires_at_unix, now_unix
            )));
        }

        // 5. Invariant Section 19: Self-approval forbidden
        if self.approver.as_str() == requester.identifier() {
            return Err(KernelSecurityError::SelfApprovalForbidden);
        }

        Ok(())
    }
}
