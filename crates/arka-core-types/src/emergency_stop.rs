//! Emergency Stop Status Model (INV-010, Section 25, Section 26).

use crate::id::OperatorId;
use serde::{Deserialize, Serialize};

/// Persistent status of the platform emergency stop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyStopStatus {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<OperatorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleared_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleared_by: Option<OperatorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clear_reason: Option<String>,
}

impl EmergencyStopStatus {
    pub fn inactive() -> Self {
        Self {
            active: false,
            triggered_at_unix: None,
            triggered_by: None,
            reason: None,
            cleared_at_unix: None,
            cleared_by: None,
            clear_reason: None,
        }
    }
}
