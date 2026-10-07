//! Audit Records and Hash Chain Models (Section 23, Section 24, INV-011).

use crate::id::MissionId;
use serde::{Deserialize, Serialize};

/// Audit event record representing a committed entry in a tamper-evident hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub event_id: String,
    pub sequence_number: u64,
    pub timestamp_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mission_id: Option<MissionId>,
    pub event_type: String,
    pub actor_id: String,
    pub details: serde_json::Value,
    pub previous_hash: String,
    pub current_hash: String,
    pub signature: String,
}

/// Audit event payload used for RFC 8785 canonical hash computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPayload {
    pub event_id: String,
    pub sequence_number: u64,
    pub timestamp_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mission_id: Option<String>,
    pub event_type: String,
    pub actor_id: String,
    pub details: serde_json::Value,
    pub previous_hash: String,
}
