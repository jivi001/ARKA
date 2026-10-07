//! Action Proposal and CanonicalAction Data Models.
//!
//! Enforces:
//! - Section 13: Strict CanonicalAction definition with parameter and action hashes.
//! - Section 14: Strict deserialization denying unknown fields in proposal envelope.
//! - Invariant INV-004, INV-005, INV-006.

use crate::capabilities::RiskClass;
use crate::id::{ActionId, CapabilityId, MissionId, ProposalId, TaskId};
use crate::scope::CanonicalTarget;
use serde::{Deserialize, Serialize};

/// Untrusted action proposal payload received from an agent, LLM, or API caller.
/// Uses strict deserialization denying unknown fields (Section 14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawActionProposal {
    pub proposal_id: ProposalId,
    pub mission_id: MissionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_task_id: Option<TaskId>,
    pub capability_id: CapabilityId,
    pub target: String,
    pub parameters: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_risk: Option<RiskClass>,
    pub nonce: String,
}

/// The authoritative, normalized, immutable security action representation.
/// No untrusted fields exist; all properties are derived and verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalAction {
    pub action_id: ActionId,
    pub proposal_id: ProposalId,
    pub mission_id: MissionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_task_id: Option<TaskId>,
    pub capability_id: CapabilityId,
    pub target: CanonicalTarget,
    pub normalized_parameters: serde_json::Value,
    pub parameter_hash: String,
    pub action_hash: String,
    pub risk_class: RiskClass,
    pub requires_approval: bool,
    pub policy_version: String,
    pub authorization_context_ref: String,
    pub nonce: String,
}
