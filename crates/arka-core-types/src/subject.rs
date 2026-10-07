//! Subject, Actor, and Authenticated Security Context primitives.
//!
//! Enforces:
//! - INV-004: Identity comes strictly from Authenticated Context, never untrusted input.
//! - Non-forgeable bindings between actor, mission, capabilities, and expiration.

use crate::id::{AgentId, CapabilityId, MissionId, OperatorId, TaskId, TokenId, WorkerId};
use serde::{Deserialize, Serialize};

/// The authenticated identity executing or requesting an action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "id")]
pub enum Subject {
    Operator(OperatorId),
    Agent(AgentId),
    Worker(WorkerId),
}

impl Subject {
    pub fn is_operator(&self) -> bool {
        matches!(self, Subject::Operator(_))
    }

    pub fn is_agent(&self) -> bool {
        matches!(self, Subject::Agent(_))
    }

    pub fn is_worker(&self) -> bool {
        matches!(self, Subject::Worker(_))
    }

    pub fn identifier(&self) -> &str {
        match self {
            Subject::Operator(id) => id.as_str(),
            Subject::Agent(id) => id.as_str(),
            Subject::Worker(id) => id.as_str(),
        }
    }
}

/// The authoritative security context constructed exclusively from a cryptographically
/// verified token. Unauthenticated action proposals CANNOT supply or mutate this context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedContext {
    pub token_id: TokenId,
    pub subject: Subject,
    pub mission_id: MissionId,
    pub parent_task_id: Option<TaskId>,
    pub capabilities: Vec<CapabilityId>,
    pub scope_ref: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub parent_token_id: Option<TokenId>,
}

impl AuthenticatedContext {
    pub fn is_expired_at(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at_unix
    }

    pub fn has_capability(&self, cap: &CapabilityId) -> bool {
        self.capabilities.contains(cap)
    }
}
