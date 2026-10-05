//! ARKA Core Types & Primitives
//!
//! Provides strongly-typed identifiers, subject and context models, clock abstractions,
//! mission lifecycle models, and internal vs. external error contracts.

#![forbid(unsafe_code)]

pub mod actions;
pub mod approval;
pub mod audit;
pub mod authority;
pub mod capabilities;
pub mod clock;
pub mod emergency_stop;
pub mod errors;
pub mod id;
pub mod mission;
pub mod scope;
pub mod subject;

pub use actions::{CanonicalAction, RawActionProposal};
pub use approval::Approval;
pub use audit::{AuditPayload, AuditRecord};
pub use authority::Authority;
pub use capabilities::{CapabilityMetadata, RiskClass, TargetClass};
pub use clock::{Clock, MockClock, SystemClock};
pub use emergency_stop::EmergencyStopStatus;
pub use errors::{ExternalSecurityError, KernelSecurityError};
pub use id::{
    ActionId, AgentId, ApprovalId, CapabilityId, EvidenceId, IdValidationError, MissionId,
    OperatorId, ProposalId, TaskId, TokenId, WorkerId,
};
pub use mission::{Mission, MissionState};
pub use scope::{CanonicalTarget, CidrBlock, ScopeDecision, ScopeDefinition, ScopeRule};
pub use subject::{AuthenticatedContext, Subject};
