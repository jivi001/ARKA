//! Storage and Transaction Trait Abstraction.
//!
//! Enforces:
//! - Invariant 4.2: Pure trait abstraction isolating the Kernel from any database implementation.
//! - Invariant 4.3: Unit of Work transaction boundary committing security transitions atomically.
//! - Invariant INV-008: Atomic check-and-consume replay protection.

use arka_core_types::actions::CanonicalAction;
use arka_core_types::approval::Approval;
use arka_core_types::audit::AuditRecord;
use arka_core_types::emergency_stop::EmergencyStopStatus;
use arka_core_types::errors::KernelSecurityError;
use arka_core_types::id::{ActionId, ApprovalId, MissionId, OperatorId, ProposalId};
use arka_core_types::mission::Mission;
use async_trait::async_trait;

#[async_trait]
pub trait StorageTransaction: Send {
    /// Retrieves a mission by ID within the current transaction context.
    async fn get_mission(&mut self, id: &MissionId)
        -> Result<Option<Mission>, KernelSecurityError>;

    /// Persists or updates a mission record within the current transaction context.
    async fn save_mission(&mut self, mission: &Mission) -> Result<(), KernelSecurityError>;

    /// Checks if platform emergency stop is currently active.
    async fn is_emergency_stop_active(&mut self) -> Result<bool, KernelSecurityError>;

    /// Atomically records a replay key in storage.
    /// Returns KernelSecurityError::ReplayDetected if the key has already been consumed.
    async fn try_consume_replay(
        &mut self,
        replay_key: &str,
        mission_id: &MissionId,
        proposal_id: &ProposalId,
        action_id: &ActionId,
        now_unix: u64,
    ) -> Result<(), KernelSecurityError>;

    /// Persists an approval record into storage.
    async fn save_approval(&mut self, approval: &Approval) -> Result<(), KernelSecurityError>;

    /// Retrieves an approval record by ID.
    async fn get_approval(
        &mut self,
        id: &ApprovalId,
    ) -> Result<Option<Approval>, KernelSecurityError>;

    /// Consumes an approval atomically, binding to the action hash.
    async fn consume_approval(
        &mut self,
        id: &ApprovalId,
        action_hash: &str,
        now_unix: u64,
    ) -> Result<(), KernelSecurityError>;

    /// Records an action's state update.
    async fn save_action_record(
        &mut self,
        action: &CanonicalAction,
        status: &str,
        now_unix: u64,
    ) -> Result<(), KernelSecurityError>;

    /// Retrieves the most recent system audit record.
    async fn get_latest_system_audit(&mut self)
        -> Result<Option<AuditRecord>, KernelSecurityError>;

    /// Retrieves the most recent mission audit record for a given mission.
    async fn get_latest_mission_audit(
        &mut self,
        mission_id: &MissionId,
    ) -> Result<Option<AuditRecord>, KernelSecurityError>;

    /// Appends a system audit record and optionally a mission audit record atomically.
    async fn append_audit_records(
        &mut self,
        system_record: &AuditRecord,
        mission_record: Option<&AuditRecord>,
    ) -> Result<(), KernelSecurityError>;

    /// Retrieves all system audit records in sequence order.
    async fn get_all_system_audit(&mut self) -> Result<Vec<AuditRecord>, KernelSecurityError>;

    /// Retrieves all mission audit records for a given mission in sequence order.
    async fn get_all_mission_audit(
        &mut self,
        mission_id: &MissionId,
    ) -> Result<Vec<AuditRecord>, KernelSecurityError>;

    /// Triggers platform emergency stop, recording operator and reason.
    async fn trigger_emergency_stop(
        &mut self,
        operator_id: &OperatorId,
        reason: &str,
        now_unix: u64,
    ) -> Result<(), KernelSecurityError>;

    /// Clears platform emergency stop, recording clearing operator and reason.
    async fn clear_emergency_stop(
        &mut self,
        operator_id: &OperatorId,
        reason: &str,
        now_unix: u64,
    ) -> Result<(), KernelSecurityError>;

    /// Gets current emergency stop detailed status.
    async fn get_emergency_stop_status(
        &mut self,
    ) -> Result<EmergencyStopStatus, KernelSecurityError>;

    /// Atomically commits all changes made within this transaction.
    async fn commit(self: Box<Self>) -> Result<(), KernelSecurityError>;

    /// Rolls back all changes made within this transaction.
    async fn rollback(self: Box<Self>) -> Result<(), KernelSecurityError>;
}

#[async_trait]
pub trait Storage: Send + Sync {
    /// Begins a new atomic transaction.
    async fn begin_transaction(&self) -> Result<Box<dyn StorageTransaction>, KernelSecurityError>;
}
