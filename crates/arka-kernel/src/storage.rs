//! Storage and Transaction Trait Abstraction.
//!
//! Enforces:
//! - Invariant 4.2: Pure trait abstraction isolating the Kernel from any database implementation.
//! - Invariant 4.3: Unit of Work transaction boundary committing security transitions atomically.
//! - Invariant INV-008: Atomic check-and-consume replay protection.

use arka_core_types::actions::CanonicalAction;
use arka_core_types::approval::Approval;
use arka_core_types::errors::KernelSecurityError;
use arka_core_types::id::{ActionId, ApprovalId, MissionId, ProposalId};
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
