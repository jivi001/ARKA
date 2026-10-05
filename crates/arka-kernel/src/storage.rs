//! Storage and Transaction Trait Abstraction.
//!
//! Enforces:
//! - Invariant 4.2: Pure trait abstraction isolating the Kernel from any database implementation.
//! - Invariant 4.3: Unit of Work transaction boundary committing security transitions atomically.

use arka_core_types::errors::KernelSecurityError;
use arka_core_types::id::MissionId;
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
