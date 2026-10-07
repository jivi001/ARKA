//! Emergency Stop Service (INV-010, Section 25, Section 26).

use crate::storage::Storage;
use arka_core_types::emergency_stop::EmergencyStopStatus;
use arka_core_types::errors::KernelSecurityError;
use arka_core_types::id::OperatorId;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct EmergencyStopService {
    storage: Arc<dyn Storage>,
    cached_active: AtomicBool,
}

impl EmergencyStopService {
    pub async fn new(storage: Arc<dyn Storage>) -> Result<Self, KernelSecurityError> {
        let mut tx = storage.begin_transaction().await?;
        let is_active = tx.is_emergency_stop_active().await?;
        tx.rollback().await?;

        Ok(Self {
            storage,
            cached_active: AtomicBool::new(is_active),
        })
    }

    /// Fast-path in-memory check.
    pub fn is_active(&self) -> bool {
        self.cached_active.load(Ordering::SeqCst)
    }

    /// Triggers platform emergency stop, persisting to storage and setting in-memory cache.
    pub async fn trigger(
        &self,
        operator_id: &OperatorId,
        reason: &str,
        now_unix: u64,
    ) -> Result<(), KernelSecurityError> {
        let mut tx = self.storage.begin_transaction().await?;
        tx.trigger_emergency_stop(operator_id, reason, now_unix)
            .await?;
        tx.commit().await?;

        self.cached_active.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Clears platform emergency stop, persisting to storage and clearing in-memory cache.
    pub async fn clear(
        &self,
        operator_id: &OperatorId,
        reason: &str,
        now_unix: u64,
    ) -> Result<(), KernelSecurityError> {
        let mut tx = self.storage.begin_transaction().await?;
        tx.clear_emergency_stop(operator_id, reason, now_unix)
            .await?;
        tx.commit().await?;

        self.cached_active.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Retrieves full detailed emergency stop status from storage.
    pub async fn get_status(&self) -> Result<EmergencyStopStatus, KernelSecurityError> {
        let mut tx = self.storage.begin_transaction().await?;
        let status = tx.get_emergency_stop_status().await?;
        tx.rollback().await?;
        Ok(status)
    }
}
