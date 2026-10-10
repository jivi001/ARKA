//! Tamper-Evident Dual-Hash Audit Chain Integration for Execution Broker.
//!
//! Enforces:
//! - GATE-AUDIT-INTEGRITY-001 (CTRL-AUDIT-INTEGRITY-001 / TEST-AUDIT-INTEGRITY-001)
//! - Invariant INV-011: Cryptographic Chaining and Non-Repudiation
//! - Invariant INV-014: Fail-Closed Audit Logging (no unaudited executions)
//! - Atomically appends events to both the platform-wide system audit chain and
//!   the mission-specific audit chain.

use crate::errors::BrokerError;
use arka_core_types::id::MissionId;
use arka_crypto::provider::DevKeyProvider;
use arka_kernel::audit::AuditChainEngine;
use arka_kernel::storage::Storage as KernelStorage;
use std::sync::Arc;
use uuid::Uuid;

/// Asynchronous service managing dual audit chain logging for broker lifecycle events.
pub struct BrokerAuditService<K: KernelStorage> {
    kernel_storage: Arc<K>,
    audit_engine: AuditChainEngine,
}

impl<K: KernelStorage> BrokerAuditService<K> {
    pub fn new(kernel_storage: Arc<K>, key_provider: Arc<DevKeyProvider>) -> Self {
        let audit_engine = AuditChainEngine::new(key_provider);
        Self {
            kernel_storage,
            audit_engine,
        }
    }

    /// Atomically records a broker lifecycle event to both the system and mission audit chains.
    /// Fails closed if audit persistence encounters any error.
    pub async fn log_event(
        &self,
        mission_id: &MissionId,
        event_type: &str,
        actor_id: &str,
        details: serde_json::Value,
        now_unix: u64,
    ) -> Result<(), BrokerError> {
        let mut tx = self.kernel_storage.begin_transaction().await.map_err(|e| {
            BrokerError::AuditPersistenceFailed(format!("Failed to begin audit transaction: {}", e))
        })?;

        // 1. Fetch previous heads
        let prev_sys = tx.get_latest_system_audit().await.map_err(|e| {
            BrokerError::AuditPersistenceFailed(format!("Failed to fetch system audit head: {}", e))
        })?;

        let prev_mis = tx.get_latest_mission_audit(mission_id).await.map_err(|e| {
            BrokerError::AuditPersistenceFailed(format!(
                "Failed to fetch mission audit head: {}",
                e
            ))
        })?;

        // 2. Generate signed records for both chains
        let sys_event_id = format!("aud-sys-{}", Uuid::new_v4().simple());
        let mis_event_id = format!("aud-mis-{}", Uuid::new_v4().simple());

        let sys_record = self
            .audit_engine
            .create_record(
                &sys_event_id,
                prev_sys.as_ref(),
                None,
                event_type,
                actor_id,
                details.clone(),
                now_unix,
            )
            .map_err(|e| {
                BrokerError::AuditPersistenceFailed(format!(
                    "Failed to create system audit record: {}",
                    e
                ))
            })?;

        let mis_record = self
            .audit_engine
            .create_record(
                &mis_event_id,
                prev_mis.as_ref(),
                Some(mission_id),
                event_type,
                actor_id,
                details,
                now_unix,
            )
            .map_err(|e| {
                BrokerError::AuditPersistenceFailed(format!(
                    "Failed to create mission audit record: {}",
                    e
                ))
            })?;

        // 3. Atomically persist both records
        tx.append_audit_records(&sys_record, Some(&mis_record))
            .await
            .map_err(|e| {
                BrokerError::AuditPersistenceFailed(format!(
                    "Failed to append audit records to storage: {}",
                    e
                ))
            })?;

        tx.commit().await.map_err(|e| {
            BrokerError::AuditPersistenceFailed(format!(
                "Failed to commit audit transaction: {}",
                e
            ))
        })?;

        Ok(())
    }
}
