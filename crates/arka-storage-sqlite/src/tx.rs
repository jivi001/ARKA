//! SQLite Storage Transaction implementation.

use arka_core_types::errors::KernelSecurityError;
use arka_core_types::id::{MissionId, OperatorId};
use arka_core_types::mission::{Mission, MissionState};
use arka_kernel::storage::StorageTransaction;
use async_trait::async_trait;
use sqlx::{Row, Sqlite, Transaction};

pub struct SqliteTransaction {
    tx: Option<Transaction<'static, Sqlite>>,
}

impl SqliteTransaction {
    pub fn new(tx: Transaction<'static, Sqlite>) -> Self {
        Self { tx: Some(tx) }
    }

    fn tx_mut(&mut self) -> Result<&mut Transaction<'static, Sqlite>, KernelSecurityError> {
        self.tx.as_mut().ok_or_else(|| {
            KernelSecurityError::StorageFailure("Transaction already finalized".to_string())
        })
    }
}

#[async_trait]
impl StorageTransaction for SqliteTransaction {
    async fn get_mission(
        &mut self,
        id: &MissionId,
    ) -> Result<Option<Mission>, KernelSecurityError> {
        let tx = self.tx_mut()?;
        let query = "SELECT id, name, state, scope_ref, created_at_unix, updated_at_unix, created_by FROM missions WHERE id = ?";
        let row = sqlx::query(query)
            .bind(id.as_str())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;

        match row {
            Some(r) => {
                let id_str: String = r.get(0);
                let name: String = r.get(1);
                let state_str: String = r.get(2);
                let scope_ref: String = r.get(3);
                let created_at: i64 = r.get(4);
                let updated_at: i64 = r.get(5);
                let created_by_str: String = r.get(6);

                let state = match state_str.as_str() {
                    "CREATED" => MissionState::Created,
                    "ACTIVE" => MissionState::Active,
                    "PAUSED" => MissionState::Paused,
                    "COMPLETED" => MissionState::Completed,
                    "TERMINATED" => MissionState::Terminated,
                    other => {
                        return Err(KernelSecurityError::StorageFailure(format!(
                            "Corrupted mission state in storage: {}",
                            other
                        )))
                    }
                };

                let mission = Mission {
                    id: MissionId::new(id_str)
                        .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?,
                    name,
                    state,
                    scope_ref,
                    created_at_unix: created_at as u64,
                    updated_at_unix: updated_at as u64,
                    created_by: OperatorId::new(created_by_str)
                        .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?,
                };
                Ok(Some(mission))
            }
            None => Ok(None),
        }
    }

    async fn save_mission(&mut self, mission: &Mission) -> Result<(), KernelSecurityError> {
        let tx = self.tx_mut()?;
        let query = r#"
            INSERT INTO missions (id, name, state, scope_ref, created_at_unix, updated_at_unix, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                state = excluded.state,
                scope_ref = excluded.scope_ref,
                updated_at_unix = excluded.updated_at_unix
        "#;

        sqlx::query(query)
            .bind(mission.id.as_str())
            .bind(&mission.name)
            .bind(mission.state.as_str())
            .bind(&mission.scope_ref)
            .bind(mission.created_at_unix as i64)
            .bind(mission.updated_at_unix as i64)
            .bind(mission.created_by.as_str())
            .execute(&mut **tx)
            .await
            .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;

        Ok(())
    }

    async fn is_emergency_stop_active(&mut self) -> Result<bool, KernelSecurityError> {
        let tx = self.tx_mut()?;
        let query = "SELECT active FROM emergency_stop WHERE id = 1";
        let row = sqlx::query(query)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;

        match row {
            Some(r) => {
                let active: i64 = r.get(0);
                Ok(active == 1)
            }
            None => Ok(false),
        }
    }

    async fn commit(mut self: Box<Self>) -> Result<(), KernelSecurityError> {
        if let Some(tx) = self.tx.take() {
            tx.commit()
                .await
                .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;
        }
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> Result<(), KernelSecurityError> {
        if let Some(tx) = self.tx.take() {
            tx.rollback()
                .await
                .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;
        }
        Ok(())
    }
}
