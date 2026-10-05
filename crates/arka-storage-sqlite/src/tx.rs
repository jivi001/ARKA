use arka_core_types::actions::CanonicalAction;
use arka_core_types::approval::Approval;
use arka_core_types::errors::KernelSecurityError;
use arka_core_types::id::{ActionId, ApprovalId, MissionId, OperatorId, ProposalId};
use arka_core_types::mission::{Mission, MissionState};
use arka_kernel::storage::StorageTransaction;
use async_trait::async_trait;
use sqlx::pool::PoolConnection;
use sqlx::{Row, Sqlite};

pub struct SqliteTransaction {
    conn: Option<PoolConnection<Sqlite>>,
}

impl SqliteTransaction {
    pub fn new(conn: PoolConnection<Sqlite>) -> Self {
        Self { conn: Some(conn) }
    }

    fn tx_mut(&mut self) -> Result<&mut PoolConnection<Sqlite>, KernelSecurityError> {
        self.conn.as_mut().ok_or_else(|| {
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

    async fn try_consume_replay(
        &mut self,
        replay_key: &str,
        mission_id: &MissionId,
        proposal_id: &ProposalId,
        action_id: &ActionId,
        now_unix: u64,
    ) -> Result<(), KernelSecurityError> {
        let tx = self.tx_mut()?;
        let query = r#"
            INSERT INTO replay_log (replay_key, mission_id, proposal_id, action_id, consumed_at_unix)
            VALUES (?, ?, ?, ?, ?)
        "#;

        let res = sqlx::query(query)
            .bind(replay_key)
            .bind(mission_id.as_str())
            .bind(proposal_id.as_str())
            .bind(action_id.as_str())
            .bind(now_unix as i64)
            .execute(&mut **tx)
            .await;

        match res {
            Ok(_) => Ok(()),
            Err(e) => {
                if let sqlx::Error::Database(ref db_err) = e {
                    if db_err.is_unique_violation()
                        || db_err.message().contains("UNIQUE constraint")
                    {
                        return Err(KernelSecurityError::ReplayDetected(format!(
                            "Replay violation: key '{}' has already been consumed",
                            replay_key
                        )));
                    }
                }
                Err(KernelSecurityError::StorageFailure(e.to_string()))
            }
        }
    }

    async fn save_approval(&mut self, approval: &Approval) -> Result<(), KernelSecurityError> {
        let tx = self.tx_mut()?;
        let query = r#"
            INSERT INTO approvals (approval_id, mission_id, action_hash, approver_id, status, issued_at_unix, expires_at_unix, consumed_at_unix)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(approval_id) DO UPDATE SET
                status = excluded.status,
                consumed_at_unix = excluded.consumed_at_unix
        "#;

        sqlx::query(query)
            .bind(approval.approval_id.as_str())
            .bind(approval.mission_id.as_str())
            .bind(&approval.action_hash)
            .bind(approval.approver.as_str())
            .bind(&approval.status)
            .bind(approval.issued_at_unix as i64)
            .bind(approval.expires_at_unix as i64)
            .bind(approval.consumed_at_unix.map(|t| t as i64))
            .execute(&mut **tx)
            .await
            .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;

        Ok(())
    }

    async fn get_approval(
        &mut self,
        id: &ApprovalId,
    ) -> Result<Option<Approval>, KernelSecurityError> {
        let tx = self.tx_mut()?;
        let query = "SELECT approval_id, mission_id, action_hash, approver_id, status, issued_at_unix, expires_at_unix, consumed_at_unix FROM approvals WHERE approval_id = ?";
        let row = sqlx::query(query)
            .bind(id.as_str())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;

        match row {
            Some(r) => {
                let apr_id: String = r.get(0);
                let mis_id: String = r.get(1);
                let act_hash: String = r.get(2);
                let apprv_id: String = r.get(3);
                let status: String = r.get(4);
                let issued: i64 = r.get(5);
                let expires: i64 = r.get(6);
                let consumed: Option<i64> = r.get(7);

                Ok(Some(Approval {
                    approval_id: ApprovalId::new(apr_id)
                        .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?,
                    mission_id: MissionId::new(mis_id)
                        .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?,
                    action_hash: act_hash,
                    approver: OperatorId::new(apprv_id)
                        .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?,
                    status,
                    issued_at_unix: issued as u64,
                    expires_at_unix: expires as u64,
                    consumed_at_unix: consumed.map(|t| t as u64),
                }))
            }
            None => Ok(None),
        }
    }

    async fn consume_approval(
        &mut self,
        id: &ApprovalId,
        action_hash: &str,
        now_unix: u64,
    ) -> Result<(), KernelSecurityError> {
        let tx = self.tx_mut()?;
        let query = r#"
            UPDATE approvals
            SET status = 'CONSUMED', consumed_at_unix = ?
            WHERE approval_id = ? AND status = 'APPROVED' AND action_hash = ?
        "#;

        let rows_affected = sqlx::query(query)
            .bind(now_unix as i64)
            .bind(id.as_str())
            .bind(action_hash)
            .execute(&mut **tx)
            .await
            .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?
            .rows_affected();

        if rows_affected == 0 {
            return Err(KernelSecurityError::ApprovalInvalid(format!(
                "Approval '{}' could not be consumed (either already consumed, expired, or action hash mismatch)",
                id
            )));
        }

        Ok(())
    }

    async fn save_action_record(
        &mut self,
        action: &CanonicalAction,
        status: &str,
        now_unix: u64,
    ) -> Result<(), KernelSecurityError> {
        let tx = self.tx_mut()?;
        let query = r#"
            INSERT INTO actions (action_id, proposal_id, mission_id, capability_id, target, parameter_hash, action_hash, status, created_at_unix, updated_at_unix)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(action_id) DO UPDATE SET
                status = excluded.status,
                updated_at_unix = excluded.updated_at_unix
        "#;

        let target_str = serde_json::to_string(&action.target)
            .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;

        sqlx::query(query)
            .bind(action.action_id.as_str())
            .bind(action.proposal_id.as_str())
            .bind(action.mission_id.as_str())
            .bind(action.capability_id.as_str())
            .bind(target_str)
            .bind(&action.parameter_hash)
            .bind(&action.action_hash)
            .bind(status)
            .bind(now_unix as i64)
            .bind(now_unix as i64)
            .execute(&mut **tx)
            .await
            .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;

        Ok(())
    }

    async fn commit(mut self: Box<Self>) -> Result<(), KernelSecurityError> {
        if let Some(mut conn) = self.conn.take() {
            sqlx::query("COMMIT")
                .execute(&mut *conn)
                .await
                .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;
        }
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> Result<(), KernelSecurityError> {
        if let Some(mut conn) = self.conn.take() {
            sqlx::query("ROLLBACK")
                .execute(&mut *conn)
                .await
                .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;
        }
        Ok(())
    }
}

impl Drop for SqliteTransaction {
    fn drop(&mut self) {
        if let Some(mut conn) = self.conn.take() {
            tokio::spawn(async move {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            });
        }
    }
}
