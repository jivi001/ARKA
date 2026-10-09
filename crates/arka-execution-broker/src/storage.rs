//! Durable persistence abstraction and SQLite implementation for Execution Broker dispatches.
//!
//! Enforces:
//! - Unique constraint on (action_id, dispatch_attempt=1) preventing duplicate dispatches
//! - Crash recovery reconciliation: active dispatches marked Failed upon startup
//! - Invariant INV-004, INV-006

use crate::errors::BrokerError;
use crate::record::{ExecutionRecord, ExecutionResultEnvelope};
use crate::state::ExecutionState;
use arka_core_types::id::{ActionId, ExecutionId};
use async_trait::async_trait;
use sqlx::{Pool, Sqlite};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[async_trait]
pub trait BrokerStorage: Send + Sync {
    /// Inserts a newly authorized execution record into durable storage.
    /// Fails with BrokerError::DuplicateDispatch if (action_id, attempt=1) already exists.
    async fn insert_execution(&self, record: &ExecutionRecord) -> Result<(), BrokerError>;

    /// Updates the state and optional result/error of an existing execution record.
    async fn update_execution_state(
        &self,
        execution_id: &ExecutionId,
        state: ExecutionState,
        result: Option<ExecutionResultEnvelope>,
        error_reason: Option<String>,
        updated_at_unix: u64,
    ) -> Result<(), BrokerError>;

    /// Retrieves an execution record by its strongly-typed ExecutionId.
    async fn get_execution(
        &self,
        execution_id: &ExecutionId,
    ) -> Result<Option<ExecutionRecord>, BrokerError>;

    /// Retrieves an execution record by ActionId to detect prior dispatches.
    async fn get_execution_by_action(
        &self,
        action_id: &ActionId,
    ) -> Result<Option<ExecutionRecord>, BrokerError>;

    /// Crash recovery: updates all non-terminal executions (DISPATCHING, RUNNING) to FAILED.
    async fn reconcile_crashed_executions(
        &self,
        reason: &str,
        updated_at_unix: u64,
    ) -> Result<usize, BrokerError>;
}

/// SQLite-backed persistent broker storage.
pub struct SqliteBrokerStorage {
    pool: Pool<Sqlite>,
}

impl SqliteBrokerStorage {
    pub async fn new(pool: Pool<Sqlite>) -> Result<Self, BrokerError> {
        let storage = Self { pool };
        storage.init_schema().await?;
        Ok(storage)
    }

    async fn init_schema(&self) -> Result<(), BrokerError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS broker_dispatches (
                execution_id TEXT PRIMARY KEY,
                action_id TEXT NOT NULL,
                proposal_id TEXT NOT NULL,
                mission_id TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                action_hash TEXT NOT NULL,
                target_json TEXT NOT NULL,
                parameters_json TEXT NOT NULL,
                state TEXT NOT NULL,
                dispatch_attempt INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                deadline INTEGER NOT NULL,
                result_json TEXT,
                error_reason TEXT,
                UNIQUE(action_id, dispatch_attempt)
            );
            CREATE INDEX IF NOT EXISTS idx_broker_action_id ON broker_dispatches(action_id);
            CREATE INDEX IF NOT EXISTS idx_broker_state ON broker_dispatches(state);
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| BrokerError::StorageError(e.to_string()))?;

        Ok(())
    }
}

#[async_trait]
impl BrokerStorage for SqliteBrokerStorage {
    async fn insert_execution(&self, record: &ExecutionRecord) -> Result<(), BrokerError> {
        let target_str = serde_json::to_string(&record.target)
            .map_err(|e| BrokerError::StorageError(e.to_string()))?;
        let params_str = serde_json::to_string(&record.parameters)
            .map_err(|e| BrokerError::StorageError(e.to_string()))?;
        let state_str = format!("{:?}", record.state).to_uppercase();

        let result = sqlx::query(
            r#"
            INSERT INTO broker_dispatches (
                execution_id, action_id, proposal_id, mission_id, capability_id,
                action_hash, target_json, parameters_json, state, dispatch_attempt,
                created_at, updated_at, deadline, result_json, error_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
            "#,
        )
        .bind(record.execution_id.to_string())
        .bind(record.action_id.to_string())
        .bind(record.proposal_id.to_string())
        .bind(record.mission_id.to_string())
        .bind(record.capability_id.to_string())
        .bind(&record.action_hash)
        .bind(&target_str)
        .bind(&params_str)
        .bind(&state_str)
        .bind(record.dispatch_attempt as i64)
        .bind(record.created_at_unix as i64)
        .bind(record.updated_at_unix as i64)
        .bind(record.deadline_unix as i64)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                Err(BrokerError::DuplicateDispatch {
                    action_id: record.action_id.to_string(),
                    attempt: record.dispatch_attempt,
                })
            }
            Err(e) => Err(BrokerError::StorageError(e.to_string())),
        }
    }

    async fn update_execution_state(
        &self,
        execution_id: &ExecutionId,
        state: ExecutionState,
        result: Option<ExecutionResultEnvelope>,
        error_reason: Option<String>,
        updated_at_unix: u64,
    ) -> Result<(), BrokerError> {
        let state_str = format!("{:?}", state).to_uppercase();
        let result_json = match result {
            Some(res) => Some(
                serde_json::to_string(&res)
                    .map_err(|e| BrokerError::StorageError(e.to_string()))?,
            ),
            None => None,
        };

        let rows_affected = sqlx::query(
            r#"
            UPDATE broker_dispatches
            SET state = ?, result_json = ?, error_reason = ?, updated_at = ?
            WHERE execution_id = ?
            "#,
        )
        .bind(&state_str)
        .bind(result_json)
        .bind(error_reason)
        .bind(updated_at_unix as i64)
        .bind(execution_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| BrokerError::StorageError(e.to_string()))?
        .rows_affected();

        if rows_affected == 0 {
            return Err(BrokerError::StorageError(format!(
                "ExecutionId {} not found for update",
                execution_id
            )));
        }

        Ok(())
    }

    async fn get_execution(
        &self,
        execution_id: &ExecutionId,
    ) -> Result<Option<ExecutionRecord>, BrokerError> {
        let row = sqlx::query_as::<
            sqlx::Sqlite,
            (
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                i64,
                i64,
                i64,
                i64,
                Option<String>,
                Option<String>,
            ),
        >(
            r#"
            SELECT execution_id, action_id, proposal_id, mission_id, capability_id,
                   action_hash, target_json, parameters_json, state, dispatch_attempt,
                   created_at, updated_at, deadline, result_json, error_reason
            FROM broker_dispatches
            WHERE execution_id = ?
            "#,
        )
        .bind(execution_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| BrokerError::StorageError(e.to_string()))?;

        match row {
            Some(r) => parse_row(r),
            None => Ok(None),
        }
    }

    async fn get_execution_by_action(
        &self,
        action_id: &ActionId,
    ) -> Result<Option<ExecutionRecord>, BrokerError> {
        let row = sqlx::query_as::<
            sqlx::Sqlite,
            (
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                i64,
                i64,
                i64,
                i64,
                Option<String>,
                Option<String>,
            ),
        >(
            r#"
            SELECT execution_id, action_id, proposal_id, mission_id, capability_id,
                   action_hash, target_json, parameters_json, state, dispatch_attempt,
                   created_at, updated_at, deadline, result_json, error_reason
            FROM broker_dispatches
            WHERE action_id = ?
            LIMIT 1
            "#,
        )
        .bind(action_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| BrokerError::StorageError(e.to_string()))?;

        match row {
            Some(r) => parse_row(r),
            None => Ok(None),
        }
    }

    async fn reconcile_crashed_executions(
        &self,
        reason: &str,
        updated_at_unix: u64,
    ) -> Result<usize, BrokerError> {
        let rows = sqlx::query(
            r#"
            UPDATE broker_dispatches
            SET state = 'FAILED', error_reason = ?, updated_at = ?
            WHERE state IN ('DISPATCHING', 'RUNNING')
            "#,
        )
        .bind(reason)
        .bind(updated_at_unix as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| BrokerError::StorageError(e.to_string()))?
        .rows_affected();

        Ok(rows as usize)
    }
}

type SqlExecutionRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    Option<String>,
    Option<String>,
);

fn parse_row(r: SqlExecutionRow) -> Result<Option<ExecutionRecord>, BrokerError> {
    use arka_core_types::id::{CapabilityId, MissionId, ProposalId};

    let execution_id =
        ExecutionId::new(&r.0).map_err(|e| BrokerError::StorageError(e.to_string()))?;
    let action_id = ActionId::new(&r.1).map_err(|e| BrokerError::StorageError(e.to_string()))?;
    let proposal_id =
        ProposalId::new(&r.2).map_err(|e| BrokerError::StorageError(e.to_string()))?;
    let mission_id = MissionId::new(&r.3).map_err(|e| BrokerError::StorageError(e.to_string()))?;
    let capability_id =
        CapabilityId::new(&r.4).map_err(|e| BrokerError::StorageError(e.to_string()))?;
    let action_hash = r.5;
    let target: serde_json::Value =
        serde_json::from_str(&r.6).map_err(|e| BrokerError::StorageError(e.to_string()))?;
    let parameters: serde_json::Value =
        serde_json::from_str(&r.7).map_err(|e| BrokerError::StorageError(e.to_string()))?;
    let state = match r.8.as_str() {
        "AUTHORIZED" => ExecutionState::Authorized,
        "DISPATCHING" => ExecutionState::Dispatching,
        "RUNNING" => ExecutionState::Running,
        "COMPLETED" => ExecutionState::Completed,
        "FAILED" => ExecutionState::Failed,
        "TIMED_OUT" => ExecutionState::TimedOut,
        "CANCELLED" => ExecutionState::Cancelled,
        other => {
            return Err(BrokerError::StorageError(format!(
                "Unknown state in DB: {}",
                other
            )))
        }
    };
    let dispatch_attempt = r.9 as u32;
    let created_at_unix = r.10 as u64;
    let updated_at_unix = r.11 as u64;
    let deadline_unix = r.12 as u64;
    let result: Option<ExecutionResultEnvelope> = match r.13 {
        Some(s) => {
            Some(serde_json::from_str(&s).map_err(|e| BrokerError::StorageError(e.to_string()))?)
        }
        None => None,
    };
    let error_reason = r.14;

    Ok(Some(ExecutionRecord {
        execution_id,
        action_id,
        proposal_id,
        mission_id,
        capability_id,
        action_hash,
        target,
        parameters,
        state,
        dispatch_attempt,
        created_at_unix,
        updated_at_unix,
        deadline_unix,
        result,
        error_reason,
    }))
}

/// In-memory storage implementation for high-speed unit testing.
pub struct InMemoryBrokerStorage {
    records: Arc<RwLock<HashMap<String, ExecutionRecord>>>,
    by_action: Arc<RwLock<HashMap<String, String>>>,
}

impl Default for InMemoryBrokerStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryBrokerStorage {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
            by_action: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl BrokerStorage for InMemoryBrokerStorage {
    async fn insert_execution(&self, record: &ExecutionRecord) -> Result<(), BrokerError> {
        let mut by_action = self.by_action.write().await;
        if by_action.contains_key(&record.action_id.to_string()) {
            return Err(BrokerError::DuplicateDispatch {
                action_id: record.action_id.to_string(),
                attempt: record.dispatch_attempt,
            });
        }

        let mut records = self.records.write().await;
        by_action.insert(
            record.action_id.to_string(),
            record.execution_id.to_string(),
        );
        records.insert(record.execution_id.to_string(), record.clone());
        Ok(())
    }

    async fn update_execution_state(
        &self,
        execution_id: &ExecutionId,
        state: ExecutionState,
        result: Option<ExecutionResultEnvelope>,
        error_reason: Option<String>,
        updated_at_unix: u64,
    ) -> Result<(), BrokerError> {
        let mut records = self.records.write().await;
        if let Some(record) = records.get_mut(&execution_id.to_string()) {
            record.state = state;
            record.result = result;
            record.error_reason = error_reason;
            record.updated_at_unix = updated_at_unix;
            Ok(())
        } else {
            Err(BrokerError::StorageError(format!(
                "ExecutionId {} not found",
                execution_id
            )))
        }
    }

    async fn get_execution(
        &self,
        execution_id: &ExecutionId,
    ) -> Result<Option<ExecutionRecord>, BrokerError> {
        let records = self.records.read().await;
        Ok(records.get(&execution_id.to_string()).cloned())
    }

    async fn get_execution_by_action(
        &self,
        action_id: &ActionId,
    ) -> Result<Option<ExecutionRecord>, BrokerError> {
        let by_action = self.by_action.read().await;
        if let Some(exec_id) = by_action.get(&action_id.to_string()) {
            let records = self.records.read().await;
            Ok(records.get(exec_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn reconcile_crashed_executions(
        &self,
        reason: &str,
        updated_at_unix: u64,
    ) -> Result<usize, BrokerError> {
        let mut records = self.records.write().await;
        let mut count = 0;
        for record in records.values_mut() {
            if record.state == ExecutionState::Dispatching
                || record.state == ExecutionState::Running
            {
                record.state = ExecutionState::Failed;
                record.error_reason = Some(reason.to_string());
                record.updated_at_unix = updated_at_unix;
                count += 1;
            }
        }
        Ok(count)
    }
}
