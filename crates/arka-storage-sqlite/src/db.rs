//! SQLite Connection Pool and Storage Engine.

use crate::schema::INIT_SCHEMA;
use crate::tx::SqliteTransaction;
use arka_core_types::errors::KernelSecurityError;
use arka_kernel::storage::{Storage, StorageTransaction};
use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Sqlite};
use std::str::FromStr;

#[derive(Clone)]
pub struct SqliteStorage {
    pool: Pool<Sqlite>,
}

impl SqliteStorage {
    /// Creates an in-memory SQLite storage pool for tests.
    pub async fn new_in_memory() -> Result<Self, KernelSecurityError> {
        // Shared in-memory database requires max_connections = 1 or URI mode
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;

        let storage = Self { pool };
        storage.init_schema().await?;
        Ok(storage)
    }

    /// Connects to a file-based SQLite database with WAL mode enabled.
    pub async fn new(connection_str: &str) -> Result<Self, KernelSecurityError> {
        let opts = SqliteConnectOptions::from_str(connection_str)
            .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(16)
            .connect_with(opts)
            .await
            .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;

        let storage = Self { pool };
        storage.init_schema().await?;
        Ok(storage)
    }

    async fn init_schema(&self) -> Result<(), KernelSecurityError> {
        sqlx::query(INIT_SCHEMA)
            .execute(&self.pool)
            .await
            .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl Storage for SqliteStorage {
    async fn begin_transaction(&self) -> Result<Box<dyn StorageTransaction>, KernelSecurityError> {
        let tx = self
            .pool
            .begin()
            .await
            .map_err(|e| KernelSecurityError::StorageFailure(e.to_string()))?;
        Ok(Box::new(SqliteTransaction::new(tx)))
    }
}
