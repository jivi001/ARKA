//! ARKA SQLite Storage Implementation.
//!
//! Provides SQLite WAL mode persistence for missions, replay logs, approvals, and emergency stop.

#![forbid(unsafe_code)]

pub mod db;
pub mod schema;
pub mod tx;

pub use db::SqliteStorage;
pub use tx::SqliteTransaction;
