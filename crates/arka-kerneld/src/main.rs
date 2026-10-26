//! ARKA Security Kernel Daemon Executable Entrypoint.

#![forbid(unsafe_code)]

use arka_core_types::clock::MockClock;
use arka_crypto::provider::DevKeyProvider;
use arka_kernel::audit::AuditChainEngine;
use arka_kernel::auth::AuthenticationService;
use arka_kernel::capabilities::StandardCapabilityRegistry;
use arka_kernel::policy::AuthorizationEngine;
use arka_kernel::ActionNormalizer;
use arka_kerneld::{KernelServer, KernelServerConfig};
use arka_storage_sqlite::SqliteStorage;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    info!("Initializing ARKA Security Kernel Daemon (arka-kerneld)...");

    let socket_path = std::env::var("ARKA_KERNEL_SOCKET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/run/arka/kernel.sock"));

    let allowed_uid = std::env::var("ARKA_KERNEL_ALLOWED_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());

    let enforce_peer_auth = std::env::var("ARKA_KERNEL_ENFORCE_PEER_AUTH")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(allowed_uid.is_some());

    let config = KernelServerConfig {
        socket_path,
        enforce_peer_auth,
        allowed_uid,
        ..Default::default()
    };

    // Storage durability configuration (VULN-005):
    // Requires persistent SQLite storage path in production; permits in-memory only when explicitly opted in.
    let storage = match std::env::var("ARKA_DATABASE_PATH") {
        Ok(db_path) => {
            info!("Initializing durable SQLite storage at: {}", db_path);
            let conn_str = format!("sqlite://{}?mode=rwc", db_path);
            Arc::new(SqliteStorage::new(&conn_str).await?)
        }
        Err(_) => {
            let allow_in_memory = std::env::var("ARKA_ALLOW_IN_MEMORY_STORAGE")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(true); // Default true for local workspace development & testing

            if allow_in_memory {
                tracing::warn!(
                    "Starting arka-kerneld with ephemeral in-memory storage (ARKA_ALLOW_IN_MEMORY_STORAGE). \
                     Audit logs and replay state will not persist across restarts."
                );
                Arc::new(SqliteStorage::new_in_memory().await?)
            } else {
                return Err("Production startup requires ARKA_DATABASE_PATH to ensure durable audit persistence. \
                            Set ARKA_ALLOW_IN_MEMORY_STORAGE=1 for non-production development."
                    .into());
            }
        }
    };
    let clock = Arc::new(MockClock::new(1000));
    let key_provider = Arc::new(DevKeyProvider::new());
    let audit_engine = Arc::new(AuditChainEngine::new(key_provider.clone()));
    let registry = Arc::new(StandardCapabilityRegistry::new());
    let normalizer = Arc::new(ActionNormalizer::new(registry));
    let auth_engine = Arc::new(AuthorizationEngine::with_audit(
        storage.clone(),
        clock.clone(),
        audit_engine,
    ));
    let auth_service = Arc::new(AuthenticationService::new(key_provider, clock.clone()));

    let server = KernelServer::new(
        config,
        normalizer,
        auth_engine,
        auth_service,
        storage,
        clock,
    );

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for ctrl-c");
        info!("SIGINT / Ctrl-C received, shutting down arka-kerneld...");
        let _ = shutdown_tx.send(());
    });

    server.run(shutdown_rx).await?;
    Ok(())
}
