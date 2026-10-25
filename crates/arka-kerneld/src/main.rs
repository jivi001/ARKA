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

    let config = KernelServerConfig::default();
    let storage = Arc::new(SqliteStorage::new_in_memory().await?);
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
