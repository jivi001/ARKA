//! ARKA Standalone LLM Gateway Daemon Binary (arka-gatewayd).

#![forbid(unsafe_code)]

use arka_gatewayd::{GatewayServer, GatewayServerConfig, MockProvider};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::broadcast;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting ARKA LLM Gateway Daemon (arka-gatewayd)...");

    let socket_path = std::env::var("ARKA_GATEWAY_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/arka/gateway.sock"));

    let config = GatewayServerConfig {
        socket_path,
        enforce_peer_auth: true,
        ..Default::default()
    };

    // Default mock provider for baseline operations
    let provider = Arc::new(MockProvider::new());
    let server = GatewayServer::new(config, provider);

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    tokio::spawn(async move {
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM");
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to register SIGINT");

        tokio::select! {
            _ = sigterm.recv() => info!("Received SIGTERM"),
            _ = sigint.recv() => info!("Received SIGINT"),
        }

        let _ = shutdown_tx.send(());
    });

    if let Err(e) = server.run(shutdown_rx).await {
        error!("Fatal gateway error: {:?}", e);
        std::process::exit(1);
    }

    info!("arka-gatewayd shutdown cleanly.");
    Ok(())
}
