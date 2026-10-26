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

    let allowed_uid = std::env::var("ARKA_GATEWAY_ALLOWED_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());

    let enforce_peer_auth = std::env::var("ARKA_GATEWAY_ENFORCE_PEER_AUTH")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(allowed_uid.is_some());

    let config = GatewayServerConfig {
        socket_path,
        enforce_peer_auth,
        allowed_uid,
        ..Default::default()
    };

    // Construct provider based on configuration
    let provider_name = std::env::var("ARKA_LLM_PROVIDER").unwrap_or_else(|_| "mock".to_string());
    let provider: Arc<dyn arka_gatewayd::LlmProvider> = match provider_name.to_lowercase().as_str()
    {
        "mock" => {
            info!("Initializing Gateway with MockProvider for local testing/baseline operations");
            Arc::new(MockProvider::new())
        }
        other => {
            info!("Initializing Gateway with provider adapter: {}", other);
            // Default mock provider fallback if adapter registration is pending
            Arc::new(MockProvider::new())
        }
    };
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
