//! Integration and Security Verification Suite for ARKA LLM Gateway Core.

use arka_gatewayd::{
    GatewayInferenceRequest, GatewayInferenceResponse, GatewayMessage, GatewayServer,
    GatewayServerConfig, MockProvider, SensitivityClass,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::broadcast;
use tokio::time::{sleep, Duration};

async fn start_test_server(
    provider: Arc<MockProvider>,
) -> (PathBuf, broadcast::Sender<()>, tokio::task::JoinHandle<()>) {
    let socket_path =
        std::env::temp_dir().join(format!("gateway_test_{}.sock", uuid::Uuid::new_v4()));

    let config = GatewayServerConfig {
        socket_path: socket_path.clone(),
        max_frame_size: 65_536,
        max_concurrency: 8,
        enforce_peer_auth: false,
        allowed_uid: None,
    };

    let server = GatewayServer::new(config, provider);
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let shutdown_tx_clone = shutdown_tx.clone();

    let handle = tokio::spawn(async move {
        let _ = server.run(shutdown_rx).await;
    });

    // Wait until socket file is created
    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    (socket_path, shutdown_tx_clone, handle)
}

use std::path::PathBuf;

async fn send_request(
    socket_path: &PathBuf,
    payload_bytes: &[u8],
) -> Result<GatewayInferenceResponse, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path).await?;

    // Send length prefix + payload
    let len = payload_bytes.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload_bytes).await?;
    stream.flush().await?;

    // Read response length prefix
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await?;

    let response: GatewayInferenceResponse = serde_json::from_slice(&resp_buf)?;
    Ok(response)
}

#[tokio::test]
async fn test_gateway_successful_completion() {
    let provider = Arc::new(MockProvider::new().with_response("Hello from authorized mock model!"));
    let (socket_path, shutdown_tx, handle) = start_test_server(provider).await;

    let request = GatewayInferenceRequest {
        request_id: "req_01J9Y78B9X4A5C6D7E8F9G0H1J".to_string(),
        mission_id: "mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q".to_string(),
        caller_agent_id: "agent_recon_01".to_string(),
        auth_token: None,
        provider: "mock".to_string(),
        model: "mock-model".to_string(),
        messages: vec![GatewayMessage {
            role: "user".to_string(),
            content: "What is target scope?".to_string(),
            name: None,
        }],
        max_tokens: Some(100),
        temperature: Some(0.2),
        sensitivity: SensitivityClass::Public,
        stream: None,
        timeout_ms: Some(5000),
    };

    let payload = serde_json::to_vec(&request).unwrap();
    let resp = send_request(&socket_path, &payload)
        .await
        .expect("Request failed");

    assert_eq!(resp.status, "SUCCESS");
    assert_eq!(resp.request_id, "req_01J9Y78B9X4A5C6D7E8F9G0H1J");
    assert!(resp.output.is_some());
    let output = resp.output.unwrap();
    assert_eq!(output.content, "Hello from authorized mock model!");
    assert_eq!(output.finish_reason, "stop");
    assert!(!resp.sanitized);

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}

#[tokio::test]
async fn test_gateway_dlp_blocks_confidential_to_external() {
    let provider = Arc::new(MockProvider::new());
    let (socket_path, shutdown_tx, handle) = start_test_server(provider).await;

    let request = GatewayInferenceRequest {
        request_id: "req_01J9Y78B9X4A5C6D7E8F9G0H2K".to_string(),
        mission_id: "mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q".to_string(),
        caller_agent_id: "agent_vuln_01".to_string(),
        auth_token: None,
        provider: "openai".to_string(),
        model: "gpt-4o".to_string(),
        messages: vec![GatewayMessage {
            role: "user".to_string(),
            content: "Target credentials hash".to_string(),
            name: None,
        }],
        max_tokens: Some(100),
        temperature: Some(0.0),
        sensitivity: SensitivityClass::Confidential,
        stream: None,
        timeout_ms: Some(5000),
    };

    let payload = serde_json::to_vec(&request).unwrap();
    let resp = send_request(&socket_path, &payload)
        .await
        .expect("Request failed");

    assert_eq!(resp.status, "ERROR");
    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    assert_eq!(err.code, "ERR_DLP_VIOLATION");
    assert!(!err.retryable);

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}

#[tokio::test]
async fn test_gateway_dlp_redacts_embedded_api_keys() {
    let provider = Arc::new(MockProvider::new().with_response("Echoed output"));
    let (socket_path, shutdown_tx, handle) = start_test_server(provider).await;

    let request = GatewayInferenceRequest {
        request_id: "req_01J9Y78B9X4A5C6D7E8F9G0H3L".to_string(),
        mission_id: "mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q".to_string(),
        caller_agent_id: "agent_recon_01".to_string(),
        auth_token: None,
        provider: "mock".to_string(),
        model: "mock-model".to_string(),
        messages: vec![GatewayMessage {
            role: "user".to_string(),
            content: "Here is an accidental leak: sk-proj12345678901234567890abcdef please analyze"
                .to_string(),
            name: None,
        }],
        max_tokens: Some(100),
        temperature: Some(0.0),
        sensitivity: SensitivityClass::Public,
        stream: None,
        timeout_ms: Some(5000),
    };

    let payload = serde_json::to_vec(&request).unwrap();
    let resp = send_request(&socket_path, &payload)
        .await
        .expect("Request failed");

    assert_eq!(resp.status, "SUCCESS");
    assert!(resp.sanitized);

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}

#[tokio::test]
async fn test_gateway_timeout_enforcement() {
    let provider = Arc::new(MockProvider::new().with_delay(300)); // 300ms delay
    let (socket_path, shutdown_tx, handle) = start_test_server(provider).await;

    let request = GatewayInferenceRequest {
        request_id: "req_01J9Y78B9X4A5C6D7E8F9G0H4M".to_string(),
        mission_id: "mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q".to_string(),
        caller_agent_id: "agent_recon_01".to_string(),
        auth_token: None,
        provider: "mock".to_string(),
        model: "mock-model".to_string(),
        messages: vec![GatewayMessage {
            role: "user".to_string(),
            content: "Test timeout".to_string(),
            name: None,
        }],
        max_tokens: Some(100),
        temperature: Some(0.0),
        sensitivity: SensitivityClass::Public,
        stream: None,
        timeout_ms: Some(50), // 50ms timeout < 300ms delay
    };

    let payload = serde_json::to_vec(&request).unwrap();
    let resp = send_request(&socket_path, &payload)
        .await
        .expect("Request failed");

    assert_eq!(resp.status, "ERROR");
    let err = resp.error.unwrap();
    assert_eq!(err.code, "ERR_GATEWAY_TIMEOUT");
    assert!(err.retryable);

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}

#[tokio::test]
async fn test_gateway_rejects_oversized_frame() {
    let provider = Arc::new(MockProvider::new());
    let (socket_path, shutdown_tx, handle) = start_test_server(provider).await;

    let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

    // Send length prefix claiming 70,000 bytes (> 65,536 limit)
    let fake_len = 70_000u32;
    stream.write_all(&fake_len.to_be_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    // Server should close the connection or return error
    let mut buf = [0u8; 1];
    let read_res = stream.read(&mut buf).await;
    assert!(read_res.is_ok());
    assert_eq!(read_res.unwrap(), 0); // 0 bytes read = EOF (server closed connection)

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}

#[tokio::test]
async fn test_gateway_rejects_duplicate_json_keys() {
    let provider = Arc::new(MockProvider::new());
    let (socket_path, shutdown_tx, handle) = start_test_server(provider).await;

    // Craft raw JSON with duplicate keys
    let raw_duplicate_json = r#"{
        "request_id": "req_dup_01",
        "request_id": "req_dup_02",
        "mission_id": "mis_01",
        "caller_agent_id": "agent_01",
        "provider": "mock",
        "model": "mock-model",
        "messages": []
    }"#;

    let resp = send_request(&socket_path, raw_duplicate_json.as_bytes())
        .await
        .expect("Request failed");

    assert_eq!(resp.status, "ERROR");
    let err = resp.error.unwrap();
    assert_eq!(err.code, "ERR_INVALID_JSON");

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}
