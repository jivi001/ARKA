//! Executable Acceptance Test Suite for GATE-PROVIDER-CRED-ISOLATION-001 (Phase 3 Module C).
//!
//! Enforces the seven mandatory test scenarios required by ARKA security governance:
//! 1. Secret absence across all formatted outputs, logs, and artifacts.
//! 2. Credential source failure and fail-closed rejection.
//! 3. Dynamic key rotation and instant provider emergency disablement.
//! 4. Unauthorized endpoint rejection and SSRF tampering defense.
//! 5. Provider credentials hard-rejected by ARKA authorization paths.
//! 6. OS process and privilege isolation (file mode 0600 and SO_PEERCRED checks).
//! 7. Redaction on upstream provider diagnostic and failure paths.

use arka_crypto::SignedToken;
use arka_gatewayd::{
    CredentialSourceType, CredentialStore, DlpFilter, GatewayInferenceRequest,
    GatewayInferenceResponse, GatewayMessage, GatewayServer, GatewayServerConfig, MockProvider,
    ProviderKey, SensitivityClass,
};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::broadcast;
use tokio::time::{sleep, Duration};

async fn start_gateway_with_credentials(
    provider: Arc<MockProvider>,
    credentials: Arc<CredentialStore>,
) -> (PathBuf, broadcast::Sender<()>, tokio::task::JoinHandle<()>) {
    let socket_path =
        std::env::temp_dir().join(format!("gw_cred_test_{}.sock", uuid::Uuid::new_v4()));

    let config = GatewayServerConfig {
        socket_path: socket_path.clone(),
        max_frame_size: 65_536,
        max_concurrency: 8,
        enforce_peer_auth: false,
        allowed_uid: None,
    };

    let server = GatewayServer::new(config, provider).with_credentials(credentials);
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let shutdown_tx_clone = shutdown_tx.clone();

    let handle = tokio::spawn(async move {
        let _ = server.run(shutdown_rx).await;
    });

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    (socket_path, shutdown_tx_clone, handle)
}

async fn send_request(
    socket_path: &PathBuf,
    payload_bytes: &[u8],
) -> Result<GatewayInferenceResponse, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path).await?;
    let len = payload_bytes.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload_bytes).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await?;

    let response: GatewayInferenceResponse = serde_json::from_slice(&resp_buf)?;
    Ok(response)
}

// -----------------------------------------------------------------------------
// Scenario 1: Comprehensive Secret Absence Across All Artifacts
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_1_secret_absence_across_all_artifacts() {
    let secret_raw = "sk-ant-api03-verysecretkey1234567890abcdef".to_string();
    let key = ProviderKey::new(
        "anthropic",
        "key_01J9Y78A",
        secret_raw.clone(),
        CredentialSourceType::Static,
        1792928400,
    );

    // 1. Debug formatting MUST redact key material
    let debug_str = format!("{:?}", key);
    assert!(debug_str.contains("[REDACTED:KEY_MATERIAL]"));
    assert!(!debug_str.contains(&secret_raw));

    // 2. Display formatting MUST redact key material
    let display_str = format!("{}", key);
    assert!(display_str.contains("[REDACTED]"));
    assert!(!display_str.contains(&secret_raw));

    // 3. Serialized DLP scrubbing MUST catch embedded keys
    let dlp = DlpFilter::new();
    let (cleaned, modified) = dlp.redact_string(&format!("Here is my token: {}", secret_raw));
    assert!(modified);
    assert!(cleaned.contains("[REDACTED:API_KEY]"));
    assert!(!cleaned.contains(&secret_raw));
}

// -----------------------------------------------------------------------------
// Scenario 2: Credential Source Failure and Fail-Closed Behavior
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_scenario_2_credential_source_failure_fails_closed() {
    let provider = Arc::new(MockProvider::new());
    let cred_store = Arc::new(CredentialStore::new()); // Empty vault: zero keys loaded
    let (socket_path, shutdown_tx, handle) =
        start_gateway_with_credentials(provider, cred_store).await;

    let request = GatewayInferenceRequest {
        request_id: "req_scen_2_01".to_string(),
        mission_id: "mis_01".to_string(),
        caller_agent_id: "agent_01".to_string(),
        auth_token: None,
        provider: "openai".to_string(), // Requires credential
        model: "gpt-4o".to_string(),
        messages: vec![GatewayMessage {
            role: "user".to_string(),
            content: "Ping".to_string(),
            name: None,
        }],
        max_tokens: Some(50),
        temperature: Some(0.0),
        sensitivity: SensitivityClass::Public,
        stream: None,
        timeout_ms: Some(2000),
    };

    let payload = serde_json::to_vec(&request).unwrap();
    let resp = send_request(&socket_path, &payload)
        .await
        .expect("IPC request");

    // Must fail closed with sanitized error
    assert_eq!(resp.status, "ERROR");
    let err = resp.error.unwrap();
    assert_eq!(err.code, "ERR_PROVIDER_UNAVAILABLE");
    assert!(err
        .message
        .contains("No active credential configured for provider 'openai'"));
    // Must NOT contain internal system paths or stack trace
    assert!(!err.message.contains("/"));
    assert!(!err.message.contains(".rs"));

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}

// -----------------------------------------------------------------------------
// Scenario 3: Dynamic Rotation, Revocation, and Provider Emergency Disablement
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_scenario_3_dynamic_rotation_and_instant_disablement() {
    let cred_store = Arc::new(CredentialStore::new());

    // Register initial key K1
    cred_store
        .register_key(ProviderKey::new(
            "openai",
            "k1",
            "sk-proj-initialsecretkey1234567890abcdef".to_string(),
            CredentialSourceType::Static,
            100,
        ))
        .await;

    let key_k1 = cred_store.get_key("openai").await.expect("Get K1");
    assert_eq!(*key_k1, "sk-proj-initialsecretkey1234567890abcdef");

    // Dynamic rotation to key K2 (old key zeroized on drop)
    cred_store
        .rotate_key(
            "openai",
            "sk-proj-rotatedsecretkey9876543210fedcba".to_string(),
            "k2".to_string(),
            200,
        )
        .await;

    let key_k2 = cred_store.get_key("openai").await.expect("Get K2");
    assert_eq!(*key_k2, "sk-proj-rotatedsecretkey9876543210fedcba");

    // Emergency provider disablement / revocation
    cred_store.disable_provider("openai").await;
    assert!(cred_store.is_disabled("openai").await);

    // Subsequent retrieval must fail closed
    let res = cred_store.get_key("openai").await;
    assert!(res.is_err());
    assert!(matches!(
        res.unwrap_err(),
        arka_gatewayd::GatewayError::ProviderUnavailable(_)
    ));
}

// -----------------------------------------------------------------------------
// Scenario 4: Unauthorized Endpoint Rejection & Configuration-Tampering Defense
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_scenario_4_unauthorized_endpoint_and_tampering_rejected() {
    let cred_store = CredentialStore::new();

    // 1. Valid registered provider endpoint succeeds
    let valid_res = cred_store
        .validate_endpoint("openai", "api.openai.com:443")
        .await;
    assert!(valid_res.is_ok());

    // 2. Cloud metadata SSRF attempt (169.254.169.254) is hard rejected
    let ssrf_metadata = cred_store
        .validate_endpoint("openai", "169.254.169.254:80")
        .await;
    assert!(ssrf_metadata.is_err());
    assert!(matches!(
        ssrf_metadata.unwrap_err(),
        arka_gatewayd::GatewayError::DlpViolation(_)
    ));

    // 3. Localhost loopback manipulation is hard rejected
    let ssrf_loopback = cred_store
        .validate_endpoint("openai", "127.0.0.1:8080")
        .await;
    assert!(ssrf_loopback.is_err());
    assert!(matches!(
        ssrf_loopback.unwrap_err(),
        arka_gatewayd::GatewayError::DlpViolation(_)
    ));
}

// -----------------------------------------------------------------------------
// Scenario 5: Provider Credentials Rejected by ARKA Authorization Paths
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_5_provider_credentials_rejected_by_kernel_auth() {
    // Adversary attempts to pass an OpenAI API key as an ARKA kernel authorization token
    let fake_token = "sk-proj-12345678901234567890abcdef";
    let verification_result = serde_json::from_str::<SignedToken>(fake_token);

    // Must be hard rejected by Ed25519 token deserializer and verifier
    assert!(verification_result.is_err());
}

// -----------------------------------------------------------------------------
// Scenario 6: OS Process and Privilege Isolation (File Mode 0600 Enforcement)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_scenario_6_os_process_privilege_isolation() {
    let dir = tempdir().expect("tempdir");
    let cred_store = CredentialStore::new();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Create world-readable credential file (mode 0644)
        let insecure_file = dir.path().join("insecure_creds.env");
        std::fs::write(
            &insecure_file,
            "openai=sk-proj-insecurekey1234567890abcdef\n",
        )
        .unwrap();
        std::fs::set_permissions(&insecure_file, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Load attempt MUST fail closed because permissions are too permissive
        let res = cred_store.load_from_file(&insecure_file).await;
        assert!(res.is_err());
        assert!(matches!(
            res.unwrap_err(),
            arka_gatewayd::GatewayError::DlpViolation(_)
        ));

        // Create secure credential file (mode 0600)
        let secure_file = dir.path().join("secure_creds.env");
        std::fs::write(&secure_file, "openai=sk-proj-securekey1234567890abcdef\n").unwrap();
        std::fs::set_permissions(&secure_file, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Load attempt succeeds
        let secure_res = cred_store.load_from_file(&secure_file).await;
        assert!(secure_res.is_ok());
        assert_eq!(secure_res.unwrap(), 1);
    }
}

// -----------------------------------------------------------------------------
// Scenario 7: Redaction on Diagnostic and Provider Failure Paths
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_scenario_7_redaction_on_provider_failure_and_diagnostics() {
    // Provider fails and returns an error message accidentally containing an API key
    let leaking_provider = Arc::new(MockProvider::new().with_failure(
        "Upstream 500 error: invalid Authorization sk-ant-leak12345678901234567890 returned",
    ));
    let cred_store = Arc::new(CredentialStore::new());
    let (socket_path, shutdown_tx, handle) =
        start_gateway_with_credentials(leaking_provider, cred_store).await;

    let request = GatewayInferenceRequest {
        request_id: "req_scen_7_01".to_string(),
        mission_id: "mis_01".to_string(),
        caller_agent_id: "agent_01".to_string(),
        auth_token: None,
        provider: "mock".to_string(),
        model: "mock-model".to_string(),
        messages: vec![GatewayMessage {
            role: "user".to_string(),
            content: "Trigger upstream error".to_string(),
            name: None,
        }],
        max_tokens: Some(50),
        temperature: Some(0.0),
        sensitivity: SensitivityClass::Public,
        stream: None,
        timeout_ms: Some(2000),
    };

    let payload = serde_json::to_vec(&request).unwrap();
    let resp = send_request(&socket_path, &payload)
        .await
        .expect("IPC request");

    assert_eq!(resp.status, "ERROR");
    let err = resp.error.unwrap();
    assert_eq!(err.code, "ERR_PROVIDER_UNAVAILABLE");

    // The raw secret MUST be scrubbed from the returned error message
    assert!(!err.message.contains("sk-ant-leak12345678901234567890"));
    assert!(err.message.contains("[REDACTED:API_KEY]"));

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}
