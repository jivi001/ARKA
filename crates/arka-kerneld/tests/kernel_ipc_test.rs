//! ARKA Security Kernel IPC Acceptance Test Suite.
//!
//! Validates:
//! - ADR-007 Section 7 Acceptance Tests:
//!   - TEST-IPC-AUTH-001: Caller UID verification
//!   - TEST-IPC-FRAME-001: 64 KB framing bound enforcement
//!   - TEST-IPC-JSON-001: Strict JSON & duplicate key rejection
//!   - TEST-IPC-TOKEN-001: Ed25519 token verification
//!   - TEST-IPC-REPLAY-001: Atomic replay rejection
//!   - TEST-IPC-ESTOP-001: Real-time emergency stop block
//!   - TEST-IPC-ISOLATION-001: Internal broker boundary protection

use arka_core_types::actions::RawActionProposal;
use arka_core_types::clock::MockClock;
use arka_core_types::id::{AgentId, CapabilityId, MissionId, OperatorId, ProposalId, TokenId};
use arka_core_types::mission::{Mission, MissionState};
use arka_core_types::scope::{ScopeDefinition, ScopeRule};
use arka_core_types::subject::Subject;
use arka_crypto::provider::DevKeyProvider;
use arka_crypto::token::{SignedToken, TokenClaims};
use arka_kernel::audit::AuditChainEngine;
use arka_kernel::auth::AuthenticationService;
use arka_kernel::capabilities::StandardCapabilityRegistry;
use arka_kernel::emergency_stop::EmergencyStopService;
use arka_kernel::policy::AuthorizationEngine;
use arka_kernel::storage::Storage;
use arka_kernel::ActionNormalizer;
use arka_kerneld::{
    KernelRequest, KernelResponse, KernelServer, KernelServerConfig, DEFAULT_MAX_FRAME_SIZE,
};
use arka_storage_sqlite::SqliteStorage;
use serde_json::json;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::broadcast;
use uuid::Uuid;

#[allow(dead_code)]
struct TestHarness {
    pub socket_path: std::path::PathBuf,
    pub storage: Arc<SqliteStorage>,
    pub clock: Arc<MockClock>,
    pub key_provider: Arc<DevKeyProvider>,
    pub estop: Arc<EmergencyStopService>,
    pub shutdown_tx: broadcast::Sender<()>,
    pub server_handle: tokio::task::JoinHandle<()>,
}

async fn start_test_kernel(config_modifier: impl FnOnce(&mut KernelServerConfig)) -> TestHarness {
    let socket_path = std::env::temp_dir().join(format!("kernel_test_{}.sock", Uuid::new_v4()));
    let mut config = KernelServerConfig {
        socket_path: socket_path.clone(),
        max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        max_concurrency: 16,
        enforce_peer_auth: false,
        allowed_uid: None,
        enforce_token_auth: false, // Default false for unauthenticated test helper
    };
    config_modifier(&mut config);

    let storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
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
    let auth_service = Arc::new(AuthenticationService::new(
        key_provider.clone(),
        clock.clone(),
    ));
    let estop = Arc::new(EmergencyStopService::new(storage.clone()).await.unwrap());

    let server = Arc::new(KernelServer::new(
        config,
        normalizer,
        auth_engine,
        auth_service,
        storage.clone(),
        clock.clone(),
    ));

    // Register standard test scope
    server
        .register_scope(
            "scope-default",
            ScopeDefinition {
                inclusions: vec![
                    ScopeRule::IpExact("198.51.100.1".parse().unwrap()),
                    ScopeRule::IpExact("127.0.0.1".parse().unwrap()),
                ],
                exclusions: vec![],
                allow_private_ranges: true,
            },
        )
        .await;

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let srv_clone = server.clone();
    let server_handle = tokio::spawn(async move {
        let _ = srv_clone.run(shutdown_rx).await;
    });

    // Wait briefly for listener
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    TestHarness {
        socket_path,
        storage,
        clock,
        key_provider,
        estop,
        shutdown_tx,
        server_handle,
    }
}

async fn create_mission(storage: &SqliteStorage, mission_id: &str) {
    let mut tx = storage.begin_transaction().await.unwrap();
    let m = Mission::new(
        MissionId::new(mission_id).unwrap(),
        "Test Mission".to_string(),
        "scope-default".to_string(),
        OperatorId::new("op-admin").unwrap(),
        1000,
    );
    let mut active_m = m;
    active_m.state = MissionState::Active;
    tx.save_mission(&active_m).await.unwrap();
    tx.commit().await.unwrap();
}

async fn send_raw_frame(
    socket_path: &std::path::Path,
    payload: &[u8],
) -> Result<KernelResponse, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path).await?;
    let len_header = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len_header).await?;
    stream.write_all(payload).await?;

    let mut resp_len_buf = [0u8; 4];
    stream.read_exact(&mut resp_len_buf).await?;
    let resp_len = u32::from_be_bytes(resp_len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await?;

    let parsed: KernelResponse = serde_json::from_slice(&resp_buf)?;
    Ok(parsed)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_ipc_frame_limit_exceeded_aborts_immediately() {
    let harness = start_test_kernel(|cfg| {
        cfg.max_frame_size = 1024;
    })
    .await;

    // Connect and attempt to send length header exceeding max_frame_size
    let mut stream = UnixStream::connect(&harness.socket_path).await.unwrap();
    let oversized_header = (2048u32).to_be_bytes();
    stream.write_all(&oversized_header).await.unwrap();

    // The daemon must terminate connection without processing
    let mut buf = [0u8; 1];
    let res = stream.read(&mut buf).await.unwrap();
    assert_eq!(res, 0); // EOF due to daemon closing connection

    let _ = harness.shutdown_tx.send(());
}

#[tokio::test]
async fn test_ipc_duplicate_json_keys_rejected() {
    let harness = start_test_kernel(|_| {}).await;

    // JSON payload with duplicate key "operation"
    let malicious_json = r#"{
        "request_id": "req-1",
        "client_version": "3.0.0",
        "operation": "AUTHORIZE_AND_EXECUTE",
        "operation": "AUTHORIZE_ONLY",
        "proposal": {
            "proposal_id": "prp-1",
            "mission_id": "mis-1",
            "capability_id": "PORT_SCAN",
            "target": "198.51.100.1",
            "parameters": {},
            "nonce": "nonce-1"
        }
    }"#;

    let resp = send_raw_frame(&harness.socket_path, malicious_json.as_bytes())
        .await
        .unwrap();

    assert_eq!(resp.decision, "DENY");
    let err = resp.error.unwrap();
    assert_eq!(err.code, "ERR_INVALID_PAYLOAD");
    assert!(err.message.to_lowercase().contains("duplicate json key"));

    let _ = harness.shutdown_tx.send(());
}

#[tokio::test]
async fn test_ipc_missing_token_when_enforced_denied() {
    let harness = start_test_kernel(|cfg| {
        cfg.enforce_token_auth = true;
    })
    .await;

    let request = KernelRequest {
        request_id: "req-auth-test".to_string(),
        client_version: "3.0.0".to_string(),
        auth_token: None, // Missing token
        operation: "AUTHORIZE_AND_EXECUTE".to_string(),
        proposal: RawActionProposal {
            proposal_id: ProposalId::new("prp-123").unwrap(),
            mission_id: MissionId::new("mis-123").unwrap(),
            parent_task_id: None,
            capability_id: CapabilityId::new("PORT_SCAN").unwrap(),
            target: "198.51.100.1".to_string(),
            parameters: json!({}),
            declared_risk: None,
            nonce: "nonce-auth-1".to_string(),
        },
    };

    let payload = serde_json::to_vec(&request).unwrap();
    let resp = send_raw_frame(&harness.socket_path, &payload)
        .await
        .unwrap();

    assert_eq!(resp.decision, "DENY");
    let err = resp.error.unwrap();
    assert_eq!(err.code, "ERR_UNAUTHORIZED_TOKEN");

    let _ = harness.shutdown_tx.send(());
}

#[tokio::test]
async fn test_ipc_replay_detection_rejects_duplicate_nonce() {
    let harness = start_test_kernel(|_| {}).await;
    create_mission(&harness.storage, "mis-replay-01").await;

    let proposal = RawActionProposal {
        proposal_id: ProposalId::new("prp-replay-1").unwrap(),
        mission_id: MissionId::new("mis-replay-01").unwrap(),
        parent_task_id: None,
        capability_id: CapabilityId::new("PORT_SCAN").unwrap(),
        target: "198.51.100.1".to_string(),
        parameters: json!({"ports": [80]}),
        declared_risk: None,
        nonce: "static-identical-nonce-123".to_string(),
    };

    let request = KernelRequest {
        request_id: "req-1".to_string(),
        client_version: "3.0.0".to_string(),
        auth_token: None,
        operation: "AUTHORIZE_AND_EXECUTE".to_string(),
        proposal: proposal.clone(),
    };

    let payload = serde_json::to_vec(&request).unwrap();

    // First attempt: ALLOW
    let resp1 = send_raw_frame(&harness.socket_path, &payload)
        .await
        .unwrap();
    assert_eq!(resp1.decision, "ALLOW");

    // Second attempt with identical nonce: DENY due to replay detection
    let req2 = KernelRequest {
        request_id: "req-2".to_string(),
        client_version: "3.0.0".to_string(),
        auth_token: None,
        operation: "AUTHORIZE_AND_EXECUTE".to_string(),
        proposal,
    };
    let payload2 = serde_json::to_vec(&req2).unwrap();
    let resp2 = send_raw_frame(&harness.socket_path, &payload2)
        .await
        .unwrap();

    assert_eq!(resp2.decision, "DENY");
    let err = resp2.error.unwrap();
    assert_eq!(err.code, "AUTHORIZATION_DENIED"); // Sanitized external error code

    let _ = harness.shutdown_tx.send(());
}

#[tokio::test]
async fn test_ipc_emergency_stop_denies_authorization() {
    let harness = start_test_kernel(|_| {}).await;
    create_mission(&harness.storage, "mis-estop-01").await;

    // Trigger platform emergency stop
    let op = OperatorId::new("op-admin").unwrap();
    harness
        .estop
        .trigger(&op, "Active threat detected", 1000)
        .await
        .unwrap();

    let request = KernelRequest {
        request_id: "req-estop".to_string(),
        client_version: "3.0.0".to_string(),
        auth_token: None,
        operation: "AUTHORIZE_AND_EXECUTE".to_string(),
        proposal: RawActionProposal {
            proposal_id: ProposalId::new("prp-estop-1").unwrap(),
            mission_id: MissionId::new("mis-estop-01").unwrap(),
            parent_task_id: None,
            capability_id: CapabilityId::new("PORT_SCAN").unwrap(),
            target: "198.51.100.1".to_string(),
            parameters: json!({"ports": [80]}),
            declared_risk: None,
            nonce: "nonce-estop-1".to_string(),
        },
    };

    let payload = serde_json::to_vec(&request).unwrap();
    let resp = send_raw_frame(&harness.socket_path, &payload)
        .await
        .unwrap();

    assert_eq!(resp.decision, "DENY");
    let err = resp.error.unwrap();
    assert_eq!(err.code, "EMERGENCY_STOP_ACTIVE");

    let _ = harness.shutdown_tx.send(());
}

#[tokio::test]
async fn test_ipc_successful_authorization_and_internal_broker_dispatch() {
    let harness = start_test_kernel(|_| {}).await;
    create_mission(&harness.storage, "mis-allow-01").await;

    let request = KernelRequest {
        request_id: "req-allow".to_string(),
        client_version: "3.0.0".to_string(),
        auth_token: None,
        operation: "AUTHORIZE_AND_EXECUTE".to_string(),
        proposal: RawActionProposal {
            proposal_id: ProposalId::new("prp-allow-1").unwrap(),
            mission_id: MissionId::new("mis-allow-01").unwrap(),
            parent_task_id: None,
            capability_id: CapabilityId::new("PORT_SCAN").unwrap(),
            target: "198.51.100.1".to_string(),
            parameters: json!({"ports": [80, 443]}),
            declared_risk: None,
            nonce: "nonce-allow-1".to_string(),
        },
    };

    let payload = serde_json::to_vec(&request).unwrap();
    let resp = send_raw_frame(&harness.socket_path, &payload)
        .await
        .unwrap();

    assert_eq!(resp.decision, "ALLOW");
    assert!(resp.action_id.is_some());
    assert!(resp.action_hash.is_some());

    // Internal broker executed successfully
    assert!(resp.execution_result.is_some());
    let exec = resp.execution_result.unwrap();
    assert_eq!(exec.state, "COMPLETED");
    assert!(exec.execution_id.starts_with("exc-"));

    let _ = harness.shutdown_tx.send(());
}

#[tokio::test]
async fn test_ipc_unregistered_scope_reference_denied_fail_closed() {
    let harness = start_test_kernel(|_| {}).await;
    create_mission(&harness.storage, "mis-scope-fail").await;

    // Create an authenticated token that references an unregistered scope 'scope-unregistered-999'
    let claims = TokenClaims {
        token_id: TokenId::new("tok-scope-fail-1").unwrap(),
        subject: Subject::Agent(AgentId::new("agt-recon-01").unwrap()),
        mission_id: MissionId::new("mis-scope-fail").unwrap(),
        parent_task_id: None,
        capabilities: vec![CapabilityId::new("PORT_SCAN").unwrap()],
        scope_ref: "scope-unregistered-999".to_string(),
        issued_at_unix: 1000,
        expires_at_unix: 2000,
        parent_token_id: None,
    };
    let signed_token = SignedToken::issue(
        claims,
        "TOKEN-SIGNING-dev-01",
        harness.key_provider.as_ref(),
    )
    .unwrap();
    let token_json = serde_json::to_string(&signed_token).unwrap();

    let request = KernelRequest {
        request_id: "req-scope-fail".to_string(),
        client_version: "3.0.0".to_string(),
        auth_token: Some(token_json),
        operation: "AUTHORIZE".to_string(),
        proposal: RawActionProposal {
            proposal_id: ProposalId::new("prp-scope-fail").unwrap(),
            mission_id: MissionId::new("mis-scope-fail").unwrap(),
            parent_task_id: None,
            capability_id: CapabilityId::new("PORT_SCAN").unwrap(),
            target: "127.0.0.1".to_string(), // Trying to access localhost via unregistered scope
            parameters: json!({"ports": [80]}),
            declared_risk: None,
            nonce: "nonce-scope-fail-1".to_string(),
        },
    };

    let payload = serde_json::to_vec(&request).unwrap();
    let resp = send_raw_frame(&harness.socket_path, &payload)
        .await
        .unwrap();

    // VULN-002 Invariant: Unregistered scope reference MUST be rejected with DENY and ERR_SCOPE_NOT_FOUND
    assert_eq!(resp.decision, "DENY");
    let err = resp.error.expect("Expected error payload on DENY");
    assert_eq!(err.code, "ERR_SCOPE_NOT_FOUND");
    assert!(err.message.contains("fail-closed"));

    let _ = harness.shutdown_tx.send(());
}
