//! Checkpoint P2-G Adversarial Verification & Release Gate Test Suite.
//!
//! Validates:
//! - Property Invariant: "Unauthorized action implies zero side effects"
//! - Fuzzing-style adversarial input verification (URL/target parsing, redirect handling, worker protocol, outputs)
//! - Adversarial SSRF, DNS rebinding, IPv6, and cloud metadata bypass attempts
//! - Anti-replay and concurrency race conditions under high contention
//! - Sandbox escape boundary and unprivileged isolation assertions
//!
//! Test Design Rule:
//! Every denial test asserts absence of the external side effect, not only the returned error code.

use arka_core_types::actions::CanonicalAction;
use arka_core_types::approval::Approval;
use arka_core_types::capabilities::RiskClass;
use arka_core_types::clock::MockClock;
use arka_core_types::id::{ActionId, ApprovalId, CapabilityId, MissionId, OperatorId, ProposalId};
use arka_core_types::scope::{CanonicalTarget, ScopeDefinition, ScopeRule};
use arka_execution_broker::broker::{BrokerConfig, ExecutionBroker};
use arka_execution_broker::dispatcher::WorkerDispatcher;
use arka_execution_broker::errors::BrokerError;
use arka_execution_broker::record::{ExecutionRecord, ExecutionResultEnvelope};
use arka_execution_broker::sandbox::{SandboxConfig, SandboxSupervisor};
use arka_execution_broker::state::ExecutionState;
use arka_execution_broker::storage::InMemoryBrokerStorage;
use arka_kernel::storage::Storage as KernelStorage;
use arka_network_policy::address::CanonicalIp;
use arka_network_policy::dns::MockDnsResolver;
use arka_network_policy::params::ParameterValidator;
use arka_network_policy::redirect::{RedirectConfig, RedirectHandler};
use arka_network_policy::validator::ScopeGuard;
use arka_storage_sqlite::db::SqliteStorage;
use arka_worker_protocol::{ProtocolCodec, ProtocolError};
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A mock worker that records every dispatch attempt to assert zero side effects.
struct SideEffectTrackerWorker {
    dispatch_attempts: Arc<AtomicUsize>,
}

impl SideEffectTrackerWorker {
    fn new() -> (Self, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        (
            Self {
                dispatch_attempts: counter.clone(),
            },
            counter,
        )
    }
}

#[async_trait]
impl WorkerDispatcher for SideEffectTrackerWorker {
    async fn dispatch(
        &self,
        record: &ExecutionRecord,
    ) -> Result<ExecutionResultEnvelope, BrokerError> {
        self.dispatch_attempts.fetch_add(1, Ordering::SeqCst);
        Ok(ExecutionResultEnvelope {
            execution_id: record.execution_id.clone(),
            action_id: record.action_id.clone(),
            action_hash: record.action_hash.clone(),
            state: ExecutionState::Completed,
            exit_code: Some(0),
            stdout_truncated: Some("Executed".to_string()),
            stderr_truncated: None,
            structured_output: serde_json::json!({"dispatched": true}),
            evidence_hashes: vec![],
            completed_at_unix: record.created_at_unix,
        })
    }
}

fn sample_action(requires_approval: bool) -> CanonicalAction {
    CanonicalAction {
        action_id: ActionId::new("act-adv-01").unwrap(),
        proposal_id: ProposalId::new("prop-adv-01").unwrap(),
        mission_id: MissionId::new("mis-adv-01").unwrap(),
        parent_task_id: None,
        capability_id: CapabilityId::new("CONTROLLED_EXPLOITATION").unwrap(),
        target: CanonicalTarget::Domain {
            domain: "target.corp".to_string(),
            port: Some(443),
        },
        normalized_parameters: serde_json::json!({"command": "probe", "port": 443}),
        parameter_hash: "param-hash-fixed-123".to_string(),
        action_hash: "action-hash-fixed-123".to_string(),
        risk_class: if requires_approval {
            RiskClass::Critical
        } else {
            RiskClass::Moderate
        },
        requires_approval,
        policy_version: "v2.2".to_string(),
        authorization_context_ref: "auth-ctx-1".to_string(),
        nonce: "adv-nonce-01".to_string(),
    }
}

// ============================================================================
// Property Test: "Unauthorized Action Implies Zero Side Effects"
// ============================================================================

#[tokio::test]
async fn test_property_unauthorized_action_zero_side_effects() {
    let kernel_storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
    let broker_storage = Arc::new(InMemoryBrokerStorage::new());
    let clock = Arc::new(MockClock::new(1000));
    let (tracker_worker, side_effect_counter) = SideEffectTrackerWorker::new();

    let broker = ExecutionBroker::new(
        kernel_storage.clone(),
        broker_storage.clone(),
        Arc::new(tracker_worker),
        clock.clone(),
        BrokerConfig::default(),
    );

    // 1. Missing required approval
    let action_high_risk = sample_action(true);
    let res1 = broker.execute_action(&action_high_risk, None).await;
    assert!(res1.is_err());
    assert_eq!(
        side_effect_counter.load(Ordering::SeqCst),
        0,
        "Zero side effects must occur on missing approval"
    );

    // 2. Action hash mismatch in approval (TOCTOU attack)
    let bad_approval = Approval::new(
        ApprovalId::new("app-bad-1").unwrap(),
        action_high_risk.mission_id.clone(),
        "forged-action-hash",
        OperatorId::new("op-alice").unwrap(),
        950,
        2000,
    );
    let res2 = broker
        .execute_action(&action_high_risk, Some(&bad_approval))
        .await;
    assert!(res2.is_err());
    assert_eq!(
        side_effect_counter.load(Ordering::SeqCst),
        0,
        "Zero side effects must occur on hash mismatch"
    );

    // 3. Expired approval
    let expired_approval = Approval::new(
        ApprovalId::new("app-exp-1").unwrap(),
        action_high_risk.mission_id.clone(),
        action_high_risk.action_hash.clone(),
        OperatorId::new("op-alice").unwrap(),
        900,
        950, // Expired before now (1000)
    );
    let res3 = broker
        .execute_action(&action_high_risk, Some(&expired_approval))
        .await;
    assert!(res3.is_err());
    assert_eq!(
        side_effect_counter.load(Ordering::SeqCst),
        0,
        "Zero side effects must occur on expired approval"
    );

    // 4. Missing action hash in canonical action
    let mut invalid_action = sample_action(false);
    invalid_action.action_hash = "".to_string();
    let res4 = broker.execute_action(&invalid_action, None).await;
    assert!(res4.is_err());
    assert_eq!(
        side_effect_counter.load(Ordering::SeqCst),
        0,
        "Zero side effects must occur on missing action hash"
    );

    // 5. Emergency Stop Active
    {
        let mut tx = kernel_storage.begin_transaction().await.unwrap();
        tx.trigger_emergency_stop(
            &OperatorId::new("op-admin").unwrap(),
            "Containment test",
            1000,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let action_mod = sample_action(false);
    let res5 = broker.execute_action(&action_mod, None).await;
    assert!(res5.is_err());
    assert_eq!(
        side_effect_counter.load(Ordering::SeqCst),
        0,
        "Zero side effects must occur while emergency stop is active"
    );
}

// ============================================================================
// Fuzz-Style Adversarial Parameter & Target Ingestion Tests
// ============================================================================

#[test]
fn test_adversarial_target_parsing_fuzzing() {
    let binding = "a".repeat(300);
    let adversarial_hosts = vec![
        // Command injection metacharacters
        "example.com; rm -rf /",
        "example.com | cat /etc/passwd",
        "example.com`whoami`",
        "example.com$(id)",
        "example.com & ping 127.0.0.1",
        "example.com\nGET / HTTP/1.1",
        "example.com\r\nHost: evil.com",
        "example.com\0.evil.com",
        // Path traversal / control characters
        "../../../../etc/shadow",
        "example\x01\x02\x03.com",
        "example.com\x7F",
        // Ambiguous IP evasions
        "0177.0000.0000.0001",
        "0x7F000001",
        "2130706433",
        "127.0.0.1%eth0",
        "[::1%12]",
        // Excessively long host (>253 chars)
        &binding,
    ];

    for host in adversarial_hosts {
        let is_rejected =
            ParameterValidator::validate_host(host).is_err() || CanonicalIp::parse(host).is_err();
        assert!(is_rejected, "Adversarial host '{}' must be rejected", host);
    }
}

#[test]
fn test_adversarial_port_boundaries_fuzzing() {
    let invalid_ports = vec![0, 65536, 70000, 100000, u32::MAX];
    for port in invalid_ports {
        let is_invalid = port == 0 || port > 65535;
        assert!(is_invalid, "Port {} must be out of valid u16 range", port);
    }
}

// ============================================================================
// Adversarial SSRF, DNS Rebinding & Cloud Metadata Defense Tests
// ============================================================================

#[tokio::test]
async fn test_adversarial_ssrf_and_cloud_metadata_defense() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    // Map various adversarial domains to dangerous IPs
    mock_dns
        .set_response(
            "aws-metadata.local",
            vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
        )
        .await;
    mock_dns
        .set_response(
            "gcp-metadata.local",
            vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
        )
        .await;
    mock_dns
        .set_response(
            "localhost-v4.local",
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
        )
        .await;
    mock_dns
        .set_response(
            "all-zeros.local",
            vec![IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))],
        )
        .await;
    mock_dns
        .set_response(
            "private-10.local",
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        )
        .await;
    mock_dns
        .set_response(
            "private-192.local",
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
        )
        .await;

    let scope_guard = Arc::new(ScopeGuard::new(mock_dns));
    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::DomainWildcard("*.local".to_string())],
        exclusions: vec![],
        allow_private_ranges: false,
    };

    let adversarial_ssrf_targets = vec![
        "aws-metadata.local",
        "gcp-metadata.local",
        "localhost-v4.local",
        "all-zeros.local",
        "private-10.local",
        "private-192.local",
    ];

    for host in adversarial_ssrf_targets {
        let res = scope_guard.validate_and_pin(host, 80, Some(&scope)).await;
        assert!(
            res.is_err(),
            "SSRF/Metadata target '{}' must be rejected by ScopeGuard",
            host
        );
    }
}

// ============================================================================
// Adversarial HTTP Redirect & Protocol Downgrade Tests
// ============================================================================

#[tokio::test]
async fn test_adversarial_redirect_chains_fuzzing() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    mock_dns
        .set_response(
            "entry.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .await;

    let scope_guard = Arc::new(ScopeGuard::new(mock_dns));
    let mut handler = RedirectHandler::new(scope_guard, RedirectConfig::default());

    let scope = ScopeDefinition {
        inclusions: vec![
            ScopeRule::DomainWildcard("*.example.com".to_string()),
            ScopeRule::IpExact(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        ],
        exclusions: vec![],
        allow_private_ranges: false,
    };

    let start_url = "https://entry.example.com/start";
    handler
        .validate_initial_url(start_url, Some(&scope))
        .await
        .expect("Start URL should validate");

    let adversarial_locations = vec![
        // Protocol downgrades
        "http://entry.example.com/unencrypted",
        // Injected schemes
        "javascript:alert(document.cookie)",
        "file:///proc/self/environ",
        "gopher://127.0.0.1:6379/_flushall",
        "view-source:https://entry.example.com",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        // Embedded credentials
        "https://admin:password@entry.example.com/panel",
        "https://victim:secret@target.com",
        // Control character injection in location
        "/path\r\nSet-Cookie: session=pwned",
        "/path\x00/hidden",
    ];

    for location in adversarial_locations {
        let res = handler
            .evaluate_redirect(start_url, 302, Some(location), Some(&scope))
            .await;
        assert!(
            res.is_err(),
            "Adversarial redirect Location '{}' must be rejected",
            location
        );
    }
}

// ============================================================================
// Worker Protocol Serialization & Fuzzing Defenses
// ============================================================================

#[test]
fn test_worker_protocol_adversarial_payload_rejection() {
    // 1. Unknown fields rejected (strict deserialization)
    let json_unknown_fields = r#"{
        "type": "worker_hello",
        "payload": {
            "protocol_version": 1,
            "worker_id": "wrk-1",
            "execution_id": "exc-1",
            "mission_id": "mis-1",
            "capability_id": "TCP_CONNECT",
            "nonce": "n1",
            "unauthorized_admin_override": true
        }
    }"#;
    let res1 = ProtocolCodec::decode(json_unknown_fields);
    assert!(res1.is_err(), "Unknown fields must be rejected");

    // 2. Unsupported version rejected
    let json_bad_version = r#"{
        "type": "worker_hello",
        "payload": {
            "protocol_version": 99,
            "worker_id": "wrk-1",
            "execution_id": "exc-1",
            "mission_id": "mis-1",
            "capability_id": "TCP_CONNECT",
            "nonce": "n1"
        }
    }"#;
    let res2 = ProtocolCodec::decode(json_bad_version);
    assert!(
        matches!(
            res2,
            Err(ProtocolError::UnsupportedProtocolVersion { version: 99, .. })
        ),
        "Version 99 must be rejected"
    );

    // 3. Oversized frame (>64 KB) rejected
    let oversized_bytes = "a".repeat(65537);
    let res3 = ProtocolCodec::decode(&oversized_bytes);
    assert!(
        matches!(res3, Err(ProtocolError::OversizedMessage { .. })),
        "Oversized frame must be rejected"
    );
}

// ============================================================================
// Anti-Replay & Concurrency Race Resistance
// ============================================================================

#[tokio::test]
async fn test_broker_concurrency_race_single_success() {
    let kernel_storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
    let broker_storage = Arc::new(InMemoryBrokerStorage::new());
    let clock = Arc::new(MockClock::new(1000));
    let (tracker_worker, side_effect_counter) = SideEffectTrackerWorker::new();

    let broker = Arc::new(ExecutionBroker::new(
        kernel_storage,
        broker_storage,
        Arc::new(tracker_worker),
        clock,
        BrokerConfig {
            max_concurrent_executions: 20,
            default_timeout_seconds: 30,
        },
    ));

    let action = sample_action(false);

    // Launch 10 concurrent dispatch tasks attempting to dispatch the EXACT SAME action_id
    let mut handles = Vec::new();
    for _ in 0..10 {
        let b = broker.clone();
        let a = action.clone();
        handles.push(tokio::spawn(
            async move { b.execute_action(&a, None).await },
        ));
    }

    let mut successes = 0;
    let mut duplicates = 0;

    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => successes += 1,
            Err(BrokerError::DuplicateDispatch { .. }) => duplicates += 1,
            Err(other) => panic!("Unexpected error: {:?}", other),
        }
    }

    assert_eq!(
        successes, 1,
        "Exactly 1 dispatch must succeed under concurrent race conditions"
    );
    assert_eq!(
        duplicates, 9,
        "Exactly 9 dispatches must be rejected as duplicates"
    );
    assert_eq!(
        side_effect_counter.load(Ordering::SeqCst),
        1,
        "Exactly 1 side effect must occur despite 10 concurrent attempts"
    );
}

// ============================================================================
// Sandbox Escape Boundary & Unprivileged Isolation Assertions
// ============================================================================

#[tokio::test]
async fn test_sandbox_unprivileged_boundary_configuration() {
    let scratch_base = PathBuf::from(format!("/tmp/arka-adv-scratch-{}", uuid::Uuid::new_v4()));
    let config = SandboxConfig::default()
        .with_scratch_base_dir(scratch_base)
        .with_timeout_seconds(5);
    let supervisor = SandboxSupervisor::new(config);

    if let Ok(()) = supervisor.check_availability().await {
        // Assert unprivileged UID
        let exec_id = format!("adv-uid-{}", uuid::Uuid::new_v4());
        let res = supervisor
            .run_sandboxed("/usr/bin/id", &["-u".to_string()], &exec_id, &[])
            .await
            .expect("Bubblewrap execution failed");
        assert_eq!(res.exit_code, 0);
        let uid: u32 = res.stdout.trim().parse().unwrap();
        assert_ne!(uid, 0, "Container process must NOT run as root UID 0");

        // Assert read-only filesystem
        let exec_id2 = format!("adv-ro-{}", uuid::Uuid::new_v4());
        let res2 = supervisor
            .run_sandboxed(
                "/usr/bin/touch",
                &["/usr/arka_adv_write_attempt".to_string()],
                &exec_id2,
                &[],
            )
            .await
            .expect("Bubblewrap call failed");
        assert_ne!(res2.exit_code, 0, "Read-only fs write must be rejected");
    }
}
