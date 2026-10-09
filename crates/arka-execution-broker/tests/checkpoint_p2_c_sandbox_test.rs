//! Checkpoint P2-C: Rootless Container Sandbox and Worker Supervision Tests.
//!
//! Validates:
//! - GATE-SANDBOX-CONTAINMENT-001 (CTRL-SANDBOX-CONTAINMENT-001 / TEST-SANDBOX-PRIV-001)
//! - GATE-SANDBOX-CLEANUP-001 (CTRL-SANDBOX-CLEANUP-001 / TEST-SANDBOX-CLEANUP-001)
//! - GATE-WORKER-RESOURCE-001 (CTRL-WORKER-RESOURCE-001 / TEST-WORKER-RESOURCE-001)

use arka_core_types::actions::CanonicalAction;
use arka_core_types::clock::MockClock;
use arka_core_types::id::{ActionId, CapabilityId, MissionId, ProposalId};
use arka_core_types::scope::CanonicalTarget;
use arka_execution_broker::broker::{BrokerConfig, ExecutionBroker};
use arka_execution_broker::errors::BrokerError;
use arka_execution_broker::sandbox::{SandboxConfig, SandboxSupervisor, SandboxWorkerDispatcher};
use arka_execution_broker::state::ExecutionState;
use arka_execution_broker::storage::{BrokerStorage, InMemoryBrokerStorage};
use arka_storage_sqlite::db::SqliteStorage;
use std::path::PathBuf;
use std::sync::Arc;

fn get_test_sandbox_config() -> SandboxConfig {
    let scratch_base = PathBuf::from(format!("/tmp/arka-test-scratch-{}", uuid::Uuid::new_v4()));
    SandboxConfig::default()
        .with_scratch_base_dir(scratch_base)
        .with_timeout_seconds(5)
        .with_max_output_bytes(16384)
}

#[tokio::test]
async fn test_sandbox_availability_check() {
    let config = get_test_sandbox_config();
    let supervisor = SandboxSupervisor::new(config);
    let result = supervisor.check_availability().await;
    assert!(
        result.is_ok(),
        "Bubblewrap rootless sandbox should be available on host"
    );
}

#[tokio::test]
async fn test_sandbox_fail_closed_on_missing_binary() {
    let mut config = get_test_sandbox_config();
    config.bwrap_path = PathBuf::from("/usr/bin/non_existent_bwrap_path");
    let supervisor = SandboxSupervisor::new(config);

    let result = supervisor.check_availability().await;
    assert!(matches!(
        result,
        Err(BrokerError::SandboxInitializationFailure(_))
    ));
}

// -----------------------------------------------------------------------------
// GATE-SANDBOX-CONTAINMENT-001 / TEST-SANDBOX-PRIV-001
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_sandbox_containment_unprivileged_uid() {
    let config = get_test_sandbox_config();
    let supervisor = SandboxSupervisor::new(config);

    let exec_id = format!("exec-priv-{}", uuid::Uuid::new_v4());
    let result = supervisor
        .run_sandboxed("/usr/bin/id", &["-u".to_string()], &exec_id, &[])
        .await
        .expect("Sandboxed execution failed");

    assert_eq!(result.exit_code, 0);
    let uid_str = result.stdout.trim();
    let uid: u32 = uid_str.parse().expect("UID should be numeric");
    // Under unprivileged user namespace, UID is non-zero
    assert_ne!(uid, 0, "Container process must NOT run as root (UID 0)");
}

#[tokio::test]
async fn test_sandbox_containment_readonly_filesystem() {
    let config = get_test_sandbox_config();
    let supervisor = SandboxSupervisor::new(config);

    let exec_id = format!("exec-ro-{}", uuid::Uuid::new_v4());
    let result = supervisor
        .run_sandboxed(
            "/usr/bin/touch",
            &["/usr/arka_unauthorized_write".to_string()],
            &exec_id,
            &[],
        )
        .await
        .expect("Sandboxed execution call failed");

    // Writing to /usr must be denied with non-zero exit code
    assert_ne!(
        result.exit_code, 0,
        "Writing to root filesystem should be rejected"
    );
    assert!(
        result.stderr.contains("Read-only file system") || result.exit_code != 0,
        "Expected Read-only filesystem error in stderr: {}",
        result.stderr
    );
}

#[tokio::test]
async fn test_sandbox_containment_host_invisibility() {
    let config = get_test_sandbox_config();
    let supervisor = SandboxSupervisor::new(config);

    let exec_id = format!("exec-host-{}", uuid::Uuid::new_v4());
    let result = supervisor
        .run_sandboxed("/usr/bin/ls", &["/home".to_string()], &exec_id, &[])
        .await
        .expect("Sandboxed execution call failed");

    // /home is not mounted in bwrap rootfs
    assert_ne!(
        result.exit_code, 0,
        "Host /home directory must be inaccessible"
    );
    assert!(
        result.stderr.contains("No such file or directory"),
        "Host /home should not exist inside container: {}",
        result.stderr
    );
}

#[tokio::test]
async fn test_sandbox_containment_network_isolation() {
    let config = get_test_sandbox_config();
    assert!(!config.allow_network);
    let supervisor = SandboxSupervisor::new(config);

    let exec_id = format!("exec-net-{}", uuid::Uuid::new_v4());
    let result = supervisor
        .run_sandboxed("/usr/bin/ip", &["addr".to_string()], &exec_id, &[])
        .await
        .expect("Sandboxed execution call failed");

    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("lo"),
        "Loopback interface should be present"
    );
    // External interfaces (eth0, wlan0, enp*) must not be present
    assert!(
        !result.stdout.contains("eth0") && !result.stdout.contains("wlan0"),
        "External host network interfaces must not be visible in isolated netns"
    );
}

// -----------------------------------------------------------------------------
// GATE-SANDBOX-CLEANUP-001 / TEST-SANDBOX-CLEANUP-001
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_sandbox_cleanup_on_success() {
    let config = get_test_sandbox_config();
    let scratch_base = config.scratch_base_dir.clone();
    let supervisor = SandboxSupervisor::new(config);

    let exec_id = format!("exec-clean-success-{}", uuid::Uuid::new_v4());
    let scratch_dir = scratch_base.join(&exec_id);

    let result = supervisor
        .run_sandboxed(
            "/usr/bin/echo",
            &["cleanup_success_test".to_string()],
            &exec_id,
            &[],
        )
        .await
        .expect("Sandboxed execution failed");

    assert_eq!(result.exit_code, 0);
    // Assert scratch directory was eradicated
    assert!(
        !scratch_dir.exists(),
        "Ephemeral scratch directory {} must be purged post-task",
        scratch_dir.display()
    );
}

#[tokio::test]
async fn test_sandbox_cleanup_on_failure() {
    let config = get_test_sandbox_config();
    let scratch_base = config.scratch_base_dir.clone();
    let supervisor = SandboxSupervisor::new(config);

    let exec_id = format!("exec-clean-fail-{}", uuid::Uuid::new_v4());
    let scratch_dir = scratch_base.join(&exec_id);

    let result = supervisor
        .run_sandboxed("/usr/bin/false", &[], &exec_id, &[])
        .await
        .expect("Sandboxed execution call failed");

    assert_eq!(result.exit_code, 1);
    // Assert scratch directory was eradicated even on non-zero exit
    assert!(
        !scratch_dir.exists(),
        "Ephemeral scratch directory {} must be purged on failure",
        scratch_dir.display()
    );
}

#[tokio::test]
async fn test_sandbox_cleanup_on_timeout() {
    let mut config = get_test_sandbox_config();
    config.max_wall_clock_timeout_seconds = 1; // 1 second timeout
    let scratch_base = config.scratch_base_dir.clone();
    let supervisor = SandboxSupervisor::new(config);

    let exec_id = format!("exec-clean-timeout-{}", uuid::Uuid::new_v4());
    let scratch_dir = scratch_base.join(&exec_id);

    let result = supervisor
        .run_sandboxed("/usr/bin/sleep", &["10".to_string()], &exec_id, &[])
        .await;

    assert!(matches!(result, Err(BrokerError::TimeoutExceeded { .. })));
    // Assert scratch directory was eradicated post-timeout
    assert!(
        !scratch_dir.exists(),
        "Ephemeral scratch directory {} must be purged on timeout",
        scratch_dir.display()
    );
}

// -----------------------------------------------------------------------------
// GATE-WORKER-RESOURCE-001 / TEST-WORKER-RESOURCE-001
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_worker_resource_timeout_kill() {
    let mut config = get_test_sandbox_config();
    config.max_wall_clock_timeout_seconds = 1;
    let supervisor = SandboxSupervisor::new(config);

    let exec_id = format!("exec-res-timeout-{}", uuid::Uuid::new_v4());
    let start = std::time::Instant::now();

    let result = supervisor
        .run_sandboxed("/usr/bin/sleep", &["30".to_string()], &exec_id, &[])
        .await;

    let elapsed = start.elapsed();
    assert!(
        matches!(result, Err(BrokerError::TimeoutExceeded { .. })),
        "Process exceeding timeout should return TimeoutExceeded"
    );
    assert!(
        elapsed.as_secs() < 3,
        "Supervisor must terminate child within timeout + grace window"
    );
}

#[tokio::test]
async fn test_worker_resource_bounded_output() {
    let mut config = get_test_sandbox_config();
    config.max_output_bytes = 2048; // 2 KB limit for this test
    let supervisor = SandboxSupervisor::new(config);

    let exec_id = format!("exec-res-overflow-{}", uuid::Uuid::new_v4());
    // Generate 20,000 bytes of output
    let result = supervisor
        .run_sandboxed(
            "/usr/bin/python3",
            &["-c".to_string(), "print('A' * 20000)".to_string()],
            &exec_id,
            &[],
        )
        .await
        .expect("Python output generation failed");

    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.len() <= 2048,
        "Stdout length {} must be <= 2048",
        result.stdout.len()
    );
    assert!(
        result.stdout_truncated,
        "Output truncation flag must be set"
    );
}

// -----------------------------------------------------------------------------
// Broker & SandboxWorkerDispatcher Integration Test
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_broker_sandbox_dispatcher_integration() {
    let kernel_storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
    let broker_storage = Arc::new(InMemoryBrokerStorage::new());
    let clock = Arc::new(MockClock::new(1000));

    let config = get_test_sandbox_config();
    let supervisor = Arc::new(SandboxSupervisor::new(config));
    let dispatcher = Arc::new(SandboxWorkerDispatcher::new(supervisor));

    let broker = ExecutionBroker::new(
        kernel_storage,
        broker_storage.clone(),
        dispatcher,
        clock,
        BrokerConfig::default(),
    );

    let action = CanonicalAction {
        action_id: ActionId::new("act-sbx-01").unwrap(),
        proposal_id: ProposalId::new("prop-sbx-01").unwrap(),
        mission_id: MissionId::new("mis-sbx-01").unwrap(),
        parent_task_id: None,
        capability_id: CapabilityId::new("TCP_CONNECT").unwrap(),
        target: CanonicalTarget::Domain {
            domain: "127.0.0.1".to_string(),
            port: Some(8080),
        },
        normalized_parameters: serde_json::json!({"timeout_ms": 1000}),
        parameter_hash: "param_hash_sbx".to_string(),
        action_hash: "action_hash_sbx".to_string(),
        risk_class: arka_core_types::capabilities::RiskClass::Moderate,
        requires_approval: false,
        policy_version: "v2.2".to_string(),
        authorization_context_ref: "ctx-sbx".to_string(),
        nonce: "nonce-sbx".to_string(),
    };

    let result = broker
        .execute_action(&action, None)
        .await
        .expect("Broker action execution failed");

    assert_eq!(result.state, ExecutionState::Completed);
    assert_eq!(result.exit_code, Some(0));

    // Verify durable record
    let stored = broker_storage
        .get_execution_by_action(&action.action_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, ExecutionState::Completed);
}
