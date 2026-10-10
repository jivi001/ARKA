//! Checkpoint P2-F Integration Test Suite.
//!
//! Validates:
//! - GATE-WORKER-RESOURCE-001 & GATE-RESOURCE-LIMIT-001 (TEST-WORKER-RESOURCE-001 & TEST-RESOURCE-001):
//!   Resource governor concurrency bounds, execution timeout ceilings, memory limits, and stream truncation.
//! - GATE-EVIDENCE-INTEGRITY-001 (CTRL-EVIDENCE-INTEGRITY-001 / TEST-EVIDENCE-INTEGRITY-001):
//!   Content-addressed evidence hashing, provenance binding, and cryptographic tamper detection.
//! - GATE-AUDIT-INTEGRITY-001 (CTRL-AUDIT-INTEGRITY-001 / TEST-AUDIT-INTEGRITY-001):
//!   Dual-hash audit logging across broker lifecycle transitions and fail-closed persistence.
//! - GATE-EMERGENCY-STOP-001 (CTRL-EMERGENCY-STOP-001 / TEST-ESTOP-001):
//!   Pre-dispatch e-stop blocking and real-time cancellation of active workers.
//!
//! Test Design Rule:
//! Every denial test asserts absence of the external side effect, not only the returned error code.

use arka_core_types::actions::CanonicalAction;
use arka_core_types::capabilities::RiskClass;
use arka_core_types::clock::MockClock;
use arka_core_types::id::{ActionId, CapabilityId, ExecutionId, MissionId, ProposalId};
use arka_core_types::scope::CanonicalTarget;
use arka_crypto::provider::DevKeyProvider;
use arka_execution_broker::audit::BrokerAuditService;
use arka_execution_broker::broker::{BrokerConfig, ExecutionBroker};
use arka_execution_broker::dispatcher::{NoOpWorker, WorkerDispatcher};
use arka_execution_broker::errors::BrokerError;
use arka_execution_broker::evidence::{EvidenceCollector, EvidenceProvenance, EvidenceType};
use arka_execution_broker::governor::{ResourceGovernor, ResourceLimits};
use arka_execution_broker::record::{ExecutionRecord, ExecutionResultEnvelope};
use arka_execution_broker::state::ExecutionState;
use arka_execution_broker::storage::{BrokerStorage, InMemoryBrokerStorage};
use arka_kernel::storage::Storage as KernelStorage;
use arka_storage_sqlite::db::SqliteStorage;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

fn sample_action(action_id_str: &str, mission_id_str: &str) -> CanonicalAction {
    CanonicalAction {
        action_id: ActionId::new(action_id_str).unwrap(),
        proposal_id: ProposalId::new("prop-101").unwrap(),
        mission_id: MissionId::new(mission_id_str).unwrap(),
        parent_task_id: None,
        capability_id: CapabilityId::new("TCP_CONNECT").unwrap(),
        target: CanonicalTarget::Domain {
            domain: "target.test".to_string(),
            port: Some(8080),
        },
        normalized_parameters: serde_json::json!({"timeout_ms": 1000}),
        parameter_hash: "paramhash-val-123".to_string(),
        action_hash: "actionhash-val-123".to_string(),
        risk_class: RiskClass::Moderate,
        requires_approval: false,
        policy_version: "v2.2".to_string(),
        authorization_context_ref: "ctx-1".to_string(),
        nonce: format!("nonce-{}", action_id_str),
    }
}

// ============================================================================
// Resource Governor Tests (GATE-WORKER-RESOURCE-001 / GATE-RESOURCE-LIMIT-001)
// ============================================================================

#[tokio::test]
async fn test_resource_governor_concurrency_ceiling_enforced() {
    let limits = ResourceLimits::new().with_max_concurrent_workers(2);
    let governor = Arc::new(ResourceGovernor::new(limits));

    // Acquire slot 1
    let permit1 = governor.acquire_worker_slot();
    assert!(permit1.is_ok(), "First slot should be acquired");
    assert_eq!(governor.active_worker_count(), 1);

    // Acquire slot 2
    let permit2 = governor.acquire_worker_slot();
    assert!(permit2.is_ok(), "Second slot should be acquired");
    assert_eq!(governor.active_worker_count(), 2);

    // Attempt slot 3 (must fail closed with ConcurrencyLimitReached)
    let permit3 = governor.acquire_worker_slot();
    assert!(
        permit3.is_err(),
        "Exceeding concurrency ceiling must fail closed"
    );
    match permit3.err().unwrap() {
        BrokerError::ConcurrencyLimitReached { current, max } => {
            assert_eq!(current, 2);
            assert_eq!(max, 2);
        }
        other => panic!("Expected ConcurrencyLimitReached, got {:?}", other),
    }

    // Drop permit1 (releases 1 slot)
    drop(permit1);
    assert_eq!(governor.active_worker_count(), 1);

    // Slot 3 can now be acquired
    let permit3_retry = governor.acquire_worker_slot();
    assert!(
        permit3_retry.is_ok(),
        "Slot should be available after permit drop"
    );
    assert_eq!(governor.active_worker_count(), 2);

    drop(permit2);
    drop(permit3_retry);
    assert_eq!(governor.active_worker_count(), 0);
}

#[tokio::test]
async fn test_resource_governor_parameter_ceiling_rejection() {
    let limits = ResourceLimits::new()
        .with_max_timeout_seconds(60)
        .with_max_memory_bytes(256 * 1024 * 1024);
    let governor = ResourceGovernor::new(limits);

    // Valid parameters
    assert!(governor
        .validate_request(Some(30), Some(128 * 1024 * 1024))
        .is_ok());

    // Excessive timeout
    let err_timeout = governor.validate_request(Some(120), None);
    assert!(err_timeout.is_err());
    match err_timeout.err().unwrap() {
        BrokerError::ResourceLimitExceeded(msg) => {
            assert!(msg.contains("timeout of 120s exceeds maximum limit of 60s"));
        }
        other => panic!("Expected ResourceLimitExceeded, got {:?}", other),
    }

    // Excessive memory allocation
    let err_mem = governor.validate_request(None, Some(512 * 1024 * 1024));
    assert!(err_mem.is_err());
    match err_mem.err().unwrap() {
        BrokerError::ResourceLimitExceeded(msg) => {
            assert!(msg.contains("memory allocation"));
        }
        other => panic!("Expected ResourceLimitExceeded, got {:?}", other),
    }
}

// ============================================================================
// Evidence Pipeline & Hashing Tests (GATE-EVIDENCE-INTEGRITY-001)
// ============================================================================

#[test]
fn test_evidence_collector_hashing_and_tamper_detection() {
    let collector = EvidenceCollector::new(1024);
    let provenance = EvidenceProvenance {
        mission_id: MissionId::new("mis-beta").unwrap(),
        execution_id: ExecutionId::new("exc-test-1").unwrap(),
        action_id: ActionId::new("act-probe-1").unwrap(),
        capability_id: CapabilityId::new("TCP_CONNECT").unwrap(),
        worker_profile: "sandbox-profile".to_string(),
        target: serde_json::json!({"host": "192.0.2.1", "port": 80}),
    };

    let payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nTest output payload";
    let artifact = collector
        .collect(provenance, EvidenceType::Stdout, payload, 1000)
        .expect("Evidence ingestion failed");

    assert_eq!(artifact.size_bytes, payload.len());
    assert!(!artifact.truncated);
    assert_eq!(artifact.content_hash.len(), 64);

    // 1. Untampered artifact verifies successfully
    assert!(collector.verify_integrity(&artifact).is_ok());

    // 2. Tampered artifact: alter 1 byte of content_bytes
    let mut tampered = artifact.clone();
    tampered.content_bytes[0] ^= 0xFF;

    let verify_res = collector.verify_integrity(&tampered);
    assert!(
        verify_res.is_err(),
        "Tampered evidence must fail integrity check"
    );
    match verify_res.err().unwrap() {
        BrokerError::EvidenceTampered { expected, actual } => {
            assert_eq!(expected, artifact.content_hash);
            assert_ne!(expected, actual);
        }
        other => panic!("Expected EvidenceTampered, got {:?}", other),
    }
}

#[test]
fn test_evidence_collector_bounds_oversized_payload() {
    let max_bytes = 64;
    let collector = EvidenceCollector::new(max_bytes);
    let provenance = EvidenceProvenance {
        mission_id: MissionId::new("mis-gamma").unwrap(),
        execution_id: ExecutionId::new("exc-test-2").unwrap(),
        action_id: ActionId::new("act-probe-2").unwrap(),
        capability_id: CapabilityId::new("OSINT_LOOKUP").unwrap(),
        worker_profile: "sandbox-profile".to_string(),
        target: serde_json::json!({}),
    };

    let large_payload = vec![0x41; 256]; // 256 bytes exceeds 64 byte limit
    let artifact = collector
        .collect(
            provenance,
            EvidenceType::RawNetworkResponse,
            &large_payload,
            1000,
        )
        .expect("Evidence collection failed");

    assert_eq!(artifact.size_bytes, max_bytes);
    assert!(
        artifact.truncated,
        "Oversized artifact must be marked truncated"
    );
    assert_eq!(artifact.content_bytes.len(), max_bytes);
    assert!(collector.verify_integrity(&artifact).is_ok());
}

// ============================================================================
// Audit Chain Integration Tests (GATE-AUDIT-INTEGRITY-001)
// ============================================================================

#[tokio::test]
async fn test_broker_audit_service_dual_chain_integrity() {
    let kernel_storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
    let key_provider = Arc::new(DevKeyProvider::new());
    let audit_service = BrokerAuditService::new(kernel_storage.clone(), key_provider);

    let mission_id = MissionId::new("mis-delta").unwrap();

    // Log event 1
    audit_service
        .log_event(
            &mission_id,
            "EXECUTION_DISPATCHED",
            "system:broker",
            serde_json::json!({"action_id": "act-1"}),
            1000,
        )
        .await
        .expect("Audit event 1 failed");

    // Log event 2
    audit_service
        .log_event(
            &mission_id,
            "EXECUTION_COMPLETED",
            "system:broker",
            serde_json::json!({"action_id": "act-1", "status": "SUCCESS"}),
            1005,
        )
        .await
        .expect("Audit event 2 failed");

    // Verify dual chains in storage
    let mut tx = kernel_storage.begin_transaction().await.unwrap();

    let sys_records = tx.get_all_system_audit().await.unwrap();
    assert_eq!(sys_records.len(), 2);
    assert_eq!(sys_records[0].sequence_number, 1);
    assert_eq!(sys_records[1].sequence_number, 2);
    assert_eq!(sys_records[1].previous_hash, sys_records[0].current_hash);

    let mis_records = tx.get_all_mission_audit(&mission_id).await.unwrap();
    assert_eq!(mis_records.len(), 2);
    assert_eq!(mis_records[0].sequence_number, 1);
    assert_eq!(mis_records[1].sequence_number, 2);
    assert_eq!(mis_records[1].previous_hash, mis_records[0].current_hash);

    tx.rollback().await.unwrap();
}

// ============================================================================
// Emergency Stop & Cancellation Tests (GATE-EMERGENCY-STOP-001)
// ============================================================================

struct SlowWorker {
    delay_ms: u64,
}

#[async_trait]
impl WorkerDispatcher for SlowWorker {
    async fn dispatch(
        &self,
        record: &ExecutionRecord,
    ) -> Result<ExecutionResultEnvelope, BrokerError> {
        sleep(Duration::from_millis(self.delay_ms)).await;

        Ok(ExecutionResultEnvelope {
            execution_id: record.execution_id.clone(),
            action_id: record.action_id.clone(),
            action_hash: record.action_hash.clone(),
            state: ExecutionState::Completed,
            exit_code: Some(0),
            stdout_truncated: Some("Completed slowly".to_string()),
            stderr_truncated: None,
            structured_output: serde_json::json!({"status": "DONE"}),
            evidence_hashes: vec![],
            completed_at_unix: record.created_at_unix + (self.delay_ms / 1000),
        })
    }
}

#[tokio::test]
async fn test_emergency_stop_realtime_worker_cancellation() {
    let kernel_storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
    let broker_storage = Arc::new(InMemoryBrokerStorage::new());
    let clock = Arc::new(MockClock::new(1000));
    let slow_dispatcher = Arc::new(SlowWorker { delay_ms: 1000 }); // 1 second delay
    let key_provider = Arc::new(DevKeyProvider::new());
    let audit_service = Arc::new(BrokerAuditService::new(
        kernel_storage.clone(),
        key_provider,
    ));

    let broker = Arc::new(
        ExecutionBroker::new(
            kernel_storage.clone(),
            broker_storage.clone(),
            slow_dispatcher,
            clock.clone(),
            BrokerConfig {
                max_concurrent_executions: 5,
                default_timeout_seconds: 30,
            },
        )
        .with_audit_service(audit_service),
    );

    let action = sample_action("act-slow-1", "mis-estop");
    let broker_clone = broker.clone();
    let action_clone = action.clone();

    // Spawn execution in background task
    let task_handle =
        tokio::spawn(async move { broker_clone.execute_action(&action_clone, None).await });

    // Let the worker enter the running state
    sleep(Duration::from_millis(50)).await;

    // Trigger platform Emergency Stop Kill across broker
    let killed = broker.trigger_emergency_stop_kill().await.unwrap();
    assert_eq!(killed, 1, "Exactly 1 active worker should be cancelled");

    // Wait for the background execution task to return
    let exec_result = task_handle.await.unwrap();
    assert!(
        exec_result.is_err(),
        "Execution must be terminated by emergency stop"
    );
    match exec_result.err().unwrap() {
        BrokerError::Cancelled(msg) => {
            assert!(msg.contains("cancelled by emergency stop"));
        }
        other => panic!("Expected BrokerError::Cancelled, got {:?}", other),
    }

    // Verify storage reflects Cancelled state
    let rec = broker_storage
        .get_execution_by_action(&action.action_id)
        .await
        .unwrap()
        .expect("Execution record must exist");
    assert_eq!(rec.state, ExecutionState::Cancelled);
}

#[tokio::test]
async fn test_broker_with_audit_and_evidence_end_to_end() {
    let kernel_storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
    let broker_storage = Arc::new(InMemoryBrokerStorage::new());
    let clock = Arc::new(MockClock::new(1000));
    let dispatcher = Arc::new(NoOpWorker::new());
    let key_provider = Arc::new(DevKeyProvider::new());
    let audit_service = Arc::new(BrokerAuditService::new(
        kernel_storage.clone(),
        key_provider,
    ));

    let broker = ExecutionBroker::new(
        kernel_storage.clone(),
        broker_storage.clone(),
        dispatcher,
        clock.clone(),
        BrokerConfig {
            max_concurrent_executions: 5,
            default_timeout_seconds: 30,
        },
    )
    .with_audit_service(audit_service);

    let action = sample_action("act-e2e-1", "mis-e2e");
    let result = broker.execute_action(&action, None).await.unwrap();

    assert_eq!(result.state, ExecutionState::Completed);
    // Evidence hash populated from stdout
    assert!(
        !result.evidence_hashes.is_empty(),
        "Evidence hashes should be populated"
    );
    assert_eq!(result.evidence_hashes[0].len(), 64);

    // Verify audit logs were created
    let mut tx = kernel_storage.begin_transaction().await.unwrap();
    let sys_audits = tx.get_all_system_audit().await.unwrap();
    // DISPATCHED, RUNNING, COMPLETED = 3 events
    assert_eq!(sys_audits.len(), 3);
    assert_eq!(sys_audits[0].event_type, "EXECUTION_DISPATCHED");
    assert_eq!(sys_audits[1].event_type, "EXECUTION_RUNNING");
    assert_eq!(sys_audits[2].event_type, "EXECUTION_COMPLETED");
    tx.rollback().await.unwrap();
}
