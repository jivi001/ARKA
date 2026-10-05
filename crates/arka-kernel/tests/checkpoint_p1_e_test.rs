//! Checkpoint P1-E Security Test Suite: Audit Chains, Emergency Stop & Atomic Invariants
//!
//! Validates:
//! - Dual Hash Chains: Per-Mission & System (Section 23, Section 24, INV-011)
//! - Chain Verification & Tamper-Evidence (Payload mutation, Chain break, Signature forgery, Sequence gaps)
//! - Atomic Transaction Commit: Decision + Replay + Approval + Audit Append commit together (INV-011)
//! - Emergency Stop Authoritative Denial (INV-010, Section 25)
//! - Emergency Stop Monotonic Restart Persistence (Survives process/storage reboot)
//! - Emergency Stop Operator Clear & Service Restoration (Section 26)

use arka_core_types::clock::MockClock;
use arka_core_types::errors::KernelSecurityError;
use arka_core_types::id::{MissionId, OperatorId};
use arka_core_types::mission::{Mission, MissionState};
use arka_core_types::scope::{ScopeDefinition, ScopeRule};
use arka_core_types::subject::{AuthenticatedContext, Subject};
use arka_crypto::provider::DevKeyProvider;
use arka_kernel::actions::ActionNormalizer;
use arka_kernel::audit::AuditChainEngine;
use arka_kernel::capabilities::StandardCapabilityRegistry;
use arka_kernel::emergency_stop::EmergencyStopService;
use arka_kernel::policy::AuthorizationEngine;
use arka_kernel::Storage;
use arka_storage_sqlite::SqliteStorage;
use serde_json::json;
use std::sync::Arc;

async fn setup_test_env(
    clock_time: u64,
) -> (
    Arc<SqliteStorage>,
    Arc<MockClock>,
    Arc<DevKeyProvider>,
    Arc<AuditChainEngine>,
    Arc<ActionNormalizer>,
    Arc<AuthorizationEngine>,
    Arc<EmergencyStopService>,
) {
    let storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
    let clock = Arc::new(MockClock::new(clock_time));
    let key_provider = Arc::new(DevKeyProvider::new());
    let audit_engine = Arc::new(AuditChainEngine::new(key_provider.clone()));
    let registry = Arc::new(StandardCapabilityRegistry::new());
    let normalizer = Arc::new(ActionNormalizer::new(registry));
    let engine = Arc::new(AuthorizationEngine::with_audit(
        storage.clone(),
        clock.clone(),
        audit_engine.clone(),
    ));
    let estop = Arc::new(EmergencyStopService::new(storage.clone()).await.unwrap());

    (
        storage,
        clock,
        key_provider,
        audit_engine,
        normalizer,
        engine,
        estop,
    )
}

async fn create_active_mission(storage: &SqliteStorage, mission_id: &str, now: u64) {
    let mut tx = storage.begin_transaction().await.unwrap();
    let mut m = Mission::new(
        MissionId::new(mission_id).unwrap(),
        "Test Mission",
        "scope-e",
        OperatorId::new("opr-lead").unwrap(),
        now,
    );
    m.state = MissionState::Active;
    tx.save_mission(&m).await.unwrap();
    tx.commit().await.unwrap();
}

fn create_auth_context(mission_id: &str, caps: Vec<&str>) -> AuthenticatedContext {
    AuthenticatedContext {
        subject: Subject::Operator(OperatorId::new("opr-sec-lead").unwrap()),
        mission_id: MissionId::new(mission_id).unwrap(),
        parent_task_id: None,
        capabilities: caps
            .into_iter()
            .map(|c| arka_core_types::id::CapabilityId::new(c).unwrap())
            .collect(),
        scope_ref: "scope-p1e".to_string(),
        token_id: arka_core_types::id::TokenId::new("tok-p1e-test").unwrap(),
        issued_at_unix: 1000,
        expires_at_unix: 2000,
        parent_token_id: None,
    }
}

// ---------------------------------------------------------------------------
// TEST-AUDIT-* : Hash Chains, Cryptographic Signatures & Tamper-Evidence
// ---------------------------------------------------------------------------

#[test]
fn test_audit_001_valid_chain_monotonic_growth() {
    let key_provider = Arc::new(DevKeyProvider::new());
    let engine = AuditChainEngine::new(key_provider);

    let mut records = Vec::new();

    // Create 5 sequential system audit records
    for i in 1..=5 {
        let prev = records.last();
        let rec = engine
            .create_record(
                &format!("evt-sys-{}", i),
                prev,
                None, // System chain
                "TEST_EVENT",
                "opr-01",
                json!({ "iteration": i }),
                1000 + i as u64,
            )
            .unwrap();
        records.push(rec);
    }

    assert_eq!(records.len(), 5);
    for (idx, r) in records.iter().enumerate() {
        assert_eq!(r.sequence_number, (idx + 1) as u64);
    }

    // Verify entire chain from genesis to tip
    assert!(engine.verify_chain(&records, None).is_ok());
}

#[test]
fn test_audit_002_per_mission_chain_and_isolation() {
    let key_provider = Arc::new(DevKeyProvider::new());
    let engine = AuditChainEngine::new(key_provider);

    let mis_a = MissionId::new("mis-audit-alpha").unwrap();
    let mis_b = MissionId::new("mis-audit-bravo").unwrap();

    let rec_a1 = engine
        .create_record(
            "evt-a-1",
            None,
            Some(&mis_a),
            "MISSION_START",
            "opr-lead",
            json!({ "mission": "alpha" }),
            1000,
        )
        .unwrap();

    let rec_b1 = engine
        .create_record(
            "evt-b-1",
            None,
            Some(&mis_b),
            "MISSION_START",
            "opr-lead",
            json!({ "mission": "bravo" }),
            1000,
        )
        .unwrap();

    // Both chains have different genesis hashes bound to their mission ID
    assert_ne!(rec_a1.previous_hash, rec_b1.previous_hash);
    assert_ne!(rec_a1.current_hash, rec_b1.current_hash);

    // Alpha chain verifies for Alpha
    assert!(engine
        .verify_chain(std::slice::from_ref(&rec_a1), Some(&mis_a))
        .is_ok());
    // Bravo chain verifies for Bravo
    assert!(engine
        .verify_chain(std::slice::from_ref(&rec_b1), Some(&mis_b))
        .is_ok());

    // Cross-mission verification fails (INV-009)
    assert!(matches!(
        engine.verify_chain(std::slice::from_ref(&rec_a1), Some(&mis_b)),
        Err(KernelSecurityError::AuditChainTampered(_))
    ));
}

#[test]
fn test_audit_003_tamper_payload_detected() {
    let key_provider = Arc::new(DevKeyProvider::new());
    let engine = AuditChainEngine::new(key_provider);

    let mut records = Vec::new();
    for i in 1..=3 {
        let prev = records.last();
        let rec = engine
            .create_record(
                &format!("evt-{}", i),
                prev,
                None,
                "EVENT",
                "opr-01",
                json!({ "state": "normal" }),
                1000 + i as u64,
            )
            .unwrap();
        records.push(rec);
    }

    // Tamper with record 2 details
    records[1].details = json!({ "state": "maliciously_altered" });

    // Verification must detect hash mismatch and fail
    let err = engine.verify_chain(&records, None).unwrap_err();
    assert!(matches!(err, KernelSecurityError::AuditChainTampered(_)));
}

#[test]
fn test_audit_004_tamper_previous_hash_detected() {
    let key_provider = Arc::new(DevKeyProvider::new());
    let engine = AuditChainEngine::new(key_provider);

    let mut records = Vec::new();
    for i in 1..=3 {
        let prev = records.last();
        let rec = engine
            .create_record(
                &format!("evt-{}", i),
                prev,
                None,
                "EVENT",
                "opr-01",
                json!({ "val": i }),
                1000 + i as u64,
            )
            .unwrap();
        records.push(rec);
    }

    // Break the hash chain link at record 3
    records[2].previous_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    let err = engine.verify_chain(&records, None).unwrap_err();
    assert!(matches!(err, KernelSecurityError::AuditChainTampered(_)));
}

#[test]
fn test_audit_005_tamper_signature_detected() {
    let key_provider = Arc::new(DevKeyProvider::new());
    let engine = AuditChainEngine::new(key_provider);

    let rec = engine
        .create_record("evt-sig-1", None, None, "EVENT", "opr-01", json!({}), 1000)
        .unwrap();

    let mut tampered = rec;
    // Corrupt the signature hex
    tampered.signature = hex::encode(vec![0xAA; 64]);

    let err = engine.verify_chain(&[tampered], None).unwrap_err();
    assert!(matches!(err, KernelSecurityError::AuditChainTampered(_)));
}

#[test]
fn test_audit_006_sequence_gap_detected() {
    let key_provider = Arc::new(DevKeyProvider::new());
    let engine = AuditChainEngine::new(key_provider);

    let mut records = Vec::new();
    for i in 1..=3 {
        let prev = records.last();
        let rec = engine
            .create_record(
                &format!("evt-{}", i),
                prev,
                None,
                "EVENT",
                "opr-01",
                json!({}),
                1000 + i as u64,
            )
            .unwrap();
        records.push(rec);
    }

    // Remove middle record to create sequence gap 1 -> 3
    records.remove(1);

    let err = engine.verify_chain(&records, None).unwrap_err();
    assert!(matches!(err, KernelSecurityError::AuditChainTampered(_)));
}

// ---------------------------------------------------------------------------
// TEST-AUDIT-AUTHZ-* : Authorization Atomic Dual-Audit Invariant (INV-011)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_audit_authz_001_atomic_dual_chain_appended_on_allow() {
    let (storage, _clock, _kp, audit_engine, normalizer, engine, _estop) =
        setup_test_env(1000).await;
    create_active_mission(&storage, "mis-dual-01", 1000).await;

    let ctx = create_auth_context("mis-dual-01", vec!["PORT_SCAN"]);
    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::IpExact("192.168.1.1".parse().unwrap())],
        exclusions: vec![],
        allow_private_ranges: true,
    };

    let proposal = json!({
        "proposal_id": "prp-dual-01",
        "mission_id": "mis-dual-01",
        "capability_id": "PORT_SCAN",
        "target": "192.168.1.1",
        "parameters": { "ports": [80] },
        "nonce": "nonce-dual-001"
    })
    .to_string();

    let action = normalizer.normalize_from_json(&proposal, &ctx).unwrap();
    let decision = engine.authorize(action, &scope, &ctx, None).await.unwrap();
    assert!(decision.is_allow());

    // Verify dual audit records were committed atomically
    let mut tx = storage.begin_transaction().await.unwrap();
    let sys_records = tx.get_all_system_audit().await.unwrap();
    let mis_records = tx
        .get_all_mission_audit(&MissionId::new("mis-dual-01").unwrap())
        .await
        .unwrap();
    tx.commit().await.unwrap();

    assert_eq!(sys_records.len(), 1);
    assert_eq!(mis_records.len(), 1);

    assert_eq!(sys_records[0].event_type, "ACTION_AUTHORIZED");
    assert_eq!(mis_records[0].event_type, "ACTION_AUTHORIZED");

    // Cryptographic verification of both committed chains
    assert!(audit_engine.verify_chain(&sys_records, None).is_ok());
    assert!(audit_engine
        .verify_chain(&mis_records, Some(&MissionId::new("mis-dual-01").unwrap()))
        .is_ok());
}

// ---------------------------------------------------------------------------
// TEST-ESTOP-* : Emergency Stop Barrier & Persistence (INV-010)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_estop_001_blocks_authorization_immediately() {
    let (storage, _clock, _kp, _audit_engine, normalizer, engine, estop) =
        setup_test_env(1000).await;
    create_active_mission(&storage, "mis-estop-01", 1000).await;

    let ctx = create_auth_context("mis-estop-01", vec!["PORT_SCAN"]);
    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::IpExact("192.168.1.1".parse().unwrap())],
        exclusions: vec![],
        allow_private_ranges: true,
    };

    let proposal = json!({
        "proposal_id": "prp-estop-01",
        "mission_id": "mis-estop-01",
        "capability_id": "PORT_SCAN",
        "target": "192.168.1.1",
        "parameters": {},
        "nonce": "nonce-estop-001"
    })
    .to_string();

    let action = normalizer.normalize_from_json(&proposal, &ctx).unwrap();

    // Trigger platform emergency stop
    let opr_safety = OperatorId::new("opr-safety-officer").unwrap();
    estop
        .trigger(&opr_safety, "Critical anomaly detected", 1005)
        .await
        .unwrap();
    assert!(estop.is_active());

    // Authorization must be DENIED immediately
    let decision = engine.authorize(action, &scope, &ctx, None).await.unwrap();
    assert!(decision.is_deny());
    if let arka_kernel::policy::AuthorizationDecision::Deny { error } = decision {
        assert!(matches!(error, KernelSecurityError::EmergencyStopActive(_)));
    } else {
        panic!("Expected EmergencyStopActive denial");
    }
}

#[tokio::test]
async fn test_estop_002_survives_storage_reboot_persistence() {
    // Persistent file-backed SQLite
    let test_id = uuid::Uuid::new_v4();
    let db_path = std::env::temp_dir().join(format!("arka_estop_persist_{}.db", test_id));
    let conn_str = format!("sqlite://{}", db_path.to_str().unwrap());

    // 1. First process / instance triggers emergency stop
    {
        let storage = Arc::new(SqliteStorage::new(&conn_str).await.unwrap());
        let estop = EmergencyStopService::new(storage).await.unwrap();
        let opr = OperatorId::new("opr-lead").unwrap();

        estop
            .trigger(&opr, "Hardware integrity warning", 1000)
            .await
            .unwrap();
        assert!(estop.is_active());
        // Dropping storage and estop closes connections
    }

    // 2. Fresh instance reconnects to the database file (simulating reboot)
    {
        let storage2 = Arc::new(SqliteStorage::new(&conn_str).await.unwrap());
        let estop2 = EmergencyStopService::new(storage2.clone()).await.unwrap();

        // Must still be active!
        assert!(
            estop2.is_active(),
            "Emergency stop must persist across restarts"
        );

        let status = estop2.get_status().await.unwrap();
        assert!(status.active);
        assert_eq!(status.reason.as_deref(), Some("Hardware integrity warning"));
        assert_eq!(status.triggered_by.unwrap().as_str(), "opr-lead");

        // Engine on fresh storage also blocks authorizations
        let clock = Arc::new(MockClock::new(1000));
        let engine2 = AuthorizationEngine::new(storage2.clone(), clock);
        create_active_mission(&storage2, "mis-reboot-01", 1000).await;

        let ctx = create_auth_context("mis-reboot-01", vec!["PORT_SCAN"]);
        let scope = ScopeDefinition {
            inclusions: vec![ScopeRule::IpExact("192.168.1.1".parse().unwrap())],
            exclusions: vec![],
            allow_private_ranges: true,
        };
        let proposal = json!({
            "proposal_id": "prp-reboot-01",
            "mission_id": "mis-reboot-01",
            "capability_id": "PORT_SCAN",
            "target": "192.168.1.1",
            "parameters": {},
            "nonce": "nonce-reboot-001"
        })
        .to_string();

        let registry = Arc::new(StandardCapabilityRegistry::new());
        let normalizer = ActionNormalizer::new(registry);
        let action = normalizer.normalize_from_json(&proposal, &ctx).unwrap();

        let decision = engine2.authorize(action, &scope, &ctx, None).await.unwrap();
        assert!(decision.is_deny());
        if let arka_kernel::policy::AuthorizationDecision::Deny { error } = decision {
            assert!(matches!(error, KernelSecurityError::EmergencyStopActive(_)));
        } else {
            panic!("Expected EmergencyStopActive denial on rebooted instance");
        }

        // Clean up db file
        drop(engine2);
        drop(storage2);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(format!("{}-wal", db_path.to_str().unwrap()));
        let _ = std::fs::remove_file(format!("{}-shm", db_path.to_str().unwrap()));
    }
}

#[tokio::test]
async fn test_estop_003_operator_clear_restores_authorization() {
    let (storage, _clock, _kp, _audit_engine, normalizer, engine, estop) =
        setup_test_env(1000).await;
    create_active_mission(&storage, "mis-clear-01", 1000).await;

    let ctx = create_auth_context("mis-clear-01", vec!["PORT_SCAN"]);
    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::IpExact("192.168.1.1".parse().unwrap())],
        exclusions: vec![],
        allow_private_ranges: true,
    };

    let proposal = json!({
        "proposal_id": "prp-clear-01",
        "mission_id": "mis-clear-01",
        "capability_id": "PORT_SCAN",
        "target": "192.168.1.1",
        "parameters": {},
        "nonce": "nonce-clear-001"
    })
    .to_string();

    let action = normalizer.normalize_from_json(&proposal, &ctx).unwrap();

    // 1. Trigger
    let opr = OperatorId::new("opr-lead").unwrap();
    estop
        .trigger(&opr, "Safety inspection", 1000)
        .await
        .unwrap();
    assert!(estop.is_active());

    // 2. Denied
    let dec1 = engine
        .authorize(action.clone(), &scope, &ctx, None)
        .await
        .unwrap();
    assert!(dec1.is_deny());

    // 3. Clear by authorized operator
    let opr_clear = OperatorId::new("opr-clear-lead").unwrap();
    estop
        .clear(&opr_clear, "Inspection passed, resuming", 1050)
        .await
        .unwrap();
    assert!(!estop.is_active());

    let status = estop.get_status().await.unwrap();
    assert!(!status.active);
    assert_eq!(
        status.clear_reason.as_deref(),
        Some("Inspection passed, resuming")
    );
    assert_eq!(status.cleared_by.unwrap().as_str(), "opr-clear-lead");

    // 4. Operation succeeds after clear
    let dec2 = engine.authorize(action, &scope, &ctx, None).await.unwrap();
    assert!(dec2.is_allow());
}
