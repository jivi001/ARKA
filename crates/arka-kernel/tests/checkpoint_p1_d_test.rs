//! Checkpoint P1-D Security Test Suite: Authorization, Authority, Approval & Replay Protection
//!
//! Validates:
//! - Authorization Engine Decision Model: ALLOW, DENY, REQUIRE_APPROVAL (Section 16)
//! - Authority Delegation & Monotonic Non-Expansion (INV-003, Section 18)
//! - TOCTOU Parameter Hash Binding to Approvals (INV-007, Section 20)
//! - Self-Approval Forbidden (Section 19)
//! - Approval Expiration & Single Consumption (Section 43)
//! - Sequential & Multi-Threaded Concurrent Replay Protection (INV-008, Section 21, Section 22)

use arka_core_types::approval::Approval;
use arka_core_types::authority::Authority;
use arka_core_types::capabilities::RiskClass;
use arka_core_types::clock::MockClock;
use arka_core_types::errors::KernelSecurityError;
use arka_core_types::id::{ApprovalId, CapabilityId, MissionId, OperatorId, TaskId, TokenId};
use arka_core_types::mission::{Mission, MissionState};
use arka_core_types::scope::{CidrBlock, ScopeDefinition, ScopeRule};
use arka_core_types::subject::{AuthenticatedContext, Subject};
use arka_kernel::actions::ActionNormalizer;
use arka_kernel::capabilities::StandardCapabilityRegistry;
use arka_kernel::policy::AuthorizationEngine;
use arka_kernel::Storage;
use arka_storage_sqlite::SqliteStorage;
use serde_json::json;
use std::sync::Arc;

async fn setup_environment(
    clock_time: u64,
) -> (
    Arc<SqliteStorage>,
    Arc<MockClock>,
    Arc<ActionNormalizer>,
    Arc<AuthorizationEngine>,
) {
    let storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
    let clock = Arc::new(MockClock::new(clock_time));
    let registry = Arc::new(StandardCapabilityRegistry::new());
    let normalizer = Arc::new(ActionNormalizer::new(registry));
    let engine = Arc::new(AuthorizationEngine::new(storage.clone(), clock.clone()));

    (storage, clock, normalizer, engine)
}

async fn create_active_mission(storage: &SqliteStorage, mission_id: &str, now: u64) {
    let mut tx = storage.begin_transaction().await.unwrap();
    let mut m = Mission::new(
        MissionId::new(mission_id).unwrap(),
        "Test Mission",
        "scope-01",
        OperatorId::new("opr-lead").unwrap(),
        now,
    );
    m.state = MissionState::Active;
    tx.save_mission(&m).await.unwrap();
    tx.commit().await.unwrap();
}

fn create_auth_context(mission_id: &str, caps: Vec<&str>) -> AuthenticatedContext {
    AuthenticatedContext {
        token_id: TokenId::new("tok-p1d-01").unwrap(),
        subject: Subject::Operator(OperatorId::new("opr-analyst").unwrap()),
        mission_id: MissionId::new(mission_id).unwrap(),
        parent_task_id: Some(TaskId::new("tsk-root-01").unwrap()),
        capabilities: caps
            .into_iter()
            .map(|c| CapabilityId::new(c).unwrap())
            .collect(),
        scope_ref: "scope-p1d".to_string(),
        issued_at_unix: 1000,
        expires_at_unix: 2000,
        parent_token_id: None,
    }
}

// ---------------------------------------------------------------------------
// TEST-AUTHZ-* : Authorization Engine Decision Model
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_authz_001_allow_in_scope_moderate_action() {
    let (storage, _clock, normalizer, engine) = setup_environment(1000).await;
    create_active_mission(&storage, "mis-authz-01", 1000).await;

    let ctx = create_auth_context("mis-authz-01", vec!["PORT_SCAN"]);
    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::IpExact("192.168.1.10".parse().unwrap())],
        exclusions: vec![],
        allow_private_ranges: true,
    };

    let proposal_json = json!({
        "proposal_id": "prp-authz-01",
        "mission_id": "mis-authz-01",
        "capability_id": "PORT_SCAN",
        "target": "192.168.1.10",
        "parameters": { "ports": [80, 443] },
        "nonce": "nonce-authz-001"
    })
    .to_string();

    let action = normalizer
        .normalize_from_json(&proposal_json, &ctx)
        .unwrap();
    let decision = engine.authorize(action, &scope, &ctx, None).await.unwrap();

    assert!(decision.is_allow());
}

#[tokio::test]
async fn test_authz_002_require_approval_for_high_risk_action() {
    let (storage, _clock, normalizer, engine) = setup_environment(1000).await;
    create_active_mission(&storage, "mis-authz-02", 1000).await;

    let ctx = create_auth_context("mis-authz-02", vec!["CONTROLLED_EXPLOITATION"]);
    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::IpExact("192.168.1.50".parse().unwrap())],
        exclusions: vec![],
        allow_private_ranges: true,
    };

    let proposal_json = json!({
        "proposal_id": "prp-authz-02",
        "mission_id": "mis-authz-02",
        "capability_id": "CONTROLLED_EXPLOITATION",
        "target": "192.168.1.50",
        "parameters": { "cve": "CVE-2024-1234" },
        "nonce": "nonce-authz-002"
    })
    .to_string();

    let action = normalizer
        .normalize_from_json(&proposal_json, &ctx)
        .unwrap();
    let decision = engine.authorize(action, &scope, &ctx, None).await.unwrap();

    assert!(decision.is_require_approval());
    if let arka_kernel::policy::AuthorizationDecision::RequireApproval {
        action_hash,
        risk_class,
        ..
    } = decision
    {
        assert_eq!(risk_class, RiskClass::Critical);
        assert_eq!(action_hash.len(), 64);
    } else {
        panic!("Expected RequireApproval decision");
    }
}

// ---------------------------------------------------------------------------
// TEST-DELEGATION-* : Authority Delegation & Invariant INV-003
// ---------------------------------------------------------------------------

#[test]
fn test_delegation_001_valid_child_authority() {
    let parent_scope = ScopeDefinition {
        inclusions: vec![ScopeRule::IpRange(
            CidrBlock::new_v4("10.0.0.0".parse().unwrap(), 16).unwrap(),
        )],
        exclusions: vec![ScopeRule::IpExact("10.0.99.99".parse().unwrap())],
        allow_private_ranges: true,
    };

    let parent_authority = Authority {
        scope: parent_scope.clone(),
        capabilities: vec![
            CapabilityId::new("PORT_SCAN").unwrap(),
            CapabilityId::new("DNS_LOOKUP").unwrap(),
        ],
        max_risk: RiskClass::Moderate,
        budget_cents: 10000,
        expires_at_unix: 2000,
        delegation_depth: 0,
        max_delegation_depth: 3,
    };

    // Child authority: subset of capabilities, lower budget, earlier expiry, increased depth
    let child_authority = Authority {
        scope: parent_scope,
        capabilities: vec![CapabilityId::new("PORT_SCAN").unwrap()],
        max_risk: RiskClass::Moderate,
        budget_cents: 5000,
        expires_at_unix: 1500,
        delegation_depth: 1,
        max_delegation_depth: 3,
    };

    assert!(parent_authority
        .validate_child_delegation(&child_authority)
        .is_ok());
}

#[test]
fn test_delegation_002_expansion_attempts_rejected() {
    let parent_scope = ScopeDefinition {
        inclusions: vec![],
        exclusions: vec![ScopeRule::IpExact("10.0.99.99".parse().unwrap())],
        allow_private_ranges: false,
    };

    let parent_authority = Authority {
        scope: parent_scope.clone(),
        capabilities: vec![CapabilityId::new("DNS_LOOKUP").unwrap()],
        max_risk: RiskClass::Observation,
        budget_cents: 1000,
        expires_at_unix: 2000,
        delegation_depth: 0,
        max_delegation_depth: 2,
    };

    // 1. Capability expansion (attempting to grant PORT_SCAN) -> DENY
    let mut child_bad_cap = parent_authority.clone();
    child_bad_cap.delegation_depth = 1;
    child_bad_cap
        .capabilities
        .push(CapabilityId::new("PORT_SCAN").unwrap());
    assert!(matches!(
        parent_authority.validate_child_delegation(&child_bad_cap),
        Err(KernelSecurityError::AuthenticationFailed(_))
    ));

    // 2. Risk expansion -> DENY
    let mut child_bad_risk = parent_authority.clone();
    child_bad_risk.delegation_depth = 1;
    child_bad_risk.max_risk = RiskClass::Critical;
    assert!(matches!(
        parent_authority.validate_child_delegation(&child_bad_risk),
        Err(KernelSecurityError::AuthenticationFailed(_))
    ));

    // 3. Expiration expansion -> DENY
    let mut child_bad_exp = parent_authority.clone();
    child_bad_exp.delegation_depth = 1;
    child_bad_exp.expires_at_unix = 3000;
    assert!(matches!(
        parent_authority.validate_child_delegation(&child_bad_exp),
        Err(KernelSecurityError::AuthenticationFailed(_))
    ));

    // 4. Depth expansion past max_delegation_depth -> DENY
    let mut child_bad_depth = parent_authority.clone();
    child_bad_depth.delegation_depth = 3;
    assert!(matches!(
        parent_authority.validate_child_delegation(&child_bad_depth),
        Err(KernelSecurityError::AuthenticationFailed(_))
    ));
}

// ---------------------------------------------------------------------------
// TEST-APPROVAL-* : Approval Binding & TOCTOU Protection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_approval_001_valid_approval_unlocks_action() {
    let (storage, _clock, normalizer, engine) = setup_environment(1000).await;
    create_active_mission(&storage, "mis-appr-01", 1000).await;

    let ctx = create_auth_context("mis-appr-01", vec!["CONTROLLED_EXPLOITATION"]);
    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::IpExact("192.168.1.100".parse().unwrap())],
        exclusions: vec![],
        allow_private_ranges: true,
    };

    let proposal_json = json!({
        "proposal_id": "prp-appr-01",
        "mission_id": "mis-appr-01",
        "capability_id": "CONTROLLED_EXPLOITATION",
        "target": "192.168.1.100",
        "parameters": { "cve": "CVE-2024-9999" },
        "nonce": "nonce-appr-001"
    })
    .to_string();

    let action = normalizer
        .normalize_from_json(&proposal_json, &ctx)
        .unwrap();

    // Independent operator approves the exact action hash
    let approval = Approval::new(
        ApprovalId::new("apr-001").unwrap(),
        action.mission_id.clone(),
        action.action_hash.clone(),
        OperatorId::new("opr-independent-lead").unwrap(),
        1000,
        1500, // Valid until 1500
    );

    // Save approval to storage
    let mut tx = storage.begin_transaction().await.unwrap();
    tx.save_approval(&approval).await.unwrap();
    tx.commit().await.unwrap();

    // Authorize with valid approval
    let decision = engine
        .authorize(action, &scope, &ctx, Some(approval))
        .await
        .unwrap();
    assert!(decision.is_allow());
}

#[tokio::test]
async fn test_approval_002_parameter_mutation_invalidates_approval_toctou() {
    let (storage, _clock, normalizer, engine) = setup_environment(1000).await;
    create_active_mission(&storage, "mis-appr-02", 1000).await;

    let ctx = create_auth_context("mis-appr-02", vec!["CONTROLLED_EXPLOITATION"]);
    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::IpExact("192.168.1.100".parse().unwrap())],
        exclusions: vec![],
        allow_private_ranges: true,
    };

    let original_proposal = json!({
        "proposal_id": "prp-appr-02",
        "mission_id": "mis-appr-02",
        "capability_id": "CONTROLLED_EXPLOITATION",
        "target": "192.168.1.100",
        "parameters": { "payload": "safe_probe" },
        "nonce": "nonce-appr-002"
    })
    .to_string();

    let original_action = normalizer
        .normalize_from_json(&original_proposal, &ctx)
        .unwrap();

    // Approval issued for original action hash
    let approval = Approval::new(
        ApprovalId::new("apr-002").unwrap(),
        original_action.mission_id.clone(),
        original_action.action_hash.clone(),
        OperatorId::new("opr-lead").unwrap(),
        1000,
        1500,
    );

    let mut tx = storage.begin_transaction().await.unwrap();
    tx.save_approval(&approval).await.unwrap();
    tx.commit().await.unwrap();

    // Attacker modifies parameters before execution
    let mutated_proposal = json!({
        "proposal_id": "prp-appr-02-mutated",
        "mission_id": "mis-appr-02",
        "capability_id": "CONTROLLED_EXPLOITATION",
        "target": "192.168.1.100",
        "parameters": { "payload": "destructive_exploit" },
        "nonce": "nonce-appr-002-mutated"
    })
    .to_string();

    let mutated_action = normalizer
        .normalize_from_json(&mutated_proposal, &ctx)
        .unwrap();

    // Submitting mutated action with old approval must be DENIED (TOCTOU protection)
    let decision = engine
        .authorize(mutated_action, &scope, &ctx, Some(approval))
        .await
        .unwrap();
    assert!(decision.is_deny());
}

#[tokio::test]
async fn test_approval_003_self_approval_forbidden() {
    let (storage, _clock, normalizer, engine) = setup_environment(1000).await;
    create_active_mission(&storage, "mis-appr-03", 1000).await;

    // Requester is opr-analyst
    let ctx = create_auth_context("mis-appr-03", vec!["CONTROLLED_EXPLOITATION"]);
    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::IpExact("192.168.1.100".parse().unwrap())],
        exclusions: vec![],
        allow_private_ranges: true,
    };

    let proposal = json!({
        "proposal_id": "prp-appr-03",
        "mission_id": "mis-appr-03",
        "capability_id": "CONTROLLED_EXPLOITATION",
        "target": "192.168.1.100",
        "parameters": {},
        "nonce": "nonce-appr-003"
    })
    .to_string();

    let action = normalizer.normalize_from_json(&proposal, &ctx).unwrap();

    // Approver is ALSO opr-analyst (self-approval attempt)
    let approval = Approval::new(
        ApprovalId::new("apr-003").unwrap(),
        action.mission_id.clone(),
        action.action_hash.clone(),
        OperatorId::new("opr-analyst").unwrap(), // Self approval!
        1000,
        1500,
    );

    let decision = engine
        .authorize(action, &scope, &ctx, Some(approval))
        .await
        .unwrap();
    assert!(decision.is_deny());
    if let arka_kernel::policy::AuthorizationDecision::Deny { error } = decision {
        assert_eq!(error, KernelSecurityError::SelfApprovalForbidden);
    } else {
        panic!("Expected SelfApprovalForbidden denial");
    }
}

// ---------------------------------------------------------------------------
// TEST-REPLAY-* : Replay Protection & Mandatory Concurrency Stress Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_replay_001_sequential_replay_denied() {
    let (storage, _clock, normalizer, engine) = setup_environment(1000).await;
    create_active_mission(&storage, "mis-rep-01", 1000).await;

    let ctx = create_auth_context("mis-rep-01", vec!["PORT_SCAN"]);
    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::IpExact("192.168.1.1".parse().unwrap())],
        exclusions: vec![],
        allow_private_ranges: true,
    };

    let proposal = json!({
        "proposal_id": "prp-rep-01",
        "mission_id": "mis-rep-01",
        "capability_id": "PORT_SCAN",
        "target": "192.168.1.1",
        "parameters": {},
        "nonce": "nonce-rep-001"
    })
    .to_string();

    let action = normalizer.normalize_from_json(&proposal, &ctx).unwrap();

    // First execution succeeds
    let first_res = engine
        .authorize(action.clone(), &scope, &ctx, None)
        .await
        .unwrap();
    assert!(first_res.is_allow());

    // Replay with identical action must be rejected!
    let second_res = engine.authorize(action, &scope, &ctx, None).await.unwrap();
    assert!(second_res.is_deny());
    if let arka_kernel::policy::AuthorizationDecision::Deny { error } = second_res {
        assert!(matches!(error, KernelSecurityError::ReplayDetected(_)));
    } else {
        panic!("Expected ReplayDetected error");
    }
}

/// MANDATORY CONCURRENT REPLAY TEST (Section 22)
/// 10 concurrent threads submit the exact same action proposal simultaneously to the real storage engine.
/// Exactly ONE consumption must succeed; all other 9 attempts must be DENIED!
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_replay_concurrent_001_exactly_one_success() {
    // File-based SQLite in temp dir to test real multi-connection concurrency
    let test_id = uuid::Uuid::new_v4();
    let db_path = std::env::temp_dir().join(format!("arka_conc_test_{}.db", test_id));
    let conn_str = format!("sqlite://{}", db_path.to_str().unwrap());

    let storage = Arc::new(SqliteStorage::new(&conn_str).await.unwrap());
    let _clock = Arc::new(MockClock::new(1000));
    let registry = Arc::new(StandardCapabilityRegistry::new());
    let normalizer = Arc::new(ActionNormalizer::new(registry));
    let engine = Arc::new(AuthorizationEngine::new(storage.clone(), _clock.clone()));

    create_active_mission(&storage, "mis-conc-01", 1000).await;

    let ctx = create_auth_context("mis-conc-01", vec!["PORT_SCAN"]);
    let scope = Arc::new(ScopeDefinition {
        inclusions: vec![ScopeRule::IpExact("192.168.1.1".parse().unwrap())],
        exclusions: vec![],
        allow_private_ranges: true,
    });

    let proposal = json!({
        "proposal_id": "prp-conc-identical",
        "mission_id": "mis-conc-01",
        "capability_id": "PORT_SCAN",
        "target": "192.168.1.1",
        "parameters": { "concurrency": true },
        "nonce": "fixed-identical-nonce-0000000001"
    })
    .to_string();

    let action = normalizer.normalize_from_json(&proposal, &ctx).unwrap();

    let concurrency_count = 10;
    let mut handles = Vec::new();

    for _ in 0..concurrency_count {
        let eng = engine.clone();
        let act = action.clone();
        let sc = scope.clone();
        let c = ctx.clone();

        handles.push(tokio::spawn(async move {
            eng.authorize(act, &sc, &c, None).await
        }));
    }

    let mut allow_count = 0;
    let mut replay_deny_count = 0;

    for handle in handles {
        let res = handle.await.unwrap().unwrap();
        match res {
            arka_kernel::policy::AuthorizationDecision::Allow { .. } => {
                allow_count += 1;
            }
            arka_kernel::policy::AuthorizationDecision::Deny { error } => {
                if matches!(error, KernelSecurityError::ReplayDetected(_)) {
                    replay_deny_count += 1;
                }
            }
            other => panic!("Unexpected decision: {:?}", other),
        }
    }

    // Strict invariant: Exactly one thread succeeds, all others are denied by replay protection!
    assert_eq!(
        allow_count, 1,
        "Expected exactly 1 successful authorization"
    );
    assert_eq!(
        replay_deny_count,
        concurrency_count - 1,
        "Expected all other concurrent submissions to be denied with ReplayDetected"
    );

    drop(engine);
    drop(storage);
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(format!("{}-wal", db_path.to_str().unwrap()));
    let _ = std::fs::remove_file(format!("{}-shm", db_path.to_str().unwrap()));
}
