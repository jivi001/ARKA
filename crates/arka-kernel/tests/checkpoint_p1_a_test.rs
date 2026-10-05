//! Checkpoint P1-A Security Test Suite
//!
//! Validates:
//! - Authentication & Token Verification (TEST-AUTH-*)
//! - Typed Identity Primitives (TEST-ID-*)
//! - Mission Lifecycle State Machine (TEST-MISSION-*)
//! - Cross-Mission Tenant Isolation (TEST-MISSION-ISOLATION-*)

use arka_core_types::clock::MockClock;
use arka_core_types::errors::{ExternalSecurityError, KernelSecurityError};
use arka_core_types::id::{
    AgentId, CapabilityId, IdValidationError, MissionId, OperatorId, TaskId, TokenId,
};
use arka_core_types::mission::MissionState;
use arka_core_types::subject::{AuthenticatedContext, Subject};
use arka_crypto::provider::{DevKeyProvider, KeyDomain, KeyProvider};
use arka_crypto::token::{SignedToken, TokenClaims};
use arka_kernel::auth::AuthenticationService;
use arka_kernel::missions::MissionService;
use arka_storage_sqlite::SqliteStorage;
use std::sync::Arc;

fn create_test_claims(
    token_id: &str,
    subject: Subject,
    mission_id: &str,
    issued_at: u64,
    expires_at: u64,
) -> TokenClaims {
    TokenClaims {
        token_id: TokenId::new(token_id).unwrap(),
        subject,
        mission_id: MissionId::new(mission_id).unwrap(),
        parent_task_id: Some(TaskId::new("tsk-root-01").unwrap()),
        capabilities: vec![
            CapabilityId::new("PORT_SCAN").unwrap(),
            CapabilityId::new("DNS_LOOKUP").unwrap(),
        ],
        scope_ref: "scope-primary-v1".to_string(),
        issued_at_unix: issued_at,
        expires_at_unix: expires_at,
        parent_token_id: None,
    }
}

// ---------------------------------------------------------------------------
// TEST-AUTH-* : Authentication and Token Verification
// ---------------------------------------------------------------------------

#[test]
fn test_auth_001_valid_token_verification() {
    let key_provider = Arc::new(DevKeyProvider::new());
    let clock = Arc::new(MockClock::new(1000));
    let auth_service = AuthenticationService::new(key_provider.clone(), clock.clone());

    let op_id = OperatorId::new("opr-lead-sec").unwrap();
    let claims = create_test_claims(
        "tok-valid-01",
        Subject::Operator(op_id.clone()),
        "mis-alpha-01",
        1000,
        1900,
    );
    let token = SignedToken::issue(claims, "TOKEN-SIGNING-dev-01", key_provider.as_ref()).unwrap();

    let auth_ctx = auth_service
        .authenticate(&token)
        .expect("Valid token must authenticate");
    assert_eq!(auth_ctx.mission_id.as_str(), "mis-alpha-01");
    assert_eq!(auth_ctx.subject, Subject::Operator(op_id));
    assert!(auth_ctx.has_capability(&CapabilityId::new("PORT_SCAN").unwrap()));
}

#[test]
fn test_auth_002_invalid_signature_rejection() {
    let key_provider = Arc::new(DevKeyProvider::new());
    let clock = Arc::new(MockClock::new(1000));
    let auth_service = AuthenticationService::new(key_provider.clone(), clock.clone());

    let op_id = OperatorId::new("opr-lead-sec").unwrap();
    let claims = create_test_claims(
        "tok-tamper-01",
        Subject::Operator(op_id),
        "mis-alpha-01",
        1000,
        1900,
    );
    let mut token =
        SignedToken::issue(claims, "TOKEN-SIGNING-dev-01", key_provider.as_ref()).unwrap();

    // Tamper with signature bytes
    token.signature = "deadbeef".repeat(8);

    let res = auth_service.authenticate(&token);
    assert!(matches!(res, Err(KernelSecurityError::InvalidSignature(_))));
}

#[test]
fn test_auth_003_expired_token_rejection() {
    let key_provider = Arc::new(DevKeyProvider::new());
    let clock = Arc::new(MockClock::new(1000));
    let auth_service = AuthenticationService::new(key_provider.clone(), clock.clone());

    let op_id = OperatorId::new("opr-lead-sec").unwrap();
    let claims = create_test_claims(
        "tok-exp-01",
        Subject::Operator(op_id),
        "mis-alpha-01",
        1000,
        1500,
    );
    let token = SignedToken::issue(claims, "TOKEN-SIGNING-dev-01", key_provider.as_ref()).unwrap();

    // Exactly at expiration boundary
    clock.set_now(1500);
    let res_at_boundary = auth_service.authenticate(&token);
    assert!(matches!(
        res_at_boundary,
        Err(KernelSecurityError::TokenExpired { .. })
    ));

    // After expiration boundary
    clock.set_now(1501);
    let res_past = auth_service.authenticate(&token);
    assert!(matches!(
        res_past,
        Err(KernelSecurityError::TokenExpired { .. })
    ));
}

#[test]
fn test_auth_004_revoked_key_rejection() {
    let key_provider = Arc::new(DevKeyProvider::new());
    let clock = Arc::new(MockClock::new(1000));
    let auth_service = AuthenticationService::new(key_provider.clone(), clock.clone());

    let op_id = OperatorId::new("opr-lead-sec").unwrap();
    let claims = create_test_claims(
        "tok-rev-01",
        Subject::Operator(op_id),
        "mis-alpha-01",
        1000,
        1900,
    );
    let token = SignedToken::issue(claims, "TOKEN-SIGNING-dev-01", key_provider.as_ref()).unwrap();

    // Revoke the key ID
    key_provider.revoke_key("TOKEN-SIGNING-dev-01");

    let res = auth_service.authenticate(&token);
    assert!(matches!(res, Err(KernelSecurityError::TokenRevoked(_))));
}

#[test]
fn test_auth_005_identity_substitution_rejected() {
    let key_provider = Arc::new(DevKeyProvider::new());
    let clock = Arc::new(MockClock::new(1000));
    let auth_service = AuthenticationService::new(key_provider.clone(), clock.clone());

    let op_id = OperatorId::new("opr-lead-sec").unwrap();
    let claims = create_test_claims(
        "tok-sub-01",
        Subject::Operator(op_id),
        "mis-alpha-01",
        1000,
        1900,
    );
    let mut token =
        SignedToken::issue(claims, "TOKEN-SIGNING-dev-01", key_provider.as_ref()).unwrap();

    // Adversary attempts to substitute subject with another identity without updating signature
    token.claims.subject = Subject::Agent(AgentId::new("agt-injected-malicious").unwrap());

    let res = auth_service.authenticate(&token);
    assert!(matches!(res, Err(KernelSecurityError::InvalidSignature(_))));
}

#[test]
fn test_auth_006_domain_separation_enforced() {
    let key_provider = Arc::new(DevKeyProvider::new());

    // Attempting to sign a token with an AUDIT-SIGNING key domain must fail
    let res = key_provider.sign(
        KeyDomain::AuditSigning,
        "TOKEN-SIGNING-dev-01",
        b"some-data",
    );
    assert!(matches!(
        res,
        Err(arka_crypto::CryptoError::DomainSeparationViolation(_))
    ));
}

// ---------------------------------------------------------------------------
// TEST-ID-* : Strongly Typed Identity Validation
// ---------------------------------------------------------------------------

#[test]
fn test_id_001_strict_validation() {
    // Empty rejected
    assert_eq!(MissionId::new(""), Err(IdValidationError::Empty));

    // Too short (< 3 chars)
    assert!(matches!(
        OperatorId::new("op"),
        Err(IdValidationError::TooShort { .. })
    ));

    // Too long (> 64 chars)
    let too_long = "a".repeat(65);
    assert!(matches!(
        AgentId::new(&too_long),
        Err(IdValidationError::TooLong { .. })
    ));

    // Path traversal / control characters / spaces rejected
    assert!(matches!(
        TaskId::new("tsk/../../root"),
        Err(IdValidationError::ForbiddenCharacter { char: '/' })
    ));
    assert!(matches!(
        CapabilityId::new("CAP SCAN"),
        Err(IdValidationError::ForbiddenCharacter { char: ' ' })
    ));
    assert!(matches!(
        TokenId::new("tok\x00null"),
        Err(IdValidationError::ForbiddenCharacter { char: '\x00' })
    ));
    assert!(matches!(
        MissionId::new("mis\nnewline"),
        Err(IdValidationError::ForbiddenCharacter { char: '\n' })
    ));

    // Valid identifiers accepted
    assert!(MissionId::new("mis-prod_01.corp:stage").is_ok());
}

// ---------------------------------------------------------------------------
// TEST-MISSION-* : Mission Lifecycle & State Machine
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mission_001_legal_lifecycle_flow() {
    let storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
    let clock = Arc::new(MockClock::new(1000));
    let mission_service = MissionService::new(storage.clone(), clock.clone());

    let op_id = OperatorId::new("opr-lead").unwrap();
    let auth_ctx = AuthenticatedContext {
        token_id: TokenId::new("tok-01").unwrap(),
        subject: Subject::Operator(op_id.clone()),
        mission_id: MissionId::new("mis-lifecycle-01").unwrap(),
        parent_task_id: None,
        capabilities: vec![],
        scope_ref: "scope-01".to_string(),
        issued_at_unix: 1000,
        expires_at_unix: 2000,
        parent_token_id: None,
    };

    // 1. Create mission (CREATED)
    let m = mission_service
        .create_mission(
            auth_ctx.mission_id.clone(),
            "RedTeam Engagement",
            "scope-01",
            &auth_ctx,
        )
        .await
        .expect("Mission creation must succeed");
    assert_eq!(m.state, MissionState::Created);

    // 2. Transition CREATED -> ACTIVE
    let m = mission_service
        .transition_mission(&auth_ctx.mission_id, MissionState::Active, &auth_ctx)
        .await
        .expect("CREATED -> ACTIVE must succeed");
    assert_eq!(m.state, MissionState::Active);

    // 3. Transition ACTIVE -> PAUSED
    let m = mission_service
        .transition_mission(&auth_ctx.mission_id, MissionState::Paused, &auth_ctx)
        .await
        .expect("ACTIVE -> PAUSED must succeed");
    assert_eq!(m.state, MissionState::Paused);

    // 4. Transition PAUSED -> ACTIVE
    let m = mission_service
        .transition_mission(&auth_ctx.mission_id, MissionState::Active, &auth_ctx)
        .await
        .expect("PAUSED -> ACTIVE must succeed");
    assert_eq!(m.state, MissionState::Active);

    // 5. Transition ACTIVE -> COMPLETED (terminal)
    let m = mission_service
        .transition_mission(&auth_ctx.mission_id, MissionState::Completed, &auth_ctx)
        .await
        .expect("ACTIVE -> COMPLETED must succeed");
    assert_eq!(m.state, MissionState::Completed);
    assert!(m.state.is_terminal());
}

#[tokio::test]
async fn test_mission_002_illegal_transitions_rejected() {
    let storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
    let clock = Arc::new(MockClock::new(1000));
    let mission_service = MissionService::new(storage.clone(), clock.clone());

    let op_id = OperatorId::new("opr-lead").unwrap();
    let auth_ctx = AuthenticatedContext {
        token_id: TokenId::new("tok-02").unwrap(),
        subject: Subject::Operator(op_id.clone()),
        mission_id: MissionId::new("mis-illegal-01").unwrap(),
        parent_task_id: None,
        capabilities: vec![],
        scope_ref: "scope-01".to_string(),
        issued_at_unix: 1000,
        expires_at_unix: 2000,
        parent_token_id: None,
    };

    mission_service
        .create_mission(
            auth_ctx.mission_id.clone(),
            "Illegal Transitions",
            "scope-01",
            &auth_ctx,
        )
        .await
        .unwrap();

    // CREATED -> PAUSED is illegal (must launch to ACTIVE first)
    let res = mission_service
        .transition_mission(&auth_ctx.mission_id, MissionState::Paused, &auth_ctx)
        .await;
    assert!(matches!(
        res,
        Err(KernelSecurityError::MissionStateInvalid { .. })
    ));

    // Transition to TERMINATED (terminal)
    mission_service
        .transition_mission(&auth_ctx.mission_id, MissionState::Terminated, &auth_ctx)
        .await
        .unwrap();

    // TERMINATED -> ACTIVE must be rejected
    let res_restart = mission_service
        .transition_mission(&auth_ctx.mission_id, MissionState::Active, &auth_ctx)
        .await;
    assert!(matches!(
        res_restart,
        Err(KernelSecurityError::MissionStateInvalid { .. })
    ));
}

#[tokio::test]
async fn test_mission_003_agent_cannot_mutate_mission_state() {
    let storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
    let clock = Arc::new(MockClock::new(1000));
    let mission_service = MissionService::new(storage.clone(), clock.clone());

    let op_id = OperatorId::new("opr-lead").unwrap();
    let op_ctx = AuthenticatedContext {
        token_id: TokenId::new("tok-03").unwrap(),
        subject: Subject::Operator(op_id),
        mission_id: MissionId::new("mis-agent-block-01").unwrap(),
        parent_task_id: None,
        capabilities: vec![],
        scope_ref: "scope-01".to_string(),
        issued_at_unix: 1000,
        expires_at_unix: 2000,
        parent_token_id: None,
    };

    mission_service
        .create_mission(
            op_ctx.mission_id.clone(),
            "Agent Block Test",
            "scope-01",
            &op_ctx,
        )
        .await
        .unwrap();

    // Agent attempts to transition mission to ACTIVE
    let agent_ctx = AuthenticatedContext {
        token_id: TokenId::new("tok-agt-01").unwrap(),
        subject: Subject::Agent(AgentId::new("agt-recon-01").unwrap()),
        mission_id: op_ctx.mission_id.clone(),
        parent_task_id: None,
        capabilities: vec![],
        scope_ref: "scope-01".to_string(),
        issued_at_unix: 1000,
        expires_at_unix: 2000,
        parent_token_id: None,
    };

    let res = mission_service
        .transition_mission(&op_ctx.mission_id, MissionState::Active, &agent_ctx)
        .await;
    assert!(matches!(
        res,
        Err(KernelSecurityError::AuthenticationFailed(_))
    ));
}

// ---------------------------------------------------------------------------
// TEST-MISSION-ISOLATION-* : Cross-Mission Tenant Access Barriers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mission_isolation_001_cross_mission_access_denied() {
    let storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
    let clock = Arc::new(MockClock::new(1000));
    let mission_service = MissionService::new(storage.clone(), clock.clone());

    let op_id = OperatorId::new("opr-lead").unwrap();
    let mission_a_id = MissionId::new("mis-tenant-alpha").unwrap();
    let mission_b_id = MissionId::new("mis-tenant-beta").unwrap();

    let ctx_a = AuthenticatedContext {
        token_id: TokenId::new("tok-a").unwrap(),
        subject: Subject::Operator(op_id.clone()),
        mission_id: mission_a_id.clone(),
        parent_task_id: None,
        capabilities: vec![],
        scope_ref: "scope-a".to_string(),
        issued_at_unix: 1000,
        expires_at_unix: 2000,
        parent_token_id: None,
    };

    let ctx_b = AuthenticatedContext {
        token_id: TokenId::new("tok-b").unwrap(),
        subject: Subject::Operator(op_id),
        mission_id: mission_b_id.clone(),
        parent_task_id: None,
        capabilities: vec![],
        scope_ref: "scope-b".to_string(),
        issued_at_unix: 1000,
        expires_at_unix: 2000,
        parent_token_id: None,
    };

    // Create Mission A under ctx_a and Mission B under ctx_b
    mission_service
        .create_mission(mission_a_id.clone(), "Alpha Engagement", "scope-a", &ctx_a)
        .await
        .unwrap();

    mission_service
        .create_mission(mission_b_id.clone(), "Beta Engagement", "scope-b", &ctx_b)
        .await
        .unwrap();

    // Adversary with Token A attempts to read Mission B
    let res = mission_service.get_mission(&mission_b_id, &ctx_a).await;
    assert!(matches!(
        res,
        Err(KernelSecurityError::CrossMissionAccessDenied {
            requester_mission,
            target_mission,
        }) if requester_mission == mission_a_id && target_mission == mission_b_id
    ));

    // Adversary with Token A attempts to transition Mission B
    let res_transition = mission_service
        .transition_mission(&mission_b_id, MissionState::Active, &ctx_a)
        .await;
    assert!(matches!(
        res_transition,
        Err(KernelSecurityError::CrossMissionAccessDenied { .. })
    ));
}

#[test]
fn test_mission_isolation_002_error_oracle_defense() {
    let mission_a = MissionId::new("mis-a").unwrap();
    let mission_b = MissionId::new("mis-b").unwrap();

    let internal_err = KernelSecurityError::CrossMissionAccessDenied {
        requester_mission: mission_a,
        target_mission: mission_b,
    };

    // External caller must receive generic AUTHORIZATION_DENIED without leaking foreign mission ID
    let external_err: ExternalSecurityError = internal_err.into();
    assert_eq!(external_err.code, "AUTHORIZATION_DENIED");
    assert!(!external_err.message.contains("mis-b"));
    assert!(!external_err.message.contains("mis-a"));
}
