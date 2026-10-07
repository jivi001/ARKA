use arka_core_types::actions::CanonicalAction;
use arka_core_types::approval::Approval;
use arka_core_types::id::{ActionId, CapabilityId, MissionId, OperatorId, ProposalId};
use arka_core_types::mission::{Mission, MissionState};
use arka_core_types::scope::ScopeDefinition;
use arka_core_types::subject::Subject;
use arka_core_types::subject::AuthenticatedContext;
use arka_kernel::policy::engine::{AuthorizationDecision, AuthorizationEngine};
use arka_storage_sqlite::db::SqliteStorage;
use arka_core_types::clock::SystemClock;
use std::sync::Arc;

#[tokio::test]
async fn test_downgrade() {
    let storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
    let clock = Arc::new(SystemClock::new());
    let engine = AuthorizationEngine::new(storage.clone(), clock.clone());

    let mission = Mission {
        id: MissionId::new("m1").unwrap(),
        name: "Mission 1".to_string(),
        state: MissionState::Active,
        scope_ref: "scope1".to_string(),
        created_at_unix: 1000,
        updated_at_unix: 1000,
        created_by: OperatorId::new("op1").unwrap(),
    };

    let mut tx = arka_kernel::storage::Storage::begin_transaction(storage.as_ref()).await.unwrap();
    tx.save_mission(&mission).await.unwrap();
    tx.commit().await.unwrap();

    let action = CanonicalAction {
        action_id: ActionId::new("act1").unwrap(),
        proposal_id: ProposalId::new("prop1").unwrap(),
        mission_id: MissionId::new("m1").unwrap(),
        capability_id: CapabilityId::new("cap1").unwrap(),
        target: serde_json::json!({"foo": "bar"}),
        parameter_hash: "hash1".to_string(),
        action_hash: "ahash1".to_string(),
        risk_class: arka_core_types::capabilities::RiskClass::High,
        requires_approval: true,
        nonce: 1,
    };

    let scope = ScopeDefinition {
        mission_id: MissionId::new("m1").unwrap(),
        capabilities: vec!["cap1".to_string()],
        conditions: vec![],
    };

    let context = AuthenticatedContext {
        subject: Subject::Operator(OperatorId::new("op2").unwrap()),
        mission_id: MissionId::new("m1").unwrap(),
    };

    let approval = Approval::new(
        arka_core_types::id::ApprovalId::new("apprv1").unwrap(),
        MissionId::new("m1").unwrap(),
        "ahash1",
        OperatorId::new("op3").unwrap(),
        1000,
        2000,
    );

    let mut tx = arka_kernel::storage::Storage::begin_transaction(storage.as_ref()).await.unwrap();
    tx.save_approval(&approval).await.unwrap();
    tx.commit().await.unwrap();

    let dec1 = engine.authorize(action.clone(), &scope, &context, Some(approval.clone())).await.unwrap();
    println!("First authorize (with approval): {:?}", dec1);

    let dec2 = engine.authorize(action.clone(), &scope, &context, None).await.unwrap();
    println!("Second authorize (no approval): {:?}", dec2);
}
