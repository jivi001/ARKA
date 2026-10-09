//! ARKA Execution Broker
//!
//! Enforces deterministic execution boundaries, pre-dispatch verification,
//! dispatch idempotency, bounded worker supervision, and audit logging.

#![forbid(unsafe_code)]

pub mod broker;
pub mod dispatcher;
pub mod errors;
pub mod record;
pub mod state;
pub mod storage;

pub use broker::{BrokerConfig, ExecutionBroker};
pub use dispatcher::{NoOpWorker, WorkerDispatcher};
pub use errors::BrokerError;
pub use record::{ExecutionRecord, ExecutionResultEnvelope};
pub use state::ExecutionState;
pub use storage::{BrokerStorage, InMemoryBrokerStorage, SqliteBrokerStorage};

#[cfg(test)]
mod tests {
    use super::*;
    use arka_core_types::actions::CanonicalAction;
    use arka_core_types::approval::Approval;
    use arka_core_types::capabilities::RiskClass;
    use arka_core_types::clock::MockClock;
    use arka_core_types::id::{
        ActionId, ApprovalId, CapabilityId, MissionId, OperatorId, ProposalId,
    };
    use arka_core_types::scope::CanonicalTarget;
    use arka_kernel::storage::Storage as KernelStorage;
    use arka_storage_sqlite::db::SqliteStorage;
    use std::sync::Arc;

    async fn setup_test_broker(
        initial_time: u64,
        max_concurrent: usize,
    ) -> (
        Arc<SqliteStorage>,
        Arc<InMemoryBrokerStorage>,
        Arc<MockClock>,
        ExecutionBroker<SqliteStorage, InMemoryBrokerStorage, NoOpWorker, MockClock>,
    ) {
        let kernel_storage = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
        let broker_storage = Arc::new(InMemoryBrokerStorage::new());
        let clock = Arc::new(MockClock::new(initial_time));
        let dispatcher = Arc::new(NoOpWorker::new());

        let broker = ExecutionBroker::new(
            kernel_storage.clone(),
            broker_storage.clone(),
            dispatcher,
            clock.clone(),
            BrokerConfig {
                max_concurrent_executions: max_concurrent,
                default_timeout_seconds: 30,
            },
        );

        (kernel_storage, broker_storage, clock, broker)
    }

    fn sample_action(requires_approval: bool) -> CanonicalAction {
        CanonicalAction {
            action_id: ActionId::new("act-101").unwrap(),
            proposal_id: ProposalId::new("prop-101").unwrap(),
            mission_id: MissionId::new("mis-alpha").unwrap(),
            parent_task_id: None,
            capability_id: CapabilityId::new("TCP_CONNECT").unwrap(),
            target: CanonicalTarget::Domain {
                domain: "local.test".to_string(),
                port: Some(8080),
            },
            normalized_parameters: serde_json::json!({"timeout_ms": 1000}),
            parameter_hash: "paramhash123".to_string(),
            action_hash: "actionhash123".to_string(),
            risk_class: if requires_approval {
                RiskClass::Critical
            } else {
                RiskClass::Moderate
            },
            requires_approval,
            policy_version: "v2.2".to_string(),
            authorization_context_ref: "ctx-1".to_string(),
            nonce: "nonce-1".to_string(),
        }
    }

    #[tokio::test]
    async fn test_successful_action_dispatch() {
        let (_ks, bs, _clock, broker) = setup_test_broker(1000, 5).await;
        let action = sample_action(false);

        let result = broker.execute_action(&action, None).await.unwrap();
        assert_eq!(result.state, ExecutionState::Completed);
        assert_eq!(result.action_id, action.action_id);

        let stored = bs
            .get_execution_by_action(&action.action_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.state, ExecutionState::Completed);
        assert_eq!(stored.dispatch_attempt, 1);
    }

    #[tokio::test]
    async fn test_duplicate_dispatch_denied_idempotently() {
        let (_ks, _bs, _clock, broker) = setup_test_broker(1000, 5).await;
        let action = sample_action(false);

        // First dispatch succeeds
        let res1 = broker.execute_action(&action, None).await;
        assert!(res1.is_ok());

        // Second dispatch for same action_id fails with DuplicateDispatch
        let res2 = broker.execute_action(&action, None).await;
        assert!(matches!(res2, Err(BrokerError::DuplicateDispatch { .. })));
    }

    #[tokio::test]
    async fn test_unapproved_action_rejected() {
        let (_ks, _bs, _clock, broker) = setup_test_broker(1000, 5).await;
        let action = sample_action(true); // requires_approval = true

        let res = broker.execute_action(&action, None).await;
        assert!(matches!(res, Err(BrokerError::ApprovalMissingOrInvalid(_))));
    }

    #[tokio::test]
    async fn test_approved_action_dispatches_successfully() {
        let (_ks, _bs, _clock, broker) = setup_test_broker(1000, 5).await;
        let action = sample_action(true);

        let approval = Approval::new(
            ApprovalId::new("app-1").unwrap(),
            action.mission_id.clone(),
            &action.action_hash,
            OperatorId::new("op-admin").unwrap(),
            1000,
            1030, // expires at 1030
        );

        let res = broker.execute_action(&action, Some(&approval)).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_expired_approval_rejected() {
        let (_ks, _bs, clock, broker) = setup_test_broker(1000, 5).await;
        let action = sample_action(true);

        let approval = Approval::new(
            ApprovalId::new("app-1").unwrap(),
            action.mission_id.clone(),
            &action.action_hash,
            OperatorId::new("op-admin").unwrap(),
            1000,
            1030,
        );

        // Advance time past approval expiration
        clock.set_now(1031);

        let res = broker.execute_action(&action, Some(&approval)).await;
        assert!(matches!(res, Err(BrokerError::ActionExpired { .. })));
    }

    #[tokio::test]
    async fn test_action_hash_mismatch_approval_rejected() {
        let (_ks, _bs, _clock, broker) = setup_test_broker(1000, 5).await;
        let action = sample_action(true);

        // Approval bound to wrong action hash (simulating parameter mutation TOCTOU)
        let approval = Approval::new(
            ApprovalId::new("app-1").unwrap(),
            action.mission_id.clone(),
            "mutated_wrong_hash",
            OperatorId::new("op-admin").unwrap(),
            1000,
            1030,
        );

        let res = broker.execute_action(&action, Some(&approval)).await;
        assert!(matches!(res, Err(BrokerError::ActionHashMismatch { .. })));
    }

    #[tokio::test]
    async fn test_emergency_stop_blocks_dispatch() {
        let (ks, _bs, _clock, broker) = setup_test_broker(1000, 5).await;
        let action = sample_action(false);

        // Engage emergency stop
        let mut tx = KernelStorage::begin_transaction(ks.as_ref()).await.unwrap();
        tx.trigger_emergency_stop(
            &OperatorId::new("op-admin").unwrap(),
            "Incident active",
            1000,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let res = broker.execute_action(&action, None).await;
        assert!(matches!(res, Err(BrokerError::EmergencyStopActive(_))));
    }

    #[tokio::test]
    async fn test_crash_recovery_marks_active_executions_failed() {
        let (_ks, bs, _clock, broker) = setup_test_broker(1000, 5).await;

        let record = ExecutionRecord::new(
            arka_core_types::id::ExecutionId::new("exc-crashed").unwrap(),
            ActionId::new("act-crashed").unwrap(),
            ProposalId::new("prop-crashed").unwrap(),
            MissionId::new("mis-crashed").unwrap(),
            CapabilityId::new("TCP_CONNECT").unwrap(),
            "hash".to_string(),
            serde_json::json!({}),
            serde_json::json!({}),
            1000,
            1030,
        );
        let mut running_record = record.clone();
        running_record.state = ExecutionState::Running;
        bs.insert_execution(&running_record).await.unwrap();

        let recovered = broker.recover_crashed_dispatches().await.unwrap();
        assert_eq!(recovered, 1);

        let updated = bs
            .get_execution(&running_record.execution_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.state, ExecutionState::Failed);
        assert!(updated.error_reason.unwrap().contains("restarted"));
    }
}
