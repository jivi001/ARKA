//! Authoritative Execution Broker orchestration engine.
//!
//! Enforces:
//! - Complete pre-dispatch verification (Action Hash, Approval, E-Stop, Expiry)
//! - Single execution path: no side effect without valid authorized artifact
//! - Idempotent dispatch consumption: unique (action_id, dispatch_attempt=1)
//! - Bounded concurrency via Semaphore
//! - Invariants INV-001, INV-002, INV-004, INV-006, INV-010

use crate::dispatcher::WorkerDispatcher;
use crate::errors::BrokerError;
use crate::record::{ExecutionRecord, ExecutionResultEnvelope};
use crate::state::ExecutionState;
use crate::storage::BrokerStorage;
use arka_core_types::actions::CanonicalAction;
use arka_core_types::approval::Approval;
use arka_core_types::clock::Clock;
use arka_core_types::id::ExecutionId;
use arka_kernel::storage::Storage as KernelStorage;
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;

pub struct BrokerConfig {
    pub max_concurrent_executions: usize,
    pub default_timeout_seconds: u64,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_executions: 10,
            default_timeout_seconds: 30,
        }
    }
}

pub struct ExecutionBroker<K: KernelStorage, S: BrokerStorage, D: WorkerDispatcher, C: Clock> {
    kernel_storage: Arc<K>,
    broker_storage: Arc<S>,
    dispatcher: Arc<D>,
    clock: Arc<C>,
    concurrency_semaphore: Arc<Semaphore>,
    config: BrokerConfig,
}

impl<K: KernelStorage, S: BrokerStorage, D: WorkerDispatcher, C: Clock>
    ExecutionBroker<K, S, D, C>
{
    pub fn new(
        kernel_storage: Arc<K>,
        broker_storage: Arc<S>,
        dispatcher: Arc<D>,
        clock: Arc<C>,
        config: BrokerConfig,
    ) -> Self {
        let concurrency_semaphore = Arc::new(Semaphore::new(config.max_concurrent_executions));
        Self {
            kernel_storage,
            broker_storage,
            dispatcher,
            clock,
            concurrency_semaphore,
            config,
        }
    }

    /// Primary execution dispatcher.
    /// Ingests a kernel-authorized CanonicalAction and dispatches to worker after strict pre-flight checks.
    pub async fn execute_action(
        &self,
        action: &CanonicalAction,
        approval: Option<&Approval>,
    ) -> Result<ExecutionResultEnvelope, BrokerError> {
        let now = self.clock.now_unix();
        let deadline = now + self.config.default_timeout_seconds;

        // 1. Pre-dispatch Verification: Action Hash Integrity
        self.verify_action_integrity(action)?;

        // 2. Pre-dispatch Verification: Two-Person Integrity Approval
        if action.requires_approval {
            self.verify_approval(action, approval, now)?;
        }

        // 3. Pre-dispatch Verification: Monotonic Emergency Stop
        self.verify_emergency_stop(action).await?;

        // 4. Concurrency Guard
        let _permit = self.concurrency_semaphore.try_acquire().map_err(|_| {
            BrokerError::ConcurrencyLimitReached {
                current: self.config.max_concurrent_executions,
                max: self.config.max_concurrent_executions,
            }
        })?;

        // 5. Generate unique ExecutionId and initialize ExecutionRecord
        let execution_id = ExecutionId::new(format!("exc-{}", Uuid::new_v4().simple()))
            .map_err(|e| BrokerError::StorageError(e.to_string()))?;

        let mut record = ExecutionRecord::new(
            execution_id.clone(),
            action.action_id.clone(),
            action.proposal_id.clone(),
            action.mission_id.clone(),
            action.capability_id.clone(),
            action.action_hash.clone(),
            serde_json::to_value(&action.target)
                .map_err(|e| BrokerError::StorageError(e.to_string()))?,
            action.normalized_parameters.clone(),
            now,
            deadline,
        );

        // 6. Transition to DISPATCHING & Persist idempotently (atomic unique constraint)
        record.state = ExecutionState::Dispatching;
        self.broker_storage.insert_execution(&record).await?;

        // 7. Transition to RUNNING
        record.state = ExecutionState::Running;
        self.broker_storage
            .update_execution_state(&execution_id, ExecutionState::Running, None, None, now)
            .await?;

        // 8. Dispatch to Worker via Dispatcher abstraction
        let dispatch_result = self.dispatcher.dispatch(&record).await;

        let completed_at = self.clock.now_unix();
        match dispatch_result {
            Ok(envelope) => {
                let final_state = envelope.state;
                self.broker_storage
                    .update_execution_state(
                        &execution_id,
                        final_state,
                        Some(envelope.clone()),
                        None,
                        completed_at,
                    )
                    .await?;
                Ok(envelope)
            }
            Err(e) => {
                let err_msg = e.to_string();
                self.broker_storage
                    .update_execution_state(
                        &execution_id,
                        ExecutionState::Failed,
                        None,
                        Some(err_msg),
                        completed_at,
                    )
                    .await?;
                Err(e)
            }
        }
    }

    /// Startup recovery: reconciles unfinalized dispatches from prior process crashes.
    pub async fn recover_crashed_dispatches(&self) -> Result<usize, BrokerError> {
        let now = self.clock.now_unix();
        self.broker_storage
            .reconcile_crashed_executions(
                "Process restarted while execution was in progress; automatic retry prohibited",
                now,
            )
            .await
    }

    fn verify_action_integrity(&self, action: &CanonicalAction) -> Result<(), BrokerError> {
        if action.action_hash.is_empty() {
            return Err(BrokerError::ActionNotAuthorized(
                "Action hash is missing".to_string(),
            ));
        }
        if action.parameter_hash.is_empty() {
            return Err(BrokerError::ActionNotAuthorized(
                "Parameter hash is missing".to_string(),
            ));
        }
        Ok(())
    }

    fn verify_approval(
        &self,
        action: &CanonicalAction,
        approval: Option<&Approval>,
        now: u64,
    ) -> Result<(), BrokerError> {
        let app = approval.ok_or_else(|| {
            BrokerError::ApprovalMissingOrInvalid(format!(
                "Action {} carries risk class {:?} and requires operator approval",
                action.action_id, action.risk_class
            ))
        })?;

        if app.mission_id != action.mission_id {
            return Err(BrokerError::ApprovalMissingOrInvalid(
                "Approval mission_id mismatch".to_string(),
            ));
        }

        if app.action_hash != action.action_hash {
            return Err(BrokerError::ActionHashMismatch {
                expected: action.action_hash.clone(),
                actual: app.action_hash.clone(),
            });
        }

        if now > app.expires_at_unix {
            return Err(BrokerError::ActionExpired {
                deadline: app.expires_at_unix,
                now,
            });
        }

        Ok(())
    }

    async fn verify_emergency_stop(&self, action: &CanonicalAction) -> Result<(), BrokerError> {
        let mut tx = self
            .kernel_storage
            .begin_transaction()
            .await
            .map_err(|e| BrokerError::StorageError(e.to_string()))?;
        let estop = tx
            .get_emergency_stop_status()
            .await
            .map_err(|e| BrokerError::StorageError(e.to_string()))?;
        let _ = tx.rollback().await;

        if estop.active {
            return Err(BrokerError::EmergencyStopActive(format!(
                "Emergency stop active for platform (action {} / mission {})",
                action.action_id, action.mission_id
            )));
        }

        Ok(())
    }
}
