//! Authorization Engine & Decision Model.
//!
//! Enforces:
//! - Section 16: ALLOW, DENY, REQUIRE_APPROVAL decision model.
//! - INV-008: Atomic check-and-consume replay protection.
//! - Section 20 & 43: TOCTOU cryptographic parameter hash binding to approvals.
//! - Emergency Stop barrier.

use crate::scope::ScopeEngine;
use crate::storage::Storage;
use arka_core_types::actions::CanonicalAction;
use arka_core_types::approval::Approval;
use arka_core_types::capabilities::RiskClass;
use arka_core_types::clock::Clock;
use arka_core_types::errors::KernelSecurityError;
use arka_core_types::scope::ScopeDefinition;
use arka_core_types::subject::AuthenticatedContext;
use arka_crypto::hashing::{sha256_hex, DOMAIN_REPLAY};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allow {
        action: CanonicalAction,
    },
    RequireApproval {
        action: CanonicalAction,
        action_hash: String,
        risk_class: RiskClass,
    },
    Deny {
        error: KernelSecurityError,
    },
}

impl AuthorizationDecision {
    pub fn is_allow(&self) -> bool {
        matches!(self, AuthorizationDecision::Allow { .. })
    }

    pub fn is_require_approval(&self) -> bool {
        matches!(self, AuthorizationDecision::RequireApproval { .. })
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, AuthorizationDecision::Deny { .. })
    }
}

pub struct AuthorizationEngine {
    storage: Arc<dyn Storage>,
    clock: Arc<dyn Clock>,
}

impl AuthorizationEngine {
    pub fn new(storage: Arc<dyn Storage>, clock: Arc<dyn Clock>) -> Self {
        Self { storage, clock }
    }

    /// Authorizes an action proposal atomically within a storage transaction boundary.
    pub async fn authorize(
        &self,
        action: CanonicalAction,
        scope: &ScopeDefinition,
        context: &AuthenticatedContext,
        approval: Option<Approval>,
    ) -> Result<AuthorizationDecision, KernelSecurityError> {
        let mut tx = self.storage.begin_transaction().await?;
        let now = self.clock.now_unix();

        // 1. Invariant INV-010: Emergency Stop Gate
        if tx.is_emergency_stop_active().await? {
            let _ = tx.rollback().await;
            return Ok(AuthorizationDecision::Deny {
                error: KernelSecurityError::EmergencyStopActive(
                    "Emergency stop active: all security-sensitive authorizations denied"
                        .to_string(),
                ),
            });
        }

        // 2. Mission State Machine Check
        let maybe_mission = tx.get_mission(&action.mission_id).await?;
        let mission = match maybe_mission {
            Some(m) => m,
            None => {
                let _ = tx.rollback().await;
                return Ok(AuthorizationDecision::Deny {
                    error: KernelSecurityError::MissionNotFound(action.mission_id.clone()),
                });
            }
        };

        if !mission.state.allows_action_execution() {
            let _ = tx.rollback().await;
            return Ok(AuthorizationDecision::Deny {
                error: KernelSecurityError::MissionStateInvalid {
                    current: mission.state.to_string(),
                    target: "ACTIVE (required for execution)".to_string(),
                },
            });
        }

        // 3. Scope Engine Check
        if let Err(e) = ScopeEngine::evaluate(scope, &action.target) {
            let _ = tx.rollback().await;
            return Ok(AuthorizationDecision::Deny { error: e });
        }

        // 4. Replay Protection: Atomic Check-and-Consume (INV-008)
        let replay_key = sha256_hex(
            DOMAIN_REPLAY,
            format!(
                "{}:{}:{}:{}",
                action.mission_id, action.proposal_id, action.action_id, action.nonce
            )
            .as_bytes(),
        );

        if let Err(e) = tx
            .try_consume_replay(
                &replay_key,
                &action.mission_id,
                &action.proposal_id,
                &action.action_id,
                now,
            )
            .await
        {
            let _ = tx.rollback().await;
            return Ok(AuthorizationDecision::Deny { error: e });
        }

        // 5. Approval Check
        let needs_approval = action.requires_approval || action.risk_class >= RiskClass::High;
        if needs_approval {
            match approval {
                None => {
                    // Record action status as APPROVAL_REQUIRED and commit replay consumption
                    tx.save_action_record(&action, "APPROVAL_REQUIRED", now)
                        .await?;
                    tx.commit().await?;

                    return Ok(AuthorizationDecision::RequireApproval {
                        action: action.clone(),
                        action_hash: action.action_hash.clone(),
                        risk_class: action.risk_class,
                    });
                }
                Some(ref apprv) => {
                    // Verify approval binding against canonical action, requester, and expiry
                    if let Err(e) = apprv.validate_for_action(&action, &context.subject, now) {
                        let _ = tx.rollback().await;
                        return Ok(AuthorizationDecision::Deny { error: e });
                    }

                    // Consume the approval atomically in storage
                    if let Err(e) = tx
                        .consume_approval(&apprv.approval_id, &action.action_hash, now)
                        .await
                    {
                        let _ = tx.rollback().await;
                        return Ok(AuthorizationDecision::Deny { error: e });
                    }
                }
            }
        }

        // 6. Record action as AUTHORIZED and commit transaction atomically
        tx.save_action_record(&action, "AUTHORIZED", now).await?;
        tx.commit().await?;

        Ok(AuthorizationDecision::Allow { action })
    }
}
