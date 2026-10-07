//! Mission Lifecycle and Mission Isolation Service.
//!
//! Enforces:
//! - INV-009: Cross-mission access strictly denied (fail closed).
//! - Section 7: 5-state lifecycle state machine enforcement.
//! - Section 8: Mission context required on all resource accesses.
//! - Emergency Stop gate blocking mission activation.

use crate::storage::Storage;
use arka_core_types::clock::Clock;
use arka_core_types::errors::KernelSecurityError;
use arka_core_types::id::MissionId;
use arka_core_types::mission::{Mission, MissionState};
use arka_core_types::subject::AuthenticatedContext;
use std::sync::Arc;

pub struct MissionService {
    storage: Arc<dyn Storage>,
    clock: Arc<dyn Clock>,
}

impl MissionService {
    pub fn new(storage: Arc<dyn Storage>, clock: Arc<dyn Clock>) -> Self {
        Self { storage, clock }
    }

    /// Creates a new mission in CREATED state.
    pub async fn create_mission(
        &self,
        id: MissionId,
        name: impl Into<String>,
        scope_ref: impl Into<String>,
        requester: &AuthenticatedContext,
    ) -> Result<Mission, KernelSecurityError> {
        let op_id = match &requester.subject {
            arka_core_types::subject::Subject::Operator(op) => op.clone(),
            _ => {
                return Err(KernelSecurityError::AuthenticationFailed(
                    "Only human operators can create missions".to_string(),
                ))
            }
        };

        let now = self.clock.now_unix();
        let mission = Mission::new(id, name, scope_ref, op_id, now);

        let mut tx = self.storage.begin_transaction().await?;
        if tx.get_mission(&mission.id).await?.is_some() {
            let _ = tx.rollback().await;
            return Err(KernelSecurityError::InternalFailure(format!(
                "Mission {} already exists",
                mission.id
            )));
        }

        tx.save_mission(&mission).await?;
        tx.commit().await?;

        Ok(mission)
    }

    /// Retrieves a mission, enforcing strict mission isolation boundaries.
    pub async fn get_mission(
        &self,
        mission_id: &MissionId,
        requester: &AuthenticatedContext,
    ) -> Result<Mission, KernelSecurityError> {
        // INV-009: Cross-mission isolation
        // If the authenticated token is bound to a specific mission, it CANNOT access another mission's state
        if requester.mission_id != *mission_id {
            return Err(KernelSecurityError::CrossMissionAccessDenied {
                requester_mission: requester.mission_id.clone(),
                target_mission: mission_id.clone(),
            });
        }

        let mut tx = self.storage.begin_transaction().await?;
        let maybe_mission = tx.get_mission(mission_id).await?;
        let _ = tx.rollback().await;

        maybe_mission.ok_or_else(|| KernelSecurityError::MissionNotFound(mission_id.clone()))
    }

    /// Transitions a mission to a new state with atomic persistence and validation.
    pub async fn transition_mission(
        &self,
        mission_id: &MissionId,
        target_state: MissionState,
        requester: &AuthenticatedContext,
    ) -> Result<Mission, KernelSecurityError> {
        // Enforce mission isolation
        if requester.mission_id != *mission_id {
            return Err(KernelSecurityError::CrossMissionAccessDenied {
                requester_mission: requester.mission_id.clone(),
                target_mission: mission_id.clone(),
            });
        }

        let mut tx = self.storage.begin_transaction().await?;

        // Check emergency stop state within the transaction
        let estop_active = tx.is_emergency_stop_active().await?;

        let mut mission = tx
            .get_mission(mission_id)
            .await?
            .ok_or_else(|| KernelSecurityError::MissionNotFound(mission_id.clone()))?;

        let now = self.clock.now_unix();
        mission.transition_to(target_state, &requester.subject, estop_active, now)?;

        tx.save_mission(&mission).await?;
        tx.commit().await?;

        Ok(mission)
    }
}
