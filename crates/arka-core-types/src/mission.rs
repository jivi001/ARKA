//! Mission Model and Lifecycle State Machine.
//!
//! Enforces:
//! - 5-State explicit lifecycle: Created -> Active <-> Paused -> Completed / Terminated
//! - Operator-only state mutations (agents cannot mutate mission state)
//! - Emergency Stop gate blocking transitions to Active
//! - Terminal immutable states (Completed, Terminated)

use crate::errors::KernelSecurityError;
use crate::id::{MissionId, OperatorId};
use crate::subject::Subject;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The explicit 5 states of the ARKA Mission lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MissionState {
    Created,
    Active,
    Paused,
    Completed,
    Terminated,
}

impl MissionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            MissionState::Created => "CREATED",
            MissionState::Active => "ACTIVE",
            MissionState::Paused => "PAUSED",
            MissionState::Completed => "COMPLETED",
            MissionState::Terminated => "TERMINATED",
        }
    }

    /// Validates if transition from `self` to `target` is legally permitted.
    pub fn can_transition_to(&self, target: MissionState) -> bool {
        match (self, target) {
            // Created can transition to Active (launched) or Terminated (aborted)
            (MissionState::Created, MissionState::Active) => true,
            (MissionState::Created, MissionState::Terminated) => true,

            // Active can transition to Paused, Completed, or Terminated
            (MissionState::Active, MissionState::Paused) => true,
            (MissionState::Active, MissionState::Completed) => true,
            (MissionState::Active, MissionState::Terminated) => true,

            // Paused can resume to Active or be Terminated
            (MissionState::Paused, MissionState::Active) => true,
            (MissionState::Paused, MissionState::Terminated) => true,

            // Self-transitions are idempotent no-ops
            (s1, s2) if *s1 == s2 => true,

            // Completed and Terminated are terminal states (no transitions allowed)
            _ => false,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, MissionState::Completed | MissionState::Terminated)
    }

    pub fn allows_action_execution(&self) -> bool {
        matches!(self, MissionState::Active)
    }
}

impl fmt::Display for MissionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Represents an authorized security mission instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mission {
    pub id: MissionId,
    pub name: String,
    pub state: MissionState,
    pub scope_ref: String,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub created_by: OperatorId,
}

impl Mission {
    pub fn new(
        id: MissionId,
        name: impl Into<String>,
        scope_ref: impl Into<String>,
        created_by: OperatorId,
        now_unix: u64,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            state: MissionState::Created,
            scope_ref: scope_ref.into(),
            created_at_unix: now_unix,
            updated_at_unix: now_unix,
            created_by,
        }
    }

    /// Evaluates and applies a state transition with strict authorization and emergency-stop checks.
    pub fn transition_to(
        &mut self,
        target_state: MissionState,
        requester: &Subject,
        emergency_stop_active: bool,
        now_unix: u64,
    ) -> Result<(), KernelSecurityError> {
        // Invariant: Only authenticated human operators can mutate mission lifecycle
        if !requester.is_operator() {
            return Err(KernelSecurityError::AuthenticationFailed(
                "Non-operator subject cannot transition mission state".to_string(),
            ));
        }

        // Invariant: Emergency stop blocks transition to Active
        if emergency_stop_active && target_state == MissionState::Active {
            return Err(KernelSecurityError::EmergencyStopActive(
                "Cannot activate mission while emergency stop is active".to_string(),
            ));
        }

        if !self.state.can_transition_to(target_state) {
            return Err(KernelSecurityError::MissionStateInvalid {
                current: self.state.to_string(),
                target: target_state.to_string(),
            });
        }

        self.state = target_state;
        self.updated_at_unix = now_unix;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::AgentId;

    #[test]
    fn test_valid_mission_lifecycle_flow() {
        let op = OperatorId::new("opr-lead").unwrap();
        let requester = Subject::Operator(op.clone());
        let mut mission = Mission::new(
            MissionId::new("mis-ctf-01").unwrap(),
            "CTF Assessment",
            "scope-01",
            op,
            1000,
        );

        assert_eq!(mission.state, MissionState::Created);
        assert!(!mission.state.allows_action_execution());

        // Created -> Active
        assert!(mission
            .transition_to(MissionState::Active, &requester, false, 1010)
            .is_ok());
        assert_eq!(mission.state, MissionState::Active);
        assert!(mission.state.allows_action_execution());

        // Active -> Paused
        assert!(mission
            .transition_to(MissionState::Paused, &requester, false, 1020)
            .is_ok());
        assert_eq!(mission.state, MissionState::Paused);
        assert!(!mission.state.allows_action_execution());

        // Paused -> Active
        assert!(mission
            .transition_to(MissionState::Active, &requester, false, 1030)
            .is_ok());
        assert_eq!(mission.state, MissionState::Active);

        // Active -> Completed (terminal)
        assert!(mission
            .transition_to(MissionState::Completed, &requester, false, 1040)
            .is_ok());
        assert_eq!(mission.state, MissionState::Completed);
        assert!(mission.state.is_terminal());

        // Completed -> Active must fail
        let res = mission.transition_to(MissionState::Active, &requester, false, 1050);
        assert!(matches!(
            res,
            Err(KernelSecurityError::MissionStateInvalid { .. })
        ));
    }

    #[test]
    fn test_agent_cannot_transition_mission_state() {
        let op = OperatorId::new("opr-lead").unwrap();
        let agent = Subject::Agent(AgentId::new("agt-worker").unwrap());
        let mut mission = Mission::new(
            MissionId::new("mis-ctf-02").unwrap(),
            "CTF Assessment",
            "scope-02",
            op,
            1000,
        );

        let res = mission.transition_to(MissionState::Active, &agent, false, 1010);
        assert!(matches!(
            res,
            Err(KernelSecurityError::AuthenticationFailed(_))
        ));
    }

    #[test]
    fn test_emergency_stop_blocks_activation() {
        let op = OperatorId::new("opr-lead").unwrap();
        let requester = Subject::Operator(op.clone());
        let mut mission = Mission::new(
            MissionId::new("mis-ctf-03").unwrap(),
            "CTF Assessment",
            "scope-03",
            op,
            1000,
        );

        let res = mission.transition_to(MissionState::Active, &requester, true, 1010);
        assert!(matches!(
            res,
            Err(KernelSecurityError::EmergencyStopActive(_))
        ));
    }
}
