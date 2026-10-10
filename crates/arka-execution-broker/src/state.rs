//! State machine for execution units in the ARKA Execution Broker.
//!
//! Enforces:
//! - Legal transitions: AUTHORIZED -> DISPATCHING -> RUNNING -> COMPLETED | FAILED | TIMED_OUT | CANCELLED
//! - Terminal state immutability (once in a terminal state, no further transitions are permitted)
//! - Invariants INV-001, INV-004, INV-006

use crate::errors::BrokerError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionState {
    Authorized,
    Dispatching,
    Running,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

impl ExecutionState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::TimedOut | Self::Cancelled
        )
    }

    pub fn validate_transition(&self, next: ExecutionState) -> Result<(), BrokerError> {
        if self.can_transition_to(next) {
            Ok(())
        } else {
            Err(BrokerError::IllegalStateTransition {
                from: format!("{:?}", self),
                to: format!("{:?}", next),
            })
        }
    }

    pub fn can_transition_to(&self, next: ExecutionState) -> bool {
        matches!(
            (self, next),
            (Self::Authorized, Self::Dispatching)
                | (Self::Authorized, Self::Cancelled)
                | (Self::Authorized, Self::Failed)
                | (Self::Dispatching, Self::Running)
                | (Self::Dispatching, Self::Failed)
                | (Self::Dispatching, Self::Cancelled)
                | (Self::Running, Self::Completed)
                | (Self::Running, Self::Failed)
                | (Self::Running, Self::TimedOut)
                | (Self::Running, Self::Cancelled)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_lifecycle_transitions() {
        assert!(ExecutionState::Authorized.can_transition_to(ExecutionState::Dispatching));
        assert!(ExecutionState::Dispatching.can_transition_to(ExecutionState::Running));
        assert!(ExecutionState::Running.can_transition_to(ExecutionState::Completed));
    }

    #[test]
    fn test_invalid_transitions_rejected() {
        assert!(!ExecutionState::Completed.can_transition_to(ExecutionState::Running));
        assert!(!ExecutionState::Cancelled.can_transition_to(ExecutionState::Dispatching));
        assert!(!ExecutionState::Failed.can_transition_to(ExecutionState::Completed));
        assert!(!ExecutionState::Authorized.can_transition_to(ExecutionState::Running));
    }
}
