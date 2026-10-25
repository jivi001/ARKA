"""
ARKA Bounded Python Agent Runtime.
Phase 3 Module E implementation.

Governed by AGENTS.md Invariants:
1. DISCOVERED != AUTHORIZED
2. Zero Direct OS, Shell, or Socket Execution Authority
3. Monotonic Child Authority & Resource Quotas
4. Immutable Mission Identity Binding
"""

from .context import CancellationToken, MissionContext, ResourceBudget
from .exceptions import (
    AgentRuntimeError,
    BudgetExceededError,
    CapabilityViolationError,
    EmergencyStopError,
    GatewayCommunicationError,
    InvalidProposalError,
)
from .proposal import RawActionProposal
from .base import AgentRole, AgentStepResult, BaseAgent
from .recon import ReconnaissanceAgent
from .vuln_analysis import VulnerabilityAnalysisAgent
from .orchestrator import OrchestratorAgent

__all__ = [
    "CancellationToken",
    "MissionContext",
    "ResourceBudget",
    "AgentRuntimeError",
    "BudgetExceededError",
    "CapabilityViolationError",
    "EmergencyStopError",
    "GatewayCommunicationError",
    "InvalidProposalError",
    "RawActionProposal",
    "AgentRole",
    "AgentStepResult",
    "BaseAgent",
    "ReconnaissanceAgent",
    "VulnerabilityAnalysisAgent",
    "OrchestratorAgent",
]
