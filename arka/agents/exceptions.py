"""
ARKA Agent Runtime Typed Exceptions.
"""


class AgentRuntimeError(Exception):
    """Base exception for all agent runtime errors."""

    pass


class BudgetExceededError(AgentRuntimeError):
    """Raised when an agent exceeds its token, step, or time budget."""

    pass


class EmergencyStopError(AgentRuntimeError):
    """Raised when an operation is cancelled or emergency stopped."""

    pass


class CapabilityViolationError(AgentRuntimeError):
    """Raised when an agent attempts to propose an action exceeding its role taxonomy."""

    pass


class InvalidProposalError(AgentRuntimeError):
    """Raised when an action proposal fails schema, identity, or nonce validation."""

    pass


class GatewayCommunicationError(AgentRuntimeError):
    """Raised when communication with the LLM Gateway fails."""

    pass
