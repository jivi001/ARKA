"""
Per-Mission Context Binding and Monotonic Resource Budget Governance.
"""

from dataclasses import dataclass, field
import threading
import time
from typing import Any, Dict, List, Optional

from .exceptions import BudgetExceededError, EmergencyStopError


class CancellationToken:
    """
    Monotonic cancellation token reacting to Kernel Emergency Stop or Operator Abort.
    Once cancelled, it can NEVER be cleared or reversed.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._cancelled = False
        self._reason = ""
        self._cancelled_at: Optional[float] = None

    def cancel(self, reason: str = "Emergency stop triggered") -> None:
        with self._lock:
            if not self._cancelled:
                self._cancelled = True
                self._reason = reason
                self._cancelled_at = time.time()

    @property
    def is_cancelled(self) -> bool:
        with self._lock:
            return self._cancelled

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason

    def check_cancelled(self) -> None:
        """Raises EmergencyStopError if the token has been triggered."""
        with self._lock:
            if self._cancelled:
                raise EmergencyStopError(
                    f"Agent execution halted: {self._reason} (cancelled at {self._cancelled_at})"
                )


@dataclass
class ResourceBudget:
    """
    Monotonic resource governor enforcing step, token, and duration ceilings.
    """

    max_steps: int = 25
    max_tokens: int = 100_000
    timeout_seconds: Optional[float] = 300.0  # 5 minutes default

    used_steps: int = 0
    used_prompt_tokens: int = 0
    used_completion_tokens: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def total_tokens_used(self) -> int:
        return self.used_prompt_tokens + self.used_completion_tokens

    def check_budget(self) -> None:
        """Checks timeout, step limit, and token ceiling, raising BudgetExceededError if breached."""
        self.check_timeout()
        if self.used_steps >= self.max_steps:
            raise BudgetExceededError(
                f"Execution step limit exceeded: {self.used_steps} >= {self.max_steps}"
            )
        if self.total_tokens_used >= self.max_tokens:
            raise BudgetExceededError(
                f"Token ceiling exceeded: {self.total_tokens_used} >= {self.max_tokens} tokens"
            )

    def record_step(self) -> None:
        self.check_timeout()
        self.used_steps += 1
        if self.used_steps > self.max_steps:
            raise BudgetExceededError(
                f"Execution step limit exceeded: {self.used_steps} > {self.max_steps}"
            )

    def record_tokens(self, prompt_tokens: int, completion_tokens: int) -> None:
        self.check_timeout()
        self.used_prompt_tokens += max(0, prompt_tokens)
        self.used_completion_tokens += max(0, completion_tokens)
        if self.total_tokens_used > self.max_tokens:
            raise BudgetExceededError(
                f"Token ceiling exceeded: {self.total_tokens_used} > {self.max_tokens} tokens"
            )

    def check_timeout(self) -> None:
        if self.timeout_seconds is not None:
            elapsed = time.time() - self.start_time
            if elapsed > self.timeout_seconds:
                raise BudgetExceededError(
                    f"Execution timeout exceeded: {elapsed:.2f}s > {self.timeout_seconds}s"
                )

    def is_exhausted(self) -> bool:
        if self.used_steps >= self.max_steps:
            return True
        if self.total_tokens_used >= self.max_tokens:
            return True
        if self.timeout_seconds is not None:
            if (time.time() - self.start_time) >= self.timeout_seconds:
                return True
        return False


@dataclass
class MissionContext:
    """
    Immutable mission scope and execution context bound to an agent run.
    """

    mission_id: str
    operator_id: str
    scope_id: str
    authorized_targets: List[str] = field(default_factory=list)
    budget: ResourceBudget = field(default_factory=ResourceBudget)
    cancellation_token: CancellationToken = field(default_factory=CancellationToken)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.mission_id or not self.mission_id.strip():
            raise ValueError("MissionContext requires a non-empty mission_id")
        if not self.operator_id or not self.operator_id.strip():
            raise ValueError("MissionContext requires a non-empty operator_id")
