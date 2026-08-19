"""Sandbox runtime abstraction for ARKA Phase 2.1."""

from abc import ABC, abstractmethod
from typing import Any

from arka.app.execution.schemas import ExecutionRequest


class SandboxRuntime(ABC):
    """Abstract base class for sandbox runtime isolation engines.

    Hides containerization, namespace filtering, and execution mechanics
    from the control plane and tool adapters.
    """

    @abstractmethod
    async def create(self, request: ExecutionRequest) -> str:
        """Create and initialize an isolated execution sandbox.

        Returns:
            sandbox_id: Unique identifier for the created sandbox.
        """

    @abstractmethod
    async def execute(
        self, request: ExecutionRequest, command: list[str]
    ) -> tuple[int, str, str, bool, bool]:
        """Execute a validated command array inside the sandbox.

        Returns:
            tuple of (exit_code, stdout, stderr, stdout_truncated, stderr_truncated)
        """

    @abstractmethod
    async def collect_metadata(self, sandbox_id: str) -> dict[str, Any]:
        """Collect runtime performance and isolation telemetry from the sandbox."""

    @abstractmethod
    async def terminate(self, sandbox_id: str) -> None:
        """Gracefully or forcefully terminate running processes in the sandbox."""

    @abstractmethod
    async def destroy(self, sandbox_id: str) -> None:
        """Clean up and release all resources associated with the sandbox."""
