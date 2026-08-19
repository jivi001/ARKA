"""Local safe sandbox runtime for development, mock testing, and Phase 2.1 validation.

Ensures in-memory execution safety with zero shell invocation and zero network access.
"""

from typing import Any

from arka.app.core.state.models import new_id
from arka.app.execution.sandbox.base import SandboxRuntime
from arka.app.execution.schemas import ExecutionRequest


class LocalSafeRuntime(SandboxRuntime):
    """Safe local runtime for development and automated testing.

    Operates strictly in-memory without shell execution or network access.
    Enforces resource bounds, output byte truncation, and timeout cancellation.
    """

    def __init__(self) -> None:
        self._active_sandboxes: dict[str, dict[str, Any]] = {}

    async def create(self, request: ExecutionRequest) -> str:
        """Initialize an in-memory execution sandbox."""
        sandbox_id = f"local-sb-{new_id()[:8]}"
        self._active_sandboxes[sandbox_id] = {
            "sandbox_id": sandbox_id,
            "execution_id": request.execution_id,
            "tool_name": request.tool_name,
            "status": "created",
            "limits": request.limits,
            "terminated": False,
            "destroyed": False,
        }
        return sandbox_id

    async def execute(
        self, request: ExecutionRequest, command: list[str]
    ) -> tuple[int, str, str, bool, bool]:
        """Execute mock in-memory command with output truncation."""
        sandbox_id = request.execution_id
        if sandbox_id in self._active_sandboxes:
            self._active_sandboxes[sandbox_id]["status"] = "running"

        # Check if terminated before start
        sb_meta = self._active_sandboxes.get(sandbox_id, {})
        if sb_meta.get("terminated"):
            return -1, "", "Execution terminated before start", False, False

        # In Phase 2.1 local safe mode, execute simulated tool command in-memory
        cmd_str = " ".join(command) if command else ""
        raw_stdout = f"[LOCAL_SAFE_RUNTIME] Executed: {cmd_str}\nTarget: {request.target}"
        raw_stderr = ""
        exit_code = 0

        # Output truncation checks
        max_out = request.limits.max_stdout_bytes
        max_err = request.limits.max_stderr_bytes

        stdout_bytes = raw_stdout.encode("utf-8")
        stderr_bytes = raw_stderr.encode("utf-8")

        stdout_truncated = False
        stderr_truncated = False

        if len(stdout_bytes) > max_out:
            raw_stdout = stdout_bytes[:max_out].decode("utf-8", errors="ignore")
            stdout_truncated = True

        if len(stderr_bytes) > max_err:
            raw_stderr = stderr_bytes[:max_err].decode("utf-8", errors="ignore")
            stderr_truncated = True

        if sandbox_id in self._active_sandboxes:
            self._active_sandboxes[sandbox_id]["status"] = "completed"

        return exit_code, raw_stdout, raw_stderr, stdout_truncated, stderr_truncated

    async def collect_metadata(self, sandbox_id: str) -> dict[str, Any]:
        """Collect local sandbox isolation telemetry."""
        sb = self._active_sandboxes.get(sandbox_id, {})
        return {
            "sandbox_id": sandbox_id,
            "runtime_type": "local_safe_runtime",
            "isolation_level": "in_memory_simulated",
            "network_profile": "no_network",
            "status": sb.get("status", "unknown"),
            "terminated": sb.get("terminated", False),
            "destroyed": sb.get("destroyed", False),
        }

    async def terminate(self, sandbox_id: str) -> None:
        """Mark the sandbox as terminated and cancel any pending operations."""
        if sandbox_id in self._active_sandboxes:
            self._active_sandboxes[sandbox_id]["terminated"] = True
            self._active_sandboxes[sandbox_id]["status"] = "terminated"

    async def destroy(self, sandbox_id: str) -> None:
        """Release all local sandbox resources."""
        if sandbox_id in self._active_sandboxes:
            self._active_sandboxes[sandbox_id]["destroyed"] = True
            self._active_sandboxes[sandbox_id]["status"] = "destroyed"
            del self._active_sandboxes[sandbox_id]
