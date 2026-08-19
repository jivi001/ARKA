"""Unit tests for ExecutionPolicy (Phase 2.1)."""

import pytest

from arka.app.core.state.models import RiskLevel
from arka.app.execution.policy import ExecutionPolicy
from arka.app.execution.schemas import ExecutionLimits, NetworkProfile
from arka.app.tools.schemas.tool_schemas import ToolDefinition, ToolRequest


@pytest.fixture
def policy():
    return ExecutionPolicy(
        default_limits=ExecutionLimits(max_execution_time_seconds=300),
        allowed_executables={"nmap", "ffuf", "nuclei", "echo"},
        allow_network=False,
    )


@pytest.fixture
def dummy_tool_def():
    return ToolDefinition(
        name="test_tool",
        description="A test tool",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        risk_level=RiskLevel.LOW,
        timeout_seconds=120,
        enabled=True,
    )


class TestExecutionPolicyEnforcement:
    def test_forbidden_shell_executables_rejected(self, policy: ExecutionPolicy):
        forbidden = [
            ["sh", "-c", "echo hello"],
            ["/bin/bash", "-c", "whoami"],
            ["cmd.exe", "/c", "dir"],
            ["powershell.exe", "-Command", "Get-Process"],
            ["python", "-c", "import os; os.system('ls')"],
        ]
        for cmd in forbidden:
            is_valid, err = policy.validate_command(cmd)
            assert is_valid is False
            assert "forbidden" in (err or "").lower()

    def test_allowed_executables_accepted(self, policy: ExecutionPolicy):
        valid_cmd = ["nmap", "-sT", "-p", "80", "192.168.1.1"]
        is_valid, err = policy.validate_command(valid_cmd)
        assert is_valid is True
        assert err is None

    def test_disallowed_executable_rejected(self, policy: ExecutionPolicy):
        disallowed_cmd = ["curl", "http://example.com"]
        is_valid, err = policy.validate_command(disallowed_cmd)
        assert is_valid is False
        assert "not in the allowed executables list" in (err or "")

    def test_invalid_command_formats_rejected(self, policy: ExecutionPolicy):
        # Empty list
        is_valid, err = policy.validate_command([])
        assert is_valid is False

        # Non-string elements
        is_valid, err = policy.validate_command(["echo", 123])  # type: ignore[list-item]
        assert is_valid is False
        assert "must be strings" in (err or "")

    def test_environment_sanitization(self, policy: ExecutionPolicy):
        untrusted_env = {
            "LD_PRELOAD": "/tmp/evil.so",
            "DATABASE_URL": "postgresql://arka:secret@db:5432/arka",
            "ARKA_LLM_API_KEY": "sk-or-v1-secret",
            "SECRET_KEY": "supersecret",
            "CUSTOM_VAR": "safe_value",
        }
        sanitized = policy.sanitize_environment(untrusted_env)

        assert "LD_PRELOAD" not in sanitized
        assert "DATABASE_URL" not in sanitized
        assert "ARKA_LLM_API_KEY" not in sanitized
        assert "SECRET_KEY" not in sanitized
        assert sanitized["CUSTOM_VAR"] == "safe_value"
        assert "LANG" in sanitized
        assert "PATH" in sanitized

    def test_network_profile_enforcement(self, policy: ExecutionPolicy):
        # When allow_network is False, all requests resolve to NO_NETWORK
        profile = policy.resolve_network_profile(NetworkProfile.AUTHORIZED_TARGET_NETWORK)
        assert profile == NetworkProfile.NO_NETWORK

    def test_derive_limits(self, policy: ExecutionPolicy, dummy_tool_def: ToolDefinition):
        limits = policy.derive_limits(dummy_tool_def)
        assert limits.max_execution_time_seconds == 120
        assert limits.max_stdout_bytes == 1_048_576
        assert limits.max_stderr_bytes == 1_048_576

    def test_validate_request_checks_stamps_and_identity(
        self, policy: ExecutionPolicy, dummy_tool_def: ToolDefinition
    ):
        # Valid request
        valid_req = ToolRequest(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            tool_name="test_tool",
            target="example.com",
            scope_validated=True,
            policy_approved=True,
        )
        is_valid, err = policy.validate_request(valid_req, dummy_tool_def)
        assert is_valid is True
        assert err is None

        # Missing task identity
        missing_task_req = ToolRequest(
            engagement_id="eng-1",
            task_id="",
            agent_id="agent-1",
            tool_name="test_tool",
            target="example.com",
            scope_validated=True,
            policy_approved=True,
        )
        is_valid, err = policy.validate_request(missing_task_req, dummy_tool_def)
        assert is_valid is False
        assert "Missing engagement or task identity" in (err or "")
