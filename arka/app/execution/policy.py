from arka.app.execution.schemas import ExecutionLimits, NetworkProfile
from arka.app.tools.schemas.tool_schemas import ToolDefinition, ToolRequest

# Denied shell executables to prevent arbitrary shell invocation
FORBIDDEN_EXECUTABLES = {
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "python",
    "python3",
    "eval",
    "exec",
}

# Dangerous environment variables that must be scrubbed from execution environments
FORBIDDEN_ENV_VARS = {
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PYTHONPATH",
    "NODE_OPTIONS",
    "RUBYOPT",
    "PERL5OPT",
    "DOCKER_HOST",
    "DOCKER_AUTH_CONFIG",
    "KUBECONFIG",
    "DATABASE_URL",
    "DATABASE_SYNC_URL",
    "REDIS_URL",
    "ARKA_LLM_API_KEY",
    "ARKA_LLM_FALLBACK_API_KEY",
    "VAULT_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
}


class ExecutionPolicyError(Exception):
    """Raised when an execution violates execution policy constraints."""


class ExecutionPolicy:
    """Deterministic policy engine for runtime execution constraints.

    Evaluates execution requests against allowlists, resource limits, environment safety,
    and argument structure. The LLM has zero influence over these policies.
    """

    def __init__(
        self,
        default_limits: ExecutionLimits | None = None,
        allowed_executables: set[str] | None = None,
        allow_network: bool = False,
    ) -> None:
        self.default_limits = default_limits or ExecutionLimits()
        self.allowed_executables = allowed_executables  # If None, all except FORBIDDEN are allowed
        self.allow_network = allow_network

    def derive_limits(self, tool_def: ToolDefinition) -> ExecutionLimits:
        """Derive authoritative execution limits from tool definition and policy bounds."""
        timeout = min(
            max(tool_def.timeout_seconds, 1),
            self.default_limits.max_execution_time_seconds,
        )
        return ExecutionLimits(
            max_execution_time_seconds=timeout,
            max_stdout_bytes=self.default_limits.max_stdout_bytes,
            max_stderr_bytes=self.default_limits.max_stderr_bytes,
            max_memory_mb=self.default_limits.max_memory_mb,
            max_cpu_seconds=timeout,
            max_processes=self.default_limits.max_processes,
            max_concurrent_executions=self.default_limits.max_concurrent_executions,
        )

    def validate_request(
        self, request: ToolRequest, tool_def: ToolDefinition
    ) -> tuple[bool, str | None]:
        """Validate that a tool request complies with runtime execution policy."""
        # 1. Authoritative security stamps check
        if not request.scope_validated:
            return False, "Execution rejected: ToolRequest is not scope-validated"
        if not request.policy_approved:
            return False, "Execution rejected: ToolRequest is not policy-approved"
        if not request.engagement_id or not request.task_id:
            return False, "Execution rejected: Missing engagement or task identity"

        # 2. Check tool enabled status
        if not tool_def.enabled:
            return False, f"Execution rejected: Tool '{tool_def.name}' is disabled"

        return True, None

    def validate_command(self, command: list[str]) -> tuple[bool, str | None]:
        """Validate command array structure for safety.

        Ensures arguments are in array format and does not invoke forbidden shells.
        """
        if not command or not isinstance(command, list):
            return False, "Command must be a non-empty list of string arguments"

        executable = command[0].strip().lower().split("/")[-1].split("\\")[-1]

        if executable in FORBIDDEN_EXECUTABLES:
            return False, f"Executable '{executable}' is forbidden by execution policy"

        if self.allowed_executables is not None and executable not in self.allowed_executables:
            return False, f"Executable '{executable}' is not in the allowed executables list"

        for arg in command:
            if not isinstance(arg, str):
                return False, f"Command arguments must be strings, got {type(arg).__name__}"

        return True, None

    def sanitize_environment(self, env: dict[str, str] | None = None) -> dict[str, str]:
        """Scrub forbidden and sensitive environment variables from runtime context."""
        safe_env = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM": "dumb",
        }
        if not env:
            return safe_env

        for k, v in env.items():
            if k.upper() not in FORBIDDEN_ENV_VARS and not k.upper().startswith(
                ("SECRET_", "TOKEN_", "API_KEY_", "PRIVATE_")
            ):
                safe_env[k] = str(v)

        return safe_env

    def resolve_network_profile(
        self, requested_profile: NetworkProfile = NetworkProfile.NO_NETWORK
    ) -> NetworkProfile:
        """Enforce network profile restrictions."""
        if requested_profile != NetworkProfile.NO_NETWORK and not self.allow_network:
            return NetworkProfile.NO_NETWORK
        return requested_profile
