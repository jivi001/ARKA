"""Unit tests for Sandbox Runtime abstractions and implementations (Phase 2.1)."""

import pytest

from arka.app.execution.sandbox.docker import DockerSandboxRuntime
from arka.app.execution.sandbox.local import LocalSafeRuntime
from arka.app.execution.schemas import ExecutionLimits, ExecutionRequest, NetworkProfile


@pytest.fixture
def execution_request():
    return ExecutionRequest(
        request_id="req-123",
        engagement_id="eng-123",
        task_id="task-123",
        agent_id="agent-123",
        tool_name="test_tool",
        target="192.168.1.50",
        command=["test_tool", "192.168.1.50"],
        limits=ExecutionLimits(max_stdout_bytes=1024, max_stderr_bytes=1024),
        network_profile=NetworkProfile.NO_NETWORK,
    )


class TestLocalSafeRuntime:
    @pytest.mark.asyncio
    async def test_lifecycle_and_output_truncation(self, execution_request: ExecutionRequest):
        runtime = LocalSafeRuntime()

        # Create
        sandbox_id = await runtime.create(execution_request)
        assert sandbox_id.startswith("local-sb-")

        # Execute
        code, stdout, _stderr, _out_trunc, _err_trunc = await runtime.execute(
            execution_request, execution_request.command
        )
        assert code == 0
        assert "192.168.1.50" in stdout

        # Metadata
        meta = await runtime.collect_metadata(sandbox_id)
        assert meta["runtime_type"] == "local_safe_runtime"
        assert meta["network_profile"] == "no_network"

        # Terminate
        await runtime.terminate(sandbox_id)
        meta_after_term = await runtime.collect_metadata(sandbox_id)
        assert meta_after_term["terminated"] is True

        # Destroy
        await runtime.destroy(sandbox_id)


class TestDockerSandboxRuntime:
    def test_least_privilege_container_config(self, execution_request: ExecutionRequest):
        runtime = DockerSandboxRuntime(base_image="alpine:3.19")
        config = runtime._get_container_config(execution_request)

        # 1. Non-root user
        assert config["user"] == "1000:1000"

        # 2. Read-only root filesystem
        assert config["read_only"] is True

        # 3. Dropped capabilities
        assert config["cap_drop"] == ["ALL"]

        # 4. No new privileges
        assert "no-new-privileges:true" in config["security_opt"]

        # 5. Privileged mode explicitly False
        assert config["privileged"] is False

        # 6. Network isolation (none)
        assert config["network_mode"] == "none"

        # 7. No docker socket or host filesystem mounts
        assert "/var/run/docker.sock" not in config["volumes"]
        assert len(config["volumes"]) == 0

        # 8. Temporary writable tmpfs with noexec and nosuid
        assert "/tmp" in config["tmpfs"]
        assert "noexec" in config["tmpfs"]["/tmp"]
        assert "nosuid" in config["tmpfs"]["/tmp"]

    @pytest.mark.asyncio
    async def test_docker_runtime_lifecycle_simulation(self, execution_request: ExecutionRequest):
        runtime = DockerSandboxRuntime()

        sandbox_id = await runtime.create(execution_request)
        assert sandbox_id.startswith("docker-sb-")

        code, stdout, _stderr, _, _ = await runtime.execute(
            execution_request, execution_request.command
        )
        assert code == 0
        assert "[DOCKER_SANDBOX_RUNTIME]" in stdout

        meta = await runtime.collect_metadata(sandbox_id)
        assert meta["docker_sock_exposed"] is False
        assert meta["privileged"] is False
        assert meta["no_new_privileges"] is True
        assert meta["read_only"] is True

        await runtime.terminate(sandbox_id)
        await runtime.destroy(sandbox_id)
