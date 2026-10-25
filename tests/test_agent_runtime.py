"""
Unit and Security Acceptance Tests for Module E:
Bounded Python Agent Runtime.

Validates:
- Monotonic step and token budget enforcement (BudgetExceededError)
- Real-time Emergency Stop cancellation token reaction (EmergencyStopError)
- Role-based capability boundary enforcement (CapabilityViolationError)
- Untrusted proposal construction and mission identity binding
- Zero direct OS, shell, or socket execution authority on agent instances
"""

import time
import unittest
from unittest.mock import MagicMock

from arka.agents import (
    AgentRole,
    BudgetExceededError,
    CancellationToken,
    CapabilityViolationError,
    EmergencyStopError,
    MissionContext,
    OrchestratorAgent,
    RawActionProposal,
    ReconnaissanceAgent,
    ResourceBudget,
    VulnerabilityAnalysisAgent,
)
from arka.gateway.models import GatewayInferenceResponse, ModelOutput


def create_mock_gateway_client(content: str, prompt_tokens: int = 50, completion_tokens: int = 50):
    client = MagicMock()
    mock_output = ModelOutput(
        content=content,
        finish_reason="stop",
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )
    mock_resp = GatewayInferenceResponse(
        request_id="req-test-123",
        status="SUCCESS",
        output=mock_output,
    )
    client.complete.return_value = mock_resp
    return client


class TestAgentRuntime(unittest.TestCase):

    def setUp(self):
        self.context = MissionContext(
            mission_id="msn-test-alpha",
            operator_id="op-sec-lead",
            scope_id="scope-prod-perimeter",
            authorized_targets=["198.51.100.1", "scanme.arka.internal"],
            budget=ResourceBudget(max_steps=5, max_tokens=1000, timeout_seconds=10.0),
        )

    def test_bounded_step_count_enforcement(self):
        """Verifies that exceeding the step ceiling raises BudgetExceededError."""
        self.context.budget.max_steps = 2
        mock_client = create_mock_gateway_client(
            '{"thought": "Step completed", "action": null, "final_summary": null}'
        )
        agent = ReconnaissanceAgent(gateway_client=mock_client)

        # Step 1
        res1 = agent.run_step(self.context, "Initial scan")
        self.assertEqual(self.context.budget.used_steps, 1)

        # Step 2
        res2 = agent.run_step(self.context, "Second scan")
        self.assertEqual(self.context.budget.used_steps, 2)

        # Step 3 must fail closed
        with self.assertRaises(BudgetExceededError) as ctx:
            agent.run_step(self.context, "Third scan attempt")
        self.assertIn("Execution step limit exceeded", str(ctx.exception))

    def test_token_ceiling_quota_enforcement(self):
        """Verifies that exceeding the token budget raises BudgetExceededError."""
        self.context.budget.max_tokens = 300
        # Each response consumes 200 tokens (100 prompt + 100 completion)
        mock_client = create_mock_gateway_client(
            '{"thought": "Analyzing perimeter", "action": null, "final_summary": null}',
            prompt_tokens=100,
            completion_tokens=100,
        )
        agent = ReconnaissanceAgent(gateway_client=mock_client)

        # First call: 200 tokens (OK)
        agent.run_step(self.context, "Step 1")
        self.assertEqual(self.context.budget.total_tokens_used, 200)

        # Second call: 200 + 200 = 400 > 300 (Exceeded)
        with self.assertRaises(BudgetExceededError) as ctx:
            agent.run_step(self.context, "Step 2")
        self.assertIn("Token ceiling exceeded", str(ctx.exception))

    def test_timeout_budget_enforcement(self):
        """Verifies that an expired execution duration raises BudgetExceededError."""
        self.context.budget.timeout_seconds = 0.05
        mock_client = create_mock_gateway_client('{"thought": "Slow step"}')
        agent = ReconnaissanceAgent(gateway_client=mock_client)

        time.sleep(0.1)  # Trigger timeout
        with self.assertRaises(BudgetExceededError) as ctx:
            agent.run_step(self.context, "Timeout task")
        self.assertIn("timeout exceeded", str(ctx.exception))

    def test_emergency_stop_cancellation_immediate_halt(self):
        """Verifies that monotonic cancellation immediately blocks reasoning execution."""
        mock_client = create_mock_gateway_client('{"thought": "Should not run"}')
        agent = ReconnaissanceAgent(gateway_client=mock_client)

        # Trigger emergency stop
        self.context.cancellation_token.cancel("Monotonic E-STOP operator signal")
        self.assertTrue(self.context.cancellation_token.is_cancelled)

        with self.assertRaises(EmergencyStopError) as ctx:
            agent.run_step(self.context, "Attempted step after E-Stop")
        self.assertIn("Monotonic E-STOP operator signal", str(ctx.exception))

        # Ensure zero inference calls were made to Gateway
        mock_client.complete.assert_not_called()

    def test_capability_violation_rejection(self):
        """
        SECURITY BOUNDARY TEST:
        Reconnaissance agent is offered CONTROLLED_EXPLOITATION.
        Must fail closed with CapabilityViolationError.
        """
        malicious_llm_output = """{
            "thought": "I found a vulnerable service. Let me exploit it directly.",
            "action": {
                "capability_id": "CONTROLLED_EXPLOITATION",
                "target": "198.51.100.1",
                "parameters": {"payload": "test_exploit"}
            },
            "final_summary": null
        }"""
        mock_client = create_mock_gateway_client(malicious_llm_output)
        agent = ReconnaissanceAgent(gateway_client=mock_client)

        with self.assertRaises(CapabilityViolationError) as ctx:
            agent.run_step(self.context, "Find vulnerabilities")

        self.assertIn("Security Boundary Violation", str(ctx.exception))
        self.assertIn("CONTROLLED_EXPLOITATION", str(ctx.exception))

    def test_valid_action_proposal_construction(self):
        """Verifies that authorized actions are parsed into valid RawActionProposals."""
        valid_llm_output = """{
            "thought": "Starting TCP port scan on target perimeter.",
            "action": {
                "capability_id": "PORT_SCAN",
                "target": "198.51.100.1",
                "parameters": {"ports": [80, 443, 8080], "mode": "syn"}
            },
            "final_summary": null
        }"""
        mock_client = create_mock_gateway_client(valid_llm_output)
        agent = ReconnaissanceAgent(gateway_client=mock_client)

        step_res = agent.run_step(self.context, "Perform network scan")
        self.assertIsNotNone(step_res.proposal)
        proposal = step_res.proposal

        self.assertEqual(proposal.mission_id, "msn-test-alpha")
        self.assertEqual(proposal.capability_id, "PORT_SCAN")
        self.assertEqual(proposal.target, "198.51.100.1")
        self.assertEqual(proposal.parameters["ports"], [80, 443, 8080])
        self.assertTrue(proposal.proposal_id.startswith("prop-"))
        self.assertTrue(len(proposal.nonce) > 10)

        # Verify wire serialization format
        proposal_dict = proposal.to_dict()
        self.assertEqual(proposal_dict["mission_id"], "msn-test-alpha")
        self.assertIn("nonce", proposal_dict)

    def test_vuln_analysis_agent_capability_boundaries(self):
        """Verifies VulnerabilityAnalysisAgent permits HTTP_REQUEST but rejects PORT_SCAN."""
        vuln_output = """{
            "thought": "Probing HTTP endpoints",
            "action": {
                "capability_id": "HTTP_REQUEST",
                "target": "198.51.100.1",
                "parameters": {"method": "GET", "path": "/"}
            }
        }"""
        mock_client = create_mock_gateway_client(vuln_output)
        agent = VulnerabilityAnalysisAgent(gateway_client=mock_client)

        res = agent.run_step(self.context, "Analyze service")
        self.assertIsNotNone(res.proposal)
        self.assertEqual(res.proposal.capability_id, "HTTP_REQUEST")

        # Now attempt PORT_SCAN (which is Recon-only)
        recon_output = """{
            "thought": "Attempting port scan",
            "action": {
                "capability_id": "PORT_SCAN",
                "target": "198.51.100.1",
                "parameters": {}
            }
        }"""
        mock_client_recon = create_mock_gateway_client(recon_output)
        agent_restricted = VulnerabilityAnalysisAgent(gateway_client=mock_client_recon)
        with self.assertRaises(CapabilityViolationError):
            agent_restricted.run_step(self.context, "Analyze ports")

    def test_orchestrator_agent_capabilities(self):
        """Verifies OrchestratorAgent permits delegation management only."""
        orch_output = """{
            "thought": "Delegating recon task",
            "action": {
                "capability_id": "DELEGATION_MANAGEMENT",
                "target": "recon-agent-01",
                "parameters": {"task": "scan perimeter"}
            }
        }"""
        mock_client = create_mock_gateway_client(orch_output)
        agent = OrchestratorAgent(gateway_client=mock_client)
        res = agent.run_step(self.context, "Orchestrate")
        self.assertIsNotNone(res.proposal)
        self.assertEqual(res.proposal.capability_id, "DELEGATION_MANAGEMENT")

    def test_zero_direct_execution_authority(self):
        """
        INVARIANT VERIFICATION:
        Ensures agents have zero OS execution, socket connection, or shell execution APIs.
        """
        agent = ReconnaissanceAgent(gateway_client=MagicMock())
        forbidden_attributes = [
            "run_command",
            "exec",
            "execute",
            "shell",
            "socket",
            "connect",
            "spawn_worker",
            "dispatch",
        ]
        for attr in forbidden_attributes:
            self.assertFalse(
                hasattr(agent, attr),
                f"Agent must not expose direct execution attribute '{attr}'",
            )

    def test_agent_gateway_uds_integration(self):
        """
        Tests end-to-end IPC integration:
        Agent -> GatewayClient -> Unix Domain Socket -> UDS Server -> Agent Response.
        """
        import asyncio
        import json
        import os
        import struct
        import tempfile
        import threading
        from arka.gateway import GatewayClient

        temp_dir = tempfile.mkdtemp()
        sock_path = os.path.join(temp_dir, "test_agent_gw.sock")

        async def handle_client(reader, writer):
            data_len_buf = await reader.readexactly(4)
            (data_len,) = struct.unpack(">I", data_len_buf)
            payload = await reader.readexactly(data_len)
            req_data = json.loads(payload.decode("utf-8"))

            resp_payload = {
                "request_id": req_data["request_id"],
                "status": "SUCCESS",
                "output": {
                    "content": json.dumps(
                        {
                            "thought": "UDS roundtrip verified",
                            "action": {
                                "capability_id": "PORT_SCAN",
                                "target": "198.51.100.1",
                                "parameters": {"ports": [80]},
                            },
                            "final_summary": None,
                        }
                    ),
                    "finish_reason": "stop",
                    "prompt_tokens": 40,
                    "completion_tokens": 15,
                },
            }
            body = json.dumps(resp_payload).encode("utf-8")
            header = struct.pack(">I", len(body))
            writer.write(header + body)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        loop = asyncio.new_event_loop()
        server = None

        def run_server():
            nonlocal server
            asyncio.set_event_loop(loop)
            server = loop.run_until_complete(
                asyncio.start_unix_server(handle_client, path=sock_path)
            )
            loop.run_forever()

        t = threading.Thread(target=run_server, daemon=True)
        t.start()
        time.sleep(0.05)

        try:
            gw_client = GatewayClient(socket_path=sock_path)
            agent = ReconnaissanceAgent(gateway_client=gw_client)
            res = agent.run_step(self.context, "Scan ports via UDS")

            self.assertIsNotNone(res.proposal)
            self.assertEqual(res.proposal.capability_id, "PORT_SCAN")
            self.assertEqual(res.proposal.target, "198.51.100.1")
            self.assertEqual(res.thought, "UDS roundtrip verified")
        finally:
            if server:
                server.close()
                loop.call_soon_threadsafe(loop.stop)
                t.join(timeout=1.0)
                if not loop.is_closed():
                    loop.close()
            if os.path.exists(sock_path):
                try:
                    os.unlink(sock_path)
                except OSError:
                    pass
            try:
                os.rmdir(temp_dir)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
