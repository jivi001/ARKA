"""
Unit and Integration Tests for Module G:
Action Normalization and Rust Kernel Bridge (Python Client).

Validates:
- Request serialization conforming to ADR-007 Section 4.2
- Length-prefixed framing and maximum frame boundary enforcement
- Typed error mappings (KernelAuthError, KernelEmergencyStopError, KernelReplayError, KernelScopeError)
- End-to-end Unix Domain Socket communication between KernelClient and UDS mock server
"""

import asyncio
import json
import os
from pathlib import Path
import struct
import tempfile
import threading
import time
import unittest

from arka.agents.proposal import RawActionProposal
from arka.kernel import (
    KernelAuthError,
    KernelBridgeError,
    KernelClient,
    KernelDecision,
    KernelEmergencyStopError,
    KernelReplayError,
    KernelRequest,
    KernelResponse,
    KernelScopeError,
)


class TestKernelBridge(unittest.TestCase):

    def setUp(self):
        self.proposal = RawActionProposal(
            mission_id="msn-test-gamma",
            capability_id="PORT_SCAN",
            target="198.51.100.1",
            parameters={"ports": [80, 443], "timing": 3},
        )

    def test_request_serialization(self):
        """Verifies KernelRequest serialization matching ADR-007 schema."""
        req = KernelRequest(
            proposal=self.proposal,
            auth_token="test.jwt.token",
            operation="AUTHORIZE_AND_EXECUTE",
        )
        d = req.to_dict()

        self.assertTrue(d["request_id"].startswith("req-"))
        self.assertEqual(d["client_version"], "3.0.0")
        self.assertEqual(d["operation"], "AUTHORIZE_AND_EXECUTE")
        self.assertEqual(d["auth_token"], "test.jwt.token")
        self.assertEqual(d["proposal"]["capability_id"], "PORT_SCAN")
        self.assertEqual(d["proposal"]["target"], "198.51.100.1")

    def test_connection_failure_fails_closed(self):
        """Verifies fail-closed exception when kernel socket does not exist."""
        client = KernelClient(socket_path="/tmp/nonexistent_arka_kernel.sock")

        with self.assertRaises(KernelBridgeError) as ctx:
            client.submit_proposal_sync(self.proposal)
        self.assertEqual(ctx.exception.code, "ERR_KERNEL_CONNECTION_FAILED")

    def test_oversized_payload_rejection(self):
        """Verifies client rejects payloads > 64 KB before sending."""
        client = KernelClient()
        huge_params = {"data": "A" * 70_000}
        oversized_proposal = RawActionProposal(
            mission_id="msn-large",
            capability_id="PORT_SCAN",
            target="198.51.100.1",
            parameters=huge_params,
        )

        with self.assertRaises(KernelBridgeError) as ctx:
            client.submit_proposal_sync(oversized_proposal)
        self.assertEqual(ctx.exception.code, "ERR_FRAME_TOO_LARGE")

    def test_end_to_end_uds_roundtrip(self):
        """
        Tests end-to-end Unix Domain Socket IPC:
        KernelClient -> Length-Prefixed Frame -> UDS Server -> KernelResponse.
        """
        temp_dir = tempfile.mkdtemp()
        sock_path = os.path.join(temp_dir, "test_kernel.sock")

        async def handle_client(reader, writer):
            len_buf = await reader.readexactly(4)
            (payload_len,) = struct.unpack(">I", len_buf)
            payload_bytes = await reader.readexactly(payload_len)
            req_data = json.loads(payload_bytes.decode("utf-8"))

            resp_data = {
                "request_id": req_data["request_id"],
                "decision": "ALLOW",
                "action_id": "act-test-12345",
                "action_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "execution_result": {
                    "state": "COMPLETED",
                    "evidence_hashes": ["sha256:fedcba9876543210"],
                    "execution_id": "exc-test-9999",
                },
                "error": None,
            }

            resp_body = json.dumps(resp_data).encode("utf-8")
            resp_header = struct.pack(">I", len(resp_body))
            writer.write(resp_header + resp_body)
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
            client = KernelClient(socket_path=sock_path)
            resp = client.submit_proposal_sync(self.proposal)

            self.assertTrue(resp.is_allow)
            self.assertEqual(resp.action_id, "act-test-12345")
            self.assertEqual(
                resp.action_hash,
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            )
            self.assertIsNotNone(resp.execution_result)
            self.assertEqual(resp.execution_result.state, "COMPLETED")
            self.assertEqual(resp.execution_result.execution_id, "exc-test-9999")
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

    def test_typed_error_raising(self):
        """Verifies raise_for_status properly converts error codes to typed exceptions."""
        temp_dir = tempfile.mkdtemp()
        sock_path = os.path.join(temp_dir, "test_err_kernel.sock")

        current_error_code = "EMERGENCY_STOP_ACTIVE"

        async def handle_err_client(reader, writer):
            len_buf = await reader.readexactly(4)
            (payload_len,) = struct.unpack(">I", len_buf)
            _ = await reader.readexactly(payload_len)

            resp_data = {
                "request_id": "req-err-test",
                "decision": "DENY",
                "action_id": None,
                "action_hash": None,
                "execution_result": None,
                "error": {
                    "code": current_error_code,
                    "message": f"Simulated kernel denial: {current_error_code}",
                    "retryable": False,
                },
            }

            resp_body = json.dumps(resp_data).encode("utf-8")
            resp_header = struct.pack(">I", len(resp_body))
            writer.write(resp_header + resp_body)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        loop = asyncio.new_event_loop()
        server = None

        def run_server():
            nonlocal server
            asyncio.set_event_loop(loop)
            server = loop.run_until_complete(
                asyncio.start_unix_server(handle_err_client, path=sock_path)
            )
            loop.run_forever()

        t = threading.Thread(target=run_server, daemon=True)
        t.start()
        time.sleep(0.05)

        try:
            client = KernelClient(socket_path=sock_path)

            # 1. Emergency stop active
            current_error_code = "EMERGENCY_STOP_ACTIVE"
            with self.assertRaises(KernelEmergencyStopError):
                client.submit_proposal_sync(self.proposal, raise_for_status=True)

            # 2. Scope denied
            current_error_code = "SCOPE_DENIED"
            with self.assertRaises(KernelScopeError):
                client.submit_proposal_sync(self.proposal, raise_for_status=True)

            # 3. Token unauthorized
            current_error_code = "ERR_UNAUTHORIZED_TOKEN"
            with self.assertRaises(KernelAuthError):
                client.submit_proposal_sync(self.proposal, raise_for_status=True)

            # 4. Replay detected
            current_error_code = "REPLAY_DETECTED"
            with self.assertRaises(KernelReplayError):
                client.submit_proposal_sync(self.proposal, raise_for_status=True)

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
