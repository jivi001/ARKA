"""Unit and integration tests for ARKA Python LLM Gateway Client."""

import asyncio
import json
import struct
import tempfile
import unittest
from pathlib import Path

from arka.gateway import (
    LlmGatewayClient,
    GatewayInferenceRequest,
    GatewayInferenceResponse,
    GatewayMessage,
    SensitivityClass,
    ModelOutput,
    GatewayDlpError,
    GatewayTimeoutError,
    GatewayPayloadError,
)


class TestGatewayModels(unittest.TestCase):
    def test_request_serialization(self):
        req = GatewayInferenceRequest(
            request_id="req_01J9Y78B9X4A5C6D7E8F9G0H1J",
            mission_id="mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q",
            caller_agent_id="agent_recon_01",
            provider="mock",
            model="mock-model",
            messages=[GatewayMessage(role="user", content="Test message")],
            sensitivity=SensitivityClass.PUBLIC,
        )
        d = req.to_dict()
        self.assertEqual(d["request_id"], "req_01J9Y78B9X4A5C6D7E8F9G0H1J")
        self.assertEqual(d["messages"][0]["content"], "Test message")
        self.assertEqual(d["sensitivity"], "public")

    def test_response_deserialization(self):
        raw_data = {
            "request_id": "req_01J9Y78B9X4A5C6D7E8F9G0H1J",
            "status": "SUCCESS",
            "output": {
                "content": "Model output text",
                "finish_reason": "stop",
                "prompt_tokens": 15,
                "completion_tokens": 5,
            },
            "error": None,
            "sanitized": False,
        }
        resp = GatewayInferenceResponse.from_dict(raw_data)
        self.assertEqual(resp.status, "SUCCESS")
        self.assertIsNotNone(resp.output)
        self.assertEqual(resp.output.content, "Model output text")
        self.assertFalse(resp.sanitized)


class TestGatewayClientUds(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.socket_path = Path(self.temp_dir.name) / "test_gw.sock"
        self.server = None

    async def asyncTearDown(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self.temp_dir.cleanup()

    async def _mock_server_handler(self, reader, writer):
        header = await reader.readexactly(4)
        (length,) = struct.unpack(">I", header)
        payload = await reader.readexactly(length)
        req = json.loads(payload.decode("utf-8"))

        if req.get("sensitivity") == "confidential":
            resp_dict = {
                "request_id": req["request_id"],
                "status": "ERROR",
                "output": None,
                "error": {
                    "code": "ERR_DLP_VIOLATION",
                    "message": "Confidential data barred from external provider.",
                    "retryable": False,
                },
                "sanitized": False,
            }
        else:
            resp_dict = {
                "request_id": req["request_id"],
                "status": "SUCCESS",
                "output": {
                    "content": f"Echo: {req['messages'][0]['content']}",
                    "finish_reason": "stop",
                    "prompt_tokens": 10,
                    "completion_tokens": 5,
                },
                "error": None,
                "sanitized": False,
            }

        resp_bytes = json.dumps(resp_dict).encode("utf-8")
        writer.write(struct.pack(">I", len(resp_bytes)) + resp_bytes)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def test_client_successful_roundtrip(self):
        self.server = await asyncio.start_unix_server(
            self._mock_server_handler,
            path=str(self.socket_path),
        )

        client = LlmGatewayClient(socket_path=self.socket_path)
        req = GatewayInferenceRequest(
            request_id="req_001",
            mission_id="mis_001",
            caller_agent_id="agent_001",
            provider="mock",
            model="mock",
            messages=[GatewayMessage(role="user", content="Ping")],
            sensitivity=SensitivityClass.PUBLIC,
        )

        resp = await client.complete(req)
        self.assertEqual(resp.status, "SUCCESS")
        self.assertEqual(resp.output.content, "Echo: Ping")

    async def test_client_dlp_error_raised(self):
        self.server = await asyncio.start_unix_server(
            self._mock_server_handler,
            path=str(self.socket_path),
        )

        client = LlmGatewayClient(socket_path=self.socket_path)
        req = GatewayInferenceRequest(
            request_id="req_002",
            mission_id="mis_001",
            caller_agent_id="agent_001",
            provider="openai",
            model="gpt-4o",
            messages=[GatewayMessage(role="user", content="Secret data")],
            sensitivity=SensitivityClass.CONFIDENTIAL,
        )

        with self.assertRaises(GatewayDlpError):
            await client.complete(req)

    async def test_client_rejects_oversized_payload(self):
        client = LlmGatewayClient(socket_path=self.socket_path)
        huge_content = "X" * 70_000
        req = GatewayInferenceRequest(
            request_id="req_003",
            mission_id="mis_001",
            caller_agent_id="agent_001",
            provider="mock",
            model="mock",
            messages=[GatewayMessage(role="user", content=huge_content)],
        )

        with self.assertRaises(GatewayPayloadError):
            await client.complete(req)


if __name__ == "__main__":
    unittest.main()
