"""ARKA LLM Gateway Client (Async Unix Domain Socket IPC)."""

import asyncio
import json
import struct
from pathlib import Path
from typing import Union, Optional

from arka.gateway.errors import (
    GatewayClientError,
    GatewayTimeoutError,
    GatewayDlpError,
    GatewayPeerAuthError,
    GatewayPayloadError,
)
from arka.gateway.models import (
    GatewayInferenceRequest,
    GatewayInferenceResponse,
)

MAX_FRAME_SIZE = 65_536  # 64 KB


class LlmGatewayClient:
    """Client for connecting to the standalone arka-gatewayd daemon over UDS."""

    def __init__(self, socket_path: Union[str, Path] = "/run/arka/gateway.sock", default_timeout: float = 30.0):
        self.socket_path = Path(socket_path)
        self.default_timeout = default_timeout

    async def complete(
        self,
        request: GatewayInferenceRequest,
        raise_for_status: bool = True,
    ) -> GatewayInferenceResponse:
        """Sends an inference request to arka-gatewayd and returns the validated completion."""
        payload_dict = request.to_dict()
        payload_bytes = json.dumps(payload_dict).encode("utf-8")

        if len(payload_bytes) > MAX_FRAME_SIZE:
            raise GatewayPayloadError(
                f"Payload size {len(payload_bytes)} bytes exceeds maximum {MAX_FRAME_SIZE} bytes",
                code="ERR_FRAME_TOO_LARGE",
            )

        try:
            reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        except (FileNotFoundError, ConnectionRefusedError, PermissionError) as e:
            raise GatewayClientError(f"Failed to connect to arka-gatewayd at {self.socket_path}: {e}")

        try:
            # Send length-prefixed frame (4-byte big-endian unsigned int)
            header = struct.pack(">I", len(payload_bytes))
            writer.write(header + payload_bytes)
            await writer.drain()

            # Read response length header
            resp_header = await reader.readexactly(4)
            (resp_len,) = struct.unpack(">I", resp_header)

            if resp_len > MAX_FRAME_SIZE:
                raise GatewayPayloadError(f"Response length {resp_len} exceeds maximum {MAX_FRAME_SIZE}")

            resp_bytes = await reader.readexactly(resp_len)
            resp_dict = json.loads(resp_bytes.decode("utf-8"))
            response = GatewayInferenceResponse.from_dict(resp_dict)

            if raise_for_status and response.status == "ERROR" and response.error:
                code = response.error.code
                msg = response.error.message
                if code == "ERR_DLP_VIOLATION":
                    raise GatewayDlpError(msg)
                elif code == "ERR_GATEWAY_TIMEOUT":
                    raise GatewayTimeoutError(msg)
                elif code == "ERR_PEER_AUTH_FAILED":
                    raise GatewayPeerAuthError(msg)
                else:
                    raise GatewayClientError(msg, code=code, retryable=response.error.retryable)

            return response

        finally:
            writer.close()
            await writer.wait_closed()


# Alias for concise developer API
GatewayClient = LlmGatewayClient

