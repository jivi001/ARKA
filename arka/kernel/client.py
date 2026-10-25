"""
Kernel Client: Length-Prefixed Unix Domain Socket Client for arka-kerneld.
Adheres strictly to ADR-007 Section 4.1.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import struct
from typing import Optional, Union

from arka.agents.proposal import RawActionProposal
from .errors import (
    KernelAuthError,
    KernelBridgeError,
    KernelEmergencyStopError,
    KernelReplayError,
    KernelScopeError,
)
from .models import KernelRequest, KernelResponse

MAX_FRAME_SIZE = 65_536  # 64 KB


class KernelClient:
    """Client for connecting to the standalone arka-kerneld daemon over UDS."""

    def __init__(
        self,
        socket_path: Union[str, Path] = "/run/arka/kernel.sock",
        default_timeout: float = 30.0,
    ):
        self.socket_path = Path(socket_path)
        self.default_timeout = default_timeout

    async def submit_proposal(
        self,
        proposal: RawActionProposal,
        auth_token: Optional[str] = None,
        operation: str = "AUTHORIZE_AND_EXECUTE",
        raise_for_status: bool = False,
    ) -> KernelResponse:
        """Sends an action proposal to arka-kerneld and returns the authorization response."""
        req = KernelRequest(
            proposal=proposal,
            auth_token=auth_token,
            operation=operation,
        )
        return await self.send_request(req, raise_for_status=raise_for_status)

    async def send_request(
        self,
        request: KernelRequest,
        raise_for_status: bool = False,
    ) -> KernelResponse:
        """Serializes and dispatches a KernelRequest over the Unix Domain Socket."""
        payload_dict = request.to_dict()
        payload_bytes = json.dumps(payload_dict).encode("utf-8")

        if len(payload_bytes) > MAX_FRAME_SIZE:
            raise KernelBridgeError(
                f"Payload size {len(payload_bytes)} bytes exceeds maximum {MAX_FRAME_SIZE} bytes",
                code="ERR_FRAME_TOO_LARGE",
            )

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(str(self.socket_path)),
                timeout=self.default_timeout,
            )
        except (FileNotFoundError, ConnectionRefusedError, PermissionError) as e:
            raise KernelBridgeError(
                f"Failed to connect to arka-kerneld at {self.socket_path}: {e}",
                code="ERR_KERNEL_CONNECTION_FAILED",
            ) from e

        try:
            # 1. Write length-prefixed frame (4-byte big-endian unsigned integer)
            header = struct.pack(">I", len(payload_bytes))
            writer.write(header + payload_bytes)
            await writer.drain()

            # 2. Read 4-byte response length header
            resp_header = await asyncio.wait_for(
                reader.readexactly(4),
                timeout=self.default_timeout,
            )
            (resp_len,) = struct.unpack(">I", resp_header)

            if resp_len > MAX_FRAME_SIZE:
                raise KernelBridgeError(
                    f"Response frame size {resp_len} exceeds maximum {MAX_FRAME_SIZE} bytes",
                    code="ERR_FRAME_TOO_LARGE",
                )

            # 3. Read response payload
            resp_bytes = await asyncio.wait_for(
                reader.readexactly(resp_len),
                timeout=self.default_timeout,
            )
            data = json.loads(resp_bytes.decode("utf-8"))
            response = KernelResponse.from_dict(data)

            # 4. Optional typed error raising
            if raise_for_status and response.is_deny and response.error:
                code = response.error.code
                msg = response.error.message
                if code in ("ERR_UNAUTHORIZED_TOKEN", "TOKEN_EXPIRED"):
                    raise KernelAuthError(msg, code=code)
                elif code == "EMERGENCY_STOP_ACTIVE":
                    raise KernelEmergencyStopError(msg, code=code)
                elif code == "SCOPE_DENIED":
                    raise KernelScopeError(msg, code=code)
                elif code in ("REPLAY_DETECTED", "ERR_REPLAY_DETECTED"):
                    raise KernelReplayError(msg, code=code)
                else:
                    raise KernelBridgeError(msg, code=code, retryable=response.error.retryable)

            return response

        finally:
            writer.close()
            await writer.wait_closed()

    def submit_proposal_sync(
        self,
        proposal: RawActionProposal,
        auth_token: Optional[str] = None,
        operation: str = "AUTHORIZE_AND_EXECUTE",
        raise_for_status: bool = False,
    ) -> KernelResponse:
        """Synchronous wrapper for submit_proposal()."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            with ThreadPoolExecutor(max_workers=1) as executor:
                return executor.submit(
                    lambda: asyncio.run(
                        self.submit_proposal(
                            proposal,
                            auth_token=auth_token,
                            operation=operation,
                            raise_for_status=raise_for_status,
                        )
                    )
                ).result()
        else:
            return asyncio.run(
                self.submit_proposal(
                    proposal,
                    auth_token=auth_token,
                    operation=operation,
                    raise_for_status=raise_for_status,
                )
            )
