"""ARKA LLM Gateway Client Data Models."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Dict, Any
import uuid


class SensitivityClass(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


@dataclass
class GatewayMessage:
    role: str
    content: str
    name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {"role": self.role, "content": self.content}
        if self.name is not None:
            d["name"] = self.name
        return d


@dataclass
class GatewayInferenceRequest:
    mission_id: str
    caller_agent_id: str
    provider: str
    model: str
    messages: List[GatewayMessage]
    request_id: str = field(default_factory=lambda: f"req-{uuid.uuid4().hex[:16]}")
    auth_token: Optional[str] = None
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    sensitivity: SensitivityClass = SensitivityClass.PUBLIC
    stream: Optional[bool] = None
    timeout_ms: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "request_id": self.request_id,
            "mission_id": self.mission_id,
            "caller_agent_id": self.caller_agent_id,
            "provider": self.provider,
            "model": self.model,
            "messages": [m.to_dict() for m in self.messages],
            "sensitivity": self.sensitivity.value,
        }
        if self.auth_token is not None:
            d["auth_token"] = self.auth_token
        if self.max_tokens is not None:
            d["max_tokens"] = self.max_tokens
        if self.temperature is not None:
            d["temperature"] = self.temperature
        if self.stream is not None:
            d["stream"] = self.stream
        if self.timeout_ms is not None:
            d["timeout_ms"] = self.timeout_ms
        return d


@dataclass
class ModelOutput:
    content: str
    finish_reason: str
    prompt_tokens: int
    completion_tokens: int


@dataclass
class GatewayErrorPayload:
    code: str
    message: str
    retryable: bool


@dataclass
class GatewayInferenceResponse:
    request_id: str
    status: str
    output: Optional[ModelOutput] = None
    error: Optional[GatewayErrorPayload] = None
    sanitized: bool = False

    @property
    def is_success(self) -> bool:
        return self.status == "SUCCESS"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GatewayInferenceResponse":
        output = None
        if data.get("output"):
            o = data["output"]
            output = ModelOutput(
                content=o["content"],
                finish_reason=o["finish_reason"],
                prompt_tokens=o["prompt_tokens"],
                completion_tokens=o["completion_tokens"],
            )

        err = None
        if data.get("error"):
            e = data["error"]
            err = GatewayErrorPayload(
                code=e["code"],
                message=e["message"],
                retryable=e.get("retryable", False),
            )

        return cls(
            request_id=data["request_id"],
            status=data["status"],
            output=output,
            error=err,
            sanitized=data.get("sanitized", False),
        )
