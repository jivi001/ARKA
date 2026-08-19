"""Execution domain models and schemas for ARKA Phase 2.1.

Defines execution requests, results, statuses, limits, and evidence references.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from arka.app.core.state.models import new_id, utc_now


class ExecutionStatus(str, Enum):
    """Lifecycle statuses for a sandboxed execution."""

    CREATED = "created"
    VALIDATING = "validating"
    STARTING = "starting"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    REJECTED = "rejected"


class NetworkProfile(str, Enum):
    """Network isolation profiles for sandboxed execution."""

    NO_NETWORK = "no_network"  # Completely offline (default Phase 2.1)
    CONTROLLED_NETWORK = "controlled_network"  # Filtered egress
    AUTHORIZED_TARGET_NETWORK = "authorized_target_network"  # Explicit target IP/port only


class ExecutionLimits(BaseModel):
    """Resource, time, and output limits for tool execution."""

    max_execution_time_seconds: int = Field(default=300, ge=1, le=3600)
    max_stdout_bytes: int = Field(
        default=1_048_576, ge=1024, le=52_428_800
    )  # 1MB default, 50MB max
    max_stderr_bytes: int = Field(default=1_048_576, ge=1024, le=52_428_800)  # 1MB default
    max_memory_mb: int = Field(default=512, ge=64, le=8192)
    max_cpu_seconds: int = Field(default=300, ge=1, le=3600)
    max_processes: int = Field(default=10, ge=1, le=100)
    max_concurrent_executions: int = Field(default=5, ge=1, le=50)


class EvidenceReference(BaseModel):
    """Cryptographic provenance record for execution output and artifacts."""

    evidence_id: str = Field(default_factory=new_id)
    execution_id: str
    request_id: str
    engagement_id: str
    task_id: str
    evidence_type: str = "raw_tool_output"  # raw_tool_output, structured_result, log
    location: str = "in_memory"  # in_memory, filesystem path, or artifact storage
    sha256: str
    size_bytes: int = 0
    created_at: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExecutionRequest(BaseModel):
    """Authoritative execution request dispatched from the control plane to the execution engine.

    Only constructed from an authoritative ToolRequest that has passed ScopeGuard,
    PolicyEngine, and ApprovalManager validation.
    """

    execution_id: str = Field(default_factory=new_id)
    request_id: str
    engagement_id: str
    task_id: str
    agent_id: str
    tool_name: str
    target: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    command: list[str] = Field(default_factory=list)  # Executable argument array
    environment: dict[str, str] = Field(default_factory=dict)  # Sanitized environment
    limits: ExecutionLimits = Field(default_factory=ExecutionLimits)
    network_profile: NetworkProfile = NetworkProfile.NO_NETWORK
    created_at: datetime = Field(default_factory=utc_now)


class ExecutionResult(BaseModel):
    """Comprehensive result of a sandboxed execution."""

    execution_id: str
    request_id: str
    engagement_id: str
    task_id: str
    tool_name: str
    status: ExecutionStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int = 0
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    structured_output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    sandbox_id: str | None = None
    evidence_references: list[EvidenceReference] = Field(default_factory=list)
    resource_usage: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
