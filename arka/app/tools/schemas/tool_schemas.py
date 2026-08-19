"""
Tool request and response schemas.
"""
from typing import Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from arka.app.core.state.models import RiskLevel, new_id, utc_now

class ToolDefinition(BaseModel):
    """Registration schema for a tool in the Tool Registry."""
    name: str
    description: str
    version: str = "1.0.0"
    input_schema: dict[str, Any]  # JSON Schema
    output_schema: dict[str, Any]  # JSON Schema
    risk_level: RiskLevel
    required_permissions: list[str] = Field(default_factory=list)
    allowed_environments: list[str] = Field(default_factory=lambda: ["sandbox"])
    timeout_seconds: int = 300
    rate_limit_per_minute: int = 60
    evidence_required: bool = True
    category: str = "general"
    enabled: bool = True

class ToolRequest(BaseModel):
    """A validated request to execute a tool."""
    request_id: str = Field(default_factory=new_id)
    engagement_id: str
    task_id: str
    agent_id: str
    tool_name: str
    target: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str
    risk_level: RiskLevel = RiskLevel.LOW
    scope_validated: bool = False
    policy_approved: bool = False
    approval_id: Optional[str] = None
    requested_at: datetime = Field(default_factory=utc_now)

class ToolResult(BaseModel):
    """Result from a tool execution."""
    result_id: str = Field(default_factory=new_id)
    request_id: str
    engagement_id: str
    task_id: str
    tool_name: str
    success: bool
    output: dict[str, Any] = Field(default_factory=dict)
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time_ms: int = 0
    evidence_refs: list[str] = Field(default_factory=list)
    executed_at: datetime = Field(default_factory=utc_now)
    completed_at: Optional[datetime] = None
