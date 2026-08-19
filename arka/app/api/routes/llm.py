"""LLM provider management API endpoints."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from arka.app.api.deps import get_llm_gateway
from arka.app.llm.gateway.gateway import LLMGateway, LLMGatewayError
from arka.app.llm.schemas import LLMRequest, LLMMessage

router = APIRouter(tags=["llm"])


class LLMTestRequest(BaseModel):
    """Request to test LLM connectivity."""

    prompt: str = "Say 'ARKA is operational' and nothing else."
    provider: str | None = None
    model: str | None = None


class LLMTestResponse(BaseModel):
    """Response from LLM connectivity test."""

    status: str
    provider: str = ""
    model: str = ""
    response: str = ""
    latency_ms: int = 0
    tokens_used: int = 0
    error: str | None = None


class ProviderInfo(BaseModel):
    """Information about a configured LLM provider."""

    name: str
    model: str
    role: str
    configured: bool


@router.post("/llm/test", response_model=LLMTestResponse)
async def test_llm(
    request: LLMTestRequest,
    gateway: LLMGateway = Depends(get_llm_gateway),
) -> LLMTestResponse:
    """Test LLM provider connectivity.

    Sends a simple prompt to verify the configured LLM provider is reachable
    and returning valid responses.
    """
    try:
        llm_request = LLMRequest(
            messages=[LLMMessage(role="user", content=request.prompt)],
            provider=request.provider,
            model=request.model,
            max_tokens=50,
            temperature=0.0,
        )
        response = await gateway.complete(llm_request)
        return LLMTestResponse(
            status="success",
            provider=response.provider,
            model=response.model,
            response=response.content,
            latency_ms=response.latency_ms,
            tokens_used=response.usage.total_tokens,
        )
    except LLMGatewayError as e:
        return LLMTestResponse(
            status="error",
            provider=e.provider,
            model=e.model,
            error=str(e),
        )
    except Exception as e:
        return LLMTestResponse(
            status="error",
            error=f"Unexpected error: {type(e).__name__}",
        )


@router.get("/providers", response_model=list[ProviderInfo])
async def list_providers(
    gateway: LLMGateway = Depends(get_llm_gateway),
) -> list[ProviderInfo]:
    """List configured LLM providers."""
    providers = await gateway.get_providers()
    return [ProviderInfo(**p) for p in providers]
