import asyncio
import time
import json
import litellm
from litellm import Router as LiteLLMRouter
from litellm.exceptions import (
    AuthenticationError, BadRequestError, ContextWindowExceededError,
    RateLimitError, Timeout, APIConnectionError, ServiceUnavailableError,
    ContentPolicyViolationError, APIError,
)
from arka.app.core.config import get_settings
from arka.app.core.config.settings import LLMProvider
from arka.app.llm.schemas.llm_schemas import (
    LLMRequest, LLMResponse, TokenUsage, LLMMessage, MultimodalContent, ContentType
)
from arka.app.audit.schemas import AuditEvent, AuditEventType
from arka.app.audit.service import AuditService


class LLMGatewayError(Exception):
    """Base exception for LLM Gateway errors."""
    def __init__(self, message: str, provider: str = "", model: str = "", 
                 status_code: int = 500, retryable: bool = False):
        self.provider = provider
        self.model = model
        self.status_code = status_code
        self.retryable = retryable
        super().__init__(message)


class LLMGateway:
    """ARKA LLM Gateway — provider-neutral interface for all LLM operations.
    
    Agents must use this gateway exclusively. Never instantiate provider clients directly.
    """
    
    def __init__(self, audit_service: AuditService | None = None):
        settings = get_settings()
        litellm.drop_params = True
        litellm.set_verbose = False
        
        self._settings = settings
        self._audit = audit_service
        self._router = self._build_router(settings)
    
    def _get_model_string(self, provider: LLMProvider, model: str, base_url: str | None = None) -> str:
        """Convert ARKA provider/model to litellm model string."""
        # Map ARKA providers to LiteLLM prefixes
        prefix_map = {
            LLMProvider.OPENAI: "",  # OpenAI models use no prefix in litellm
            LLMProvider.ANTHROPIC: "",  # Claude models auto-detected
            LLMProvider.GOOGLE: "gemini/",
            LLMProvider.NVIDIA: "nvidia_nim/",
            LLMProvider.KIMI: "openai/",  # Kimi uses OpenAI-compatible
            LLMProvider.CUSTOM: "openai/",  # Custom endpoints use OpenAI-compatible
        }
        prefix = prefix_map.get(provider, "openai/")
        return f"{prefix}{model}"
    
    def _build_router(self, settings) -> LiteLLMRouter | None:
        """Build a LiteLLM Router with primary and optional fallback."""
        model_list = []
        fallbacks = []
        
        # Primary provider
        api_key = settings.arka_llm_api_key.get_secret_value() if settings.arka_llm_api_key else ""
        if not api_key:
            return None  # No API key configured
            
        primary_model = self._get_model_string(
            settings.arka_llm_provider, settings.arka_llm_model, settings.arka_llm_base_url
        )
        primary_params = {
            "model": primary_model,
            "api_key": api_key,
            "timeout": float(settings.arka_llm_timeout),
        }
        if settings.arka_llm_base_url:
            primary_params["api_base"] = settings.arka_llm_base_url
            
        model_list.append({
            "model_name": "arka-primary",
            "litellm_params": primary_params,
        })
        
        # Fallback provider (optional)
        if (settings.arka_llm_fallback_provider and 
            settings.arka_llm_fallback_model and 
            settings.arka_llm_fallback_api_key):
            
            fb_api_key = settings.arka_llm_fallback_api_key.get_secret_value()
            fb_model = self._get_model_string(
                settings.arka_llm_fallback_provider,
                settings.arka_llm_fallback_model,
                settings.arka_llm_fallback_base_url,
            )
            fb_params = {
                "model": fb_model,
                "api_key": fb_api_key,
                "timeout": float(settings.arka_llm_timeout),
            }
            if settings.arka_llm_fallback_base_url:
                fb_params["api_base"] = settings.arka_llm_fallback_base_url
                
            model_list.append({
                "model_name": "arka-fallback",
                "litellm_params": fb_params,
            })
            fallbacks.append({"arka-primary": ["arka-fallback"]})
        
        return LiteLLMRouter(
            model_list=model_list,
            fallbacks=fallbacks if fallbacks else None,
            num_retries=settings.arka_llm_max_retries,
            allowed_fails=3,
            cooldown_time=60,
            timeout=float(settings.arka_llm_timeout),
        )
    
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Send a completion request through the gateway.
        
        Handles provider routing, retries, fallbacks, token tracking, and error normalization.
        """
        if self._router is None:
            raise LLMGatewayError(
                "LLM Gateway not configured. Set ARKA_LLM_API_KEY.",
                status_code=503,
            )
        
        settings = self._settings
        provider = request.provider or settings.arka_llm_provider.value
        model = request.model or settings.arka_llm_model
        
        # Build messages for litellm
        messages = []
        for msg in request.messages:
            if isinstance(msg.content, str):
                messages.append({"role": msg.role, "content": msg.content})
            else:
                # Multimodal content - build content array
                content_parts = []
                for part in msg.content:
                    if part.content_type.value == "text":
                        content_parts.append({"type": "text", "text": part.text or ""})
                    elif part.content_type.value == "image":
                        if part.media_url:
                            content_parts.append({
                                "type": "image_url",
                                "image_url": {"url": part.media_url}
                            })
                        elif part.media_base64:
                            mime = part.mime_type or "image/png"
                            content_parts.append({
                                "type": "image_url",
                                "image_url": {"url": f"data:{mime};base64,{part.media_base64}"}
                            })
                    else:
                        # For HTML, JSON, terminal_output, http_response — send as text
                        content_parts.append({"type": "text", "text": part.text or ""})
                messages.append({"role": msg.role, "content": content_parts})
        
        # Build call kwargs
        call_kwargs = {
            "model": "arka-primary",
            "messages": messages,
            "temperature": request.temperature,
        }
        if request.max_tokens:
            call_kwargs["max_tokens"] = request.max_tokens
        if request.response_format:
            call_kwargs["response_format"] = request.response_format
        if request.timeout:
            call_kwargs["timeout"] = float(request.timeout)
        
        start_time = time.monotonic()
        
        try:
            response = await self._router.acompletion(**call_kwargs)
            latency_ms = int((time.monotonic() - start_time) * 1000)
            
            content = response.choices[0].message.content or ""
            usage = response.usage
            
            # Calculate cost
            try:
                cost = float(litellm.completion_cost(completion_response=response))
            except Exception:
                cost = None
            
            token_usage = TokenUsage(
                prompt_tokens=getattr(usage, 'prompt_tokens', 0),
                completion_tokens=getattr(usage, 'completion_tokens', 0),
                total_tokens=getattr(usage, 'total_tokens', 0),
                cost_usd=cost,
            )
            
            # Try to parse structured output
            structured = None
            if request.response_format and content:
                try:
                    structured = json.loads(content)
                except json.JSONDecodeError:
                    pass
            
            llm_response = LLMResponse(
                request_id=request.request_id,
                provider=provider,
                model=response.model or model,
                content=content,
                structured_output=structured,
                usage=token_usage,
                latency_ms=latency_ms,
                success=True,
            )
            
            # Audit logging (don't await to avoid blocking)
            if self._audit:
                await self._audit.record_action(
                    event_type=AuditEventType.LLM_RESPONSE,
                    actor="llm_gateway",
                    action="completion",
                    engagement_id=request.engagement_id,
                    task_id=request.task_id,
                    agent_id=request.agent_id,
                    parameters={
                        "provider": provider,
                        "model": response.model or model,
                        "prompt_tokens": token_usage.prompt_tokens,
                        "completion_tokens": token_usage.completion_tokens,
                        "total_tokens": token_usage.total_tokens,
                        "latency_ms": latency_ms,
                    },
                    result_status="success",
                    correlation_id=request.request_id,
                )
            
            return llm_response
            
        except AuthenticationError as e:
            raise LLMGatewayError(
                f"Authentication failed for provider '{provider}'",
                provider=provider, model=model, status_code=401,
            ) from e
        except ContextWindowExceededError as e:
            raise LLMGatewayError(
                f"Context window exceeded for model '{model}'",
                provider=provider, model=model, status_code=400,
            ) from e
        except RateLimitError as e:
            raise LLMGatewayError(
                f"Rate limit exceeded for provider '{provider}'",
                provider=provider, model=model, status_code=429, retryable=True,
            ) from e
        except (Timeout, TimeoutError) as e:
            raise LLMGatewayError(
                f"Request timed out after {settings.arka_llm_timeout}s",
                provider=provider, model=model, status_code=504, retryable=True,
            ) from e
        except (APIConnectionError, ServiceUnavailableError) as e:
            raise LLMGatewayError(
                f"Provider '{provider}' is unavailable",
                provider=provider, model=model, status_code=503, retryable=True,
            ) from e
        except ContentPolicyViolationError as e:
            raise LLMGatewayError(
                f"Content policy violation from provider '{provider}'",
                provider=provider, model=model, status_code=400,
            ) from e
        except APIError as e:
            status = getattr(e, 'status_code', 500)
            raise LLMGatewayError(
                f"API error from provider '{provider}': {e}",
                provider=provider, model=model, status_code=status,
            ) from e
    
    async def health_check(self) -> dict:
        """Check if the LLM provider is reachable."""
        if self._router is None:
            return {"status": "not_configured", "provider": "", "model": ""}
        
        try:
            response = await self.complete(LLMRequest(
                messages=[LLMMessage(role="user", content="ping")],
                max_tokens=5,
                temperature=0.0,
            ))
            return {
                "status": "healthy",
                "provider": response.provider,
                "model": response.model,
                "latency_ms": response.latency_ms,
            }
        except LLMGatewayError as e:
            return {
                "status": "unhealthy",
                "provider": e.provider,
                "model": e.model,
                "error": str(e),
            }
    
    async def get_providers(self) -> list[dict]:
        """List configured providers."""
        providers = []
        settings = self._settings
        providers.append({
            "name": settings.arka_llm_provider.value,
            "model": settings.arka_llm_model,
            "role": "primary",
            "configured": bool(settings.arka_llm_api_key.get_secret_value() if settings.arka_llm_api_key else False),
        })
        if settings.arka_llm_fallback_provider:
            providers.append({
                "name": settings.arka_llm_fallback_provider.value,
                "model": settings.arka_llm_fallback_model or "",
                "role": "fallback",
                "configured": bool(
                    settings.arka_llm_fallback_api_key 
                    and settings.arka_llm_fallback_api_key.get_secret_value()
                ),
            })
        return providers
