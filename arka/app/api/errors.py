"""ARKA API error handling and consistent error responses."""
from typing import Any
from pydantic import BaseModel, Field
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


class ErrorResponse(BaseModel):
    """Standardized error response for all ARKA API endpoints."""

    error: str
    detail: str = ""
    status_code: int = 500
    request_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ArkaAPIError(HTTPException):
    """Base ARKA API exception with structured error details."""

    def __init__(
        self,
        status_code: int,
        error: str,
        detail: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.error = error
        self.error_detail = detail
        self.error_metadata = metadata or {}
        super().__init__(status_code=status_code, detail=error)


class NotFoundError(ArkaAPIError):
    """Resource not found."""

    def __init__(self, resource: str, resource_id: str) -> None:
        super().__init__(
            status_code=404,
            error=f"{resource} not found",
            detail=f"{resource} with id '{resource_id}' does not exist.",
        )


class ValidationError(ArkaAPIError):
    """Request validation failed."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=422, error="Validation error", detail=detail)


class ConflictError(ArkaAPIError):
    """Resource state conflict."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=409, error="Conflict", detail=detail)


async def arka_exception_handler(request: Request, exc: ArkaAPIError) -> JSONResponse:
    """Global exception handler for ArkaAPIError."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.error,
            detail=exc.error_detail,
            status_code=exc.status_code,
            metadata=exc.error_metadata,
        ).model_dump(),
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all exception handler to prevent leaking internals."""
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal server error",
            detail="An unexpected error occurred. Check server logs for details.",
            status_code=500,
        ).model_dump(),
    )
