"""OpenAPI and Swagger specification analysis package."""

from arka.app.web.openapi.analyzer import CONVENTIONAL_OPENAPI_PATHS, OpenAPIAnalyzer
from arka.app.web.openapi.models import (
    OpenAPIOperation,
    OpenAPISchema,
    OpenAPISecurityScheme,
    OpenAPIServer,
)
from arka.app.web.openapi.parser import (
    DEFAULT_MAX_DOCUMENT_SIZE,
    MAX_RECURSION_DEPTH,
    OpenAPIParseError,
    SafeOpenAPIParser,
)

__all__ = [
    "CONVENTIONAL_OPENAPI_PATHS",
    "DEFAULT_MAX_DOCUMENT_SIZE",
    "MAX_RECURSION_DEPTH",
    "OpenAPIAnalyzer",
    "OpenAPIOperation",
    "OpenAPIParseError",
    "OpenAPISchema",
    "OpenAPISecurityScheme",
    "OpenAPIServer",
    "SafeOpenAPIParser",
]
