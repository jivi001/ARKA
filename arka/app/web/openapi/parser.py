"""Safe OpenAPI and Swagger Specification Parser.

Implements hardened, resource-bounded JSON/YAML parsing with cycle detection,
external reference blocking, and safe normalization.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import yaml

from arka.app.web.models.http import HTTPMethod
from arka.app.web.models.parameters import Parameter, ParameterLocation
from arka.app.web.openapi.models import (
    OpenAPIOperation,
    OpenAPISchema,
    OpenAPISecurityScheme,
    OpenAPIServer,
)

# Hard limit on document size (5 MB default)
DEFAULT_MAX_DOCUMENT_SIZE = 5 * 1024 * 1024
# Maximum recursion depth for nested schema definitions and $ref traversal
MAX_RECURSION_DEPTH = 20

_DESTRUCTIVE_METHODS = {HTTPMethod.DELETE, HTTPMethod.PUT, HTTPMethod.PATCH}


class OpenAPIParseError(Exception):
    """Raised when an OpenAPI document is invalid, malformed, or exceeds bounds."""


class SafeOpenAPIParser:
    """Safe, bounded OpenAPI and Swagger parser."""

    def __init__(
        self,
        max_document_size: int = DEFAULT_MAX_DOCUMENT_SIZE,
        max_recursion_depth: int = MAX_RECURSION_DEPTH,
    ) -> None:
        self.max_document_size = max_document_size
        self.max_recursion_depth = max_recursion_depth

    def parse(self, content: str | bytes, source_url: str = "") -> OpenAPISchema:
        """Parse raw JSON or YAML OpenAPI specification into a normalized OpenAPISchema.

        Enforces size bounds, safe YAML parsing, recursion limits, and schema structure.
        """
        raw_bytes = content.encode("utf-8") if isinstance(content, str) else content
        if len(raw_bytes) > self.max_document_size:
            raise OpenAPIParseError(
                f"Document size {len(raw_bytes)} bytes exceeds maximum allowed "
                f"limit of {self.max_document_size} bytes."
            )

        doc_hash = hashlib.sha256(raw_bytes).hexdigest()
        text = raw_bytes.decode("utf-8", errors="replace")

        # 1. Parse JSON or YAML safely
        data: dict[str, Any]
        try:
            data = json.loads(text)
        except Exception:
            try:
                # yaml.safe_load prevents arbitrary python object execution
                data = yaml.safe_load(text)
            except Exception as e:
                raise OpenAPIParseError(f"Failed to parse document as JSON or YAML: {e}") from e

        if not isinstance(data, dict):
            raise OpenAPIParseError("Root OpenAPI specification must be a dictionary.")

        # 2. Determine specification version
        spec_version = ""
        if "openapi" in data:
            spec_version = str(data["openapi"])
        elif "swagger" in data:
            spec_version = str(data["swagger"])
        else:
            raise OpenAPIParseError(
                "Document missing required 'openapi' or 'swagger' version declaration."
            )

        info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
        title = str(info.get("title", "Untitled API"))
        version = str(info.get("version", "1.0.0"))
        description = info.get("description")

        # 3. Parse Servers
        servers = self._extract_servers(data, spec_version, source_url)

        # 4. Parse Security Schemes
        security_schemes = self._extract_security_schemes(data, spec_version)

        # 5. Parse Paths and Operations
        operations = self._extract_operations(data)

        return OpenAPISchema(
            title=title,
            version=version,
            spec_version=spec_version,
            description=description,
            source_url=source_url,
            servers=servers,
            operations=operations,
            security_schemes=security_schemes,
            raw_size_bytes=len(raw_bytes),
            document_hash=doc_hash,
            metadata={
                "paths_count": len(data.get("paths", {}))
                if isinstance(data.get("paths"), dict)
                else 0
            },
        )

    def _extract_servers(
        self, data: dict[str, Any], spec_version: str, source_url: str
    ) -> list[OpenAPIServer]:
        servers: list[OpenAPIServer] = []

        if spec_version.startswith("3"):
            raw_servers = data.get("servers", [])
            if isinstance(raw_servers, list):
                for s in raw_servers:
                    if isinstance(s, dict) and "url" in s:
                        servers.append(
                            OpenAPIServer(
                                url=str(s["url"]),
                                description=s.get("description"),
                                in_authorized_scope=False,
                            )
                        )
        elif spec_version.startswith("2"):
            # Swagger 2.0 uses host, basePath, schemes
            host = str(data.get("host", ""))
            base_path = str(data.get("basePath", "/"))
            schemes = (
                data.get("schemes", ["http"]) if isinstance(data.get("schemes"), list) else ["http"]
            )
            if host:
                for scheme in schemes:
                    servers.append(
                        OpenAPIServer(
                            url=f"{scheme}://{host}{base_path}".rstrip("/"),
                            description="Swagger 2.0 base host",
                            in_authorized_scope=False,
                        )
                    )

        return servers

    def _extract_security_schemes(
        self, data: dict[str, Any], spec_version: str
    ) -> dict[str, OpenAPISecurityScheme]:
        schemes: dict[str, OpenAPISecurityScheme] = {}

        if spec_version.startswith("3"):
            components = data.get("components", {})
            if isinstance(components, dict):
                raw_schemes = components.get("securitySchemes", {})
                if isinstance(raw_schemes, dict):
                    for name, s in raw_schemes.items():
                        if isinstance(s, dict):
                            schemes[name] = OpenAPISecurityScheme(
                                scheme_name=name,
                                scheme_type=str(s.get("type", "unknown")),
                                location=s.get("in"),
                                param_name=s.get("name"),
                                http_scheme=s.get("scheme"),
                                bearer_format=s.get("bearerFormat"),
                                description=s.get("description"),
                            )
        elif spec_version.startswith("2"):
            raw_defs = data.get("securityDefinitions", {})
            if isinstance(raw_defs, dict):
                for name, s in raw_defs.items():
                    if isinstance(s, dict):
                        schemes[name] = OpenAPISecurityScheme(
                            scheme_name=name,
                            scheme_type=str(s.get("type", "unknown")),
                            location=s.get("in"),
                            param_name=s.get("name"),
                            description=s.get("description"),
                        )

        return schemes

    def _extract_operations(self, data: dict[str, Any]) -> list[OpenAPIOperation]:
        operations: list[OpenAPIOperation] = []
        paths = data.get("paths", {})
        if not isinstance(paths, dict):
            return operations

        for path_key, path_item in paths.items():
            if not isinstance(path_item, dict) or not str(path_key).startswith("/"):
                continue

            # Shared path-level parameters
            path_level_params = self._parse_parameters(
                path_item.get("parameters", []), data, depth=0
            )

            for method_str, op_dict in path_item.items():
                if method_str.upper() not in [m.value for m in HTTPMethod]:
                    continue
                if not isinstance(op_dict, dict):
                    continue

                method = HTTPMethod(method_str.upper())
                is_destructive = method in _DESTRUCTIVE_METHODS

                # Operation-level parameters
                op_params = self._parse_parameters(op_dict.get("parameters", []), data, depth=0)

                # Merge parameters (operation-level overrides path-level by location+name)
                param_map: dict[str, Parameter] = {}
                for p in path_level_params:
                    param_map[f"{p.location.value}:{p.name}"] = p
                for p in op_params:
                    param_map[f"{p.location.value}:{p.name}"] = p

                # Request body parsing for OpenAPI 3
                request_body_types: list[str] = []
                req_body = op_dict.get("requestBody", {})
                if isinstance(req_body, dict):
                    content = req_body.get("content", {})
                    if isinstance(content, dict):
                        request_body_types = list(content.keys())
                        # Extract body field parameters if json schema is present
                        json_content = content.get("application/json", {})
                        if isinstance(json_content, dict) and "schema" in json_content:
                            body_params = self._extract_schema_properties(
                                json_content["schema"], data, depth=0
                            )
                            for bp in body_params:
                                param_map[f"{bp.location.value}:{bp.name}"] = bp

                # Security requirements
                security_reqs: list[str] = []
                raw_sec = op_dict.get("security", [])
                if isinstance(raw_sec, list):
                    for sec_item in raw_sec:
                        if isinstance(sec_item, dict):
                            security_reqs.extend(sec_item.keys())

                operations.append(
                    OpenAPIOperation(
                        path=str(path_key),
                        method=method,
                        operation_id=op_dict.get("operationId"),
                        summary=op_dict.get("summary"),
                        description=op_dict.get("description"),
                        tags=op_dict.get("tags", [])
                        if isinstance(op_dict.get("tags"), list)
                        else [],
                        parameters=list(param_map.values()),
                        request_body_content_types=request_body_types,
                        security_requirements=list(set(security_reqs)),
                        is_destructive=is_destructive,
                    )
                )

        return operations

    def _parse_parameters(
        self, raw_params: Any, root_data: dict[str, Any], depth: int
    ) -> list[Parameter]:
        if not isinstance(raw_params, list):
            return []

        parameters: list[Parameter] = []
        for p in raw_params:
            if not isinstance(p, dict):
                continue

            # Safe internal $ref resolution
            resolved_p = p
            if "$ref" in p:
                resolved_p = self._resolve_internal_ref(p["$ref"], root_data, depth=depth + 1)
                if not isinstance(resolved_p, dict):
                    continue

            name = resolved_p.get("name")
            if not name or not isinstance(name, str):
                continue

            in_loc = str(resolved_p.get("in", "query")).lower()
            location = ParameterLocation.QUERY
            if in_loc == "path":
                location = ParameterLocation.PATH
            elif in_loc == "header":
                location = ParameterLocation.HEADER
            elif in_loc == "cookie":
                location = ParameterLocation.COOKIE
            elif in_loc in ("body", "formData"):
                location = ParameterLocation.BODY

            param_type = None
            schema = resolved_p.get("schema", {})
            if isinstance(schema, dict):
                param_type = schema.get("type")
            elif "type" in resolved_p:
                param_type = resolved_p.get("type")

            parameters.append(
                Parameter(
                    name=name,
                    location=location,
                    param_type=str(param_type) if param_type else None,
                    sample_value=str(resolved_p.get("example"))
                    if "example" in resolved_p
                    else None,
                    required=bool(resolved_p.get("required", False)),
                    description=resolved_p.get("description"),
                    schema_info=schema if isinstance(schema, dict) else {},
                )
            )

        return parameters

    def _extract_schema_properties(
        self, schema: Any, root_data: dict[str, Any], depth: int
    ) -> list[Parameter]:
        if not isinstance(schema, dict) or depth > self.max_recursion_depth:
            return []

        # Resolve internal ref if present
        if "$ref" in schema:
            resolved = self._resolve_internal_ref(schema["$ref"], root_data, depth=depth + 1)
            if isinstance(resolved, dict):
                schema = resolved
            else:
                return []

        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return []

        required_set = (
            set(schema.get("required", [])) if isinstance(schema.get("required"), list) else set()
        )
        params: list[Parameter] = []

        for prop_name, prop_def in properties.items():
            if not isinstance(prop_def, dict):
                continue

            prop_type = prop_def.get("type")
            params.append(
                Parameter(
                    name=str(prop_name),
                    location=ParameterLocation.JSON,
                    param_type=str(prop_type) if prop_type else None,
                    required=prop_name in required_set,
                    description=prop_def.get("description"),
                )
            )

        return params

    def _resolve_internal_ref(
        self, ref: str, root_data: dict[str, Any], depth: int, visited: set[str] | None = None
    ) -> Any:
        """Safely resolve an internal JSON Pointer reference (#/components/schemas/...).

        Rejects external URLs or file paths to prevent SSRF and arbitrary resource access.
        Enforces cycle detection and maximum recursion depth.
        """
        if depth > self.max_recursion_depth:
            return None

        # Absolute security invariant: reject external references
        if not ref.startswith("#/"):
            return None

        if visited is None:
            visited = set()
        if ref in visited:
            # Cycle detected
            return None
        visited.add(ref)

        tokens = ref[2:].split("/")
        curr: Any = root_data
        for token in tokens:
            # Decode escaped characters per RFC 6901
            clean_token = token.replace("~1", "/").replace("~0", "~")
            if isinstance(curr, dict) and clean_token in curr:
                curr = curr[clean_token]
            else:
                return None

        # If resolved item is itself a $ref, recurse safely
        if isinstance(curr, dict) and "$ref" in curr:
            return self._resolve_internal_ref(
                curr["$ref"], root_data, depth=depth + 1, visited=visited
            )

        return curr
