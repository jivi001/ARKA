"""GraphQL Discovery and Introspection Schema Analyzer."""

from __future__ import annotations

import json
import urllib.parse
from typing import TYPE_CHECKING

from arka.app.web.graphql.introspection import (
    GRAPHQL_INTROSPECTION_QUERY,
    format_type_signature,
)
from arka.app.web.graphql.models import (
    GraphQLArgument,
    GraphQLField,
    GraphQLOperation,
    GraphQLOperationType,
    GraphQLSchema,
    GraphQLType,
)
from arka.app.web.models.endpoint import DiscoveredWebEndpoint
from arka.app.web.models.http import HTTPMethod, HTTPRequest
from arka.app.web.models.parameters import Parameter, ParameterLocation

if TYPE_CHECKING:
    from arka.app.core.scope.scopeguard import ScopeGuard
    from arka.app.web.client.client import ControlledHTTPClient

CONVENTIONAL_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/api/query",
]

DEFAULT_MAX_GRAPHQL_RESPONSE_SIZE = 2 * 1024 * 1024  # 2 MB
DEFAULT_MAX_TYPES = 1000
DEFAULT_MAX_FIELDS = 500


class GraphQLAnalyzerError(Exception):
    """Raised when GraphQL analysis encounters bounds or protocol errors."""


class GraphQLAnalyzer:
    """Discovers and safely analyzes GraphQL endpoints and schemas."""

    def __init__(
        self,
        http_client: ControlledHTTPClient | None = None,
        scope_guard: ScopeGuard | None = None,
        max_response_size: int = DEFAULT_MAX_GRAPHQL_RESPONSE_SIZE,
        max_types: int = DEFAULT_MAX_TYPES,
        max_fields: int = DEFAULT_MAX_FIELDS,
    ) -> None:
        self.http_client = http_client
        self.scope_guard = scope_guard
        self.max_response_size = max_response_size
        self.max_types = max_types
        self.max_fields = max_fields

    async def discover_endpoints(
        self,
        base_url: str,
        custom_paths: list[str] | None = None,
    ) -> list[GraphQLSchema]:
        """Probe conventional GraphQL paths on base_url and run introspection if authorized."""
        if not self.http_client:
            raise ValueError("ControlledHTTPClient is required for network GraphQL discovery.")

        candidate_paths = custom_paths or CONVENTIONAL_GRAPHQL_PATHS
        parsed_base = urllib.parse.urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}".rstrip("/")

        schemas: list[GraphQLSchema] = []

        for path in candidate_paths:
            full_url = urllib.parse.urljoin(origin, path)

            # Pre-check ScopeGuard
            if self.scope_guard and not self.scope_guard.validate_url(full_url):
                continue

            schema = await self.introspect_endpoint(full_url)
            if schema and (schema.introspection_enabled or schema.metadata.get("is_graphql")):
                schemas.append(schema)

        return schemas

    async def introspect_endpoint(
        self, endpoint_url: str, engagement_id: str = ""
    ) -> GraphQLSchema | None:
        """Send introspection query to an authorized GraphQL endpoint and parse schema."""
        if not self.http_client:
            raise ValueError("ControlledHTTPClient is required for network GraphQL introspection.")

        if self.scope_guard and not self.scope_guard.validate_url(endpoint_url):
            return None

        req = HTTPRequest(
            method=HTTPMethod.POST,
            url=endpoint_url,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            body=json.dumps({"query": GRAPHQL_INTROSPECTION_QUERY}),
            timeout=10.0,
            follow_redirects=True,
        )

        tx = await self.http_client.execute(req, engagement_id=engagement_id)
        if tx.error or not tx.response or not tx.response.body:
            return None

        if len(tx.response.body) > self.max_response_size:
            raise GraphQLAnalyzerError(
                f"GraphQL response size ({len(tx.response.body)} bytes) exceeds "
                f"maximum allowed limit of {self.max_response_size} bytes."
            )

        return self.parse_introspection_response(tx.response.body, endpoint_url)

    def parse_introspection_response(
        self, raw_content: str | bytes, endpoint_url: str
    ) -> GraphQLSchema:
        """Parse raw JSON GraphQL introspection response into a structured GraphQLSchema."""
        raw_bytes = raw_content.encode("utf-8") if isinstance(raw_content, str) else raw_content
        if len(raw_bytes) > self.max_response_size:
            raise GraphQLAnalyzerError(
                f"GraphQL content size exceeds maximum limit of {self.max_response_size} bytes."
            )

        try:
            data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
        except Exception as e:
            raise GraphQLAnalyzerError(f"Failed to parse GraphQL response as JSON: {e}") from e

        if not isinstance(data, dict):
            raise GraphQLAnalyzerError("GraphQL response must be a JSON object.")

        # Check for GraphQL errors
        errors = data.get("errors", [])
        if errors and not data.get("data"):
            # Introspection might be disabled or query rejected
            return GraphQLSchema(
                endpoint_url=endpoint_url,
                introspection_enabled=False,
                raw_size_bytes=len(raw_bytes),
                metadata={"errors": errors, "is_graphql": True},
            )

        schema_dict = data.get("data", {}).get("__schema")
        if not isinstance(schema_dict, dict):
            # Not an introspection schema response
            return GraphQLSchema(
                endpoint_url=endpoint_url,
                introspection_enabled=False,
                raw_size_bytes=len(raw_bytes),
                metadata={"is_graphql": False},
            )

        # Extract root type names
        query_type_name = (
            schema_dict.get("queryType", {}).get("name") if schema_dict.get("queryType") else None
        )
        mutation_type_name = (
            schema_dict.get("mutationType", {}).get("name")
            if schema_dict.get("mutationType")
            else None
        )
        subscription_type_name = (
            schema_dict.get("subscriptionType", {}).get("name")
            if schema_dict.get("subscriptionType")
            else None
        )

        raw_types = schema_dict.get("types", [])
        types_map: dict[str, GraphQLType] = {}

        if isinstance(raw_types, list):
            for t in raw_types[: self.max_types]:
                if not isinstance(t, dict):
                    continue
                type_name = str(t.get("name", ""))
                if not type_name:
                    continue

                fields: list[GraphQLField] = []
                raw_fields = t.get("fields")
                if isinstance(raw_fields, list):
                    for f in raw_fields[: self.max_fields]:
                        if not isinstance(f, dict):
                            continue
                        f_name = str(f.get("name", ""))
                        if not f_name:
                            continue

                        ret_type = format_type_signature(f.get("type"))
                        args: list[GraphQLArgument] = []
                        for a in f.get("args", []) if isinstance(f.get("args"), list) else []:
                            if isinstance(a, dict) and "name" in a:
                                a_type = format_type_signature(a.get("type"))
                                args.append(
                                    GraphQLArgument(
                                        name=str(a["name"]),
                                        arg_type=a_type,
                                        default_value=str(a.get("defaultValue"))
                                        if a.get("defaultValue") is not None
                                        else None,
                                        is_required=a_type.endswith("!"),
                                        description=a.get("description"),
                                    )
                                )

                        fields.append(
                            GraphQLField(
                                name=f_name,
                                return_type=ret_type,
                                arguments=args,
                                is_deprecated=bool(f.get("isDeprecated", False)),
                                deprecation_reason=f.get("deprecationReason"),
                                description=f.get("description"),
                            )
                        )

                types_map[type_name] = GraphQLType(
                    name=type_name,
                    kind=str(t.get("kind", "OBJECT")),
                    description=t.get("description"),
                    fields=fields,
                )

        # Build root queries, mutations, subscriptions
        queries: list[GraphQLOperation] = []
        if query_type_name and query_type_name in types_map:
            for f in types_map[query_type_name].fields:
                queries.append(self._field_to_operation(f, GraphQLOperationType.QUERY))

        mutations: list[GraphQLOperation] = []
        if mutation_type_name and mutation_type_name in types_map:
            for f in types_map[mutation_type_name].fields:
                mutations.append(self._field_to_operation(f, GraphQLOperationType.MUTATION))

        subscriptions: list[GraphQLOperation] = []
        if subscription_type_name and subscription_type_name in types_map:
            for f in types_map[subscription_type_name].fields:
                subscriptions.append(self._field_to_operation(f, GraphQLOperationType.SUBSCRIPTION))

        # Directives
        directives: list[str] = []
        raw_directives = schema_dict.get("directives", [])
        if isinstance(raw_directives, list):
            for d in raw_directives:
                if isinstance(d, dict) and "name" in d:
                    directives.append(str(d["name"]))

        return GraphQLSchema(
            endpoint_url=endpoint_url,
            introspection_enabled=True,
            queries=queries,
            mutations=mutations,
            subscriptions=subscriptions,
            types=types_map,
            directives=directives,
            raw_size_bytes=len(raw_bytes),
        )

    def _field_to_operation(
        self, field: GraphQLField, op_type: GraphQLOperationType
    ) -> GraphQLOperation:
        params: list[Parameter] = []
        for arg in field.arguments:
            params.append(
                Parameter(
                    name=arg.name,
                    location=ParameterLocation.GRAPHQL,
                    param_type=arg.arg_type,
                    required=arg.is_required,
                    description=arg.description,
                )
            )

        is_destructive = op_type == GraphQLOperationType.MUTATION

        return GraphQLOperation(
            name=field.name,
            operation_type=op_type,
            return_type=field.return_type,
            arguments=field.arguments,
            parameters=params,
            is_destructive=is_destructive,
            description=field.description,
        )

    def extract_endpoints_from_schema(self, schema: GraphQLSchema) -> list[DiscoveredWebEndpoint]:
        """Convert GraphQL operations into canonical DiscoveredWebEndpoints."""
        all_ops = schema.queries + schema.mutations + schema.subscriptions
        endpoints: list[DiscoveredWebEndpoint] = []

        for op in all_ops:
            ep = DiscoveredWebEndpoint(
                url=schema.endpoint_url,
                method=HTTPMethod.POST,
                parameters=op.parameters,
                source="graphql",
                title=f"GraphQL {op.operation_type.value}: {op.name}",
                metadata={
                    "discovered_not_authorized": True,
                    "graphql_operation": op.name,
                    "graphql_type": op.operation_type.value,
                    "return_type": op.return_type,
                    "is_destructive": op.is_destructive,
                },
            )
            endpoints.append(ep)

        return endpoints
