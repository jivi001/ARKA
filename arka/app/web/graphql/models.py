"""Domain models for GraphQL schema and operation analysis."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from arka.app.web.models.parameters import Parameter


class GraphQLOperationType(str, Enum):
    """GraphQL operation classifications."""

    QUERY = "query"
    MUTATION = "mutation"
    SUBSCRIPTION = "subscription"


class GraphQLArgument(BaseModel):
    """Argument accepted by a GraphQL field or operation."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Argument name")
    arg_type: str = Field(..., description="Type signature (e.g. String!, Int, UserInput)")
    default_value: str | None = Field(default=None)
    is_required: bool = Field(default=False)
    description: str | None = Field(default=None)


class GraphQLField(BaseModel):
    """A field exposed on a GraphQL object or interface."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Field name")
    return_type: str = Field(..., description="Return type signature")
    arguments: list[GraphQLArgument] = Field(default_factory=list)
    is_deprecated: bool = Field(default=False)
    deprecation_reason: str | None = Field(default=None)
    description: str | None = Field(default=None)


class GraphQLType(BaseModel):
    """A GraphQL type definition extracted from the schema."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Type name")
    kind: str = Field(..., description="OBJECT, SCALAR, INTERFACE, UNION, ENUM, INPUT_OBJECT")
    description: str | None = Field(default=None)
    fields: list[GraphQLField] = Field(default_factory=list)
    input_fields: list[GraphQLArgument] = Field(default_factory=list)
    enum_values: list[str] = Field(default_factory=list)


class GraphQLOperation(BaseModel):
    """A root GraphQL operation (Query, Mutation, or Subscription)."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Operation field name")
    operation_type: GraphQLOperationType = Field(...)
    return_type: str = Field(default="Unknown")
    arguments: list[GraphQLArgument] = Field(default_factory=list)
    parameters: list[Parameter] = Field(
        default_factory=list, description="Canonical Parameter representation of arguments"
    )
    is_destructive: bool = Field(
        default=False,
        description="Whether this operation is a mutation that alters state or data",
    )
    description: str | None = Field(default=None)


class GraphQLSchema(BaseModel):
    """Complete analyzed GraphQL schema representation."""

    model_config = ConfigDict(frozen=True)

    endpoint_url: str = Field(..., description="URL of the GraphQL endpoint")
    introspection_enabled: bool = Field(default=False)
    queries: list[GraphQLOperation] = Field(default_factory=list)
    mutations: list[GraphQLOperation] = Field(default_factory=list)
    subscriptions: list[GraphQLOperation] = Field(default_factory=list)
    types: dict[str, GraphQLType] = Field(default_factory=dict)
    directives: list[str] = Field(default_factory=list)
    raw_size_bytes: int = Field(default=0)
    metadata: dict[str, Any] = Field(default_factory=dict)
