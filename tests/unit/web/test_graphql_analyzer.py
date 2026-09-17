"""Unit tests for Phase 3.5: GraphQL Discovery and Introspection Analysis."""

import pytest

from arka.app.web.graphql.analyzer import GraphQLAnalyzer, GraphQLAnalyzerError
from arka.app.web.graphql.models import GraphQLOperationType
from arka.app.web.models.http import HTTPMethod
from arka.app.web.models.parameters import ParameterLocation

SAMPLE_INTROSPECTION_JSON = """{
  "data": {
    "__schema": {
      "queryType": {"name": "Query"},
      "mutationType": {"name": "Mutation"},
      "subscriptionType": null,
      "types": [
        {
          "name": "Query",
          "kind": "OBJECT",
          "description": "Root query type",
          "fields": [
            {
              "name": "user",
              "description": "Get user by ID",
              "type": {"kind": "OBJECT", "name": "User"},
              "args": [
                {
                  "name": "id",
                  "description": "User ID",
                  "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}
                }
              ]
            },
            {
              "name": "users",
              "description": "List all users",
              "type": {
                "kind": "LIST",
                "ofType": {"kind": "OBJECT", "name": "User"}
              },
              "args": []
            }
          ]
        },
        {
          "name": "Mutation",
          "kind": "OBJECT",
          "description": "Root mutation type",
          "fields": [
            {
              "name": "deleteUser",
              "description": "Delete a user account",
              "type": {"kind": "SCALAR", "name": "Boolean"},
              "args": [
                {
                  "name": "id",
                  "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}
                }
              ]
            }
          ]
        },
        {
          "name": "User",
          "kind": "OBJECT",
          "description": "A system user",
          "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}},
            {"name": "email", "type": {"kind": "SCALAR", "name": "String"}},
            {"name": "name", "type": {"kind": "SCALAR", "name": "String"}}
          ]
        }
      ],
      "directives": [
        {"name": "deprecated", "description": "Marks element as deprecated"}
      ]
    }
  }
}"""

INTROSPECTION_DISABLED_JSON = """{
  "errors": [
    {
      "message": "GraphQL introspection is not allowed by server policy.",
      "locations": [{"line": 2, "column": 3}]
    }
  ]
}"""


def test_parse_valid_introspection_schema() -> None:
    analyzer = GraphQLAnalyzer()
    schema = analyzer.parse_introspection_response(
        SAMPLE_INTROSPECTION_JSON, endpoint_url="https://api.example.com/graphql"
    )

    assert schema.introspection_enabled is True
    assert schema.endpoint_url == "https://api.example.com/graphql"
    assert len(schema.queries) == 2
    assert len(schema.mutations) == 1
    assert len(schema.subscriptions) == 0

    # Verify query
    q_map = {q.name: q for q in schema.queries}
    assert "user" in q_map
    user_q = q_map["user"]
    assert user_q.operation_type == GraphQLOperationType.QUERY
    assert user_q.return_type == "User"
    assert len(user_q.arguments) == 1
    assert user_q.arguments[0].name == "id"
    assert user_q.arguments[0].arg_type == "ID!"
    assert user_q.arguments[0].is_required is True

    # Verify mutation and is_destructive flag
    del_mut = schema.mutations[0]
    assert del_mut.name == "deleteUser"
    assert del_mut.operation_type == GraphQLOperationType.MUTATION
    assert del_mut.is_destructive is True

    # Directives
    assert "deprecated" in schema.directives


def test_parse_introspection_disabled() -> None:
    analyzer = GraphQLAnalyzer()
    schema = analyzer.parse_introspection_response(
        INTROSPECTION_DISABLED_JSON, endpoint_url="https://api.example.com/graphql"
    )

    assert schema.introspection_enabled is False
    assert schema.metadata.get("is_graphql") is True
    assert "errors" in schema.metadata


def test_parse_malformed_json() -> None:
    analyzer = GraphQLAnalyzer()
    with pytest.raises(GraphQLAnalyzerError, match="Failed to parse GraphQL response as JSON"):
        analyzer.parse_introspection_response(
            "INVALID_JSON", endpoint_url="https://api.example.com/graphql"
        )


def test_oversized_response_blocked() -> None:
    analyzer = GraphQLAnalyzer(max_response_size=100)
    with pytest.raises(GraphQLAnalyzerError, match="exceeds maximum limit"):
        analyzer.parse_introspection_response(
            SAMPLE_INTROSPECTION_JSON, endpoint_url="https://api.example.com/graphql"
        )


def test_extract_endpoints_from_graphql_schema() -> None:
    analyzer = GraphQLAnalyzer()
    schema = analyzer.parse_introspection_response(
        SAMPLE_INTROSPECTION_JSON, endpoint_url="https://api.example.com/graphql"
    )

    endpoints = analyzer.extract_endpoints_from_schema(schema)
    assert len(endpoints) == 3  # 2 queries + 1 mutation

    for ep in endpoints:
        assert ep.url == "https://api.example.com/graphql"
        assert ep.method == HTTPMethod.POST
        assert ep.source == "graphql"
        assert ep.metadata["discovered_not_authorized"] is True

    mut_ep = next(e for e in endpoints if e.metadata["graphql_operation"] == "deleteUser")
    assert mut_ep.metadata["is_destructive"] is True
    assert any(
        p.name == "id" and p.location == ParameterLocation.GRAPHQL for p in mut_ep.parameters
    )
