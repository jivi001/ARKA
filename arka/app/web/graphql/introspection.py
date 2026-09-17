"""Controlled GraphQL Introspection Queries and Type Formatters.

Enforces query complexity bounds and limits recursion depth during schema parsing.
"""

from __future__ import annotations

from typing import Any

# Lightweight probe query to test if an endpoint speaks GraphQL
GRAPHQL_PROBE_QUERY = "query Probe { __typename }"

# Standard bounded GraphQL introspection query
GRAPHQL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
        args {
          name
          description
          defaultValue
          type {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
        type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
      inputFields {
        name
        description
        defaultValue
        type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
      enumValues(includeDeprecated: true) {
        name
      }
    }
    directives {
      name
      description
    }
  }
}
""".strip()


def format_type_signature(
    type_dict: dict[str, Any] | None, depth: int = 0, max_depth: int = 10
) -> str:
    """Format a nested GraphQL type dictionary into a readable type string (e.g. '[String!]!')."""
    if not type_dict or depth > max_depth:
        return "Unknown"

    kind = type_dict.get("kind")
    name = type_dict.get("name")
    of_type = type_dict.get("ofType")

    if kind == "NON_NULL":
        inner = format_type_signature(of_type, depth + 1, max_depth)
        return f"{inner}!"
    if kind == "LIST":
        inner = format_type_signature(of_type, depth + 1, max_depth)
        return f"[{inner}]"
    if name:
        return str(name)

    return "Unknown"
