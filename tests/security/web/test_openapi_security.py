"""Security tests for Phase 3.4 OpenAPI schema analysis."""

import pytest

from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.web.openapi.analyzer import OpenAPIAnalyzer
from arka.app.web.openapi.parser import OpenAPIParseError, SafeOpenAPIParser


@pytest.fixture
def scope_guard() -> ScopeGuard:
    scope = ScopeDefinition(
        engagement_id="eng-sec-openapi",
        includes=ScopeTarget(
            domains=["authorized.example.com"],
            ports=[80, 443],
        ),
        excludes=ScopeTarget(
            domains=["attacker.evil.com", "internal.corp"],
        ),
    )
    return ScopeGuard(scope)


def test_attacker_controlled_server_does_not_expand_scope(scope_guard: ScopeGuard) -> None:
    """Security Invariant: Declared servers are NEVER automatically authorized."""
    hostile_openapi = """{
      "openapi": "3.0.0",
      "info": {"title": "Hostile Spec", "version": "1.0"},
      "servers": [
        {"url": "https://authorized.example.com/api", "description": "Authorized"},
        {"url": "https://attacker.evil.com/c2", "description": "Attacker controlled"},
        {"url": "https://internal.corp/secret", "description": "Internal target"}
      ],
      "paths": {
        "/status": {"get": {"responses": {"200": {"description": "OK"}}}}
      }
    }"""

    analyzer = OpenAPIAnalyzer(scope_guard=scope_guard)
    schema = analyzer.analyze_content(
        hostile_openapi, source_url="https://authorized.example.com/openapi.json"
    )

    # Verify each server's authorization status
    server_auth = {s.url: s.in_authorized_scope for s in schema.servers}
    assert server_auth["https://authorized.example.com/api"] is True
    assert server_auth["https://attacker.evil.com/c2"] is False
    assert server_auth["https://internal.corp/secret"] is False

    # Verify ScopeGuard has not been modified or expanded
    assert scope_guard.validate_url("https://attacker.evil.com/c2") is False
    assert scope_guard.validate_url("https://internal.corp/secret") is False


def test_external_ref_rejected() -> None:
    """Security: External $ref targets (HTTP/file) must be rejected
    to prevent SSRF and arbitrary inclusion.
    """
    spec_with_external_ref = """{
      "openapi": "3.0.0",
      "info": {"title": "External Ref Spec", "version": "1.0"},
      "paths": {
        "/test": {
          "get": {
            "parameters": [
              {"$ref": "https://attacker.evil.com/external-param.json"}
            ],
            "responses": {"200": {"description": "OK"}}
          }
        }
      }
    }"""

    parser = SafeOpenAPIParser()
    schema = parser.parse(spec_with_external_ref)

    assert len(schema.operations) == 1
    op = schema.operations[0]
    # The external ref must NOT be fetched or resolved
    assert len(op.parameters) == 0


def test_circular_ref_handled_without_infinite_loop() -> None:
    """Security: Circular internal $ref must not cause infinite loops or stack overflow."""
    spec_with_cycle = """{
      "openapi": "3.0.0",
      "info": {"title": "Cycle Spec", "version": "1.0"},
      "paths": {
        "/tree": {
          "post": {
            "requestBody": {
              "content": {
                "application/json": {
                  "schema": {"$ref": "#/components/schemas/Node"}
                }
              }
            },
            "responses": {"200": {"description": "OK"}}
          }
        }
      },
      "components": {
        "schemas": {
          "Node": {
            "type": "object",
            "properties": {
              "parent": {"$ref": "#/components/schemas/Node"},
              "value": {"type": "string"}
            }
          }
        }
      }
    }"""

    parser = SafeOpenAPIParser(max_recursion_depth=10)
    schema = parser.parse(spec_with_cycle)

    assert len(schema.operations) == 1
    op = schema.operations[0]
    param_names = [p.name for p in op.parameters]
    assert "value" in param_names


def test_unsafe_yaml_deserialization_blocked() -> None:
    """Security: Unsafe YAML tags must fail parsing rather than
    executing arbitrary Python bytecode.
    """
    malicious_yaml = """
openapi: 3.0.0
info:
  title: !!python/object/apply:os.system ["echo PWNED"]
  version: 1.0
paths: {}
"""
    parser = SafeOpenAPIParser()
    with pytest.raises(OpenAPIParseError):
        parser.parse(malicious_yaml)
