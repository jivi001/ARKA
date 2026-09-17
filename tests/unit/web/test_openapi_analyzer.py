"""Unit tests for Phase 3.4: OpenAPI and Swagger Parsing and Discovery."""

import pytest

from arka.app.web.models.http import HTTPMethod
from arka.app.web.models.parameters import ParameterLocation
from arka.app.web.openapi.analyzer import OpenAPIAnalyzer
from arka.app.web.openapi.parser import OpenAPIParseError, SafeOpenAPIParser

SAMPLE_OPENAPI_JSON = """{
  "openapi": "3.0.1",
  "info": {
    "title": "User Service API",
    "version": "1.2.0",
    "description": "API for managing users and sessions"
  },
  "servers": [
    {"url": "https://api.example.com/v1", "description": "Production"}
  ],
  "paths": {
    "/users": {
      "get": {
        "summary": "List users",
        "operationId": "listUsers",
        "parameters": [
          {"name": "page", "in": "query", "schema": {"type": "integer"}, "example": 1},
          {"name": "search", "in": "query", "schema": {"type": "string"}}
        ],
        "responses": {"200": {"description": "Success"}}
      },
      "post": {
        "summary": "Create user",
        "operationId": "createUser",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["email", "username"],
                "properties": {
                  "username": {"type": "string", "description": "User login name"},
                  "email": {"type": "string", "description": "Primary email"}
                }
              }
            }
          }
        },
        "responses": {"201": {"description": "Created"}}
      }
    },
    "/users/{id}": {
      "parameters": [
        {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
      ],
      "get": {
        "summary": "Get user by ID",
        "responses": {"200": {"description": "User found"}}
      },
      "delete": {
        "summary": "Delete user",
        "responses": {"204": {"description": "Deleted"}}
      }
    }
  },
  "components": {
    "securitySchemes": {
      "BearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT"
      },
      "ApiKeyAuth": {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-KEY"
      }
    }
  }
}"""

SAMPLE_OPENAPI_YAML = """
openapi: 3.0.0
info:
  title: Products API
  version: 2.0.0
servers:
  - url: https://products.example.com
paths:
  /products:
    get:
      summary: Get products
      parameters:
        - name: category
          in: query
          schema:
            type: string
      responses:
        '200':
          description: OK
"""

SAMPLE_SWAGGER_JSON = """{
  "swagger": "2.0",
  "info": {
    "title": "Legacy Swagger API",
    "version": "1.0.0"
  },
  "host": "legacy.example.com",
  "basePath": "/v1",
  "schemes": ["https"],
  "paths": {
    "/items": {
      "get": {
        "summary": "List items",
        "parameters": [
          {"name": "limit", "in": "query", "type": "integer"}
        ],
        "responses": {"200": {"description": "OK"}}
      }
    }
  }
}"""


def test_parse_valid_openapi_json() -> None:
    parser = SafeOpenAPIParser()
    schema = parser.parse(SAMPLE_OPENAPI_JSON, source_url="https://api.example.com/openapi.json")

    assert schema.title == "User Service API"
    assert schema.version == "1.2.0"
    assert schema.spec_version == "3.0.1"
    assert len(schema.servers) == 1
    assert schema.servers[0].url == "https://api.example.com/v1"

    # Operations: GET /users, POST /users, GET /users/{id}, DELETE /users/{id}
    assert len(schema.operations) == 4
    op_map = {(op.path, op.method): op for op in schema.operations}

    # Verify GET /users
    get_users = op_map[("/users", HTTPMethod.GET)]
    assert get_users.summary == "List users"
    param_names = {p.name for p in get_users.parameters}
    assert "page" in param_names
    assert "search" in param_names

    # Verify POST /users with JSON body parameters
    post_users = op_map[("/users", HTTPMethod.POST)]
    body_params = {p.name: p for p in post_users.parameters if p.location == ParameterLocation.JSON}
    assert "username" in body_params
    assert body_params["username"].required is True
    assert "email" in body_params

    # Verify DELETE /users/{id}
    del_user = op_map[("/users/{id}", HTTPMethod.DELETE)]
    assert del_user.is_destructive is True
    assert any(p.name == "id" and p.location == ParameterLocation.PATH for p in del_user.parameters)

    # Verify Security Schemes
    assert "BearerAuth" in schema.security_schemes
    assert schema.security_schemes["BearerAuth"].http_scheme == "bearer"
    assert "ApiKeyAuth" in schema.security_schemes
    assert schema.security_schemes["ApiKeyAuth"].location == "header"


def test_parse_valid_openapi_yaml() -> None:
    parser = SafeOpenAPIParser()
    schema = parser.parse(
        SAMPLE_OPENAPI_YAML, source_url="https://products.example.com/openapi.yaml"
    )

    assert schema.title == "Products API"
    assert schema.version == "2.0.0"
    assert len(schema.operations) == 1
    op = schema.operations[0]
    assert op.path == "/products"
    assert op.method == HTTPMethod.GET
    assert op.parameters[0].name == "category"


def test_parse_swagger_2_json() -> None:
    parser = SafeOpenAPIParser()
    schema = parser.parse(SAMPLE_SWAGGER_JSON, source_url="https://legacy.example.com/swagger.json")

    assert schema.title == "Legacy Swagger API"
    assert schema.spec_version == "2.0"
    assert len(schema.servers) == 1
    assert schema.servers[0].url == "https://legacy.example.com/v1"
    assert len(schema.operations) == 1
    assert schema.operations[0].path == "/items"


def test_oversized_document_rejected() -> None:
    parser = SafeOpenAPIParser(max_document_size=100)
    with pytest.raises(OpenAPIParseError, match="exceeds maximum allowed limit"):
        parser.parse(SAMPLE_OPENAPI_JSON)


def test_malformed_document_rejected() -> None:
    parser = SafeOpenAPIParser()
    with pytest.raises(OpenAPIParseError, match="Failed to parse document"):
        parser.parse("NOT_VALID_JSON_OR_YAML: [ { unclosed")


def test_missing_version_rejected() -> None:
    parser = SafeOpenAPIParser()
    with pytest.raises(OpenAPIParseError, match="missing required 'openapi' or 'swagger'"):
        parser.parse('{"info": {"title": "No Version API"}}')


def test_extract_endpoints_from_schema() -> None:
    analyzer = OpenAPIAnalyzer()
    schema = SafeOpenAPIParser().parse(
        SAMPLE_OPENAPI_JSON, source_url="https://api.example.com/openapi.json"
    )

    endpoints = analyzer.extract_endpoints_from_schema(
        schema, fallback_origin="https://api.example.com"
    )
    assert len(endpoints) == 4

    ep_urls = {ep.url for ep in endpoints}
    assert "https://api.example.com/users" in ep_urls
    assert "https://api.example.com/users/{id}" in ep_urls

    for ep in endpoints:
        assert ep.metadata["discovered_not_authorized"] is True
        assert ep.source == "openapi"
