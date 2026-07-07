"""
Unit tests for APIScanner and OpenAPI spec parsing (Phase 13).
"""
import pytest
import respx
import httpx
from core.context import ScanContext
from core.findings import Finding
from scanners.api_scanner import APIScanner


@pytest.mark.asyncio
@respx.mock
async def test_api_scanner_openapi_discovery():
    target = "https://api-test.local"
    ctx = ScanContext(target=target, host="api-test.local", profile="quick")
    
    # Mock Swagger specification exposure
    mock_spec = {
        "swagger": "2.0",
        "info": {"title": "Test API", "version": "1.0"},
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "type": "integer"}
                    ]
                }
            },
            "/search": {
                "get": {
                    "parameters": [
                        {"name": "query", "in": "query", "required": False, "type": "string"},
                        {"name": "limit", "in": "query", "required": False, "type": "integer"}
                    ]
                }
            }
        }
    }
    
    respx.get(f"{target}/swagger.json").mock(
        return_value=httpx.Response(200, json=mock_spec)
    )
    
    # Mock other endpoints as 404
    for r in ["api", "api/v1", "api/v2", "api/v3", "openapi.json", "api-docs", "graphql", "rest", "v1/api", "v2/api", ".well-known/openid-configuration", "actuator", "actuator/health"]:
        respx.get(f"{target}/{r}").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient() as client:
        scanner = APIScanner(ctx, client)
        findings = await scanner.scan()

    # Findings should include Swagger exposed and API Route Detected
    assert any("API Specification Publicly Exposed" in f.title for f in findings)
    assert any("API Route Detected: /swagger.json" in f.title for f in findings)
    
    # Discovered URLs should be populated from paths
    assert f"{target}/users/1" in ctx.discovered_urls
    assert f"{target}/search?query=test&limit=test" in ctx.discovered_urls


@pytest.mark.asyncio
@respx.mock
async def test_api_scanner_graphql_introspection():
    target = "https://graphql-test.local"
    ctx = ScanContext(target=target, host="graphql-test.local", profile="quick")
    
    respx.get(f"{target}/graphql").mock(return_value=httpx.Response(200))
    respx.post(f"{target}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"__schema": {"types": [{"name": "User"}]}}})
    )
    
    # Mock all other endpoints as 404
    for r in ["api", "api/v1", "api/v2", "api/v3", "swagger.json", "openapi.json", "api-docs", "rest", "v1/api", "v2/api", ".well-known/openid-configuration", "actuator", "actuator/health"]:
        respx.get(f"{target}/{r}").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient() as client:
        scanner = APIScanner(ctx, client)
        findings = await scanner.scan()

    assert any("GraphQL Introspection Enabled" in f.title for f in findings)


@pytest.mark.asyncio
@respx.mock
async def test_api_scanner_spring_actuator():
    target = "https://actuator-test.local"
    ctx = ScanContext(target=target, host="actuator-test.local", profile="quick")
    
    respx.get(f"{target}/actuator").mock(return_value=httpx.Response(200))
    
    # Mock all other endpoints as 404
    for r in ["api", "api/v1", "api/v2", "api/v3", "swagger.json", "openapi.json", "api-docs", "graphql", "rest", "v1/api", "v2/api", ".well-known/openid-configuration", "actuator/health"]:
        respx.get(f"{target}/{r}").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient() as client:
        scanner = APIScanner(ctx, client)
        findings = await scanner.scan()

    assert any("Spring Actuator Endpoint Exposed" in f.title for f in findings)
