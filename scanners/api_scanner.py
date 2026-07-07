"""
scanners/api_scanner.py — API endpoint discovery scanner (v2 async rewrite).
Probes common API routes and checks for Swagger/OpenAPI exposure and GraphQL introspection.
"""
from __future__ import annotations

import asyncio
import json
from typing import Dict, List, Optional
import httpx

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner

_API_ROUTES = [
    "api", "api/v1", "api/v2", "api/v3", "swagger.json", "openapi.json",
    "api-docs", "graphql", "rest", "v1/api", "v2/api",
    ".well-known/openid-configuration", "actuator", "actuator/health",
]


class APIScanner(BaseScanner):
    """Async API endpoint discovery scanner."""

    async def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        base_url = self.ctx.target.rstrip("/")
        semaphore = asyncio.Semaphore(5)

        async def test_route(route: str) -> dict:
            url = f"{base_url}/{route}"
            async with semaphore:
                resp = await self.get(url)
                if resp and resp.status_code in (200, 401, 403, 405):
                    rtype = "REST"
                    if "graphql" in route:
                        rtype = "GraphQL"
                    elif any(k in route for k in ("swagger", "openapi", "json")):
                        rtype = "Swagger Spec"
                    elif "actuator" in route:
                        rtype = "Spring Actuator"
                    return {"route": route, "url": url, "status": resp.status_code, "type": rtype, "body": resp.text}
            return {}

        tasks = [test_route(r) for r in _API_ROUTES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        discovered = [r for r in results if isinstance(r, dict) and r.get("route")]

        for r in discovered:
            findings.append(self.finding(
                title=f"API Route Detected: /{r['route']}",
                severity="INFO",
                description=f"API endpoint or specification at /{r['route']} ({r['type']}).",
                evidence={"url": r["url"], "status_code": r["status"], "type": r["type"]},
                remediation="Enforce authentication and authorization on all API endpoints.",
                target=r["url"],
                tags=["api", r["type"].lower().replace(" ", "-")],
            ))

            # Swagger/OpenAPI spec exposure
            if r["type"] == "Swagger Spec" and r["status"] == 200:
                findings.append(self.finding(
                    title="API Specification Publicly Exposed",
                    severity="LOW",
                    description="Swagger/OpenAPI spec is publicly accessible, revealing API structure.",
                    evidence={"spec_url": r["url"]},
                    remediation="Restrict API spec access in production behind authentication.",
                    target=r["url"],
                    tags=["api", "swagger"],
                ))

                # Actively parse the schema to discover sub-endpoints!
                discovered_api_urls = self._parse_openapi_spec(r["body"], base_url)
                if discovered_api_urls:
                    self.log.info(f"APIScanner: Discovered {len(discovered_api_urls)} API endpoints from schema spec!")
                    for api_url in discovered_api_urls:
                        if api_url not in self.ctx.discovered_urls:
                            self.ctx.discovered_urls.append(api_url)

            # GraphQL introspection
            if r["type"] == "GraphQL" and r["status"] == 200:
                intro_resp = await self.post(
                    r["url"],
                    json={"query": "{__schema{types{name}}}"},
                )
                if intro_resp and "__schema" in intro_resp.text:
                    findings.append(self.finding(
                        title="GraphQL Introspection Enabled",
                        severity="MEDIUM",
                        description="GraphQL introspection reveals the full schema to any user.",
                        evidence={"url": r["url"], "introspection": True},
                        remediation="Disable introspection in production GraphQL configuration.",
                        target=r["url"],
                        tags=["api", "graphql", "introspection"],
                    ))

            # Spring Actuator exposure
            if r["type"] == "Spring Actuator" and r["status"] == 200:
                findings.append(self.finding(
                    title="Spring Actuator Endpoint Exposed",
                    severity="MEDIUM",
                    description="Spring Boot Actuator endpoints are publicly accessible, potentially exposing env vars and health info.",
                    evidence={"url": r["url"]},
                    remediation="Restrict Actuator endpoints via Spring Security or network-level access controls.",
                    target=r["url"],
                    tags=["api", "actuator"],
                ))

        return findings

    def _parse_openapi_spec(self, spec_text: str, base_url: str) -> List[str]:
        """Parse OpenAPI/Swagger JSON and extract parameterized URLs."""
        urls = []
        try:
            data = json.loads(spec_text)
            paths = data.get("paths", {})
            if not isinstance(paths, dict):
                return []
                
            for path, path_info in paths.items():
                if not isinstance(path_info, dict):
                    continue
                
                # Check parameters defined at path level or method level
                path_params = path_info.get("parameters", [])
                
                # Construct query parameters
                for method, method_info in path_info.items():
                    if method.lower() not in ("get", "post", "put", "delete", "options", "head", "patch"):
                        continue
                    if not isinstance(method_info, dict):
                        continue
                        
                    method_params = method_info.get("parameters", [])
                    all_params = path_params + method_params
                    
                    query_args = []
                    path_str = path
                    
                    for param in all_params:
                        if not isinstance(param, dict):
                            continue
                        name = param.get("name")
                        in_type = param.get("in", "")
                        
                        if not name:
                            continue
                            
                        if in_type == "query":
                            query_args.append(f"{name}=test")
                        elif in_type == "path":
                            # Replace path parameter placeholders {name} with a test value
                            path_str = path_str.replace(f"{{{name}}}", "1")
                            
                    full_path = path_str
                    if query_args:
                        full_path += "?" + "&".join(query_args)
                        
                    full_url = base_url.rstrip("/") + "/" + full_path.lstrip("/")
                    if full_url not in urls:
                        urls.append(full_url)
        except Exception as exc:
            self.log.debug(f"Failed to parse OpenAPI spec: {exc}")
        return urls
