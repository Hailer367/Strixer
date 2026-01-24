"""
Advanced Proxy Actions for Traffic Analysis and Request Manipulation.

This module provides comprehensive proxy capabilities:
- Request listing and filtering with HTTPQL
- Detailed request/response viewing with search
- Request replay with modifications
- Scope management for targeted testing
- Sitemap exploration for attack surface mapping
- Traffic analysis and pattern detection
- Session handling and cookie management
"""

from typing import Any, Literal, Optional, Dict, List
import re

from strix.tools.registry import register_tool


RequestPart = Literal["request", "response"]


@register_tool
def list_requests(
    httpql_filter: str | None = None,
    start_page: int = 1,
    end_page: int = 1,
    page_size: int = 50,
    sort_by: Literal[
        "timestamp",
        "host",
        "method",
        "path",
        "status_code",
        "response_time",
        "response_size",
        "source",
    ] = "timestamp",
    sort_order: Literal["asc", "desc"] = "desc",
    scope_id: str | None = None,
) -> dict[str, Any]:
    """
    List intercepted HTTP requests with powerful HTTPQL filtering.
    
    Filter Examples:
    - host:example.com - Requests to specific host
    - method:POST - Only POST requests
    - status:200 - Requests with specific status
    - path:/api/* - Path pattern matching
    - body:password - Requests containing 'password' in body
    """
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.list_requests(
        httpql_filter, start_page, end_page, page_size, sort_by, sort_order, scope_id
    )


@register_tool
def view_request(
    request_id: str,
    part: RequestPart = "request",
    search_pattern: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """
    View detailed request or response content with optional search.
    
    Supports regex patterns for searching within request/response bodies.
    Useful for finding sensitive data, tokens, or specific patterns.
    """
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.view_request(request_id, part, search_pattern, page, page_size)


@register_tool
def send_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 30,
) -> dict[str, Any]:
    """
    Send a custom HTTP request through the proxy.
    
    All requests are logged and can be viewed with list_requests().
    """
    from .proxy_manager import get_proxy_manager

    if headers is None:
        headers = {}
    manager = get_proxy_manager()
    return manager.send_simple_request(method, url, headers, body, timeout)


@register_tool
def repeat_request(
    request_id: str,
    modifications: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Replay a captured request with optional modifications.
    
    Modifications can include:
    - url: Change the target URL
    - params: Modify query parameters
    - headers: Add/modify headers
    - body: Replace request body
    - cookies: Modify cookies
    
    Useful for testing parameter tampering and auth bypass.
    """
    from .proxy_manager import get_proxy_manager

    if modifications is None:
        modifications = {}
    manager = get_proxy_manager()
    return manager.repeat_request(request_id, modifications)


@register_tool
def scope_rules(
    action: Literal["get", "list", "create", "update", "delete"],
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> dict[str, Any]:
    """
    Manage proxy scope rules to filter traffic.
    
    Scopes define which hosts/paths are captured:
    - allowlist: Only capture matching patterns
    - denylist: Exclude matching patterns
    
    Pattern examples: *.example.com, /api/*
    """
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.scope_rules(action, allowlist, denylist, scope_id, scope_name)


@register_tool
def list_sitemap(
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: Literal["DIRECT", "ALL"] = "DIRECT",
    page: int = 1,
) -> dict[str, Any]:
    """
    Explore the discovered sitemap hierarchy.
    
    The sitemap is automatically built from captured traffic,
    showing the structure of discovered endpoints.
    """
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.list_sitemap(scope_id, parent_id, depth, page)


@register_tool
def view_sitemap_entry(
    entry_id: str,
) -> dict[str, Any]:
    """
    View detailed information about a sitemap entry.
    
    Shows related requests and response statistics.
    """
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.view_sitemap_entry(entry_id)


@register_tool
def analyze_traffic(
    httpql_filter: str | None = None,
    scope_id: str | None = None,
    analysis_type: Literal["security", "performance", "patterns", "all"] = "all",
) -> dict[str, Any]:
    """
    Perform comprehensive traffic analysis on captured requests.
    
    Analysis Types:
    - security: Find potential security issues (auth tokens, sensitive data)
    - performance: Analyze response times and sizes
    - patterns: Detect repeated patterns and anomalies
    - all: Complete analysis
    
    Returns actionable insights for security testing.
    """
    from .proxy_manager import get_proxy_manager
    
    manager = get_proxy_manager()
    
    # Get all requests matching filter
    requests_result = manager.list_requests(
        httpql_filter=httpql_filter,
        start_page=1,
        end_page=10,
        page_size=100,
        scope_id=scope_id,
    )
    
    requests = requests_result.get("requests", [])
    
    analysis = {
        "total_requests": len(requests),
        "filter_applied": httpql_filter,
        "findings": [],
        "statistics": {},
        "patterns": [],
    }
    
    if not requests:
        return {"success": True, "analysis": analysis, "message": "No requests to analyze"}
    
    # Security Analysis
    if analysis_type in ("security", "all"):
        security_findings = _analyze_security_patterns(requests, manager)
        analysis["findings"].extend(security_findings)
    
    # Performance Analysis
    if analysis_type in ("performance", "all"):
        perf_stats = _analyze_performance(requests)
        analysis["statistics"]["performance"] = perf_stats
    
    # Pattern Analysis
    if analysis_type in ("patterns", "all"):
        patterns = _detect_patterns(requests)
        analysis["patterns"] = patterns
    
    # Calculate overall statistics
    analysis["statistics"]["methods"] = _count_by_field(requests, "method")
    analysis["statistics"]["status_codes"] = _count_by_field(
        [r for r in requests if r.get("response")],
        lambda r: r.get("response", {}).get("statusCode")
    )
    analysis["statistics"]["hosts"] = _count_by_field(requests, "host")[:10]  # Top 10
    
    return {"success": True, "analysis": analysis}


def _analyze_security_patterns(
    requests: List[Dict[str, Any]],
    manager: Any,
) -> List[Dict[str, Any]]:
    """Analyze requests for security-relevant patterns."""
    findings = []
    
    # Patterns to look for in requests
    sensitive_patterns = {
        "jwt_token": r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        "api_key": r'(?:api[_-]?key|apikey|api_secret)[=:]\s*["\']?([a-zA-Z0-9_-]{20,})',
        "password_param": r'(?:password|passwd|pwd)[=:]',
        "bearer_token": r'Bearer\s+[a-zA-Z0-9._-]+',
        "basic_auth": r'Basic\s+[a-zA-Z0-9+/=]+',
        "session_id": r'(?:session|sess|sid)[_-]?id[=:]["\']?([a-zA-Z0-9_-]+)',
        "credit_card": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
    }
    
    for req in requests[:50]:  # Analyze first 50 requests
        host = req.get("host", "")
        path = req.get("path", "")
        method = req.get("method", "GET")
        
        # Check for sensitive endpoints
        sensitive_endpoints = [
            "/login", "/auth", "/signin", "/token", "/oauth",
            "/admin", "/api/user", "/account", "/password"
        ]
        for endpoint in sensitive_endpoints:
            if endpoint in path.lower():
                findings.append({
                    "severity": "info",
                    "type": "sensitive_endpoint",
                    "message": f"Sensitive endpoint accessed: {method} {host}{path}",
                    "request_id": req.get("id"),
                })
                break
        
        # Check for potential parameter tampering points
        if req.get("query"):
            findings.append({
                "severity": "info",
                "type": "parameter_found",
                "message": f"Request with parameters: {method} {host}{path}?{req.get('query', '')[:50]}",
                "request_id": req.get("id"),
            })
        
        # Check response status for interesting codes
        response = req.get("response", {})
        status = response.get("statusCode", 0) if response else 0
        
        if status == 401:
            findings.append({
                "severity": "info",
                "type": "auth_required",
                "message": f"Authentication required: {method} {host}{path}",
                "request_id": req.get("id"),
            })
        elif status == 403:
            findings.append({
                "severity": "medium",
                "type": "forbidden_resource",
                "message": f"Forbidden resource (potential authz bypass target): {method} {host}{path}",
                "request_id": req.get("id"),
            })
        elif status >= 500:
            findings.append({
                "severity": "medium",
                "type": "server_error",
                "message": f"Server error detected: {status} at {method} {host}{path}",
                "request_id": req.get("id"),
            })
    
    return findings


def _analyze_performance(requests: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze performance metrics from requests."""
    response_times = []
    response_sizes = []
    
    for req in requests:
        response = req.get("response", {})
        if response:
            rt = response.get("roundtripTime", 0)
            if rt:
                response_times.append(rt)
            size = response.get("length", 0)
            if size:
                response_sizes.append(size)
    
    stats = {
        "total_requests": len(requests),
        "requests_with_response": len(response_times),
    }
    
    if response_times:
        stats["response_time"] = {
            "min_ms": min(response_times),
            "max_ms": max(response_times),
            "avg_ms": sum(response_times) / len(response_times),
        }
    
    if response_sizes:
        stats["response_size"] = {
            "min_bytes": min(response_sizes),
            "max_bytes": max(response_sizes),
            "avg_bytes": sum(response_sizes) / len(response_sizes),
            "total_bytes": sum(response_sizes),
        }
    
    return stats


def _detect_patterns(requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect patterns in request traffic."""
    patterns = []
    
    # Group by host
    hosts = {}
    for req in requests:
        host = req.get("host", "unknown")
        if host not in hosts:
            hosts[host] = []
        hosts[host].append(req)
    
    # Detect API versioning patterns
    version_pattern = re.compile(r'/v\d+/')
    for host, reqs in hosts.items():
        versions = set()
        for req in reqs:
            path = req.get("path", "")
            match = version_pattern.search(path)
            if match:
                versions.add(match.group())
        
        if len(versions) > 1:
            patterns.append({
                "type": "api_versioning",
                "host": host,
                "versions": list(versions),
                "message": f"Multiple API versions detected on {host}: {', '.join(versions)}",
            })
    
    # Detect file extensions
    extension_pattern = re.compile(r'\.([a-zA-Z0-9]{1,5})(?:\?|$)')
    extensions = {}
    for req in requests:
        path = req.get("path", "")
        match = extension_pattern.search(path)
        if match:
            ext = match.group(1).lower()
            extensions[ext] = extensions.get(ext, 0) + 1
    
    if extensions:
        patterns.append({
            "type": "file_extensions",
            "extensions": dict(sorted(extensions.items(), key=lambda x: -x[1])[:10]),
            "message": f"Common file extensions: {', '.join(list(extensions.keys())[:5])}",
        })
    
    return patterns


def _count_by_field(items: List[Any], field: Any) -> List[tuple]:
    """Count occurrences by field value."""
    counts = {}
    for item in items:
        if callable(field):
            value = field(item)
        else:
            value = item.get(field, "unknown") if isinstance(item, dict) else getattr(item, field, "unknown")
        
        if value:
            counts[value] = counts.get(value, 0) + 1
    
    return sorted(counts.items(), key=lambda x: -x[1])


@register_tool
def extract_parameters(
    request_id: str | None = None,
    httpql_filter: str | None = None,
) -> dict[str, Any]:
    """
    Extract and categorize parameters from requests.
    
    Useful for building wordlists and identifying injection points.
    Returns parameters categorized by type (query, body, header, cookie).
    """
    from .proxy_manager import get_proxy_manager
    
    manager = get_proxy_manager()
    
    if request_id:
        # Extract from single request
        request_data = manager.view_request(request_id, "request")
        if "error" in request_data:
            return request_data
        
        content = request_data.get("content", "")
        return _parse_parameters_from_content(content)
    
    # Extract from multiple requests
    requests_result = manager.list_requests(
        httpql_filter=httpql_filter,
        start_page=1,
        end_page=5,
        page_size=50,
    )
    
    all_params = {
        "query_params": set(),
        "body_params": set(),
        "headers": set(),
        "cookies": set(),
        "paths": set(),
    }
    
    for req in requests_result.get("requests", []):
        # Extract from query string
        query = req.get("query", "")
        if query:
            for param in query.split("&"):
                if "=" in param:
                    all_params["query_params"].add(param.split("=")[0])
        
        # Extract path parameters (looking for UUIDs, IDs, etc.)
        path = req.get("path", "")
        if path:
            # Detect potential path parameters
            segments = path.split("/")
            for segment in segments:
                if re.match(r'^[0-9a-f-]{36}$', segment):  # UUID
                    all_params["paths"].add("UUID")
                elif re.match(r'^\d+$', segment):  # Numeric ID
                    all_params["paths"].add("numeric_id")
    
    return {
        "success": True,
        "parameters": {k: list(v) for k, v in all_params.items()},
        "total_unique": sum(len(v) for v in all_params.values()),
    }


def _parse_parameters_from_content(content: str) -> dict[str, Any]:
    """Parse parameters from raw HTTP content."""
    params = {
        "query_params": [],
        "body_params": [],
        "headers": [],
        "cookies": [],
    }
    
    lines = content.split("\n")
    in_body = False
    body_content = []
    
    for line in lines:
        line = line.strip()
        
        if not line:
            in_body = True
            continue
        
        if not in_body:
            # Parse request line for query params
            if line.startswith(("GET", "POST", "PUT", "DELETE", "PATCH")):
                if "?" in line:
                    query_part = line.split("?")[1].split(" ")[0]
                    for param in query_part.split("&"):
                        if "=" in param:
                            params["query_params"].append(param.split("=")[0])
            
            # Parse headers
            elif ":" in line:
                header_name = line.split(":")[0]
                params["headers"].append(header_name)
                
                # Extract cookie params
                if header_name.lower() == "cookie":
                    cookie_value = line.split(":", 1)[1].strip()
                    for cookie in cookie_value.split(";"):
                        if "=" in cookie:
                            params["cookies"].append(cookie.strip().split("=")[0])
        else:
            body_content.append(line)
    
    # Parse body for parameters
    body = "\n".join(body_content)
    if body:
        # Try JSON parsing
        try:
            import json
            json_data = json.loads(body)
            if isinstance(json_data, dict):
                params["body_params"].extend(json_data.keys())
        except (json.JSONDecodeError, ValueError):
            # Try form data parsing
            for param in body.split("&"):
                if "=" in param:
                    params["body_params"].append(param.split("=")[0])
    
    return {"success": True, "parameters": params}


@register_tool
def compare_requests(
    request_id_1: str,
    request_id_2: str,
) -> dict[str, Any]:
    """
    Compare two requests to identify differences.
    
    Useful for analyzing auth bypass attempts or parameter changes.
    """
    from .proxy_manager import get_proxy_manager
    
    manager = get_proxy_manager()
    
    req1 = manager.view_request(request_id_1, "request")
    req2 = manager.view_request(request_id_2, "request")
    
    if "error" in req1:
        return {"error": f"Failed to load request 1: {req1['error']}"}
    if "error" in req2:
        return {"error": f"Failed to load request 2: {req2['error']}"}
    
    content1 = req1.get("content", "")
    content2 = req2.get("content", "")
    
    lines1 = set(content1.split("\n"))
    lines2 = set(content2.split("\n"))
    
    only_in_1 = lines1 - lines2
    only_in_2 = lines2 - lines1
    common = lines1 & lines2
    
    return {
        "success": True,
        "comparison": {
            "only_in_request_1": list(only_in_1)[:20],
            "only_in_request_2": list(only_in_2)[:20],
            "common_lines": len(common),
            "total_differences": len(only_in_1) + len(only_in_2),
        },
        "request_1_id": request_id_1,
        "request_2_id": request_id_2,
    }
