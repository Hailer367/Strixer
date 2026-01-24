"""
Advanced Browser Actions for Security Testing.

This module provides comprehensive browser automation capabilities:
- Standard navigation and interaction
- Advanced traffic interception and analysis
- Session management and cookie manipulation
- JavaScript execution and debugging
- Security-focused DOM analysis
"""

from typing import TYPE_CHECKING, Any, Literal, NoReturn, Optional, Dict, List

from strix.tools.registry import register_tool


if TYPE_CHECKING:
    from .tab_manager import BrowserTabManager


BrowserAction = Literal[
    "launch",
    "goto",
    "click",
    "type",
    "scroll_down",
    "scroll_up",
    "back",
    "forward",
    "new_tab",
    "switch_tab",
    "close_tab",
    "wait",
    "execute_js",
    "double_click",
    "hover",
    "press_key",
    "save_pdf",
    "get_console_logs",
    "view_source",
    "close",
    "list_tabs",
    # Advanced security actions
    "get_cookies",
    "set_cookie",
    "delete_cookies",
    "get_storage",
    "clear_storage",
    "intercept_requests",
    "get_network_logs",
    "analyze_dom",
    "find_forms",
    "extract_links",
    "check_headers",
    "screenshot_element",
]


def _validate_url(action_name: str, url: str | None) -> None:
    if not url:
        raise ValueError(f"url parameter is required for {action_name} action")


def _validate_coordinate(action_name: str, coordinate: str | None) -> None:
    if not coordinate:
        raise ValueError(f"coordinate parameter is required for {action_name} action")


def _validate_text(action_name: str, text: str | None) -> None:
    if not text:
        raise ValueError(f"text parameter is required for {action_name} action")


def _validate_tab_id(action_name: str, tab_id: str | None) -> None:
    if not tab_id:
        raise ValueError(f"tab_id parameter is required for {action_name} action")


def _validate_js_code(action_name: str, js_code: str | None) -> None:
    if not js_code:
        raise ValueError(f"js_code parameter is required for {action_name} action")


def _validate_duration(action_name: str, duration: float | None) -> None:
    if duration is None:
        raise ValueError(f"duration parameter is required for {action_name} action")


def _validate_key(action_name: str, key: str | None) -> None:
    if not key:
        raise ValueError(f"key parameter is required for {action_name} action")


def _validate_file_path(action_name: str, file_path: str | None) -> None:
    if not file_path:
        raise ValueError(f"file_path parameter is required for {action_name} action")


def _handle_navigation_actions(
    manager: "BrowserTabManager",
    action: str,
    url: str | None = None,
    tab_id: str | None = None,
) -> dict[str, Any]:
    if action == "launch":
        return manager.launch_browser(url)
    if action == "goto":
        _validate_url(action, url)
        assert url is not None
        return manager.goto_url(url, tab_id)
    if action == "back":
        return manager.back(tab_id)
    if action == "forward":
        return manager.forward(tab_id)
    raise ValueError(f"Unknown navigation action: {action}")


def _handle_interaction_actions(
    manager: "BrowserTabManager",
    action: str,
    coordinate: str | None = None,
    text: str | None = None,
    key: str | None = None,
    tab_id: str | None = None,
) -> dict[str, Any]:
    if action in {"click", "double_click", "hover"}:
        _validate_coordinate(action, coordinate)
        assert coordinate is not None
        action_map = {
            "click": manager.click,
            "double_click": manager.double_click,
            "hover": manager.hover,
        }
        return action_map[action](coordinate, tab_id)

    if action in {"scroll_down", "scroll_up"}:
        direction = "down" if action == "scroll_down" else "up"
        return manager.scroll(direction, tab_id)

    if action == "type":
        _validate_text(action, text)
        assert text is not None
        return manager.type_text(text, tab_id)
    if action == "press_key":
        _validate_key(action, key)
        assert key is not None
        return manager.press_key(key, tab_id)

    raise ValueError(f"Unknown interaction action: {action}")


def _raise_unknown_action(action: str) -> NoReturn:
    raise ValueError(f"Unknown action: {action}")


def _handle_tab_actions(
    manager: "BrowserTabManager",
    action: str,
    url: str | None = None,
    tab_id: str | None = None,
) -> dict[str, Any]:
    if action == "new_tab":
        return manager.new_tab(url)
    if action == "switch_tab":
        _validate_tab_id(action, tab_id)
        assert tab_id is not None
        return manager.switch_tab(tab_id)
    if action == "close_tab":
        _validate_tab_id(action, tab_id)
        assert tab_id is not None
        return manager.close_tab(tab_id)
    if action == "list_tabs":
        return manager.list_tabs()
    raise ValueError(f"Unknown tab action: {action}")


def _handle_utility_actions(
    manager: "BrowserTabManager",
    action: str,
    duration: float | None = None,
    js_code: str | None = None,
    file_path: str | None = None,
    tab_id: str | None = None,
    clear: bool = False,
) -> dict[str, Any]:
    if action == "wait":
        _validate_duration(action, duration)
        assert duration is not None
        return manager.wait_browser(duration, tab_id)
    if action == "execute_js":
        _validate_js_code(action, js_code)
        assert js_code is not None
        return manager.execute_js(js_code, tab_id)
    if action == "save_pdf":
        _validate_file_path(action, file_path)
        assert file_path is not None
        return manager.save_pdf(file_path, tab_id)
    if action == "get_console_logs":
        return manager.get_console_logs(tab_id, clear)
    if action == "view_source":
        return manager.view_source(tab_id)
    if action == "close":
        return manager.close_browser()
    raise ValueError(f"Unknown utility action: {action}")


def _handle_security_actions(
    manager: "BrowserTabManager",
    action: str,
    tab_id: str | None = None,
    cookie_data: dict | None = None,
    storage_type: str | None = None,
    selector: str | None = None,
) -> dict[str, Any]:
    """Handle advanced security-focused browser actions."""
    
    if action == "get_cookies":
        return manager.get_cookies(tab_id)
    
    if action == "set_cookie":
        if not cookie_data:
            raise ValueError("cookie_data parameter is required for set_cookie action")
        return manager.set_cookie(cookie_data, tab_id)
    
    if action == "delete_cookies":
        return manager.delete_cookies(tab_id)
    
    if action == "get_storage":
        storage = storage_type or "local"
        return manager.get_storage(storage, tab_id)
    
    if action == "clear_storage":
        storage = storage_type or "all"
        return manager.clear_storage(storage, tab_id)
    
    if action == "get_network_logs":
        return manager.get_network_logs(tab_id)
    
    if action == "analyze_dom":
        return manager.analyze_dom(tab_id)
    
    if action == "find_forms":
        return manager.find_forms(tab_id)
    
    if action == "extract_links":
        return manager.extract_links(tab_id)
    
    if action == "check_headers":
        return manager.check_headers(tab_id)
    
    if action == "screenshot_element":
        if not selector:
            raise ValueError("selector parameter is required for screenshot_element action")
        return manager.screenshot_element(selector, tab_id)
    
    raise ValueError(f"Unknown security action: {action}")


@register_tool
def browser_action(
    action: BrowserAction,
    url: str | None = None,
    coordinate: str | None = None,
    text: str | None = None,
    tab_id: str | None = None,
    js_code: str | None = None,
    duration: float | None = None,
    key: str | None = None,
    file_path: str | None = None,
    clear: bool = False,
    cookie_data: dict | None = None,
    storage_type: str | None = None,
    selector: str | None = None,
) -> dict[str, Any]:
    """
    Execute browser actions for security testing and automation.
    
    Standard Actions:
    - launch: Launch browser with optional URL
    - goto: Navigate to URL
    - click/double_click/hover: Mouse interactions at coordinate
    - type: Type text input
    - scroll_down/scroll_up: Page scrolling
    - back/forward: Navigation history
    - new_tab/switch_tab/close_tab/list_tabs: Tab management
    - wait: Wait for specified duration
    - execute_js: Execute JavaScript code
    - press_key: Press keyboard key
    - save_pdf: Save page as PDF
    - get_console_logs: Get browser console output
    - view_source: Get page HTML source
    - close: Close browser
    
    Security Actions:
    - get_cookies: Get all cookies for current domain
    - set_cookie: Set a cookie with specified data
    - delete_cookies: Delete all cookies
    - get_storage: Get localStorage/sessionStorage
    - clear_storage: Clear storage data
    - get_network_logs: Get captured network requests
    - analyze_dom: Security analysis of DOM structure
    - find_forms: Find and analyze forms for testing
    - extract_links: Extract all links from page
    - check_headers: Analyze security headers
    - screenshot_element: Screenshot specific element
    """
    from .tab_manager import get_browser_tab_manager

    manager = get_browser_tab_manager()

    try:
        navigation_actions = {"launch", "goto", "back", "forward"}
        interaction_actions = {
            "click",
            "type",
            "double_click",
            "hover",
            "press_key",
            "scroll_down",
            "scroll_up",
        }
        tab_actions = {"new_tab", "switch_tab", "close_tab", "list_tabs"}
        utility_actions = {
            "wait",
            "execute_js",
            "save_pdf",
            "get_console_logs",
            "view_source",
            "close",
        }
        security_actions = {
            "get_cookies",
            "set_cookie",
            "delete_cookies",
            "get_storage",
            "clear_storage",
            "intercept_requests",
            "get_network_logs",
            "analyze_dom",
            "find_forms",
            "extract_links",
            "check_headers",
            "screenshot_element",
        }

        if action in navigation_actions:
            return _handle_navigation_actions(manager, action, url, tab_id)
        if action in interaction_actions:
            return _handle_interaction_actions(manager, action, coordinate, text, key, tab_id)
        if action in tab_actions:
            return _handle_tab_actions(manager, action, url, tab_id)
        if action in utility_actions:
            return _handle_utility_actions(
                manager, action, duration, js_code, file_path, tab_id, clear
            )
        if action in security_actions:
            return _handle_security_actions(
                manager, action, tab_id, cookie_data, storage_type, selector
            )

        _raise_unknown_action(action)

    except (ValueError, RuntimeError) as e:
        return {
            "error": str(e),
            "tab_id": tab_id,
            "screenshot": "",
            "is_running": False,
        }


@register_tool
def browser_security_scan(
    url: str,
    scan_type: Literal["quick", "comprehensive", "passive"] = "quick",
) -> dict[str, Any]:
    """
    Perform automated security scanning of a web page.
    
    Scan Types:
    - quick: Fast scan for common issues (forms, links, basic headers)
    - comprehensive: Full scan including DOM analysis, storage, cookies
    - passive: Non-intrusive observation of page behavior
    
    Returns a structured security report with findings.
    """
    from .tab_manager import get_browser_tab_manager
    
    manager = get_browser_tab_manager()
    
    try:
        # Launch browser if not already running
        try:
            result = manager.launch_browser(url)
        except ValueError:
            # Browser already launched, just navigate
            result = manager.goto_url(url)
        
        findings = {
            "url": url,
            "scan_type": scan_type,
            "findings": [],
            "forms": [],
            "links": [],
            "cookies": [],
            "headers": {},
            "storage": {},
            "risk_score": 0.0,
        }
        
        # Quick scan - always run
        forms_result = manager.find_forms()
        findings["forms"] = forms_result.get("forms", [])
        
        links_result = manager.extract_links()
        findings["links"] = links_result.get("links", [])
        
        headers_result = manager.check_headers()
        findings["headers"] = headers_result.get("headers", {})
        findings["findings"].extend(headers_result.get("issues", []))
        
        if scan_type in ("comprehensive", "passive"):
            # Get cookies
            cookies_result = manager.get_cookies()
            findings["cookies"] = cookies_result.get("cookies", [])
            
            # Analyze cookie security
            for cookie in findings["cookies"]:
                if not cookie.get("httpOnly"):
                    findings["findings"].append({
                        "severity": "medium",
                        "type": "cookie_security",
                        "message": f"Cookie '{cookie.get('name')}' missing HttpOnly flag",
                    })
                if not cookie.get("secure") and "https" in url.lower():
                    findings["findings"].append({
                        "severity": "medium",
                        "type": "cookie_security",
                        "message": f"Cookie '{cookie.get('name')}' missing Secure flag on HTTPS",
                    })
        
        if scan_type == "comprehensive":
            # Get storage data
            local_storage = manager.get_storage("local")
            session_storage = manager.get_storage("session")
            findings["storage"] = {
                "localStorage": local_storage.get("data", {}),
                "sessionStorage": session_storage.get("data", {}),
            }
            
            # DOM analysis
            dom_result = manager.analyze_dom()
            findings["findings"].extend(dom_result.get("issues", []))
            
            # Analyze forms for potential vulnerabilities
            for form in findings["forms"]:
                if form.get("method", "").upper() == "GET" and any(
                    f.get("type") == "password" for f in form.get("fields", [])
                ):
                    findings["findings"].append({
                        "severity": "high",
                        "type": "form_security",
                        "message": f"Password field in GET form at {form.get('action', 'unknown')}",
                    })
                if not form.get("action", "").startswith("https"):
                    findings["findings"].append({
                        "severity": "medium",
                        "type": "form_security",
                        "message": f"Form submits to non-HTTPS endpoint: {form.get('action', 'unknown')}",
                    })
        
        # Calculate risk score
        severity_weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2, "info": 0.05}
        total_risk = sum(
            severity_weights.get(f.get("severity", "info"), 0.1)
            for f in findings["findings"]
        )
        findings["risk_score"] = min(1.0, total_risk / 5.0)  # Normalize to 0-1
        
        findings["screenshot"] = result.get("screenshot", "")
        
        return findings
        
    except Exception as e:
        return {
            "error": str(e),
            "url": url,
            "scan_type": scan_type,
            "findings": [],
        }
