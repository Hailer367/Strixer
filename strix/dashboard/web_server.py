"""
Dashboard Web Server.

HTTP server that serves the React dashboard frontend and API endpoints.
Designed to run alongside the Strix agent during scans.
"""

from __future__ import annotations

import json
import os
import threading
import time
from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs

from strix.dashboard.state import (
    get_state,
    update_state as state_update,
    add_vulnerability,
    add_tool_execution,
    add_live_feed_entry,
    init_state,
    load_state_from_file,
)


# Server configuration
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = int(os.getenv("STRIX_DASHBOARD_PORT", "8080"))
FRONTEND_DIR = Path(__file__).parent / "frontend" / "dist"


class DashboardHandler(SimpleHTTPRequestHandler):
    """HTTP handler for dashboard requests."""
    
    def __init__(self, *args, frontend_dir: Path = FRONTEND_DIR, **kwargs):
        self.frontend_dir = frontend_dir
        super().__init__(*args, directory=str(frontend_dir), **kwargs)
    
    def log_message(self, format: str, *args) -> None:
        """Suppress default logging."""
        pass
    
    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path
        
        # API endpoints
        if path == "/api/state":
            self._send_json(get_state().to_dict())
        elif path == "/api/health":
            self._send_json({"status": "ok", "timestamp": time.time()})
        elif path == "/api/vulnerabilities":
            self._send_json([v.__dict__ for v in get_state().vulnerabilities])
        elif path == "/api/agents":
            self._send_json([a.__dict__ for a in get_state().agents])
        elif path == "/api/tools":
            self._send_json([t.__dict__ for t in get_state().tool_executions])
        elif path == "/api/stats":
            self._send_json(get_state().stats.__dict__)
        elif path == "/api/agent-tree":
            self._send_json(get_state().get_agent_tree() or {})
        elif path == "/api/feed":
            self._send_json(get_state().live_feed)
        elif path == "/health":
            self._send_json({"status": "ok"})
        else:
            # Serve static files
            if path == "/" or not (self.frontend_dir / path.lstrip("/")).exists():
                # Serve index.html for SPA routing
                self.path = "/index.html"
            super().do_GET()
    
    def do_POST(self):
        """Handle POST requests (for state updates)."""
        parsed = urlparse(self.path)
        path = parsed.path
        
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON"}, status=400)
            return
        
        if path == "/api/state":
            state_update(data)
            self._send_json({"success": True})
        elif path == "/api/vulnerability":
            add_vulnerability(data)
            self._send_json({"success": True})
        elif path == "/api/tool":
            add_tool_execution(
                data.get("tool", ""),
                data.get("input", ""),
                data.get("output", ""),
                data.get("status", "success"),
                data.get("duration_ms", 0),
            )
            self._send_json({"success": True})
        elif path == "/api/feed":
            add_live_feed_entry(
                data.get("type", "info"),
                data.get("message", ""),
                **{k: v for k, v in data.items() if k not in ("type", "message")},
            )
            self._send_json({"success": True})
        else:
            self._send_json({"error": "Not found"}, status=404)
    
    def _send_json(self, data: Any, status: int = 200) -> None:
        """Send JSON response."""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
    
    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


class DashboardServer:
    """Dashboard HTTP server."""
    
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self.server: HTTPServer | None = None
        self.thread: threading.Thread | None = None
        self._running = False
    
    def start(self, scan_config: dict[str, Any] | None = None) -> None:
        """Start the dashboard server."""
        if self._running:
            return
        
        # Initialize state
        init_state(scan_config)
        
        # Check if frontend is built
        if not FRONTEND_DIR.exists():
            print(f"Warning: Frontend not built at {FRONTEND_DIR}")
            print("Dashboard will serve API only. Run 'npm run build' in frontend/")
        
        handler = partial(DashboardHandler, frontend_dir=FRONTEND_DIR)
        self.server = HTTPServer((self.host, self.port), handler)
        
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        self._running = True
        
        print(f"Dashboard server started at http://{self.host}:{self.port}")
    
    def _serve(self) -> None:
        """Server loop."""
        if self.server:
            self.server.serve_forever()
    
    def stop(self) -> None:
        """Stop the dashboard server."""
        if self.server:
            self.server.shutdown()
            self._running = False
            print("Dashboard server stopped")
    
    @property
    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running


# Global server instance
_server: DashboardServer | None = None


def start_dashboard(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    scan_config: dict[str, Any] | None = None,
) -> DashboardServer:
    """Start the dashboard server."""
    global _server
    _server = DashboardServer(host, port)
    _server.start(scan_config)
    return _server


def stop_dashboard() -> None:
    """Stop the dashboard server."""
    global _server
    if _server:
        _server.stop()
        _server = None


def get_server() -> DashboardServer | None:
    """Get the current server instance."""
    return _server


# Convenience exports
update_state = state_update
