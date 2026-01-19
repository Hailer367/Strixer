"""
Strix Dashboard Module.

Real-time dashboard for monitoring Strix agent activity during scans.
Provides:
- Web server for React frontend + API endpoints
- State synchronization between agent and dashboard
- Cloudflare tunnel integration for public access
"""

from strix.dashboard.web_server import (
    DashboardServer,
    start_dashboard,
    stop_dashboard,
    update_state,
    get_state,
)
from strix.dashboard.state import DashboardState

__all__ = [
    "DashboardServer",
    "DashboardState",
    "start_dashboard",
    "stop_dashboard",
    "update_state",
    "get_state",
]
