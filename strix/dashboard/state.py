"""
Dashboard State Management.

Manages the shared state between Strix agent and dashboard frontend.
State is stored in a JSON file for process isolation (agent vs server).
"""

from __future__ import annotations

import json
import os
import time
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# Default state file path
DEFAULT_STATE_FILE = os.getenv("STRIX_DASHBOARD_STATE_FILE", "/tmp/strix_dashboard_state.json")


@dataclass
class ScanConfig:
    """Scan configuration."""
    target: str = ""
    timeframe: int = 60
    scan_mode: str = "deep"
    model: str = "qwen3-coder-plus"
    prompt: str = ""


@dataclass
class TimeInfo:
    """Time tracking information."""
    start_time: str = ""
    duration_minutes: int = 60
    elapsed_minutes: float = 0
    remaining_minutes: float = 60
    progress_percentage: float = 0
    phase: str = "plenty"
    is_warning: bool = False
    is_critical: bool = False


@dataclass
class AgentInfo:
    """Agent status information."""
    id: str = ""
    name: str = ""
    type: str = "scanner"  # orchestrator, scanner, fuzzer, etc.
    parent_id: str | None = None
    status: str = "idle"
    current_task: str = ""
    tool_count: int = 0


@dataclass
class Vulnerability:
    """Detected vulnerability."""
    id: str = ""
    severity: str = "info"
    title: str = ""
    description: str = ""
    endpoint: str = ""
    evidence: str = ""
    timestamp: str = ""


@dataclass
class ToolExecution:
    """Tool execution record."""
    id: str = ""
    tool: str = ""
    input: str = ""
    output: str = ""
    status: str = "success"
    duration_ms: int = 0
    timestamp: str = ""


@dataclass
class Stats:
    """Dashboard statistics."""
    api_calls: int = 0
    tokens_used: int = 0
    cost_usd: float = 0.0
    tools_executed: int = 0
    vulnerabilities_found: int = 0
    active_agents: int = 1


@dataclass
class DashboardState:
    """Complete dashboard state."""
    scan_config: ScanConfig = field(default_factory=ScanConfig)
    time: TimeInfo = field(default_factory=TimeInfo)
    agents: list[AgentInfo] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    tool_executions: list[ToolExecution] = field(default_factory=list)
    stats: Stats = field(default_factory=Stats)
    live_feed: list[dict[str, Any]] = field(default_factory=list)
    last_updated: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["last_updated"] = datetime.now(timezone.utc).isoformat()
        return data

    def get_agent_tree(self) -> dict[str, Any] | None:
        """Generate a hierarchical tree from flat agents list."""
        if not self.agents:
            return None
            
        agents_by_id = {a.id: {**asdict(a), "children": []} for a in self.agents}
        root = None
        
        for agent_id, agent_data in agents_by_id.items():
            parent_id = agent_data.get("parent_id")
            if parent_id and parent_id in agents_by_id:
                agents_by_id[parent_id]["children"].append(agent_data)
            else:
                # If no parent or parent not found, it's a root (usually orchestrator)
                if not root or agent_data.get("type") == "orchestrator":
                    root = agent_data
                    
        return root
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DashboardState":
        """Create from dictionary."""
        state = cls()
        if "scan_config" in data:
            state.scan_config = ScanConfig(**data["scan_config"])
        if "time" in data:
            state.time = TimeInfo(**data["time"])
        if "stats" in data:
            state.stats = Stats(**data["stats"])
        if "agents" in data:
            state.agents = [AgentInfo(**a) for a in data["agents"]]
        if "vulnerabilities" in data:
            state.vulnerabilities = [Vulnerability(**v) for v in data["vulnerabilities"]]
        if "tool_executions" in data:
            state.tool_executions = [ToolExecution(**t) for t in data["tool_executions"]]
        if "live_feed" in data:
            state.live_feed = data["live_feed"]
        return state


# Global state instance
_state = DashboardState()
_state_lock = threading.Lock()
_state_file = DEFAULT_STATE_FILE


def set_state_file(path: str) -> None:
    """Set the state file path."""
    global _state_file
    _state_file = path


def get_state() -> DashboardState:
    """Get current state."""
    return _state


def update_state(updates: dict[str, Any]) -> None:
    """Update state with partial updates and write to file."""
    global _state
    
    with _state_lock:
        # Apply updates
        if "scan_config" in updates:
            for k, v in updates["scan_config"].items():
                setattr(_state.scan_config, k, v)
        
        if "time" in updates:
            for k, v in updates["time"].items():
                setattr(_state.time, k, v)
        
        if "stats" in updates:
            for k, v in updates["stats"].items():
                setattr(_state.stats, k, v)
        
        if "agents" in updates:
            _state.agents = [AgentInfo(**a) if isinstance(a, dict) else a for a in updates["agents"]]
        
        if "vulnerabilities" in updates:
            _state.vulnerabilities = [Vulnerability(**v) if isinstance(v, dict) else v for v in updates["vulnerabilities"]]
        
        if "tool_executions" in updates:
            _state.tool_executions = [ToolExecution(**t) if isinstance(t, dict) else t for t in updates["tool_executions"]]
        
        if "live_feed" in updates:
            # Keep only last 65 events to prevent lag when dashboard has 100+ events
            _state.live_feed = updates["live_feed"][-65:]
        
        # Write to file
        _write_state_file()


def add_vulnerability(vuln: dict[str, Any]) -> None:
    """Add a vulnerability to state."""
    with _state_lock:
        v = Vulnerability(
            id=vuln.get("id", f"V-{len(_state.vulnerabilities) + 1}"),
            severity=vuln.get("severity", "info"),
            title=vuln.get("title", ""),
            description=vuln.get("description", ""),
            endpoint=vuln.get("endpoint", ""),
            evidence=vuln.get("evidence", ""),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        _state.vulnerabilities.append(v)
        _state.stats.vulnerabilities_found = len(_state.vulnerabilities)
        _write_state_file()


def add_tool_execution(tool: str, input_str: str, output_str: str, status: str = "success", duration_ms: int = 0) -> None:
    """Add a tool execution to state."""
    with _state_lock:
        t = ToolExecution(
            id=f"T-{len(_state.tool_executions) + 1}",
            tool=tool,
            input=input_str[:500],  # Truncate
            output=output_str[:1000],  # Truncate
            status=status,
            duration_ms=duration_ms,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        _state.tool_executions.append(t)
        _state.stats.tools_executed = len(_state.tool_executions)
        # Keep only last 50 tool executions
        if len(_state.tool_executions) > 50:
            _state.tool_executions = _state.tool_executions[-50:]
        _write_state_file()


def add_live_feed_entry(entry_type: str, message: str, **kwargs) -> None:
    """Add an entry to the live feed."""
    with _state_lock:
        entry = {
            "id": f"F-{len(_state.live_feed) + 1}",
            "type": entry_type,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **kwargs,
        }
        _state.live_feed.append(entry)
        # Keep only last 65 entries to prevent performance issues at 100+ events
        if len(_state.live_feed) > 65:
            _state.live_feed = _state.live_feed[-65:]
        _write_state_file()


def _write_state_file() -> None:
    """Write state to file."""
    try:
        Path(_state_file).parent.mkdir(parents=True, exist_ok=True)
        with open(_state_file, "w") as f:
            json.dump(_state.to_dict(), f, indent=2)
    except Exception as e:
        print(f"Error writing state file: {e}")


def load_state_from_file() -> None:
    """Load state from file."""
    global _state
    try:
        if Path(_state_file).exists():
            with open(_state_file, "r") as f:
                content = f.read().strip()
                if content and content != "{}":
                    data = json.loads(content)
                    if data:  # Only update if we have actual data
                        _state = DashboardState.from_dict(data)
    except json.JSONDecodeError as e:
        print(f"Error parsing state file JSON: {e}")
    except Exception as e:
        print(f"Error loading state file: {e}")


# Initialize state file
def init_state(scan_config: dict[str, Any] | None = None) -> None:
    """Initialize state with scan configuration."""
    global _state
    
    # First try to load existing state
    load_state_from_file()
    
    # If scan config provided, update it
    if scan_config:
        # Filter out None values and only use valid keys for ScanConfig
        valid_keys = {'target', 'timeframe', 'scan_mode', 'model', 'prompt'}
        filtered_config = {k: v for k, v in scan_config.items() if k in valid_keys and v is not None}
        
        # Set defaults for missing values
        if 'target' not in filtered_config:
            filtered_config['target'] = ''
        if 'timeframe' not in filtered_config:
            filtered_config['timeframe'] = 60
        if 'scan_mode' not in filtered_config:
            filtered_config['scan_mode'] = 'deep'
        if 'model' not in filtered_config:
            filtered_config['model'] = 'qwen3-coder-plus'
        if 'prompt' not in filtered_config:
            filtered_config['prompt'] = ''
            
        _state.scan_config = ScanConfig(**filtered_config)
    
    # Set time info
    _state.time.start_time = datetime.now(timezone.utc).isoformat()
    _state.time.duration_minutes = _state.scan_config.timeframe
    _state.time.remaining_minutes = float(_state.scan_config.timeframe)
    _state.time.progress_percentage = 0.0
    _state.time.phase = "starting"
    _state.time.elapsed_minutes = 0.0
    
    # Initialize stats with proper defaults
    _state.stats.active_agents = 1
    
    # Add initial live feed entry to show dashboard is working
    if not _state.live_feed:
        _state.live_feed.append({
            "id": "F-1",
            "type": "system",
            "message": "Dashboard initialized - waiting for scan activity...",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": "info"
        })
    
    _write_state_file()
