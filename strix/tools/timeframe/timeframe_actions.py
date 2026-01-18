"""
Timeframe Tracking Module - Scan duration management.

This module provides tools for agents to track their remaining time
and make decisions about when to wrap up or continue scanning.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)

# Module-level storage for timeframe data
_scan_start_time: float | None = None
_scan_duration_minutes: int = 60


def _initialize_from_env() -> None:
    """Initialize timeframe from environment variables."""
    global _scan_start_time, _scan_duration_minutes

    start_time_str = os.getenv("STRIX_SCAN_START_TIME")
    if start_time_str:
        try:
            _scan_start_time = float(start_time_str)
        except ValueError:
            _scan_start_time = time.time()
    else:
        _scan_start_time = time.time()

    duration_str = os.getenv("STRIX_SCAN_DURATION_MINUTES", "60")
    try:
        _scan_duration_minutes = int(duration_str)
    except ValueError:
        _scan_duration_minutes = 60


# Initialize on module load
_initialize_from_env()


@register_tool(sandbox_execution=False)
def get_remaining_time(agent_state: Any) -> dict[str, Any]:
    """
    Get the remaining time in the current scan session.

    Call this regularly to check how much time is left. This helps you
    decide whether to start new tests or begin wrapping up.

    Returns:
        Dictionary with:
        - remaining_minutes: Minutes remaining (float)
        - remaining_seconds: Total seconds remaining
        - elapsed_minutes: Minutes elapsed since start
        - elapsed_percent: Percentage of time used (0-100)
        - is_critical: True if less than 10% time remains
        - recommendation: What to do based on remaining time
    """
    global _scan_start_time, _scan_duration_minutes

    if _scan_start_time is None:
        _initialize_from_env()

    current_time = time.time()
    elapsed_seconds = current_time - (_scan_start_time or current_time)
    elapsed_minutes = elapsed_seconds / 60

    total_seconds = _scan_duration_minutes * 60
    remaining_seconds = max(0, total_seconds - elapsed_seconds)
    remaining_minutes = remaining_seconds / 60

    elapsed_percent = min(100, (elapsed_seconds / total_seconds) * 100) if total_seconds > 0 else 100

    # Determine criticality and recommendations
    is_critical = elapsed_percent >= 90
    is_warning = elapsed_percent >= 75

    if elapsed_percent >= 95:
        recommendation = "WRAP UP NOW - Less than 5% time remaining. Complete current task and prepare final report."
    elif elapsed_percent >= 90:
        recommendation = "CRITICAL - Start wrapping up. No new major tests. Focus on documenting findings."
    elif elapsed_percent >= 75:
        recommendation = "WARNING - Consider prioritizing remaining high-value tests. Avoid starting long-running scans."
    elif elapsed_percent >= 50:
        recommendation = "GOOD - Continue testing but be mindful of time. Start critical tests now."
    else:
        recommendation = "PLENTY OF TIME - Continue comprehensive testing. Explore all attack vectors."

    return {
        "success": True,
        "remaining_minutes": round(remaining_minutes, 2),
        "remaining_seconds": int(remaining_seconds),
        "elapsed_minutes": round(elapsed_minutes, 2),
        "elapsed_percent": round(elapsed_percent, 1),
        "total_minutes": _scan_duration_minutes,
        "is_critical": is_critical,
        "is_warning": is_warning,
        "recommendation": recommendation,
        "started_at": datetime.fromtimestamp(_scan_start_time or time.time(), tz=timezone.utc).isoformat(),
    }


@register_tool(sandbox_execution=False)
def get_elapsed_time(agent_state: Any) -> dict[str, Any]:
    """
    Get the elapsed time since scan start.

    Returns:
        Dictionary with elapsed time information
    """
    return get_remaining_time(agent_state)


@register_tool(sandbox_execution=False)
def is_timeframe_critical(agent_state: Any) -> dict[str, Any]:
    """
    Quick check if the timeframe is critical (less than 10% remaining).

    Use this for fast decisions about whether to continue testing.

    Returns:
        Dictionary with:
        - is_critical: True if less than 10% time remains
        - should_wrap_up: True if should start wrapping up
        - remaining_minutes: Minutes remaining
    """
    time_info = get_remaining_time(agent_state)

    return {
        "success": True,
        "is_critical": time_info["is_critical"],
        "should_wrap_up": time_info["elapsed_percent"] >= 85,
        "remaining_minutes": time_info["remaining_minutes"],
        "elapsed_percent": time_info["elapsed_percent"],
    }


@register_tool(sandbox_execution=False)
def set_scan_timeframe(
    agent_state: Any,
    duration_minutes: int,
    reset_start_time: bool = True,
) -> dict[str, Any]:
    """
    Set or reset the scan timeframe.

    Args:
        agent_state: Current agent state
        duration_minutes: Total scan duration in minutes
        reset_start_time: Whether to reset the start time to now

    Returns:
        Dictionary with updated timeframe settings
    """
    global _scan_start_time, _scan_duration_minutes

    if duration_minutes < 1:
        return {"success": False, "error": "Duration must be at least 1 minute"}

    if duration_minutes > 720:
        return {"success": False, "error": "Duration cannot exceed 720 minutes (12 hours)"}

    _scan_duration_minutes = duration_minutes

    if reset_start_time:
        _scan_start_time = time.time()

    logger.info(f"[Timeframe] Set duration to {duration_minutes} minutes")

    return {
        "success": True,
        "message": f"Timeframe set to {duration_minutes} minutes",
        "duration_minutes": duration_minutes,
        "started_at": datetime.fromtimestamp(_scan_start_time, tz=timezone.utc).isoformat(),
    }


@register_tool(sandbox_execution=False)
def should_continue_scanning(agent_state: Any) -> dict[str, Any]:
    """
    Determine if the agent should continue scanning or wrap up.

    This is the main decision function for timeframe-aware scanning.
    The agent should call this before starting major new test phases.

    IMPORTANT: Even when vulnerabilities are found, continue scanning
    until the timeframe is exhausted. Only stop when time runs out.

    Returns:
        Dictionary with:
        - should_continue: True if should continue scanning
        - should_start_new_tests: True if safe to start new major tests
        - reason: Explanation of the decision
    """
    time_info = get_remaining_time(agent_state)
    elapsed_percent = time_info["elapsed_percent"]
    remaining_minutes = time_info["remaining_minutes"]

    # ALWAYS continue until timeframe is exhausted
    should_continue = remaining_minutes > 0.5  # Continue until last 30 seconds

    # Can start new tests if enough time remains
    should_start_new_tests = elapsed_percent < 85 and remaining_minutes > 5

    if remaining_minutes <= 0.5:
        reason = "Timeframe exhausted. Complete final report and finish scan."
    elif elapsed_percent >= 95:
        reason = f"Only {remaining_minutes:.1f} minutes left. Complete current tasks only."
    elif elapsed_percent >= 85:
        reason = f"{remaining_minutes:.1f} minutes remaining. Finish current tests, avoid starting new ones."
    elif elapsed_percent >= 70:
        reason = f"{remaining_minutes:.1f} minutes remaining. Continue testing but prioritize high-value tests."
    else:
        reason = f"{remaining_minutes:.1f} minutes remaining. Full testing capacity available."

    return {
        "success": True,
        "should_continue": should_continue,
        "should_start_new_tests": should_start_new_tests,
        "remaining_minutes": remaining_minutes,
        "elapsed_percent": elapsed_percent,
        "reason": reason,
        "reminder": "Continue scanning until timeframe is exhausted. Finding vulnerabilities does NOT mean stopping early!",
    }
