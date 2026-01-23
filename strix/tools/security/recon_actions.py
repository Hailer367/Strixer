import subprocess
import json
import logging
from typing import Any, Dict, List, Optional
from strix.tools.registry import register_tool

logger = logging.getLogger(__name__)

@register_tool(sandbox_execution=True)
def whatweb_scan(
    target: str,
    aggression: int = 1,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Runs WhatWeb to fingerprint a target's technology stack.
    """
    cmd = ["whatweb", f"--aggression={aggression}"]
    if verbose:
        cmd.append("-v")
    cmd.append(target)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@register_tool(sandbox_execution=True)
def theharvester_search(
    domain: str,
    limit: int = 100,
    source: str = "all"
) -> Dict[str, Any]:
    """
    Runs TheHarvester to gather OSINT data (emails, subdomains, etc.).
    """
    cmd = ["theHarvester", "-d", domain, "-l", str(limit), "-b", source]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
