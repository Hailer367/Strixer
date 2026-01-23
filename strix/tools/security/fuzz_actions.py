import subprocess
import logging
from typing import Any, Dict, List, Optional
from strix.tools.registry import register_tool

logger = logging.getLogger(__name__)

@register_tool(sandbox_execution=True)
def feroxbuster_scan(
    target: str,
    wordlist: str = "/home/pentester/wordlists/raft-medium-files.txt",
    threads: int = 50,
    extensions: Optional[str] = None,
    depth: int = 1
) -> Dict[str, Any]:
    """
    Runs Feroxbuster for recursive directory discovery.
    """
    cmd = [
        "feroxbuster", 
        "-u", target, 
        "-w", wordlist, 
        "-t", str(threads),
        "--depth", str(depth),
        "-n" # No recursion depth increase unless specified
    ]
    if extensions:
        cmd.extend(["-x", extensions])
    
    try:
        # We limit the output to avoid overwhelming the LLM
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {
            "success": True,
            "stdout": result.stdout[-5000:], # Return last 5k chars if too long
            "exit_code": result.returncode
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@register_tool(sandbox_execution=True)
def kiterunner_scan(
    target: str,
    wordlist: str = "/home/pentester/wordlists/common.txt"
) -> Dict[str, Any]:
    """
    Runs Kiterunner for API endpoint discovery.
    """
    cmd = ["kr", "scan", target, "-w", wordlist]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {
            "success": True,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
