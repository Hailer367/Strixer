import subprocess
import logging
from typing import Any, Dict, List, Optional
from strix.tools.registry import register_tool

logger = logging.getLogger(__name__)

@register_tool(sandbox_execution=True)
def graphw00f_scan(
    target: str,
    output_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    Runs GraphW00f to fingerprint the GraphQL engine.
    """
    cmd = ["graphw00f", "-t", target]
    if output_file:
        cmd.extend(["-o", output_file])
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {
            "success": True,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@register_tool(sandbox_execution=True)
def clairvoyance_scan(
    target: str,
    wordlist: Optional[str] = None
) -> Dict[str, Any]:
    """
    Runs Clairvoyance to reconstruct GraphQL schema through introspection or brute-force.
    """
    cmd = ["clairvoyance", target]
    if wordlist:
        cmd.extend(["-w", wordlist])
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {
            "success": True,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
