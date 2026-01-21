from typing import Any, Dict, List

from strix.agents.waf_evasion_agent import WAFEvasionAgent
from strix.tools.security.waf_evasion import WAFEvasionEngine


class SecurityActions:
    """
    Tools for advanced security operations and WAF evasion.
    """

    def __init__(self, sandbox=None):
        self.sandbox = sandbox
        self.engine = WAFEvasionEngine()

    def waf_probe(self, url: str, payload: str, method: str = "GET") -> Dict[str, Any]:
        """
        [Advanced] Initiates a smart WAF evasion session.
        This spawns a sub-agent to iteratively test mutations against the target.
        """
        # In a full remote implementation, this would spawn the agent process.
        # For this implementation, we will perform a 'quick probe' using heuristics
        # and return the results, simulating what the agent would do in its first step.
        
        # 1. Generate Heuristics
        mutations = self.engine.generate_heuristic_mutations(payload)
        
        return {
            "status": "probe_complete",
            "detected_strategies": [m.strategy for m in mutations],
            "suggested_payloads": [m.payload for m in mutations],
            "message": "Heuristic mutations generated. Use specific mutation tools to execute them."
        }

    def mutate_payload(self, payload: str, strategy: str = "all") -> List[Dict[str, str]]:
        """
        Generates deterministic mutations for a payload.
        """
        mutations = self.engine.generate_heuristic_mutations(payload)
        
        results = []
        for m in mutations:
            if strategy == "all" or strategy.lower() in m.strategy.lower():
                results.append({
                    "strategy": m.strategy,
                    "payload": m.payload,
                    "description": m.description
                })
        return results

    def detect_waf_signature(self, headers: Dict[str, str], body: str, status: int) -> Dict[str, str]:
        """
        Analyzes response to detect WAF vendor.
        """
        waf_name = self.engine.detect_waf(headers, body, status)
        return {
            "is_waf_detected": bool(waf_name),
            "waf_name": waf_name or "None",
            "confidence": "high" if waf_name else "low"
        }
