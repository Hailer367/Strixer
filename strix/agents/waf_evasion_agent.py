"""
Advanced WAF Evasion Agent - Autonomous WAF Bypass Specialist.

This agent specializes in bypassing Web Application Firewalls through:
- Adaptive payload mutation strategies
- WAF fingerprinting and targeted evasion
- Multi-iteration polymorphic generation
- Knowledge graph integration for bypass sharing
- Automatic technique learning and refinement

IMPORTANT: This agent operates within authorized security testing scope only.
"""

from typing import Any, Dict, List, Optional
import json

from strix.agents.base_agent import BaseAgent
from strix.llm.llm import LLMConfig
from strix.tools.security.waf_evasion import (
    WAFEvasionEngine,
    WAFVendor,
    EvasionStrategy,
    EvasionContext,
    WAFFingerprint,
    MutationResult,
)


class WAFEvasionAgent(BaseAgent):
    """
    A specialized agent for bypassing Web Application Firewalls (WAFs).
    
    This agent combines LLM reasoning with deterministic mutation strategies
    to iteratively discover WAF bypass techniques. It maintains context
    across iterations and learns from successful/failed attempts.
    
    Key Capabilities:
    - Advanced WAF fingerprinting
    - Adaptive strategy selection
    - Multi-layer encoding chains
    - Semantic and polymorphic mutations
    - Integration with Knowledge Graph for bypass sharing
    """
    
    def __init__(self, config: Dict[str, Any]):
        # Configure LLM for creative, high-temperature reasoning
        if "llm_config" not in config:
            config["llm_config"] = LLMConfig(
                model="gpt-4o",
                temperature=0.85,  # High temperature for creative evasion
            )
        
        # Ensure required tools are available
        required_tools = [
            "web_search",
            "search_web",
            "execute_terminal",
            "run_python",
            "get_waf_bypass_history",
            "record_waf_bypass",
        ]
        
        if "tools" in config and isinstance(config["tools"], list):
            for tool in required_tools:
                if tool not in config["tools"]:
                    config["tools"].append(tool)
        
        super().__init__(config)
        
        # Initialize the evasion engine
        self.engine = WAFEvasionEngine()
        
        # Evasion context for tracking attempts
        self.evasion_context: Optional[EvasionContext] = None
        
        # Current WAF fingerprint
        self.waf_fingerprint: Optional[WAFFingerprint] = None
        
        # Iteration tracking
        self.mutation_history: List[Dict[str, Any]] = []
        self.successful_bypasses: List[Dict[str, Any]] = []
    
    def initialize_evasion(
        self,
        target_url: str,
        initial_payload: str,
        waf_vendor: Optional[str] = None,
    ) -> EvasionContext:
        """
        Initialize an evasion session for a target.
        
        Args:
            target_url: The URL being tested
            initial_payload: The original blocked payload
            waf_vendor: Optional known WAF vendor name
        
        Returns:
            EvasionContext for tracking the session
        """
        vendor = None
        if waf_vendor:
            try:
                vendor = WAFVendor(waf_vendor)
            except ValueError:
                vendor = WAFVendor.UNKNOWN
        
        self.evasion_context = EvasionContext(
            target_url=target_url,
            waf_vendor=vendor,
            blocked_payloads=[initial_payload],
        )
        
        return self.evasion_context
    
    def fingerprint_target(
        self,
        headers: Dict[str, str],
        body: str,
        status_code: int,
        cookies: Optional[Dict[str, str]] = None,
    ) -> WAFFingerprint:
        """
        Fingerprint the WAF protecting a target.
        
        Returns detailed fingerprint with:
        - WAF vendor identification
        - Confidence score
        - Recommended evasion strategies
        - Known bypass techniques
        """
        self.waf_fingerprint = self.engine.fingerprint_waf(
            headers=headers,
            body=body,
            status_code=status_code,
            cookies=cookies,
        )
        
        if self.evasion_context:
            self.evasion_context.waf_vendor = self.waf_fingerprint.vendor
        
        return self.waf_fingerprint
    
    def generate_bypass_payloads(
        self,
        payload: str,
        max_payloads: int = 20,
        prioritize_untested: bool = True,
    ) -> List[MutationResult]:
        """
        Generate bypass payloads for a blocked payload.
        
        Uses WAF fingerprint (if available) to prioritize techniques
        and filters out previously tested mutations.
        """
        # Get recommended mutations based on WAF
        if self.waf_fingerprint and self.waf_fingerprint.vendor != WAFVendor.UNKNOWN:
            mutations = self.engine.get_recommended_mutations(
                payload=payload,
                waf_fingerprint=self.waf_fingerprint,
                max_mutations=max_payloads * 2,
            )
        else:
            mutations = self.engine.generate_mutations(
                payload=payload,
                context=self.evasion_context,
                max_mutations=max_payloads * 2,
            )
        
        # Filter out already tested payloads
        if self.evasion_context and prioritize_untested:
            tested = set(self.evasion_context.blocked_payloads + 
                        self.evasion_context.successful_payloads)
            mutations = [m for m in mutations if m.payload not in tested]
        
        # Sort by confidence (descending)
        mutations.sort(key=lambda x: -x.confidence)
        
        return mutations[:max_payloads]
    
    def record_attempt(
        self,
        payload: str,
        technique: str,
        success: bool,
        response_code: Optional[int] = None,
        response_body: Optional[str] = None,
    ) -> None:
        """
        Record a bypass attempt result.
        
        Updates the evasion context and mutation history for
        adaptive strategy selection.
        """
        attempt = {
            "payload": payload,
            "technique": technique,
            "success": success,
            "response_code": response_code,
            "iteration": len(self.mutation_history) + 1,
        }
        
        self.mutation_history.append(attempt)
        
        if self.evasion_context:
            self.evasion_context.iteration += 1
            
            if success:
                self.evasion_context.successful_payloads.append(payload)
                self.evasion_context.successful_techniques.append(technique)
                self.successful_bypasses.append(attempt)
                
                # Record to engine for learning
                if self.waf_fingerprint:
                    self.engine.record_bypass(
                        original_payload=self.evasion_context.blocked_payloads[0] if self.evasion_context.blocked_payloads else payload,
                        successful_payload=payload,
                        waf_vendor=self.waf_fingerprint.vendor,
                        technique=technique,
                        target_url=self.evasion_context.target_url,
                    )
            else:
                self.evasion_context.blocked_payloads.append(payload)
                self.evasion_context.blocked_techniques.append(technique)
    
    def get_next_strategy(self) -> List[EvasionStrategy]:
        """
        Determine the next evasion strategy based on history.
        
        Analyzes failed attempts to recommend unexplored strategies.
        """
        if not self.evasion_context:
            return list(EvasionStrategy)
        
        # Count technique usage by category
        category_attempts = {s: 0 for s in EvasionStrategy}
        category_successes = {s: 0 for s in EvasionStrategy}
        
        for attempt in self.mutation_history:
            technique = attempt["technique"]
            # Infer category from technique name
            if "encoding" in technique.lower() or "encode" in technique.lower():
                category_attempts[EvasionStrategy.ENCODING] += 1
                if attempt["success"]:
                    category_successes[EvasionStrategy.ENCODING] += 1
            elif "syntax" in technique.lower() or "case" in technique.lower():
                category_attempts[EvasionStrategy.SYNTAX] += 1
                if attempt["success"]:
                    category_successes[EvasionStrategy.SYNTAX] += 1
            elif "semantic" in technique.lower() or "alt" in technique.lower():
                category_attempts[EvasionStrategy.SEMANTIC] += 1
                if attempt["success"]:
                    category_successes[EvasionStrategy.SEMANTIC] += 1
            elif "protocol" in technique.lower() or "hpp" in technique.lower():
                category_attempts[EvasionStrategy.PROTOCOL] += 1
                if attempt["success"]:
                    category_successes[EvasionStrategy.PROTOCOL] += 1
            elif "poly" in technique.lower() or "random" in technique.lower():
                category_attempts[EvasionStrategy.POLYMORPHIC] += 1
                if attempt["success"]:
                    category_successes[EvasionStrategy.POLYMORPHIC] += 1
            elif "frag" in technique.lower() or "chunk" in technique.lower():
                category_attempts[EvasionStrategy.FRAGMENTATION] += 1
                if attempt["success"]:
                    category_successes[EvasionStrategy.FRAGMENTATION] += 1
        
        # Prioritize: 1) unexplored, 2) high success rate, 3) WAF-recommended
        recommended = []
        
        # Add unexplored strategies
        for strategy in EvasionStrategy:
            if category_attempts[strategy] == 0:
                recommended.append(strategy)
        
        # Add strategies with some success
        for strategy in EvasionStrategy:
            if category_successes[strategy] > 0 and strategy not in recommended:
                recommended.append(strategy)
        
        # Add WAF-specific recommendations
        if self.waf_fingerprint:
            for strategy in self.waf_fingerprint.recommended_strategies:
                if strategy not in recommended:
                    recommended.append(strategy)
        
        # If still empty, include all
        if not recommended:
            recommended = list(EvasionStrategy)
        
        return recommended
    
    def should_continue(self) -> bool:
        """
        Determine if evasion attempts should continue.
        
        Returns False if:
        - Max iterations reached
        - Multiple successful bypasses found
        - All strategies exhausted
        """
        if not self.evasion_context:
            return True
        
        # Stop if max iterations reached
        if self.evasion_context.iteration >= self.evasion_context.max_iterations:
            return False
        
        # Stop if we have enough successful bypasses
        if len(self.successful_bypasses) >= 3:
            return False
        
        return True
    
    def get_evasion_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the evasion session.
        
        Returns comprehensive statistics and findings.
        """
        summary = {
            "total_attempts": len(self.mutation_history),
            "successful_bypasses": len(self.successful_bypasses),
            "success_rate": (
                len(self.successful_bypasses) / len(self.mutation_history)
                if self.mutation_history else 0.0
            ),
            "waf_detected": (
                self.waf_fingerprint.vendor.value
                if self.waf_fingerprint else "Unknown"
            ),
            "waf_confidence": (
                self.waf_fingerprint.confidence
                if self.waf_fingerprint else 0.0
            ),
            "techniques_tested": list(set(
                a["technique"] for a in self.mutation_history
            )),
            "successful_techniques": list(set(
                a["technique"] for a in self.successful_bypasses
            )),
            "successful_payloads": [
                b["payload"] for b in self.successful_bypasses
            ],
        }
        
        if self.evasion_context:
            summary["target_url"] = self.evasion_context.target_url
            summary["iterations_used"] = self.evasion_context.iteration
        
        return summary
    
    def get_context_for_llm(self) -> str:
        """
        Generate context string for LLM reasoning.
        
        Provides the LLM with relevant information about:
        - Current WAF type
        - Attempted techniques
        - Recommended strategies
        - Previous successful bypasses
        """
        context_parts = []
        
        # WAF information
        if self.waf_fingerprint:
            context_parts.append(f"""
WAF INTELLIGENCE:
- Detected WAF: {self.waf_fingerprint.vendor.value}
- Detection Confidence: {self.waf_fingerprint.confidence:.0%}
- Signatures Matched: {', '.join(self.waf_fingerprint.signatures_matched[:5])}
- Recommended Strategies: {', '.join(s.value for s in self.waf_fingerprint.recommended_strategies)}
- Known Bypass Techniques: {', '.join(self.waf_fingerprint.known_bypasses[:5])}
""")
        
        # Attempt history
        if self.mutation_history:
            recent = self.mutation_history[-10:]  # Last 10 attempts
            context_parts.append(f"""
RECENT ATTEMPTS ({len(self.mutation_history)} total):
""")
            for attempt in recent:
                status = "SUCCESS" if attempt["success"] else "BLOCKED"
                context_parts.append(
                    f"  - [{status}] {attempt['technique']}: {attempt['payload'][:50]}..."
                )
        
        # Successful bypasses
        if self.successful_bypasses:
            context_parts.append(f"""
SUCCESSFUL BYPASSES ({len(self.successful_bypasses)}):
""")
            for bypass in self.successful_bypasses:
                context_parts.append(
                    f"  - {bypass['technique']}: {bypass['payload'][:80]}..."
                )
        
        # Strategy recommendations
        next_strategies = self.get_next_strategy()
        context_parts.append(f"""
RECOMMENDED NEXT STRATEGIES:
{', '.join(s.value for s in next_strategies[:3])}
""")
        
        return '\n'.join(context_parts)
    
    def export_findings(self) -> Dict[str, Any]:
        """
        Export all findings for reporting or knowledge graph storage.
        """
        return {
            "summary": self.get_evasion_summary(),
            "waf_fingerprint": {
                "vendor": self.waf_fingerprint.vendor.value if self.waf_fingerprint else None,
                "confidence": self.waf_fingerprint.confidence if self.waf_fingerprint else 0,
                "signatures": self.waf_fingerprint.signatures_matched if self.waf_fingerprint else [],
                "recommended_strategies": [
                    s.value for s in self.waf_fingerprint.recommended_strategies
                ] if self.waf_fingerprint else [],
            },
            "all_attempts": self.mutation_history,
            "successful_bypasses": self.successful_bypasses,
            "context": {
                "target_url": self.evasion_context.target_url if self.evasion_context else None,
                "total_iterations": self.evasion_context.iteration if self.evasion_context else 0,
            },
        }
