"""
Advanced Security Actions - WAF Evasion, Payload Mutation, and Security Testing Tools.

This module provides comprehensive security testing capabilities including:
- Advanced WAF fingerprinting and detection
- Polymorphic payload mutation
- Adaptive evasion strategies
- Protocol-level bypass techniques
- Encoding chain generation
"""

from typing import Any, Dict, List, Optional

from strix.tools.registry import register_tool
from strix.tools.security.waf_evasion import (
    WAFEvasionEngine,
    WAFVendor,
    EvasionStrategy,
    EvasionContext,
    MutationResult,
)


# Global engine instance for stateful operations
_engine: Optional[WAFEvasionEngine] = None
_evasion_context: Optional[EvasionContext] = None


def _get_engine() -> WAFEvasionEngine:
    """Get or create the global WAF evasion engine."""
    global _engine
    if _engine is None:
        _engine = WAFEvasionEngine()
    return _engine


@register_tool(sandbox_execution=False)
def waf_fingerprint(
    headers: Dict[str, str],
    body: str,
    status_code: int,
    cookies: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Advanced WAF fingerprinting with confidence scoring.
    
    Analyzes HTTP response artifacts to identify the WAF vendor
    with detailed confidence scoring and bypass recommendations.
    
    Use this BEFORE attempting bypasses to optimize your strategy.
    """
    engine = _get_engine()
    
    fingerprint = engine.fingerprint_waf(
        headers=headers,
        body=body,
        status_code=status_code,
        cookies=cookies,
    )
    
    return {
        "success": True,
        "waf_detected": fingerprint.vendor != WAFVendor.UNKNOWN,
        "waf_vendor": fingerprint.vendor.value,
        "confidence": fingerprint.confidence,
        "signatures_matched": fingerprint.signatures_matched,
        "headers_detected": fingerprint.headers_detected,
        "behavior_indicators": fingerprint.behavior_indicators,
        "recommended_strategies": [s.value for s in fingerprint.recommended_strategies],
        "known_bypasses": fingerprint.known_bypasses,
    }


@register_tool(sandbox_execution=False)
def waf_probe(
    url: str,
    payload: str,
    method: str = "GET",
) -> Dict[str, Any]:
    """
    Initialize a WAF evasion probe session.
    
    This creates an evasion context and generates initial mutation
    strategies based on the payload type. Use this as the first step
    when a request is blocked.
    """
    global _evasion_context
    engine = _get_engine()
    
    _evasion_context = EvasionContext(
        target_url=url,
        blocked_payloads=[payload],
    )
    
    # Generate initial mutations
    mutations = engine.generate_mutations(
        payload=payload,
        context=_evasion_context,
        max_mutations=30,
    )
    
    # Group by strategy
    strategies_used = {}
    for m in mutations:
        cat = m.category.value
        if cat not in strategies_used:
            strategies_used[cat] = []
        strategies_used[cat].append({
            "technique": m.technique,
            "payload": m.payload,
            "confidence": m.confidence,
            "description": m.description,
        })
    
    return {
        "success": True,
        "status": "probe_initialized",
        "target_url": url,
        "original_payload": payload,
        "mutations_generated": len(mutations),
        "strategies_available": list(strategies_used.keys()),
        "top_mutations": [
            {
                "technique": m.technique,
                "payload": m.payload,
                "confidence": m.confidence,
                "description": m.description,
                "category": m.category.value,
            }
            for m in mutations[:10]
        ],
        "mutations_by_strategy": strategies_used,
        "message": "Probe initialized. Use mutate_payload or get_adaptive_mutations for specific strategies.",
    }


@register_tool(sandbox_execution=False)
def mutate_payload(
    payload: str,
    strategy: str = "all",
    max_mutations: int = 20,
    waf_vendor: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate payload mutations using specified strategy.
    
    Strategies:
    - all: All available strategies
    - encoding: URL, HTML, Unicode, Base64, Hex encodings
    - syntax: Whitespace, comments, case mutations
    - semantic: Keyword alternatives, equivalent expressions
    - protocol: HTTP parameter pollution, multipart tricks
    - polymorphic: Combined multi-technique mutations
    - fragmentation: Chunked encoding, null byte injection
    """
    engine = _get_engine()
    
    # Parse strategy
    if strategy == "all":
        strategies = list(EvasionStrategy)
    else:
        try:
            strategies = [EvasionStrategy(strategy)]
        except ValueError:
            # Try matching by name
            strategies = [
                s for s in EvasionStrategy
                if strategy.lower() in s.value.lower()
            ]
            if not strategies:
                strategies = list(EvasionStrategy)
    
    # Generate mutations
    mutations = engine.generate_mutations(
        payload=payload,
        strategies=strategies,
        max_mutations=max_mutations,
    )
    
    # If WAF vendor specified, prioritize relevant techniques
    if waf_vendor:
        try:
            vendor = WAFVendor(waf_vendor)
            known_techniques = engine.WAF_BYPASS_TECHNIQUES.get(vendor, [])
            for m in mutations:
                if m.technique in known_techniques:
                    m.confidence = min(1.0, m.confidence + 0.2)
            mutations.sort(key=lambda x: -x.confidence)
        except ValueError:
            pass
    
    return {
        "success": True,
        "original_payload": payload,
        "strategy": strategy,
        "mutations_count": len(mutations),
        "mutations": [
            {
                "technique": m.technique,
                "payload": m.payload,
                "confidence": m.confidence,
                "description": m.description,
                "category": m.category.value,
                "encoding_chain": m.encoding_chain,
            }
            for m in mutations
        ],
    }


@register_tool(sandbox_execution=False)
def get_adaptive_mutations(
    payload: str,
    blocked_payloads: Optional[List[str]] = None,
    blocked_techniques: Optional[List[str]] = None,
    successful_techniques: Optional[List[str]] = None,
    waf_vendor: Optional[str] = None,
    max_mutations: int = 15,
) -> Dict[str, Any]:
    """
    Generate adaptive mutations based on previous attempts.
    
    This learns from blocked/successful attempts to prioritize
    techniques more likely to succeed.
    """
    engine = _get_engine()
    
    # Create context from history
    context = EvasionContext(
        target_url="adaptive",
        blocked_payloads=blocked_payloads or [],
        blocked_techniques=blocked_techniques or [],
        successful_techniques=successful_techniques or [],
    )
    
    if waf_vendor:
        try:
            context.waf_vendor = WAFVendor(waf_vendor)
        except ValueError:
            pass
    
    mutations = engine.generate_mutations(
        payload=payload,
        context=context,
        max_mutations=max_mutations,
    )
    
    # Analyze strategy effectiveness
    strategy_recommendations = []
    if successful_techniques:
        strategy_recommendations.append(
            f"Previously successful: {', '.join(successful_techniques[:3])}"
        )
    if blocked_techniques:
        strategy_recommendations.append(
            f"Avoid similar to: {', '.join(blocked_techniques[:3])}"
        )
    
    return {
        "success": True,
        "adaptive_mode": True,
        "context": {
            "blocked_count": len(blocked_payloads or []),
            "blocked_techniques_count": len(blocked_techniques or []),
            "successful_techniques": successful_techniques or [],
        },
        "strategy_recommendations": strategy_recommendations,
        "mutations": [
            {
                "technique": m.technique,
                "payload": m.payload,
                "confidence": m.confidence,
                "description": m.description,
                "category": m.category.value,
            }
            for m in mutations
        ],
    }


@register_tool(sandbox_execution=False)
def detect_waf_signature(
    headers: Dict[str, str],
    body: str,
    status: int,
) -> Dict[str, Any]:
    """
    Quick WAF detection (backward compatible).
    
    For detailed fingerprinting, use waf_fingerprint() instead.
    """
    engine = _get_engine()
    waf_name = engine.detect_waf(headers, body, status)
    
    return {
        "is_waf_detected": bool(waf_name),
        "waf_name": waf_name or "None",
        "confidence": "high" if waf_name else "low",
        "hint": "Use waf_fingerprint() for detailed analysis and bypass recommendations",
    }


@register_tool(sandbox_execution=False)
def encode_payload(
    payload: str,
    encoding: str,
) -> Dict[str, Any]:
    """
    Encode a payload using a specific encoding.
    
    Available encodings:
    - url: Standard URL encoding
    - url_double: Double URL encoding
    - url_unicode: Unicode URL encoding (%uXXXX)
    - html_entity: HTML entity encoding
    - html_entity_decimal: HTML decimal entities (&#XX;)
    - html_entity_hex: HTML hex entities (&#xXX;)
    - base64: Base64 encoding
    - hex: Hex escape (\\xXX)
    - unicode_escape: Unicode escape (\\uXXXX)
    - octal: Octal escape (\\XXX)
    """
    engine = _get_engine()
    
    if encoding not in engine.ENCODERS:
        return {
            "success": False,
            "error": f"Unknown encoding: {encoding}",
            "available_encodings": list(engine.ENCODERS.keys()),
        }
    
    try:
        encoded = engine.ENCODERS[encoding](payload)
        return {
            "success": True,
            "original": payload,
            "encoding": encoding,
            "encoded": encoded,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@register_tool(sandbox_execution=False)
def encode_payload_chain(
    payload: str,
    encodings: List[str],
) -> Dict[str, Any]:
    """
    Apply a chain of encodings to a payload.
    
    Each encoding is applied in sequence to the result of the previous.
    Example: ["url", "base64"] first URL-encodes, then Base64-encodes.
    """
    engine = _get_engine()
    
    result = payload
    chain_steps = [{"step": 0, "encoding": "original", "value": payload}]
    
    for i, encoding in enumerate(encodings):
        if encoding not in engine.ENCODERS:
            return {
                "success": False,
                "error": f"Unknown encoding at step {i+1}: {encoding}",
                "available_encodings": list(engine.ENCODERS.keys()),
            }
        
        try:
            result = engine.ENCODERS[encoding](result)
            chain_steps.append({
                "step": i + 1,
                "encoding": encoding,
                "value": result,
            })
        except Exception as e:
            return {
                "success": False,
                "error": f"Error at step {i+1} ({encoding}): {e}",
                "partial_result": result,
            }
    
    return {
        "success": True,
        "original": payload,
        "encoding_chain": encodings,
        "final_result": result,
        "chain_steps": chain_steps,
    }


@register_tool(sandbox_execution=False)
def get_waf_bypass_techniques(
    waf_vendor: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get known bypass techniques for a specific WAF or all WAFs.
    """
    engine = _get_engine()
    
    if waf_vendor:
        try:
            vendor = WAFVendor(waf_vendor)
            techniques = engine.WAF_BYPASS_TECHNIQUES.get(vendor, [])
            return {
                "success": True,
                "waf_vendor": waf_vendor,
                "techniques": techniques,
                "strategies_recommended": [
                    s.value for s in engine._get_recommended_strategies(vendor, [])
                ],
            }
        except ValueError:
            return {
                "success": False,
                "error": f"Unknown WAF vendor: {waf_vendor}",
                "known_vendors": [v.value for v in WAFVendor if v != WAFVendor.UNKNOWN],
            }
    
    # Return all
    all_techniques = {}
    for vendor, techniques in engine.WAF_BYPASS_TECHNIQUES.items():
        all_techniques[vendor.value] = techniques
    
    return {
        "success": True,
        "waf_techniques": all_techniques,
        "known_vendors": [v.value for v in WAFVendor if v != WAFVendor.UNKNOWN],
    }


@register_tool(sandbox_execution=False)
def record_bypass_attempt(
    original_payload: str,
    mutated_payload: str,
    technique: str,
    success: bool,
    waf_vendor: Optional[str] = None,
    target_url: Optional[str] = None,
    response_code: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Record a bypass attempt for adaptive learning.
    
    Records both successful and failed attempts to improve
    future mutation strategies.
    """
    global _evasion_context
    engine = _get_engine()
    
    if success and waf_vendor and target_url:
        try:
            vendor = WAFVendor(waf_vendor)
            engine.record_bypass(
                original_payload=original_payload,
                successful_payload=mutated_payload,
                waf_vendor=vendor,
                technique=technique,
                target_url=target_url,
            )
        except ValueError:
            pass
    
    if _evasion_context:
        if success:
            _evasion_context.successful_payloads.append(mutated_payload)
            _evasion_context.successful_techniques.append(technique)
        else:
            _evasion_context.blocked_payloads.append(mutated_payload)
            _evasion_context.blocked_techniques.append(technique)
        _evasion_context.iteration += 1
    
    return {
        "success": True,
        "recorded": True,
        "attempt": {
            "original": original_payload,
            "mutated": mutated_payload,
            "technique": technique,
            "bypass_success": success,
            "waf_vendor": waf_vendor,
            "response_code": response_code,
        },
        "context_updated": _evasion_context is not None,
    }


@register_tool(sandbox_execution=False)
def get_bypass_history(
    waf_vendor: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get recorded successful bypasses from the current session.
    """
    engine = _get_engine()
    
    if waf_vendor:
        try:
            vendor = WAFVendor(waf_vendor)
            history = engine.get_bypass_history(vendor)
        except ValueError:
            history = []
    else:
        history = engine.get_bypass_history()
    
    return {
        "success": True,
        "filter": waf_vendor,
        "bypass_count": len(history),
        "bypasses": history,
    }


@register_tool(sandbox_execution=False)
def generate_sqli_bypasses(
    payload: str,
    max_mutations: int = 15,
) -> Dict[str, Any]:
    """
    Generate SQL injection specific bypass payloads.
    
    Focuses on SQL-specific techniques like:
    - Inline comments
    - Case toggling
    - Whitespace alternatives
    - Keyword alternatives
    - Encoding tricks
    """
    engine = _get_engine()
    
    mutations = engine.generate_mutations(
        payload=payload,
        strategies=[
            EvasionStrategy.ENCODING,
            EvasionStrategy.SYNTAX,
            EvasionStrategy.SEMANTIC,
        ],
        max_mutations=max_mutations * 2,
    )
    
    # Filter for SQL-relevant mutations
    sql_keywords = ["sql", "union", "select", "comment", "whitespace", "case", "concat"]
    sql_mutations = [
        m for m in mutations
        if any(kw in m.technique.lower() or kw in m.description.lower() for kw in sql_keywords)
    ]
    
    # Add fallback if not enough SQL-specific mutations
    if len(sql_mutations) < max_mutations:
        sql_mutations = mutations[:max_mutations]
    
    return {
        "success": True,
        "payload_type": "SQL Injection",
        "original": payload,
        "mutations_count": len(sql_mutations[:max_mutations]),
        "mutations": [
            {
                "technique": m.technique,
                "payload": m.payload,
                "confidence": m.confidence,
                "description": m.description,
            }
            for m in sql_mutations[:max_mutations]
        ],
    }


@register_tool(sandbox_execution=False)
def generate_xss_bypasses(
    payload: str,
    max_mutations: int = 15,
) -> Dict[str, Any]:
    """
    Generate XSS specific bypass payloads.
    
    Focuses on XSS-specific techniques like:
    - Tag alternatives
    - Event handler alternatives
    - Encoding tricks
    - Protocol handlers
    """
    engine = _get_engine()
    
    mutations = engine.generate_mutations(
        payload=payload,
        strategies=[
            EvasionStrategy.ENCODING,
            EvasionStrategy.SYNTAX,
            EvasionStrategy.SEMANTIC,
            EvasionStrategy.POLYMORPHIC,
        ],
        max_mutations=max_mutations * 2,
    )
    
    # Filter for XSS-relevant mutations
    xss_keywords = ["xss", "script", "img", "svg", "onerror", "onload", "javascript", "event", "tag"]
    xss_mutations = [
        m for m in mutations
        if any(kw in m.technique.lower() or kw in m.description.lower() for kw in xss_keywords)
    ]
    
    # Add fallback if not enough XSS-specific mutations
    if len(xss_mutations) < max_mutations:
        xss_mutations = mutations[:max_mutations]
    
    return {
        "success": True,
        "payload_type": "Cross-Site Scripting (XSS)",
        "original": payload,
        "mutations_count": len(xss_mutations[:max_mutations]),
        "mutations": [
            {
                "technique": m.technique,
                "payload": m.payload,
                "confidence": m.confidence,
                "description": m.description,
            }
            for m in xss_mutations[:max_mutations]
        ],
    }


# Backward compatibility class wrapper
class SecurityActions:
    """
    Backward compatible wrapper for security actions.
    
    Prefer using the @register_tool functions directly.
    """
    
    def __init__(self, sandbox=None):
        self.sandbox = sandbox
        self.engine = WAFEvasionEngine()
    
    def waf_probe(self, url: str, payload: str, method: str = "GET") -> Dict[str, Any]:
        """Backward compatible waf_probe."""
        mutations = self.engine.generate_heuristic_mutations(payload)
        return {
            "status": "probe_complete",
            "detected_strategies": [m.strategy for m in mutations],
            "suggested_payloads": [m.payload for m in mutations],
            "message": "Heuristic mutations generated.",
        }
    
    def mutate_payload(self, payload: str, strategy: str = "all") -> List[Dict[str, str]]:
        """Backward compatible mutate_payload."""
        mutations = self.engine.generate_heuristic_mutations(payload)
        results = []
        for m in mutations:
            if strategy == "all" or strategy.lower() in m.strategy.lower():
                results.append({
                    "strategy": m.strategy,
                    "payload": m.payload,
                    "description": m.description,
                })
        return results
    
    def detect_waf_signature(
        self,
        headers: Dict[str, str],
        body: str,
        status: int,
    ) -> Dict[str, str]:
        """Backward compatible detect_waf_signature."""
        waf_name = self.engine.detect_waf(headers, body, status)
        return {
            "is_waf_detected": bool(waf_name),
            "waf_name": waf_name or "None",
            "confidence": "high" if waf_name else "low",
        }
