import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional


@dataclass
class MutationResult:
    payload: str
    strategy: str
    description: str


class WAFEvasionEngine:
    """
    Core engine for handling WAF analysis and payload mutation.
    This class is pure logic and does not make network requests.
    """

    # Common WAF Error Signatures
    WAF_SIGNATURES = {
        "Cloudflare": [
            "cloudflare",
            "cf-ray",
            "Error 1020",
            "Attention Required!",
            "WAF",
        ],
        "AWS WAF": [
            "AWSALB",
            "AWSALBCORS",
            "x-amzn-errortype",
            "Forbidden",
        ],
        "Akamai": [
            "AkamaiGHost",
            "Reference #",
        ],
        "ModSecurity": [
            "ModSecurity",
            "Not Acceptable",
            "406 Not Acceptable",
        ],
        "Imperva": [
            "Incapsula",
            "visid_incap",
            "incap_ses",
        ],
        "F5 BIG-IP": [
            "BigIP",
            "TS",
            "F5",
        ],
    }

    @staticmethod
    def detect_waf(headers: dict, body: str, status_code: int) -> Optional[str]:
        """
        Analyze response headers and body to identify the WAF.
        """
        # 1. Check Headers
        for header, value in headers.items():
            h_str = f"{header}: {value}"
            for waf_name, sigs in WAFEvasionEngine.WAF_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in h_str.lower():
                        return waf_name

        # 2. Check Body (if 403/406)
        if status_code in (403, 406):
            for waf_name, sigs in WAFEvasionEngine.WAF_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in body.lower():
                        return waf_name

        return None

    @staticmethod
    def _mutate_sql_encoding(payload: str) -> str:
        """Encodes characters to bypass keyword filters."""
        # Simple URL encoding of spaces and sensitive chars
        return urllib.parse.quote(payload)

    @staticmethod
    def _mutate_sql_comments(payload: str) -> str:
        """Injects inline comments to break keyword patterns."""
        # e.g., UNION SELECT -> UNION/**/SELECT
        return payload.replace(" ", "/**/")

    @staticmethod
    def _mutate_sql_case(payload: str) -> str:
        """Randomizes or alternates case."""
        # e.g., UNION SELECT -> UnIoN SeLeCt
        return "".join(
            c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)
        )

    @staticmethod
    def _mutate_sql_whitespace(payload: str) -> str:
        """Replaces spaces with other valid whitespace characters."""
        # %09 (tab), %0A (newline), %0C (form feed), %0D (carriage return)
        # Note: We return raw chars, caller handles encoding if needed
        return payload.replace(" ", "\t")

    @staticmethod
    def _mutate_xss_script_tag(payload: str) -> str:
        """Replaces <script> with other execution contexts."""
        if "<script>" in payload:
            return payload.replace("<script>", "<img src=x onerror=")
        return payload

    @staticmethod
    def _mutate_xss_unicode(payload: str) -> str:
        """Unicode escapes for JS keywords."""
        # alert(1) -> \u0061lert(1)
        return payload.replace("alert", "\\u0061lert").replace(
            "prompt", "\\u0070rompt"
        )

    def generate_heuristic_mutations(self, payload: str) -> list[MutationResult]:
        """
        Generates a set of deterministic mutations for a given payload.
        """
        mutations = []

        # SQL Injection Strategies
        mutations.append(
            MutationResult(
                self._mutate_sql_comments(payload),
                "SQL_InlineComments",
                "Replaces spaces with inline comments /**/",
            )
        )
        mutations.append(
            MutationResult(
                self._mutate_sql_case(payload),
                "SQL_MixedCase",
                "Alternates character casing",
            )
        )
        mutations.append(
            MutationResult(
                self._mutate_sql_whitespace(payload),
                "SQL_TabWhitespace",
                "Replaces spaces with tabs",
            )
        )
        mutations.append(
            MutationResult(
                self._mutate_sql_encoding(payload),
                "URL_DoubleEncoding",
                "Standard URL encoding (often bypassed by double encoding)",
            )
        )

        # XSS Strategies
        if "<" in payload or "alert" in payload:
            mutations.append(
                MutationResult(
                    self._mutate_xss_script_tag(payload),
                    "XSS_ImageOnerror",
                    "Replaces script tag with img onerror",
                )
            )
            mutations.append(
                MutationResult(
                    self._mutate_xss_unicode(payload),
                    "XSS_UnicodeEscape",
                    "Escapes JS keywords (e.g. \\u0061lert)",
                )
            )

        return mutations
