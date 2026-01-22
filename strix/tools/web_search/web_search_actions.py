import os
from typing import Any

import requests

from strix.tools.registry import register_tool


SYSTEM_PROMPT = """You are assisting a cybersecurity agent specialized in vulnerability scanning
and security assessment running on Kali Linux. When responding to search queries:

1. Prioritize cybersecurity-relevant information including:
   - Vulnerability details (CVEs, CVSS scores, impact)
   - Security tools, techniques, and methodologies
   - Exploit information and proof-of-concepts
   - Security best practices and mitigations
   - Penetration testing approaches
   - Web application security findings

2. Provide technical depth appropriate for security professionals
3. Include specific versions, configurations, and technical details when available
4. Focus on actionable intelligence for security assessment
5. Cite reliable security sources (NIST, OWASP, CVE databases, security vendors)
6. When providing commands or installation instructions, prioritize Kali Linux compatibility
   and use apt package manager or tools pre-installed in Kali
7. Be detailed and specific - avoid general answers. Always include concrete code examples,
   command-line instructions, configuration snippets, or practical implementation steps
   when applicable

Structure your response to be comprehensive yet concise, emphasizing the most critical
security implications and details."""


@register_tool(sandbox_execution=False)
def web_search(query: str, method: str = "auto") -> dict[str, Any]:
    """
    Advanced web search with multiple methods and automatic fallback.
    Methods: auto, perplexity, ddg, browser
    """
    from strix.tools.web_search.ddg_search import perform_ddg_search
    from strix.tools.web_search.browser_search import perform_browser_search

    results_data = []
    content = ""
    used_method = method

    # 1. Try Perplexity if requested or auto
    if method in ("auto", "perplexity"):
        api_key = os.getenv("PERPLEXITY_API_KEY")
        if api_key:
            try:
                url = "https://api.perplexity.ai/chat/completions"
                headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
                payload = {
                    "model": "sonar-reasoning",
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": query},
                    ],
                }
                response = requests.post(url, headers=headers, json=payload, timeout=60)
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                return {
                    "success": True,
                    "query": query,
                    "content": content,
                    "method": "perplexity",
                    "message": "Search completed via Perplexity.",
                }
            except Exception as e:
                print(f"Perplexity failed: {e}")
                if method == "perplexity":
                    return {"success": False, "message": f"Perplexity failed: {e}", "results": []}

    # 2. Try DuckDuckGo if requested or fallback from perplexity
    if method in ("auto", "ddg") or (method == "auto" and not content):
        try:
            ddg_results = perform_ddg_search(query)
            if ddg_results:
                used_method = "ddg"
                # Formulate a prompt-like content for consistency
                formatted_results = "\n\n".join([f"### {r['title']}\nURL: {r['url']}\n{r['snippet']}" for r in ddg_results])
                return {
                    "success": True,
                    "query": query,
                    "results": ddg_results,
                    "content": formatted_results,
                    "method": "ddg",
                    "message": "Search completed via DuckDuckGo.",
                }
        except Exception as e:
            print(f"DuckDuckGo failed: {e}")
            if method == "ddg":
                return {"success": False, "message": f"DuckDuckGo failed: {e}", "results": []}

    # 3. Last Resort: Browser Search
    if method in ("auto", "browser") or (method == "auto" and not content):
        try:
            browser_res = perform_browser_search(query)
            if browser_res["success"]:
                return {
                    "success": True,
                    "query": query,
                    "results": browser_res["results"],
                    "content": "\n\n".join([f"### {r['title']}\nURL: {r['url']}\n{r['snippet']}" for r in browser_res["results"]]),
                    "method": "browser",
                    "message": "Search completed via Headless Browser.",
                }
        except Exception as e:
            return {"success": False, "message": f"All search methods failed. Last error: {e}", "results": []}

    return {"success": False, "message": "Search failed or no results found.", "results": []}
