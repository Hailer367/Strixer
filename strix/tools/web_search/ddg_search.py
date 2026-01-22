from duckduckgo_search import DDGS
from typing import List, Dict, Any

def perform_ddg_search(query: str, max_results: int = 10) -> List[Dict[str, Any]]:
    """
    Performs a text search using DuckDuckGo.
    Returns a list of results with 'title', 'href' (url), and 'body' (snippet).
    """
    results = []
    try:
        with DDGS() as ddgs:
            ddg_results = ddgs.text(query, max_results=max_results)
            for r in ddg_results:
                results.append({
                    "title": r.get("title"),
                    "url": r.get("href"),
                    "snippet": r.get("body")
                })
    except Exception as e:
        # In a real tool, we might want to log this but here we return whatever we have or empty
        print(f"DuckDuckGo search error: {e}")
        
    return results

def perform_ddg_news_search(query: str, max_results: int = 5) -> List[Dict[str, Any]]:
    """
    Performs a news search using DuckDuckGo.
    Useful for finding recent zero-day info or vulnerability disclosures.
    """
    results = []
    try:
        with DDGS() as ddgs:
            ddg_results = ddgs.news(query, max_results=max_results)
            for r in ddg_results:
                results.append({
                    "title": r.get("title"),
                    "url": r.get("url"),
                    "snippet": r.get("body"),
                    "date": r.get("date"),
                    "source": r.get("source")
                })
    except Exception as e:
        print(f"DuckDuckGo news search error: {e}")
        
    return results
