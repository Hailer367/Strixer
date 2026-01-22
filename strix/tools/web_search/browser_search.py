import time
from typing import List, Dict, Any
from strix.tools.browser.tab_manager import get_browser_tab_manager

def perform_browser_search(query: str, engine: str = "duckduckgo") -> Dict[str, Any]:
    """
    Performs a web search using a headless browser.
    Mimics human activity to bypass basic bot detection.
    """
    manager = get_browser_tab_manager()
    results = []
    
    try:
        # Launch or use existing browser
        manager.launch_browser()
        
        # Navigate to search engine
        if engine == "duckduckgo":
            search_url = f"https://duckduckgo.com/?q={query.replace(' ', '+')}"
        else:
            search_url = f"https://www.google.com/search?q={query.replace(' ', '+')}"
            
        manager.goto_url(search_url)
        
        # Wait for results to load
        time.sleep(3) 
        
        # Parse results using JS
        if engine == "duckduckgo":
            js_code = """
            Array.from(document.querySelectorAll('.react-results--main article')).map(el => ({
                title: el.querySelector('h2')?.innerText,
                url: el.querySelector('h2 a')?.href,
                snippet: el.querySelector('div[data-testid="result-snippet"]')?.innerText
            })).filter(r => r.title && r.url)
            """
        else:
            js_code = """
            Array.from(document.querySelectorAll('div.g')).map(el => ({
                title: el.querySelector('h3')?.innerText,
                url: el.querySelector('a')?.href,
                snippet: el.querySelector('div.VwiC3b')?.innerText
            })).filter(r => r.title && r.url)
            """
            
        execution_result = manager.execute_js(js_code)
        results = execution_result.get("js_result", [])
        
        # Limit to top 8
        results = results[:8]
        
        return {
            "success": True,
            "results": results,
            "engine": engine,
            "message": f"Successfully retrieved {len(results)} results via browser."
        }
        
    except Exception as e:
        return {
            "success": False,
            "results": [],
            "error": str(e),
            "message": "Browser search failed."
        }
    finally:
        # We don't close the browser here to keep it persistent for the session if needed
        pass
