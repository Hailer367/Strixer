import asyncio
import base64
import logging
import threading
from pathlib import Path
from typing import Any, cast

from playwright.async_api import Browser, BrowserContext, Page, Playwright, async_playwright


logger = logging.getLogger(__name__)

MAX_PAGE_SOURCE_LENGTH = 20_000
MAX_CONSOLE_LOG_LENGTH = 30_000
MAX_INDIVIDUAL_LOG_LENGTH = 1_000
MAX_CONSOLE_LOGS_COUNT = 200
MAX_JS_RESULT_LENGTH = 5_000


class BrowserInstance:
    def __init__(self) -> None:
        self.is_running = True
        self._execution_lock = threading.Lock()

        self.playwright: Playwright | None = None
        self.browser: Browser | None = None
        self.context: BrowserContext | None = None
        self.pages: dict[str, Page] = {}
        self.current_page_id: str | None = None
        self._next_tab_id = 1

        self.console_logs: dict[str, list[dict[str, Any]]] = {}

        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None

        self._start_event_loop()

    def _start_event_loop(self) -> None:
        def run_loop() -> None:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_forever()

        self._loop_thread = threading.Thread(target=run_loop, daemon=True)
        self._loop_thread.start()

        while self._loop is None:
            threading.Event().wait(0.01)

    def _run_async(self, coro: Any) -> dict[str, Any]:
        if not self._loop or not self.is_running:
            raise RuntimeError("Browser instance is not running")

        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return cast("dict[str, Any]", future.result(timeout=30))  # 30 second timeout

    async def _setup_console_logging(self, page: Page, tab_id: str) -> None:
        self.console_logs[tab_id] = []

        def handle_console(msg: Any) -> None:
            text = msg.text
            if len(text) > MAX_INDIVIDUAL_LOG_LENGTH:
                text = text[:MAX_INDIVIDUAL_LOG_LENGTH] + "... [TRUNCATED]"

            log_entry = {
                "type": msg.type,
                "text": text,
                "location": msg.location,
                "timestamp": asyncio.get_event_loop().time(),
            }

            self.console_logs[tab_id].append(log_entry)

            if len(self.console_logs[tab_id]) > MAX_CONSOLE_LOGS_COUNT:
                self.console_logs[tab_id] = self.console_logs[tab_id][-MAX_CONSOLE_LOGS_COUNT:]

        page.on("console", handle_console)

    async def _launch_browser(self, url: str | None = None) -> dict[str, Any]:
        self.playwright = await async_playwright().start()

        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-web-security",
                "--disable-features=VizDisplayCompositor",
            ],
        )

        self.context = await self.browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            ),
        )

        page = await self.context.new_page()
        tab_id = f"tab_{self._next_tab_id}"
        self._next_tab_id += 1
        self.pages[tab_id] = page
        self.current_page_id = tab_id

        await self._setup_console_logging(page, tab_id)

        if url:
            await page.goto(url, wait_until="domcontentloaded")

        return await self._get_page_state(tab_id)

    async def _get_page_state(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]

        await asyncio.sleep(2)

        screenshot_bytes = await page.screenshot(type="png", full_page=False)
        screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")

        url = page.url
        title = await page.title()
        viewport = page.viewport_size

        all_tabs = {}
        for tid, tab_page in self.pages.items():
            all_tabs[tid] = {
                "url": tab_page.url,
                "title": await tab_page.title() if not tab_page.is_closed() else "Closed",
            }

        return {
            "screenshot": screenshot_b64,
            "url": url,
            "title": title,
            "viewport": viewport,
            "tab_id": tab_id,
            "all_tabs": all_tabs,
        }

    def launch(self, url: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            if self.browser is not None:
                raise ValueError("Browser is already launched")

            return self._run_async(self._launch_browser(url))

    def goto(self, url: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._goto(url, tab_id))

    async def _goto(self, url: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]
        await page.goto(url, wait_until="domcontentloaded")

        return await self._get_page_state(tab_id)

    def click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._click(coordinate, tab_id))

    async def _click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        try:
            x, y = map(int, coordinate.split(","))
        except ValueError as e:
            raise ValueError(f"Invalid coordinate format: {coordinate}. Use 'x,y'") from e

        page = self.pages[tab_id]
        await page.mouse.click(x, y)

        return await self._get_page_state(tab_id)

    def type_text(self, text: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._type_text(text, tab_id))

    async def _type_text(self, text: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]
        await page.keyboard.type(text)

        return await self._get_page_state(tab_id)

    def scroll(self, direction: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._scroll(direction, tab_id))

    async def _scroll(self, direction: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]

        if direction == "down":
            await page.keyboard.press("PageDown")
        elif direction == "up":
            await page.keyboard.press("PageUp")
        else:
            raise ValueError(f"Invalid scroll direction: {direction}")

        return await self._get_page_state(tab_id)

    def back(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._back(tab_id))

    async def _back(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]
        await page.go_back(wait_until="domcontentloaded")

        return await self._get_page_state(tab_id)

    def forward(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._forward(tab_id))

    async def _forward(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]
        await page.go_forward(wait_until="domcontentloaded")

        return await self._get_page_state(tab_id)

    def new_tab(self, url: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._new_tab(url))

    async def _new_tab(self, url: str | None = None) -> dict[str, Any]:
        if not self.context:
            raise ValueError("Browser not launched")

        page = await self.context.new_page()
        tab_id = f"tab_{self._next_tab_id}"
        self._next_tab_id += 1
        self.pages[tab_id] = page
        self.current_page_id = tab_id

        await self._setup_console_logging(page, tab_id)

        if url:
            await page.goto(url, wait_until="domcontentloaded")

        return await self._get_page_state(tab_id)

    def switch_tab(self, tab_id: str) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._switch_tab(tab_id))

    async def _switch_tab(self, tab_id: str) -> dict[str, Any]:
        if tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        self.current_page_id = tab_id
        return await self._get_page_state(tab_id)

    def close_tab(self, tab_id: str) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._close_tab(tab_id))

    async def _close_tab(self, tab_id: str) -> dict[str, Any]:
        if tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        if len(self.pages) == 1:
            raise ValueError("Cannot close the last tab")

        page = self.pages.pop(tab_id)
        await page.close()

        if tab_id in self.console_logs:
            del self.console_logs[tab_id]

        if self.current_page_id == tab_id:
            self.current_page_id = next(iter(self.pages.keys()))

        return await self._get_page_state(self.current_page_id)

    def wait(self, duration: float, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._wait(duration, tab_id))

    async def _wait(self, duration: float, tab_id: str | None = None) -> dict[str, Any]:
        await asyncio.sleep(duration)
        return await self._get_page_state(tab_id)

    def execute_js(self, js_code: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._execute_js(js_code, tab_id))

    async def _execute_js(self, js_code: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]

        try:
            result = await page.evaluate(js_code)
        except Exception as e:  # noqa: BLE001
            result = {
                "error": True,
                "error_type": type(e).__name__,
                "error_message": str(e),
            }

        result_str = str(result)
        if len(result_str) > MAX_JS_RESULT_LENGTH:
            result = result_str[:MAX_JS_RESULT_LENGTH] + "... [JS result truncated at 5k chars]"

        state = await self._get_page_state(tab_id)
        state["js_result"] = result
        return state

    def get_console_logs(self, tab_id: str | None = None, clear: bool = False) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._get_console_logs(tab_id, clear))

    async def _get_console_logs(
        self, tab_id: str | None = None, clear: bool = False
    ) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        logs = self.console_logs.get(tab_id, [])

        total_length = sum(len(str(log)) for log in logs)
        if total_length > MAX_CONSOLE_LOG_LENGTH:
            truncated_logs: list[dict[str, Any]] = []
            current_length = 0

            for log in reversed(logs):
                log_length = len(str(log))
                if current_length + log_length <= MAX_CONSOLE_LOG_LENGTH:
                    truncated_logs.insert(0, log)
                    current_length += log_length
                else:
                    break

            if len(truncated_logs) < len(logs):
                truncation_notice = {
                    "type": "info",
                    "text": (
                        f"[TRUNCATED: {len(logs) - len(truncated_logs)} older logs "
                        f"removed to stay within {MAX_CONSOLE_LOG_LENGTH} character limit]"
                    ),
                    "location": {},
                    "timestamp": 0,
                }
                truncated_logs.insert(0, truncation_notice)

            logs = truncated_logs

        if clear:
            self.console_logs[tab_id] = []

        state = await self._get_page_state(tab_id)
        state["console_logs"] = logs
        return state

    def view_source(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._view_source(tab_id))

    async def _view_source(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]
        source = await page.content()
        original_length = len(source)

        if original_length > MAX_PAGE_SOURCE_LENGTH:
            truncation_message = (
                f"\n\n<!-- [TRUNCATED: {original_length - MAX_PAGE_SOURCE_LENGTH} "
                "characters removed] -->\n\n"
            )
            available_space = MAX_PAGE_SOURCE_LENGTH - len(truncation_message)
            truncate_point = available_space // 2

            source = source[:truncate_point] + truncation_message + source[-truncate_point:]

        state = await self._get_page_state(tab_id)
        state["page_source"] = source
        return state

    def double_click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._double_click(coordinate, tab_id))

    async def _double_click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        try:
            x, y = map(int, coordinate.split(","))
        except ValueError as e:
            raise ValueError(f"Invalid coordinate format: {coordinate}. Use 'x,y'") from e

        page = self.pages[tab_id]
        await page.mouse.dblclick(x, y)

        return await self._get_page_state(tab_id)

    def hover(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._hover(coordinate, tab_id))

    async def _hover(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        try:
            x, y = map(int, coordinate.split(","))
        except ValueError as e:
            raise ValueError(f"Invalid coordinate format: {coordinate}. Use 'x,y'") from e

        page = self.pages[tab_id]
        await page.mouse.move(x, y)

        return await self._get_page_state(tab_id)

    def press_key(self, key: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._press_key(key, tab_id))

    async def _press_key(self, key: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]
        await page.keyboard.press(key)

        return await self._get_page_state(tab_id)

    def save_pdf(self, file_path: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._save_pdf(file_path, tab_id))

    async def _save_pdf(self, file_path: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        if not Path(file_path).is_absolute():
            file_path = str(Path("/workspace") / file_path)

        page = self.pages[tab_id]
        await page.pdf(path=file_path)

        state = await self._get_page_state(tab_id)
        state["pdf_saved"] = file_path
        return state

    def close(self) -> None:
        with self._execution_lock:
            self.is_running = False
            if self._loop:
                asyncio.run_coroutine_threadsafe(self._close_browser(), self._loop)

                self._loop.call_soon_threadsafe(self._loop.stop)

                if self._loop_thread:
                    self._loop_thread.join(timeout=5)

    async def _close_browser(self) -> None:
        try:
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
        except (OSError, RuntimeError) as e:
            logger.warning(f"Error closing browser: {e}")

    def is_alive(self) -> bool:
        return self.is_running and self.browser is not None and self.browser.is_connected()

    # Advanced Security Methods
    
    def get_cookies(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._get_cookies(tab_id))
    
    async def _get_cookies(self, tab_id: str | None = None) -> dict[str, Any]:
        if not self.context:
            raise ValueError("Browser not launched")
        
        cookies = await self.context.cookies()
        state = await self._get_page_state(tab_id)
        state["cookies"] = [
            {
                "name": c.get("name"),
                "value": c.get("value", "")[:100] + ("..." if len(c.get("value", "")) > 100 else ""),
                "domain": c.get("domain"),
                "path": c.get("path"),
                "expires": c.get("expires"),
                "httpOnly": c.get("httpOnly"),
                "secure": c.get("secure"),
                "sameSite": c.get("sameSite"),
            }
            for c in cookies
        ]
        return state
    
    def set_cookie(self, cookie_data: dict, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._set_cookie(cookie_data, tab_id))
    
    async def _set_cookie(self, cookie_data: dict, tab_id: str | None = None) -> dict[str, Any]:
        if not self.context:
            raise ValueError("Browser not launched")
        
        await self.context.add_cookies([cookie_data])
        return await self._get_page_state(tab_id)
    
    def delete_cookies(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._delete_cookies(tab_id))
    
    async def _delete_cookies(self, tab_id: str | None = None) -> dict[str, Any]:
        if not self.context:
            raise ValueError("Browser not launched")
        
        await self.context.clear_cookies()
        return await self._get_page_state(tab_id)
    
    def get_storage(self, storage_type: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._get_storage(storage_type, tab_id))
    
    async def _get_storage(self, storage_type: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id
        
        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")
        
        page = self.pages[tab_id]
        storage_key = "localStorage" if storage_type == "local" else "sessionStorage"
        
        try:
            data = await page.evaluate(f"""
                () => {{
                    const storage = window.{storage_key};
                    const result = {{}};
                    for (let i = 0; i < storage.length; i++) {{
                        const key = storage.key(i);
                        result[key] = storage.getItem(key);
                    }}
                    return result;
                }}
            """)
        except Exception:
            data = {}
        
        state = await self._get_page_state(tab_id)
        state["data"] = data
        state["storage_type"] = storage_type
        return state
    
    def clear_storage(self, storage_type: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._clear_storage(storage_type, tab_id))
    
    async def _clear_storage(self, storage_type: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id
        
        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")
        
        page = self.pages[tab_id]
        
        if storage_type in ("local", "all"):
            await page.evaluate("() => localStorage.clear()")
        if storage_type in ("session", "all"):
            await page.evaluate("() => sessionStorage.clear()")
        
        return await self._get_page_state(tab_id)
    
    def get_network_logs(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._get_network_logs(tab_id))
    
    async def _get_network_logs(self, tab_id: str | None = None) -> dict[str, Any]:
        # Network logs would require request interception setup
        # For now, return console logs that contain network info
        state = await self._get_page_state(tab_id)
        state["requests"] = []
        state["note"] = "Network interception requires explicit setup with intercept_requests"
        return state
    
    def analyze_dom(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._analyze_dom(tab_id))
    
    async def _analyze_dom(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id
        
        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")
        
        page = self.pages[tab_id]
        
        analysis = await page.evaluate("""
            () => {
                const issues = [];
                
                // Check for inline scripts
                const inlineScripts = document.querySelectorAll('script:not([src])');
                if (inlineScripts.length > 0) {
                    issues.push({
                        severity: 'info',
                        type: 'inline_script',
                        message: `Found ${inlineScripts.length} inline scripts (potential XSS vectors)`
                    });
                }
                
                // Check for onclick handlers
                const onclickElements = document.querySelectorAll('[onclick]');
                if (onclickElements.length > 0) {
                    issues.push({
                        severity: 'low',
                        type: 'inline_handler',
                        message: `Found ${onclickElements.length} elements with onclick handlers`
                    });
                }
                
                // Check for password fields
                const passwordFields = document.querySelectorAll('input[type="password"]');
                passwordFields.forEach((field, idx) => {
                    if (!field.autocomplete || field.autocomplete === 'on') {
                        issues.push({
                            severity: 'low',
                            type: 'password_autocomplete',
                            message: `Password field #${idx + 1} has autocomplete enabled`
                        });
                    }
                });
                
                // Check for iframes
                const iframes = document.querySelectorAll('iframe');
                iframes.forEach((iframe, idx) => {
                    if (!iframe.sandbox) {
                        issues.push({
                            severity: 'medium',
                            type: 'unsandboxed_iframe',
                            message: `Iframe #${idx + 1} is not sandboxed: ${iframe.src || 'inline'}`
                        });
                    }
                });
                
                // Check for external resources
                const externalScripts = document.querySelectorAll('script[src]');
                const externalStyles = document.querySelectorAll('link[rel="stylesheet"]');
                
                return {
                    issues: issues,
                    stats: {
                        total_scripts: document.querySelectorAll('script').length,
                        inline_scripts: inlineScripts.length,
                        external_scripts: externalScripts.length,
                        stylesheets: externalStyles.length,
                        iframes: iframes.length,
                        forms: document.querySelectorAll('form').length,
                        inputs: document.querySelectorAll('input').length,
                        links: document.querySelectorAll('a').length
                    }
                };
            }
        """)
        
        state = await self._get_page_state(tab_id)
        state["analysis"] = analysis
        state["issues"] = analysis.get("issues", [])
        state["stats"] = analysis.get("stats", {})
        return state
    
    def find_forms(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._find_forms(tab_id))
    
    async def _find_forms(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id
        
        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")
        
        page = self.pages[tab_id]
        
        forms = await page.evaluate("""
            () => {
                const forms = [];
                document.querySelectorAll('form').forEach((form, idx) => {
                    const fields = [];
                    form.querySelectorAll('input, textarea, select').forEach(field => {
                        fields.push({
                            name: field.name || field.id || 'unnamed',
                            type: field.type || field.tagName.toLowerCase(),
                            id: field.id,
                            required: field.required,
                            placeholder: field.placeholder || ''
                        });
                    });
                    
                    forms.push({
                        index: idx,
                        action: form.action || window.location.href,
                        method: form.method || 'GET',
                        enctype: form.enctype || 'application/x-www-form-urlencoded',
                        id: form.id,
                        name: form.name,
                        fields: fields,
                        hasFileUpload: form.querySelector('input[type="file"]') !== null,
                        hasPassword: form.querySelector('input[type="password"]') !== null,
                        hasHidden: form.querySelectorAll('input[type="hidden"]').length > 0
                    });
                });
                return forms;
            }
        """)
        
        state = await self._get_page_state(tab_id)
        state["forms"] = forms
        return state
    
    def extract_links(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._extract_links(tab_id))
    
    async def _extract_links(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id
        
        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")
        
        page = self.pages[tab_id]
        
        links = await page.evaluate("""
            () => {
                const links = [];
                const baseUrl = window.location.origin;
                
                document.querySelectorAll('a[href]').forEach(link => {
                    const href = link.href;
                    const isExternal = href && !href.startsWith(baseUrl) && 
                                      !href.startsWith('/') && !href.startsWith('#');
                    
                    links.push({
                        href: href,
                        text: (link.textContent || '').trim().substring(0, 100),
                        target: link.target || '_self',
                        rel: link.rel || '',
                        isExternal: isExternal,
                        hasNoopener: link.rel.includes('noopener'),
                        hasNoreferrer: link.rel.includes('noreferrer')
                    });
                });
                
                return links.slice(0, 500); // Limit to 500 links
            }
        """)
        
        state = await self._get_page_state(tab_id)
        state["links"] = links
        state["total_links"] = len(links)
        return state
    
    def check_headers(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._check_headers(tab_id))
    
    async def _check_headers(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id
        
        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")
        
        page = self.pages[tab_id]
        
        # Get page URL and make a fetch request to analyze headers
        url = page.url
        
        header_check = await page.evaluate("""
            async (url) => {
                try {
                    const response = await fetch(url, { method: 'HEAD' });
                    const headers = {};
                    response.headers.forEach((value, key) => {
                        headers[key.toLowerCase()] = value;
                    });
                    return { headers: headers, status: response.status };
                } catch (e) {
                    return { headers: {}, status: 0, error: e.message };
                }
            }
        """, url)
        
        headers = header_check.get("headers", {})
        issues = []
        
        # Security header checks
        security_headers = {
            "strict-transport-security": {
                "severity": "medium",
                "message": "Missing Strict-Transport-Security header (HSTS)"
            },
            "x-content-type-options": {
                "severity": "low",
                "message": "Missing X-Content-Type-Options header"
            },
            "x-frame-options": {
                "severity": "medium",
                "message": "Missing X-Frame-Options header (clickjacking protection)"
            },
            "content-security-policy": {
                "severity": "medium",
                "message": "Missing Content-Security-Policy header"
            },
            "x-xss-protection": {
                "severity": "low",
                "message": "Missing X-XSS-Protection header"
            },
            "referrer-policy": {
                "severity": "low",
                "message": "Missing Referrer-Policy header"
            },
            "permissions-policy": {
                "severity": "low",
                "message": "Missing Permissions-Policy header"
            }
        }
        
        for header, info in security_headers.items():
            if header not in headers:
                issues.append({
                    "severity": info["severity"],
                    "type": "missing_header",
                    "header": header,
                    "message": info["message"]
                })
        
        # Check for information disclosure
        disclosure_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
        for header in disclosure_headers:
            if header in headers:
                issues.append({
                    "severity": "info",
                    "type": "information_disclosure",
                    "header": header,
                    "value": headers[header],
                    "message": f"Server discloses {header}: {headers[header]}"
                })
        
        state = await self._get_page_state(tab_id)
        state["headers"] = headers
        state["issues"] = issues
        state["security_score"] = max(0, 100 - (len(issues) * 10))  # Simple score
        return state
    
    def screenshot_element(self, selector: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._screenshot_element(selector, tab_id))
    
    async def _screenshot_element(self, selector: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id
        
        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")
        
        page = self.pages[tab_id]
        
        try:
            element = await page.query_selector(selector)
            if not element:
                raise ValueError(f"Element not found: {selector}")
            
            screenshot_bytes = await element.screenshot(type="png")
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to screenshot element: {e}") from e
        
        state = await self._get_page_state(tab_id)
        state["element_screenshot"] = screenshot_b64
        state["selector"] = selector
        return state
