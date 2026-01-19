"""
HTTP-based LLM Client for CLIProxyAPI.

This module provides a direct HTTP client for interacting with CLIProxyAPI,
replacing LiteLLM with native HTTP requests for better control and simplicity.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Generator

import requests


logger = logging.getLogger(__name__)


class LLMClient:
    """Direct HTTP client for OpenAI-compatible LLM APIs."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout: int = 300,
        max_retries: int = 5,
        retry_delay: float = 1.0,
    ):
        """Initialize the LLM client.

        Args:
            base_url: API base URL (default: from env CLIPROXY_ENDPOINT or LLM_API_BASE)
            api_key: API key (default: from env OPENAI_API_KEY, can be dummy for CLIProxyAPI)
            model: Model name (default: from env STRIX_LLM)
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Initial delay between retries (exponential backoff)
        """
        self.base_url = (
            base_url
            or os.getenv("CLIPROXY_ENDPOINT")
            or os.getenv("LLM_API_BASE")
            or os.getenv("OPENAI_API_BASE")
            or "http://127.0.0.1:8317/v1"
        )
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "sk-dummy")
        self.model = model or os.getenv("STRIX_LLM", "qwen3-coder-plus")
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        # Clean up model name (remove provider prefix like "openai/")
        if "/" in self.model:
            self.model = self.model.split("/", 1)[1]

        # Ensure base_url doesn't end with /v1 if it's already there
        self.base_url = self.base_url.rstrip("/")
        if not self.base_url.endswith("/v1"):
            self.base_url = f"{self.base_url}/v1"

    def _get_headers(self) -> dict[str, str]:
        """Get request headers."""
        headers = {"Content-Type": "application/json"}
        
        # Only add Authorization header if API key is real (not dummy)
        # CLIProxyAPI doesn't require auth, so skip for local/dummy keys
        if self.api_key and not self.api_key.startswith("sk-dummy"):
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        return headers

    def _make_request(
        self,
        endpoint: str,
        payload: dict[str, Any],
        stream: bool = False,
    ) -> requests.Response | Generator[str, None, None]:
        """Make an HTTP request with retry logic."""
        url = f"{self.base_url}/{endpoint}"

        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    url,
                    headers=self._get_headers(),
                    json=payload,
                    timeout=self.timeout,
                    stream=stream,
                )

                if response.status_code == 200:
                    if stream:
                        return self._handle_stream(response)
                    return response

                # Handle rate limiting
                if response.status_code in (429, 503):
                    delay = self.retry_delay * (2 ** attempt)
                    logger.warning(
                        f"Rate limited (attempt {attempt + 1}/{self.max_retries}). "
                        f"Waiting {delay:.1f}s..."
                    )
                    time.sleep(delay)
                    continue

                # Handle server errors
                if response.status_code >= 500:
                    delay = self.retry_delay * (2 ** attempt)
                    logger.warning(
                        f"Server error {response.status_code} "
                        f"(attempt {attempt + 1}/{self.max_retries}). "
                        f"Waiting {delay:.1f}s..."
                    )
                    time.sleep(delay)
                    continue

                # Client errors should not be retried
                response.raise_for_status()

            except requests.exceptions.Timeout:
                delay = self.retry_delay * (2 ** attempt)
                logger.warning(
                    f"Request timeout (attempt {attempt + 1}/{self.max_retries}). "
                    f"Waiting {delay:.1f}s..."
                )
                time.sleep(delay)
                continue

            except requests.exceptions.ConnectionError as e:
                delay = self.retry_delay * (2 ** attempt)
                logger.warning(
                    f"Connection error: {e} (attempt {attempt + 1}/{self.max_retries}). "
                    f"Waiting {delay:.1f}s..."
                )
                time.sleep(delay)
                continue

        raise RuntimeError(f"Failed after {self.max_retries} attempts")

    def _handle_stream(
        self, response: requests.Response
    ) -> Generator[str, None, None]:
        """Handle streaming response."""
        for line in response.iter_lines():
            if line:
                line_str = line.decode("utf-8")
                if line_str.startswith("data: "):
                    data = line_str[6:]
                    if data == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data)
                        if choices := chunk.get("choices"):
                            if delta := choices[0].get("delta"):
                                if content := delta.get("content"):
                                    yield content
                    except json.JSONDecodeError:
                        continue

    def chat_completion(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any] | Generator[str, None, None]:
        """Send a chat completion request.

        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model to use (overrides default)
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            stream: Whether to stream the response
            **kwargs: Additional parameters to pass to the API

        Returns:
            If stream=False: Full response dict
            If stream=True: Generator yielding content chunks
        """
        payload = {
            "model": model or self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": stream,
        }

        if max_tokens:
            payload["max_tokens"] = max_tokens

        # Add any extra parameters (but filter out unsupported ones)
        supported_params = {
            "top_p", "n", "stop", "presence_penalty",
            "frequency_penalty", "logit_bias", "user",
        }
        for key, value in kwargs.items():
            if key in supported_params and value is not None:
                payload[key] = value

        result = self._make_request("chat/completions", payload, stream=stream)

        if stream:
            return result

        return result.json()

    def list_models(self) -> list[str]:
        """List available models."""
        try:
            response = requests.get(
                f"{self.base_url}/models",
                headers=self._get_headers(),
                timeout=30,
            )
            if response.status_code == 200:
                data = response.json()
                return [m["id"] for m in data.get("data", [])]
            return []
        except requests.RequestException:
            return []

    def health_check(self) -> bool:
        """Check if the API is available."""
        try:
            models = self.list_models()
            return len(models) > 0
        except Exception:
            return False


# Convenience function for simple usage
def get_llm_client() -> LLMClient:
    """Get a configured LLM client instance."""
    return LLMClient()


def chat(
    messages: list[dict[str, str]],
    model: str | None = None,
    **kwargs: Any,
) -> str:
    """Simple chat completion function.

    Args:
        messages: List of message dicts
        model: Optional model override
        **kwargs: Additional parameters

    Returns:
        The assistant's response content
    """
    client = get_llm_client()
    response = client.chat_completion(messages, model=model, **kwargs)
    return response["choices"][0]["message"]["content"]


def stream_chat(
    messages: list[dict[str, str]],
    model: str | None = None,
    **kwargs: Any,
) -> Generator[str, None, None]:
    """Stream a chat completion.

    Args:
        messages: List of message dicts
        model: Optional model override
        **kwargs: Additional parameters

    Yields:
        Content chunks as they arrive
    """
    client = get_llm_client()
    yield from client.chat_completion(messages, model=model, stream=True, **kwargs)
