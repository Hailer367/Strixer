"""
LLM module for Strix - Direct HTTP-based LLM client.

This module provides an async LLM client using direct HTTP requests
to OpenAI-compatible APIs, replacing LiteLLM for simplicity.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import aiohttp
from jinja2 import Environment, FileSystemLoader, select_autoescape

from strix.config import Config
from strix.llm.config import LLMConfig
from strix.llm.memory_compressor import MemoryCompressor
from strix.llm.utils import (
    _truncate_to_first_function,
    fix_incomplete_tool_call,
    parse_tool_invocations,
)
from strix.skills import load_skills
from strix.tools import get_tools_prompt
from strix.utils.resource_paths import get_strix_resource_path


logger = logging.getLogger(__name__)


class LLMRequestFailedError(Exception):
    def __init__(self, message: str, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details


@dataclass
class LLMResponse:
    content: str
    tool_invocations: list[dict[str, Any]] | None = None
    thinking_blocks: list[dict[str, Any]] | None = None


@dataclass
class RequestStats:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    cost: float = 0.0
    requests: int = 0

    def to_dict(self) -> dict[str, int | float]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_tokens": self.cached_tokens,
            "cost": round(self.cost, 4),
            "requests": self.requests,
        }


class LLM:
    """Direct HTTP-based LLM client for OpenAI-compatible APIs."""

    def __init__(self, config: LLMConfig, agent_name: str | None = None):
        self.config = config
        self.agent_name = agent_name
        self.agent_id: str | None = None
        self._total_stats = RequestStats()
        self.memory_compressor = MemoryCompressor(model_name=config.model_name)
        self.system_prompt = self._load_system_prompt(agent_name)

        # API configuration
        self.api_base = (
            Config.get("cliproxy_endpoint")
            or Config.get("llm_api_base")
            or Config.get("openai_api_base")
            or "http://127.0.0.1:8317/v1"
        )
        self.api_key = Config.get("llm_api_key") or Config.get("openai_api_key") or "sk-dummy"

        # Clean model name (remove provider prefix like "openai/")
        self.model_name = config.model_name
        if "/" in self.model_name:
            self.model_name = self.model_name.split("/", 1)[1]

        # Ensure base URL format
        self.api_base = self.api_base.rstrip("/")
        if not self.api_base.endswith("/v1"):
            self.api_base = f"{self.api_base}/v1"

        # Retry configuration
        self.max_retries = int(Config.get("strix_llm_max_retries") or "5")
        self.retry_delay = 1.0

        reasoning = Config.get("strix_reasoning_effort")
        if reasoning:
            self._reasoning_effort = reasoning
        elif config.scan_mode == "quick":
            self._reasoning_effort = "medium"
        else:
            self._reasoning_effort = "high"

    def _load_system_prompt(self, agent_name: str | None) -> str:
        if not agent_name:
            return ""

        try:
            prompt_dir = get_strix_resource_path("agents", agent_name)
            skills_dir = get_strix_resource_path("skills")
            env = Environment(
                loader=FileSystemLoader([prompt_dir, skills_dir]),
                autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
            )

            skills_to_load = [
                *list(self.config.skills or []),
                f"scan_modes/{self.config.scan_mode}",
            ]
            skill_content = load_skills(skills_to_load, env)
            env.globals["get_skill"] = lambda name: skill_content.get(name, "")

            result = env.get_template("system_prompt.jinja").render(
                get_tools_prompt=get_tools_prompt,
                loaded_skill_names=list(skill_content.keys()),
                **skill_content,
            )
            return str(result)
        except Exception:  # noqa: BLE001
            return ""

    def set_agent_identity(self, agent_name: str | None, agent_id: str | None) -> None:
        if agent_name:
            self.agent_name = agent_name
        if agent_id:
            self.agent_id = agent_id

    async def generate(
        self, conversation_history: list[dict[str, Any]]
    ) -> AsyncIterator[LLMResponse]:
        messages = self._prepare_messages(conversation_history)

        for attempt in range(self.max_retries + 1):
            try:
                async for response in self._stream(messages):
                    yield response
                return  # noqa: TRY300
            except Exception as e:  # noqa: BLE001
                if attempt >= self.max_retries or not self._should_retry(e):
                    self._raise_error(e)
                wait = min(10, 2 * (2**attempt))
                logger.warning(f"LLM request failed (attempt {attempt + 1}), retrying in {wait}s: {e}")
                await asyncio.sleep(wait)

    async def _stream(self, messages: list[dict[str, Any]]) -> AsyncIterator[LLMResponse]:
        accumulated = ""
        self._total_stats.requests += 1

        payload = {
            "model": self.model_name,
            "messages": messages,
            "stream": True,
            "timeout": self.config.timeout,
        }

        headers = {"Content-Type": "application/json"}
        
        # Only add Authorization header if API key is real (not dummy)
        # CLIProxyAPI doesn't require auth, so skip for local/dummy keys
        if self.api_key and not self.api_key.startswith("sk-dummy"):
            headers["Authorization"] = f"Bearer {self.api_key}"

        url = f"{self.api_base}/chat/completions"

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                headers=headers,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise LLMRequestFailedError(
                        f"API request failed with status {response.status}",
                        error_text
                    )

                async for line in response.content:
                    if line:
                        line_str = line.decode("utf-8").strip()
                        if line_str.startswith("data: "):
                            data = line_str[6:]
                            if data == "[DONE]":
                                break
                            try:
                                chunk = json.loads(data)
                                if choices := chunk.get("choices"):
                                    if delta := choices[0].get("delta"):
                                        if content := delta.get("content"):
                                            accumulated += content
                                            if "</function>" in accumulated:
                                                accumulated = accumulated[
                                                    : accumulated.find("</function>") + len("</function>")
                                                ]
                                                yield LLMResponse(content=accumulated)
                                                break
                                            yield LLMResponse(content=accumulated)

                                # Track usage if available
                                if usage := chunk.get("usage"):
                                    self._total_stats.input_tokens += usage.get("prompt_tokens", 0)
                                    self._total_stats.output_tokens += usage.get("completion_tokens", 0)
                            except json.JSONDecodeError:
                                continue

        accumulated = fix_incomplete_tool_call(_truncate_to_first_function(accumulated))
        yield LLMResponse(
            content=accumulated,
            tool_invocations=parse_tool_invocations(accumulated),
            thinking_blocks=None,
        )

    def _prepare_messages(self, conversation_history: list[dict[str, Any]]) -> list[dict[str, Any]]:
        messages = [{"role": "system", "content": self.system_prompt}]

        if self.agent_name:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"\n\n<agent_identity>\n"
                        f"<meta>Internal metadata: do not echo or reference.</meta>\n"
                        f"<agent_name>{self.agent_name}</agent_name>\n"
                        f"<agent_id>{self.agent_id}</agent_id>\n"
                        f"</agent_identity>\n\n"
                    ),
                }
            )

        compressed = list(self.memory_compressor.compress_history(conversation_history))
        conversation_history.clear()
        conversation_history.extend(compressed)
        messages.extend(compressed)

        # Strip images if model doesn't support vision
        messages = self._strip_images(messages)

        return messages

    def _should_retry(self, e: Exception) -> bool:
        # Retry on connection errors, timeouts, and 5xx errors
        if isinstance(e, (aiohttp.ClientError, asyncio.TimeoutError)):
            return True
        if isinstance(e, LLMRequestFailedError):
            # Check if it's a server error (5xx) or rate limit (429)
            if e.details and ("500" in str(e.details) or "502" in str(e.details) or
                             "503" in str(e.details) or "429" in str(e.details)):
                return True
        return False

    def _raise_error(self, e: Exception) -> None:
        from strix.telemetry import posthog

        posthog.error("llm_error", type(e).__name__)
        raise LLMRequestFailedError(f"LLM request failed: {type(e).__name__}", str(e)) from e

    def _strip_images(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result = []
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, list):
                text_parts = []
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text_parts.append(item.get("text", ""))
                    elif isinstance(item, dict) and item.get("type") == "image_url":
                        text_parts.append("[Image removed - model doesn't support vision]")
                result.append({**msg, "content": "\n".join(text_parts)})
            else:
                result.append(msg)
        return result
