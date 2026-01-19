"""LLM module for Strix - Direct HTTP-based LLM client."""

# Core LLM classes (HTTP-based, no LiteLLM)
from strix.llm.config import LLMConfig
from strix.llm.llm import LLM, LLMRequestFailedError, LLMResponse, RequestStats

# Direct HTTP client for simple usage
from strix.llm.http_client import (
    LLMClient,
    chat,
    get_llm_client,
    stream_chat,
)

__all__ = [
    # Core LLM classes
    "LLM",
    "LLMConfig",
    "LLMRequestFailedError",
    "LLMResponse",
    "RequestStats",
    # HTTP client
    "LLMClient",
    "chat",
    "get_llm_client",
    "stream_chat",
]
