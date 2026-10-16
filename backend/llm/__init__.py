"""LLM provider session factory and public interface."""

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv

load_dotenv()

from backend.llm.base import LLMError, LLMSession, LLMTurn, ToolCall, ToolResult, ToolSpec
from backend.llm.fake_client import FakeSession
from backend.llm.schema import assert_simple_schema, simplify_schema


def make_session(
    provider: str | None = None,
    system: str = "",
    tools: list[ToolSpec] | None = None,
    **kwargs: Any,
) -> LLMSession:
    """Factory creating an LLMSession for the configured provider (gemini, fake, or anthropic)."""
    chosen_provider: str = (provider or os.getenv("LLM_PROVIDER", "gemini")).strip().lower()

    # Simplify all tool schemas before passing to LLM session
    sanitized_tools: list[ToolSpec] = []
    for t in tools or []:
        simple_schema = simplify_schema(t.input_schema)
        assert_simple_schema(simple_schema)
        sanitized_tools.append(
            ToolSpec(
                name=t.name,
                description=t.description,
                input_schema=simple_schema,
            )
        )

    if chosen_provider == "gemini":
        from backend.llm.gemini_client import GeminiSession

        api_key: str = kwargs.get("api_key") or os.getenv("GEMINI_API_KEY", "")
        model: str = kwargs.get("model") or os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
        thinking_level: str = kwargs.get("thinking_level") or os.getenv("GEMINI_THINKING_LEVEL", "low")

        return GeminiSession(
            api_key=api_key,
            model=model,
            thinking_level=thinking_level,
            system=system,
            tools=sanitized_tools,
            timeout_s=kwargs.get("timeout_s", 60.0),
            client=kwargs.get("client"),
        )

    if chosen_provider in ("fake", "mock", "test"):
        return FakeSession(
            turns=kwargs.get("turns", []),
            system=system,
            tools=sanitized_tools,
        )

    if chosen_provider == "anthropic":
        from backend.llm.anthropic_client import AnthropicSession

        return AnthropicSession(
            api_key=kwargs.get("api_key"),
            model=kwargs.get("model", "claude-3-5-sonnet-20241022"),
            system=system,
            tools=sanitized_tools,
        )

    raise ValueError(
        f"Unsupported LLM provider '{chosen_provider}'. Must be 'gemini', 'fake', or 'anthropic'."
    )


__all__ = [
    "LLMError",
    "LLMSession",
    "LLMTurn",
    "ToolCall",
    "ToolResult",
    "ToolSpec",
    "assert_simple_schema",
    "make_session",
    "simplify_schema",
]
