"""Optional Anthropic client adapter implementing LLMSession protocol."""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any

from backend.llm.base import LLMError, LLMSession, LLMTurn, ToolCall, ToolResult, ToolSpec

logger: logging.Logger = logging.getLogger(__name__)


class AnthropicSession(LLMSession):
    """LLMSession implementation using Anthropic Messages API."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-3-5-sonnet-20241022",
        system: str = "",
        tools: list[ToolSpec] | None = None,
    ) -> None:
        try:
            import anthropic
        except ImportError as err:
            raise LLMError(
                "The 'anthropic' package is not installed. Install with 'pip install anthropic' to use AnthropicSession."
            ) from err

        key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        if not key:
            raise LLMError("ANTHROPIC_API_KEY must be set to initialize AnthropicSession.")

        self.client = anthropic.AsyncAnthropic(api_key=key)
        self.model = model
        self.system = system
        self.tools = [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in (tools or [])
        ]
        self.messages: list[dict[str, Any]] = []

    async def send_user(self, text: str) -> LLMTurn:
        """Send a user message and return the model's turn response."""
        self.messages.append({"role": "user", "content": text})
        return await self._generate()

    async def send_tool_results(self, results: list[ToolResult]) -> LLMTurn:
        """Send tool results back to Anthropic in role='user' content blocks."""
        content_blocks: list[dict[str, Any]] = []
        for r in results:
            content_blocks.append({
                "type": "tool_result",
                "tool_use_id": r.call_id,
                "content": str(r.content),
                "is_error": r.is_error,
            })
        self.messages.append({"role": "user", "content": content_blocks})
        return await self._generate()

    async def _generate(self) -> LLMTurn:
        """Call Anthropic messages.create and translate response to LLMTurn."""
        try:
            resp = await self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=self.system,
                messages=self.messages,
                tools=self.tools if self.tools else None,
            )
            # Append assistant message to history
            self.messages.append({"role": "assistant", "content": resp.content})

            text_parts: list[str] = [
                b.text for b in resp.content if getattr(b, "type", "") == "text"
            ]
            calls: list[ToolCall] = [
                ToolCall(
                    id=getattr(b, "id", f"call-{uuid.uuid4().hex[:8]}"),
                    name=b.name,
                    args=dict(b.input or {}),
                )
                for b in resp.content
                if getattr(b, "type", "") == "tool_use"
            ]

            return LLMTurn(text="".join(text_parts), tool_calls=calls)
        except Exception as err:
            logger.exception("Anthropic API error")
            raise LLMError(f"Anthropic API call failed: {err}") from err
