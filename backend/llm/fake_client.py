"""Scripted FakeSession for testing LLM agent loops without external network calls."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from backend.llm.base import LLMSession, LLMTurn, ToolResult, ToolSpec


class FakeSession(LLMSession):
    """Scripted LLMSession protocol implementation for unit testing."""

    def __init__(
        self,
        turns: list[LLMTurn | Callable[[list[ToolResult]], LLMTurn]] | None = None,
        system: str = "",
        tools: list[ToolSpec] | None = None,
    ) -> None:
        self.system: str = system
        self.tools: list[ToolSpec] = tools or []
        self._turns: list[LLMTurn | Callable[[list[ToolResult]], LLMTurn]] = list(turns or [])
        self._turn_index: int = 0
        self.history: list[dict[str, Any]] = []

    async def send_user(self, text: str) -> LLMTurn:
        """Record user message and return the next scripted turn."""
        self.history.append({"role": "user", "text": text})
        return self._next_turn([])

    async def send_tool_results(self, results: list[ToolResult]) -> LLMTurn:
        """Record tool results and return the next scripted turn."""
        self.history.append({"role": "tool_results", "results": results})
        return self._next_turn(results)

    def _next_turn(self, results: list[ToolResult]) -> LLMTurn:
        """Fetch or compute the next turn in the scripted sequence."""
        if self._turn_index >= len(self._turns):
            return LLMTurn(text="", tool_calls=[])

        turn_item = self._turns[self._turn_index]
        self._turn_index += 1

        if callable(turn_item):
            return turn_item(results)
        return turn_item
