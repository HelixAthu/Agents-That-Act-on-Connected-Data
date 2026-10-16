"""Provider-neutral LLM adapter dataclasses and session protocol."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class LLMError(Exception):
    """Exception raised for unrecoverable LLM API errors."""



@dataclass
class ToolSpec:
    """Specification of an MCP tool exposed to the LLM via JSON schema."""

    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class ToolCall:
    """A tool invocation requested by the model turn."""

    id: str
    name: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    """A tool execution outcome sent back to the model."""

    call_id: str
    name: str
    content: dict[str, Any]
    is_error: bool = False


@dataclass
class LLMTurn:
    """A single turn response from the model containing thought text and tool calls."""

    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMSession(Protocol):
    """Protocol for provider-neutral LLM conversation sessions that manage their own history."""

    async def send_user(self, text: str) -> LLMTurn:
        """Send a user message to the model and return the model's turn response."""
        ...

    async def send_tool_results(self, results: list[ToolResult]) -> LLMTurn:
        """Send tool execution results back to the model and return the subsequent turn response."""
        ...
