"""Gemini 3 LLM adapter implementing LLMSession protocol using google-genai."""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from typing import Any

from google import genai
from google.genai import types

from backend.llm.base import LLMError, LLMSession, LLMTurn, ToolCall, ToolResult, ToolSpec

logger: logging.Logger = logging.getLogger(__name__)

SUPPORTED_THINKING_LEVELS: set[str] = {"low", "medium", "high"}


class GeminiSession(LLMSession):
    """LLM session managing conversation history and function calls with Gemini 3."""

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-3.8-flash",
        thinking_level: str = "low",
        system: str = "",
        tools: list[ToolSpec] | None = None,
        timeout_s: float = 60.0,
        client: genai.Client | None = None,
    ) -> None:
        if thinking_level == "minimal":
            raise ValueError(
                "thinking_level='minimal' is not supported by Gemini 3. Must be 'low', 'medium', or 'high'."
            )
        if thinking_level not in SUPPORTED_THINKING_LEVELS:
            raise ValueError(
                f"Invalid thinking_level '{thinking_level}'. Must be one of: {sorted(SUPPORTED_THINKING_LEVELS)}"
            )

        self.model: str = model
        self.thinking_level: str = thinking_level
        self.timeout_s: float = timeout_s
        self.client: genai.Client = client or genai.Client(api_key=api_key)

        tool_declarations: list[types.FunctionDeclaration] = []
        for t in tools or []:
            tool_declarations.append(
                types.FunctionDeclaration(
                    name=t.name,
                    description=t.description,
                    parameters_json_schema=t.input_schema,
                )
            )

        thinking_cfg: types.ThinkingConfig
        if "3" in model or "flash-thinking" in model:
            thinking_cfg = types.ThinkingConfig(thinking_level=thinking_level)
        else:
            budget_map: dict[str, int] = {"low": 1024, "medium": 2048, "high": 4096}
            thinking_cfg = types.ThinkingConfig(thinking_budget=budget_map.get(thinking_level, 1024))

        self.config: types.GenerateContentConfig = types.GenerateContentConfig(
            system_instruction=system,
            tools=[types.Tool(function_declarations=tool_declarations)] if tool_declarations else None,
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            thinking_config=thinking_cfg,
        )
        self.contents: list[types.Content] = []

    async def send_user(self, text: str) -> LLMTurn:
        """Send a user message part and return the model's turn response."""
        user_content = types.Content(role="user", parts=[types.Part.from_text(text=text)])
        self.contents.append(user_content)
        return await self._generate()

    async def send_tool_results(self, results: list[ToolResult]) -> LLMTurn:
        """Send all function execution responses in one Content message preserving call order."""
        parts: list[types.Part] = []
        for r in results:
            response_payload: dict[str, Any] = {"error": r.content} if r.is_error else {"output": r.content}
            parts.append(
                types.Part.from_function_response(
                    name=r.name,
                    response=response_payload,
                )
            )

        results_content = types.Content(role="user", parts=parts)
        self.contents.append(results_content)
        return await self._generate()

    async def _generate(self) -> LLMTurn:
        """Invoke generate_content with retries on 429/5xx, no retry on 400, and timeout handling."""
        max_retries: int = 3
        last_error: Exception | None = None

        for attempt in range(max_retries):
            try:
                resp = await asyncio.wait_for(
                    self.client.aio.models.generate_content(
                        model=self.model,
                        contents=self.contents,
                        config=self.config,
                    ),
                    timeout=self.timeout_s,
                )

                candidate = resp.candidates[0]
                content: types.Content = candidate.content
                # Append VERBATIM to history to preserve thought signatures
                self.contents.append(content)

                text_parts: list[str] = [
                    p.text for p in content.parts
                    if getattr(p, "text", None) and not getattr(p, "thought", False)
                ]
                text: str = "".join(text_parts)

                calls: list[ToolCall] = [
                    ToolCall(
                        id=f"call-{uuid.uuid4().hex[:8]}",
                        name=p.function_call.name,
                        args=dict(p.function_call.args or {}),
                    )
                    for p in content.parts
                    if getattr(p, "function_call", None)
                ]

                return LLMTurn(text=text, tool_calls=calls)

            except Exception as err:
                last_error = err
                err_str = str(err).lower()
                status_code = getattr(err, "code", getattr(err, "status_code", None))

                # Auto-fallback if the specific model variant rejects the thinking configuration
                if "thinking level is not supported" in err_str:
                    logger.warning("Thinking level unsupported for %s; falling back to thinking_budget", self.model)
                    budget_map: dict[str, int] = {"low": 1024, "medium": 2048, "high": 4096}
                    self.config.thinking_config = types.ThinkingConfig(
                        thinking_budget=budget_map.get(self.thinking_level, 1024)
                    )
                    continue

                if "thinking budget is not supported" in err_str:
                    logger.warning("Thinking budget unsupported for %s; disabling thinking_config", self.model)
                    self.config.thinking_config = None
                    continue

                # Never retry other 400 invalid argument errors
                if status_code == 400 or "400" in err_str or "invalid_argument" in err_str:
                    logger.error("Gemini API rejected request with 400 error: %s", err)
                    raise LLMError(f"Gemini API 400 Bad Request (non-retryable): {err}") from err

                is_retryable = (
                    status_code in (429, 500, 502, 503, 504)
                    or "429" in err_str
                    or "resource_exhausted" in err_str
                    or "503" in err_str
                    or "rate" in err_str
                )

                if not is_retryable or attempt == max_retries - 1:
                    logger.error("Gemini call failed on attempt %d: %s", attempt + 1, err)
                    raise LLMError(f"Gemini API call failed: {err}") from err

                backoff_s: float = float(2 ** attempt)
                delay_match = re.search(r"retry in ([\d\.]+)s", err_str)
                if delay_match:
                    try:
                        backoff_s = min(float(delay_match.group(1)) + 0.5, 15.0)
                    except ValueError:
                        pass
                logger.warning(
                    "Gemini API returned retryable error (%s). Retrying in %.1fs (attempt %d/%d)...",
                    err,
                    backoff_s,
                    attempt + 1,
                    max_retries,
                )
                await asyncio.sleep(backoff_s)

        raise LLMError(f"Gemini API failed after retries: {last_error}")
