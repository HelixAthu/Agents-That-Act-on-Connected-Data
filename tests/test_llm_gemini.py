"""Unit tests for GeminiSession with a stubbed genai.Client asserting T8a contract rules."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from google.genai import types

from backend.llm.base import LLMError, ToolResult
from backend.llm.gemini_client import GeminiSession


def make_mock_client(return_content: types.Content | None = None) -> MagicMock:
    """Helper creating a stubbed genai.Client with an async generate_content method."""
    mock_client = MagicMock()
    mock_aio = MagicMock()
    mock_models = MagicMock()

    content = return_content or types.Content(
        role="model",
        parts=[types.Part.from_text(text="Model response text")],
    )
    mock_response = MagicMock()
    mock_candidate = MagicMock()
    mock_candidate.content = content
    mock_response.candidates = [mock_candidate]

    mock_models.generate_content = AsyncMock(return_value=mock_response)
    mock_aio.models = mock_models
    mock_client.aio = mock_aio
    return mock_client


@pytest.mark.asyncio
async def test_gemini_content_verbatim_identity_check() -> None:
    """Assert the model's exact Content object is appended to history unchanged (identity check)."""
    model_content = types.Content(
        role="model",
        parts=[types.Part.from_text(text="Verbatim model thought and answer")],
    )
    stub_client = make_mock_client(return_content=model_content)

    session = GeminiSession(
        api_key="test-api-key",
        client=stub_client,
        thinking_level="low",
    )

    turn = await session.send_user("What is the status?")
    assert turn.text == "Verbatim model thought and answer"

    # Strict object identity check
    assert session.contents[-1] is model_content


@pytest.mark.asyncio
async def test_gemini_multiple_function_calls_produce_single_content_same_order() -> None:
    """Assert multiple tool results produce one user Content object preserving order."""
    stub_client = make_mock_client()
    session = GeminiSession(
        api_key="test-api-key",
        client=stub_client,
        thinking_level="low",
    )

    results = [
        ToolResult(call_id="call-01", name="tool_alpha", content={"data": 123}),
        ToolResult(call_id="call-02", name="tool_beta", content={"error": "not found"}, is_error=True),
    ]

    await session.send_tool_results(results)

    # History contains: user message with tool results, then model response
    user_results_content = session.contents[-2]
    assert user_results_content.role == "user"
    assert len(user_results_content.parts) == 2

    # Verify first part
    p1 = user_results_content.parts[0]
    assert p1.function_response.name == "tool_alpha"
    assert p1.function_response.response == {"output": {"data": 123}}

    # Verify second part preserving exact order and error wrap
    p2 = user_results_content.parts[1]
    assert p2.function_response.name == "tool_beta"
    assert p2.function_response.response == {"error": {"error": "not found"}}


@pytest.mark.asyncio
async def test_gemini_retries_on_429_and_aborts_immediately_on_400() -> None:
    """Assert retry happens on simulated 429 and does not happen on simulated 400."""
    # 1. Test 429 retry
    stub_client_429 = MagicMock()
    mock_models_429 = MagicMock()

    class RateLimitError(Exception):
        code = 429

    success_content = types.Content(role="model", parts=[types.Part.from_text(text="Success after retry")])
    mock_resp = MagicMock()
    mock_cand = MagicMock()
    mock_cand.content = success_content
    mock_resp.candidates = [mock_cand]

    # First attempt raises 429, second attempt succeeds
    mock_models_429.generate_content = AsyncMock(
        side_effect=[RateLimitError("429 Resource Exhausted"), mock_resp]
    )
    stub_client_429.aio.models = mock_models_429

    session_429 = GeminiSession(
        api_key="test-api-key",
        client=stub_client_429,
        thinking_level="low",
    )
    turn = await session_429.send_user("Retry check")
    assert turn.text == "Success after retry"
    assert mock_models_429.generate_content.call_count == 2

    # 2. Test 400 non-retry
    stub_client_400 = MagicMock()
    mock_models_400 = MagicMock()

    class BadRequestError(Exception):
        code = 400

    mock_models_400.generate_content = AsyncMock(
        side_effect=BadRequestError("400 Invalid Argument: thought signature missing")
    )
    stub_client_400.aio.models = mock_models_400

    session_400 = GeminiSession(
        api_key="test-api-key",
        client=stub_client_400,
        thinking_level="low",
    )

    with pytest.raises(LLMError, match="400 Bad Request"):
        await session_400.send_user("Fail fast check")

    # Exactly 1 call was made (no retry)
    assert mock_models_400.generate_content.call_count == 1


def test_thinking_level_minimal_rejected_by_config_validation() -> None:
    """Assert thinking_level='minimal' is rejected before any API call is attempted."""
    with pytest.raises(ValueError, match="thinking_level='minimal' is not supported"):
        GeminiSession(api_key="test-key", thinking_level="minimal")

    with pytest.raises(ValueError, match="Invalid thinking_level 'unsupported'"):
        GeminiSession(api_key="test-key", thinking_level="unsupported")
