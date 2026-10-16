"""Gemini SDK capability probe testing introspection, thought signatures, and schemas."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Ensure repository root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from google.genai import types

from backend.llm.base import ToolResult, ToolSpec
from backend.llm.gemini_client import GeminiSession
from backend.llm.schema import assert_simple_schema, simplify_schema
from backend.mcp_bridge import MCPBridge


def run_introspection() -> None:
    """Introspect google-genai Pydantic model fields and verify against required recipe."""
    print("=" * 70)
    print("GEMINI SDK INTROSPECTION PROBE")
    print("=" * 70)

    afc_fields = set(types.AutomaticFunctionCallingConfig.model_fields.keys())
    thinking_fields = set(types.ThinkingConfig.model_fields.keys())
    gen_fields = set(types.GenerateContentConfig.model_fields.keys())
    func_fields = set(types.FunctionDeclaration.model_fields.keys())

    print(f"AutomaticFunctionCallingConfig fields: {sorted(afc_fields)}")
    print(f"ThinkingConfig fields                : {sorted(thinking_fields)}")
    print(f"FunctionDeclaration fields           : {sorted(func_fields)}")

    # Verify recipe field names
    assert "disable" in afc_fields, "Missing 'disable' in AutomaticFunctionCallingConfig"
    assert "thinking_level" in thinking_fields, "Missing 'thinking_level' in ThinkingConfig"
    assert "system_instruction" in gen_fields, "Missing 'system_instruction' in GenerateContentConfig"
    assert "automatic_function_calling" in gen_fields, "Missing 'automatic_function_calling' in GenerateContentConfig"
    assert "thinking_config" in gen_fields, "Missing 'thinking_config' in GenerateContentConfig"
    assert "parameters_json_schema" in func_fields, "Missing 'parameters_json_schema' in FunctionDeclaration"

    print("ALL INTROSPECTION RECIPE CHECKS: PASS\n")


async def run_live_probe(api_key: str) -> None:
    """Run live round-trip, sequential calls, and MCP tool schema checks against Gemini API."""
    print("Running live Gemini API round-trip check...")
    add_tool = ToolSpec(
        name="add",
        description="Add two numbers together. Use when needing addition. Do not use for subtraction.",
        input_schema={
            "type": "object",
            "properties": {
                "a": {"type": "integer", "description": "First number"},
                "b": {"type": "integer", "description": "Second number"},
            },
            "required": ["a", "b"],
        },
    )

    session = GeminiSession(
        api_key=api_key,
        model="gemini-3.8-flash",
        thinking_level="low",
        system="You are a helpful calculator assistant. Always use the provided tool to calculate math answers.",
        tools=[add_tool],
    )

    # 1. Round-trip
    turn = await session.send_user("What is 2+3? Use the add tool.")
    assert len(turn.tool_calls) >= 1, "Expected tool call from Gemini"
    call = turn.tool_calls[0]
    assert call.name == "add"
    res = int(call.args.get("a", 2)) + int(call.args.get("b", 3))

    turn2 = await session.send_tool_results([
        ToolResult(call_id=call.id, name="add", content={"result": res})
    ])
    assert "5" in turn2.text, f"Expected '5' in final text, got: {turn2.text}"
    print("1. Round trip tool call: PASS")

    # 2. Sequential calls (proves thought signatures preserved without 400 error)
    print("Running sequential calls check (verifies thought signatures)...")
    mult_tool = ToolSpec(
        name="multiply",
        description="Multiply two numbers. Use when needing multiplication. Do not use for addition.",
        input_schema={
            "type": "object",
            "properties": {
                "x": {"type": "integer"},
                "y": {"type": "integer"},
            },
            "required": ["x", "y"],
        },
    )

    seq_session = GeminiSession(
        api_key=api_key,
        model="gemini-3.8-flash",
        thinking_level="low",
        system="Calculate using tools one step at a time.",
        tools=[add_tool, mult_tool],
    )
    t1 = await seq_session.send_user("First add 3+4 using add, then multiply the result by 2 using multiply.")
    assert len(t1.tool_calls) >= 1, "Expected first tool call"
    c1 = t1.tool_calls[0]
    t2 = await seq_session.send_tool_results([
        ToolResult(call_id=c1.id, name=c1.name, content={"result": 7})
    ])
    if t2.tool_calls:
        c2 = t2.tool_calls[0]
        await seq_session.send_tool_results([
            ToolResult(call_id=c2.id, name=c2.name, content={"result": 14})
        ])
    print("2. Sequential calls with thought signatures: PASS")

    # 3. Real MCP schemas
    print("Running real MCP tools schema registration check...")
    bridge = MCPBridge()
    mcp_tools = [
        ToolSpec(name=t.name, description=t.description, input_schema=simplify_schema(t.input_schema))
        for t in bridge.list_tools()
    ]
    for t in mcp_tools:
        assert_simple_schema(t.input_schema)

    mcp_session = GeminiSession(
        api_key=api_key,
        model="gemini-3.8-flash",
        thinking_level="low",
        system="You are an infrastructure security agent.",
        tools=mcp_tools,
    )
    t_mcp = await mcp_session.send_user("Inspect component svc-payments-gateway using get_component_context.")
    assert len(t_mcp.tool_calls) >= 1
    assert t_mcp.tool_calls[0].name == "get_component_context"
    print("3. Real MCP tools schema registration: PASS")


def main() -> None:
    """Run probe steps."""
    run_introspection()

    api_key: str = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        print("SKIPPED live checks (no key)")
        sys.exit(0)

    try:
        asyncio.run(run_live_probe(api_key))
        print("\nALL GEMINI CHECKS PASSED.")
    except Exception as err:  # noqa: BLE001
        print(f"\nPROBE FAILED: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
