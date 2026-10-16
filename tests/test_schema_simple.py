"""Tests for tool schema simplification and validation against all 11 MCP tools."""

from typing import Any

import pytest

from backend.llm.schema import assert_simple_schema, simplify_schema
from backend.mcp_bridge import MCPBridge


def test_simplify_schema_handles_titles_defaults_and_defs() -> None:
    """Assert simplify_schema strips title/default and preserves required fields."""
    raw_schema: dict[str, Any] = {
        "$defs": {
            "ActionType": {
                "title": "ActionType",
                "type": "string",
                "enum": ["ISOLATE_NODE", "REVOKE_ROLE"],
            }
        },
        "title": "ProposeContainmentInput",
        "type": "object",
        "properties": {
            "action": {"$ref": "#/$defs/ActionType"},
            "target_id": {
                "title": "Target ID",
                "type": "string",
                "default": "svc-default",
            },
            "hops": {
                "title": "Hops",
                "type": "integer",
                "minimum": 1,
                "maximum": 6,
                "default": 3,
            },
            "notes": {
                "title": "Notes",
                "anyOf": [{"type": "string"}, {"type": "null"}],
                "description": "Optional notes",
            },
        },
        "required": ["action", "target_id"],
    }

    simplified = simplify_schema(raw_schema)
    assert_simple_schema(simplified)

    assert "title" not in simplified
    assert "$defs" not in simplified
    props = simplified["properties"]
    assert "title" not in props["target_id"]
    assert "default" not in props["target_id"]
    assert props["action"]["enum"] == ["ISOLATE_NODE", "REVOKE_ROLE"]
    assert props["hops"]["minimum"] == 1
    assert props["hops"]["maximum"] == 6
    assert props["notes"]["type"] == "string"
    assert props["notes"]["description"] == "Optional notes"


def test_assert_simple_schema_raises_on_illegal_keys() -> None:
    """Assert assert_simple_schema rejects schemas containing forbidden keys."""
    invalid_schema: dict[str, Any] = {
        "type": "object",
        "title": "ShouldFail",
        "properties": {"id": {"type": "string"}},
    }
    with pytest.raises(ValueError, match="prohibited key 'title'"):
        assert_simple_schema(invalid_schema)


def test_all_11_mcp_tools_simplify_and_pass_assert_simple_schema() -> None:
    """Assert all 11 real MCP tools produce schemas accepted by assert_simple_schema."""
    bridge = MCPBridge()
    tools = bridge.list_tools()
    assert len(tools) == 11

    for tool in tools:
        simplified = simplify_schema(tool.input_schema)
        # Verify schema passes strict assertion
        assert_simple_schema(simplified)
        assert "type" in simplified
        assert "properties" in simplified
