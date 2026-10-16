"""Tests for MCPBridge tool introspection, argument normalization, and summary generation."""

from typing import Any

import pytest

from backend.mcp_bridge import MCPBridge, ToolInfo
from seed.seed_graph import seed_graph


@pytest.fixture(scope="session", autouse=True)
def setup_seed_graph() -> None:
    """Ensure graph has fresh canonical seed data before MCP bridge tests."""
    seed_graph(reset=True)


def test_bridge_list_tools_returns_all_11_spec_tools() -> None:
    """Assert bridge introspects exactly 11 tools with valid descriptions and parameter schemas."""
    bridge = MCPBridge()
    tools: list[ToolInfo] = bridge.list_tools()
    assert len(tools) == 11

    expected_tools: set[str] = {
        "get_component_context",
        "get_failure_impact",
        "find_attack_paths",
        "rank_critical_components",
        "compute_risk",
        "propose_containment",
        "execute_containment",
        "rollback_action",
        "notify_owners",
        "record_finding",
        "run_readonly_cypher",
    }
    found_names: set[str] = {t.name for t in tools}
    assert found_names == expected_tools

    for t in tools:
        assert len(t.name) > 0
        assert len(t.description) > 0
        assert "Use when:" in t.description or "Use when" in t.description
        assert isinstance(t.input_schema, dict)


def test_bridge_get_tool_lookup() -> None:
    """Assert get_tool returns ToolInfo for registered tools and None for missing tools."""
    bridge = MCPBridge()
    tool: ToolInfo | None = bridge.get_tool("compute_risk")
    assert tool is not None
    assert tool.name == "compute_risk"
    assert "target_id" in tool.input_schema.get("properties", {})

    missing: ToolInfo | None = bridge.get_tool("nonexistent_tool")
    assert missing is None


@pytest.mark.asyncio
async def test_bridge_call_with_argument_normalization() -> None:
    """Assert bridge correctly normalizes argument aliases like component_id -> id."""
    bridge = MCPBridge()

    # Call get_component_context using aliased 'component_id'
    res_ctx = await bridge.call("get_component_context", {"component_id": "svc-payments-gateway"})
    assert res_ctx["ok"] is True
    assert res_ctx["data"]["id"] == "svc-payments-gateway"

    # Call compute_risk using aliased 'id'
    res_risk = await bridge.call("compute_risk", {"id": "svc-payments-gateway"})
    assert res_risk["ok"] is True
    assert float(res_risk["data"]["risk"]) == pytest.approx(0.828, abs=0.003)

    # Call find_attack_paths using aliased 'source'
    res_paths = await bridge.call("find_attack_paths", {"source": "svc-payments-gateway", "max_hops": 6})
    assert res_paths["ok"] is True
    assert len(res_paths["data"]["paths"]) == 2

    # Call unknown tool
    res_unknown = await bridge.call("unknown_tool", {})
    assert res_unknown["ok"] is False
    assert res_unknown["error"]["code"] == "NOT_FOUND"


def test_bridge_build_tool_summary_formatting() -> None:
    """Assert deterministic summary string generation produces concise summaries under 200 characters."""
    bridge = MCPBridge()

    # Context summary
    ctx_env: dict[str, Any] = {
        "ok": True,
        "data": {
            "id": "svc-payments-gateway",
            "owners": ["team-payments"],
            "vulnerabilities": [{"id": "vuln-001"}],
            "incoming": [1, 2, 3],
            "outgoing": [1, 2, 3, 4, 5],
        },
    }
    s_ctx: str = bridge.build_tool_summary("get_component_context", {"id": "svc-payments-gateway"}, ctx_env)
    assert len(s_ctx) <= 200
    assert "svc-payments-gateway" in s_ctx
    assert "1 vulns" in s_ctx

    # Risk summary
    risk_env: dict[str, Any] = {"ok": True, "data": {"risk": 0.828}}
    s_risk: str = bridge.build_tool_summary("compute_risk", {"target_id": "svc-payments-gateway"}, risk_env)
    assert len(s_risk) <= 200
    assert "0.828" in s_risk

    # Error summary
    err_env: dict[str, Any] = {"ok": False, "error": {"code": "NOT_FOUND", "message": "Service not found"}}
    s_err: str = bridge.build_tool_summary("compute_risk", {"target_id": "missing"}, err_env)
    assert len(s_err) <= 200
    assert "NOT_FOUND" in s_err
