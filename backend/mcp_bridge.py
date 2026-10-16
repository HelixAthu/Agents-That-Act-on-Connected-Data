"""MCP bridge client providing in-process invocation, tool introspection, and summary generation."""

from __future__ import annotations

import inspect
import json
import logging
from dataclasses import dataclass
from typing import Any

from mcp_server.server import (
    ErrorCode,
    compute_risk,
    execute_containment,
    find_attack_paths,
    format_error,
    get_component_context,
    get_failure_impact,
    mcp,
    notify_owners,
    propose_containment,
    rank_critical_components,
    record_finding,
    rollback_action,
    run_readonly_cypher,
)

logger: logging.Logger = logging.getLogger(__name__)


@dataclass
class ToolInfo:
    """Metadata describing an MCP graph tool for LLM agent planning and schema generation."""

    name: str
    description: str
    input_schema: dict[str, Any]


TOOL_FUNCTION_MAP: dict[str, Any] = {
    "get_component_context": get_component_context,
    "get_failure_impact": get_failure_impact,
    "find_attack_paths": find_attack_paths,
    "rank_critical_components": rank_critical_components,
    "compute_risk": compute_risk,
    "propose_containment": propose_containment,
    "execute_containment": execute_containment,
    "rollback_action": rollback_action,
    "notify_owners": notify_owners,
    "record_finding": record_finding,
    "run_readonly_cypher": run_readonly_cypher,
}


def _normalize_tool_arguments(name: str, raw_args: dict[str, Any]) -> dict[str, Any]:
    """Normalize common argument aliases for LLM tool calling compatibility."""
    args: dict[str, Any] = dict(raw_args)

    if name == "get_component_context":
        if "id" not in args and "component_id" in args:
            args["id"] = args.pop("component_id")

    elif name == "get_failure_impact":
        if "id" not in args:
            if "component_id" in args:
                args["id"] = args.pop("component_id")
            elif "target_id" in args:
                args["id"] = args.pop("target_id")

    elif name == "find_attack_paths":
        if "source_id" not in args:
            if "source" in args:
                args["source_id"] = args.pop("source")
            elif "id" in args:
                args["source_id"] = args.pop("id")

    elif name == "compute_risk":
        if "target_id" not in args:
            if "id" in args:
                args["target_id"] = args.pop("id")
            elif "component_id" in args:
                args["target_id"] = args.pop("component_id")

    elif name in ("execute_containment", "rollback_action") and "action_id" not in args and "id" in args:
        args["action_id"] = args.pop("id")

    return args


class MCPBridge:
    """Client bridge for invoking MCP infrastructure graph tools with envelope serialization."""

    def __init__(self) -> None:
        self._tools_cache: list[ToolInfo] | None = None

    def list_tools(self) -> list[ToolInfo]:
        """List metadata and input schemas for all registered MCP graph tools."""
        if self._tools_cache is not None:
            return self._tools_cache

        tools: list[ToolInfo] = []
        for fastmcp_tool in mcp._tool_manager.list_tools():
            tools.append(
                ToolInfo(
                    name=fastmcp_tool.name,
                    description=fastmcp_tool.description or "",
                    input_schema=getattr(fastmcp_tool, "parameters", {}),
                )
            )

        self._tools_cache = tools
        return tools

    def get_tool(self, name: str) -> ToolInfo | None:
        """Lookup tool metadata by unique name."""
        for tool in self.list_tools():
            if tool.name == name:
                return tool
        return None

    async def call(self, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        """Invoke an MCP tool by name and return the deserialized response envelope."""
        tool_fn = TOOL_FUNCTION_MAP.get(name)
        if tool_fn is None:
            error_json: str = format_error(ErrorCode.NOT_FOUND, f"Tool '{name}' is not registered on MCP server")
            return json.loads(error_json)

        clean_args: dict[str, Any] = _normalize_tool_arguments(name, args or {})

        try:
            if inspect.iscoroutinefunction(tool_fn):
                raw_response: str = await tool_fn(**clean_args)
            else:
                raw_response: str = tool_fn(**clean_args)

            return json.loads(raw_response)
        except Exception as err:
            logger.exception("Bridge error invoking MCP tool '%s'", name)
            error_env: str = format_error(ErrorCode.DB_ERROR, f"Bridge invocation error for '{name}': {err}")
            return json.loads(error_env)

    @staticmethod
    def build_tool_summary(name: str, args: dict[str, Any], envelope: dict[str, Any]) -> str:
        """Build a deterministic summary string <= 200 characters from envelope results."""
        if not envelope.get("ok", False):
            error_obj: dict[str, Any] = envelope.get("error", {})
            code: str = str(error_obj.get("code", "ERROR"))
            msg: str = str(error_obj.get("message", "Tool invocation failed"))
            summary: str = f"Tool '{name}' failed [{code}]: {msg}"
            return summary[:200]

        data: dict[str, Any] = envelope.get("data", {})

        if name == "get_component_context":
            cid: str = str(data.get("id", args.get("id", "")))
            owners: list[str] = data.get("owners", [])
            vulns: list[Any] = data.get("vulnerabilities", [])
            in_deg: int = len(data.get("incoming", []))
            out_deg: int = len(data.get("outgoing", []))
            summary = (
                f"Context for {cid}: owners={owners}, {len(vulns)} vulns, "
                f"in_degree={in_deg}, out_degree={out_deg}"
            )

        elif name == "get_failure_impact":
            target: str = str(data.get("target", args.get("id", "")))
            impacted: list[Any] = data.get("impacted", [])
            cf_count: int = int(data.get("customer_facing_count", 0))
            summary = f"Failure impact for {target}: {len(impacted)} impacted services ({cf_count} customer-facing)"

        elif name == "find_attack_paths":
            src: str = str(data.get("source", args.get("source_id", "")))
            paths: list[Any] = data.get("paths", [])
            targets: set[str] = {str(p.get("target")) for p in paths if "target" in p}
            summary = f"Found {len(paths)} attack path(s) from {src} to {len(targets)} PII database(s)"

        elif name == "rank_critical_components":
            ranking: list[Any] = data.get("ranking", [])
            summary = f"Ranked top {len(ranking)} critical components by transitive dependents and PageRank"

        elif name == "compute_risk":
            risk: float = float(data.get("risk", 0.0))
            target: str = str(args.get("target_id", ""))
            summary = f"Risk evaluated for {target}: deterministic score={risk:.3f}"

        elif name == "propose_containment":
            aid: str = str(data.get("action_id", ""))
            decision: str = str(data.get("policy", {}).get("decision", ""))
            after: list[str] = data.get("simulation", {}).get("targets_after", [])
            summary = f"Proposed containment {aid}: policy={decision}, remaining attack targets={len(after)}"

        elif name == "execute_containment":
            aid = str(data.get("action_id", args.get("action_id", "")))
            status: str = str(data.get("status", "EXECUTED"))
            after = data.get("targets_after", [])
            summary = f"Executed containment {aid}: status={status}, remaining attack targets={len(after)}"

        elif name == "rollback_action":
            aid = str(data.get("action_id", args.get("action_id", "")))
            status = str(data.get("status", "ROLLED_BACK"))
            after = data.get("targets_after", [])
            summary = f"Rolled back action {aid}: status={status}, restored reachability targets={len(after)}"

        elif name == "notify_owners":
            notified: list[Any] = data.get("notified", [])
            summary = f"Notified {len(notified)} owner team(s) via Slack alerting channels"

        elif name == "record_finding":
            fid: str = str(data.get("finding_id", ""))
            kind: str = str(args.get("kind", ""))
            summary = f"Recorded finding {fid} of type {kind} linked to incident"

        elif name == "run_readonly_cypher":
            count: int = int(data.get("count", 0))
            ms: float = float(envelope.get("evidence", {}).get("ms", 0.0))
            summary = f"Read-only Cypher query returned {count} rows in {ms:.1f}ms"

        else:
            summary = f"Tool '{name}' executed successfully"

        return summary[:200]
