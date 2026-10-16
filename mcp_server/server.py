"""FastMCP server exposing graph inspection, traversal, and containment tools."""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from mcp_server.models import ErrorCode, VisitKind, format_error, format_success
from mcp_server.queries import get_component_context as fetch_component_context

logger = logging.getLogger(__name__)

mcp = FastMCP(
    name="blast-radius-graph-server",
    instructions="MCP server providing graph-native blast radius and attack path tools via FalkorDB",
)


@mcp.tool()
def get_component_context(id: str) -> str:
    """Get full context for a single component (service, database, IAM role, vulnerability, team)
    including properties, owner teams, vulnerabilities, and direct incoming and outgoing dependency
    and access edges.

    Use when: investigating an alert, inspecting a target component, or checking immediate neighbors.
    Do NOT use when: needing multi-hop failure impact or attack path analysis.
    """
    if not id or not isinstance(id, str):
        return format_error(ErrorCode.INVALID_INPUT, "id must be a non-empty string")

    try:
        ctx = fetch_component_context(id.strip())
        if ctx is None:
            return format_error(ErrorCode.NOT_FOUND, f"Component '{id}' was not found in the graph")

        data = {
            "id": ctx["id"],
            "label": ctx["label"],
            "props": ctx["props"],
            "owners": ctx["owners"],
            "vulnerabilities": ctx["vulnerabilities"],
            "outgoing": ctx["outgoing"],
            "incoming": ctx["incoming"],
        }
        visit = {
            "kind": VisitKind.INSPECT.value,
            "node_ids": ctx["node_ids"],
            "edge_keys": ctx["edge_keys"],
        }
        evidence = {
            "query_id": ctx["query_id"],
            "cypher": ctx["cypher"],
            "params": ctx["params"],
            "ms": ctx["ms"],
            "row_count": ctx["row_count"],
        }
        return format_success(data=data, visit=visit, evidence=evidence)
    except Exception as err:
        logger.exception("Error in get_component_context")
        return format_error(ErrorCode.DB_ERROR, f"Database error fetching component context: {err}")


def main() -> None:
    """Run the FastMCP server over standard I/O (stdio)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
