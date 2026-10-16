"""FastMCP server exposing graph inspection, traversal, and containment tools."""

from __future__ import annotations

import logging
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_server.db import run_ro
from mcp_server.models import ErrorCode, VisitKind, format_error, format_success
from mcp_server.queries import (
    find_attack_paths as execute_find_attack_paths,
)
from mcp_server.queries import (
    get_component_context as fetch_component_context,
)
from mcp_server.queries import (
    get_failure_impact as execute_failure_impact,
)
from mcp_server.queries import (
    rank_critical_components as execute_criticality_ranking,
)

logger = logging.getLogger(__name__)

FORBIDDEN_CYPHER_KEYWORDS = re.compile(
    r"\b(CREATE|MERGE|SET|DELETE|REMOVE|DROP|CALL)\b",
    re.IGNORECASE,
)

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
    if not id or not isinstance(id, str) or not id.strip():
        return format_error(ErrorCode.INVALID_INPUT, "id must be a non-empty string")

    try:
        ctx = fetch_component_context(id.strip())
        if ctx is None:
            return format_error(ErrorCode.NOT_FOUND, f"Component '{id}' was not found in the graph")

        data: dict[str, Any] = {
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


@mcp.tool()
def get_failure_impact(id: str, max_hops: int = 3, critical_only: bool = False) -> str:
    """Compute the reverse failure blast radius of a failing service or database (who depends on this component).

    Use when: assessing outage blast radius, identifying customer-facing services affected by an outage,
    or determining incident severity and scope.
    Do NOT use when: tracing forward attacker reachability or checking security permissions.
    """
    if not id or not isinstance(id, str) or not id.strip():
        return format_error(ErrorCode.INVALID_INPUT, "id must be a non-empty string")
    if not (1 <= max_hops <= 6):
        return format_error(
            ErrorCode.INVALID_INPUT, f"max_hops must be between 1 and 6, got {max_hops}"
        )

    try:
        impact_result = execute_failure_impact(
            target_id=id.strip(),
            max_hops=max_hops,
            critical_only=critical_only,
        )
        data: dict[str, Any] = {
            "target": impact_result["target"],
            "impacted": impact_result["impacted"],
            "customer_facing_count": impact_result["customer_facing_count"],
            "owners": impact_result["owners"],
        }
        visit = {
            "kind": VisitKind.IMPACT.value,
            "node_ids": impact_result["node_ids"],
            "edge_keys": impact_result["edge_keys"],
        }
        evidence = {
            "query_id": impact_result["query_id"],
            "cypher": impact_result["cypher"],
            "params": impact_result["params"],
            "ms": impact_result["ms"],
            "row_count": impact_result["row_count"],
        }
        return format_success(data=data, visit=visit, evidence=evidence)
    except Exception as err:
        logger.exception("Error in get_failure_impact")
        return format_error(ErrorCode.DB_ERROR, f"Database error evaluating failure impact: {err}")


@mcp.tool()
def find_attack_paths(source_id: str, max_hops: int = 6) -> str:
    """Find all reachable paths from a compromised service to sensitive PII databases honoring containment boundaries.

    Use when: analyzing compromised credentials, assessing vulnerability exploitability,
    or checking attacker reachability to PII databases.
    Do NOT use when: calculating failure blast radius or general system topology.
    """
    if not source_id or not isinstance(source_id, str) or not source_id.strip():
        return format_error(ErrorCode.INVALID_INPUT, "source_id must be a non-empty string")
    if not (1 <= max_hops <= 6):
        return format_error(
            ErrorCode.INVALID_INPUT, f"max_hops must be between 1 and 6, got {max_hops}"
        )

    try:
        attack_result = execute_find_attack_paths(
            source_id=source_id.strip(),
            max_hops=max_hops,
            engine="fallback",
        )
        data: dict[str, Any] = {
            "source": attack_result["source"],
            "paths": attack_result["paths"],
            "engine": attack_result["engine"],
        }
        visit = {
            "kind": VisitKind.ATTACK_PATH.value,
            "node_ids": attack_result["node_ids"],
            "edge_keys": attack_result["edge_keys"],
        }
        evidence = {
            "query_id": attack_result["query_id"],
            "cypher": attack_result["cypher"],
            "params": attack_result["params"],
            "ms": attack_result["ms"],
            "row_count": attack_result["row_count"],
        }
        return format_success(data=data, visit=visit, evidence=evidence)
    except Exception as err:
        logger.exception("Error in find_attack_paths")
        return format_error(ErrorCode.DB_ERROR, f"Database error discovering attack paths: {err}")


@mcp.tool()
def rank_critical_components(top_n: int = 5) -> str:
    """Rank services across the infrastructure by structural criticality (transitive dependents count and PageRank).

    Use when: identifying key bottlenecks, determining tiering importance, or triaging system-wide priority.
    Do NOT use when: investigating an isolated single-service incident.
    """
    if not (1 <= top_n <= 20):
        return format_error(ErrorCode.INVALID_INPUT, f"top_n must be between 1 and 20, got {top_n}")

    try:
        rank_result = execute_criticality_ranking(top_n=top_n)
        data: dict[str, Any] = {
            "ranking": rank_result["ranking"],
        }
        visit = {
            "kind": VisitKind.INSPECT.value,
            "node_ids": rank_result["node_ids"],
            "edge_keys": [],
        }
        evidence = {
            "query_id": rank_result["query_id"],
            "cypher": rank_result["cypher"],
            "params": rank_result["params"],
            "ms": rank_result["ms"],
            "row_count": rank_result["row_count"],
        }
        return format_success(data=data, visit=visit, evidence=evidence)
    except Exception as err:
        logger.exception("Error in rank_critical_components")
        return format_error(ErrorCode.DB_ERROR, f"Database error ranking components: {err}")


@mcp.tool()
def run_readonly_cypher(query: str) -> str:
    """Execute an arbitrary read-only Cypher query against the FalkorDB infrastructure graph.

    Use when: custom ad-hoc inspection is needed that is not covered by existing graph tools.
    Do NOT use when: executing mutations, containment actions, or writes (rejected by policy).
    """
    if not query or not isinstance(query, str) or not query.strip():
        return format_error(ErrorCode.INVALID_INPUT, "query must be a non-empty string")

    cleaned_query = query.strip()
    if FORBIDDEN_CYPHER_KEYWORDS.search(cleaned_query):
        return format_error(
            ErrorCode.POLICY_DENIED,
            "Query contains prohibited mutation or procedure call keywords (CREATE, MERGE, SET, DELETE, REMOVE, DROP, CALL)",
        )

    try:
        rows, elapsed_ms = run_ro(cleaned_query)
        capped_rows = rows[:200]
        data: dict[str, Any] = {
            "rows": capped_rows,
            "count": len(capped_rows),
        }
        visit = {
            "kind": VisitKind.INSPECT.value,
            "node_ids": [],
            "edge_keys": [],
        }
        evidence = {
            "query_id": "Q-READONLY",
            "cypher": cleaned_query,
            "params": {},
            "ms": elapsed_ms,
            "row_count": len(capped_rows),
        }
        return format_success(data=data, visit=visit, evidence=evidence)
    except Exception as err:
        logger.exception("Error in run_readonly_cypher")
        return format_error(ErrorCode.DB_ERROR, f"Database error executing read-only Cypher: {err}")


def main() -> None:
    """Run the FastMCP server over standard I/O (stdio)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
