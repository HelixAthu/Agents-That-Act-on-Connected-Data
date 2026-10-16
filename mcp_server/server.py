"""FastMCP server exposing graph inspection, traversal, and containment tools."""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import os
import re
import uuid
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_server.db import run_ro
from mcp_server.models import ErrorCode, VisitKind, format_error, format_success
from mcp_server.policy import ContainmentAction, PolicyDecision, evaluate_containment_policy
from mcp_server.queries import (
    create_finding,
    get_teams_by_ids,
    isolate_node,
    record_action,
    record_notification_action,
    revoke_role,
    rollback_action_node,
    rollback_node,
    rollback_role,
    set_action_executed,
)
from mcp_server.queries import (
    find_attack_paths as execute_find_attack_paths,
)
from mcp_server.queries import (
    get_action as fetch_action,
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
from mcp_server.scoring import compute_target_risk

logger = logging.getLogger(__name__)

# Global containment lock ensuring safe non-transactional simulation and execution writes
_CONTAINMENT_LOCK = asyncio.Lock()

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
def compute_risk(target_id: str) -> str:
    """Compute the deterministic risk score for a target component using CVSS severity, PII database
    reachability, failure blast radius, and architectural centrality.

    Use when: evaluating risk of an alert or security finding, or deciding whether containment actions
    require human approval.
    Do NOT use when: needing full multi-hop traversal paths or executing containment mutations.
    """
    if not target_id or not isinstance(target_id, str) or not target_id.strip():
        return format_error(ErrorCode.INVALID_INPUT, "target_id must be a non-empty string")

    cleaned_id: str = target_id.strip()
    try:
        result = compute_target_risk(cleaned_id)
        data: dict[str, Any] = {
            "risk": result["data"]["risk"],
            "components": result["data"]["components"],
            "vulnerability": result["data"]["vulnerability"],
            "attack_target_count": result["data"]["attack_target_count"],
            "impacted_cf_count": result["data"]["impacted_cf_count"],
        }
        return format_success(data=data, visit=result["visit"], evidence=result["evidence"])
    except KeyError:
        return format_error(ErrorCode.NOT_FOUND, f"Component '{cleaned_id}' was not found in the graph")
    except Exception as err:
        logger.exception("Error in compute_risk for '%s'", cleaned_id)
        return format_error(ErrorCode.DB_ERROR, f"Database error computing risk: {err}")


@mcp.tool()
async def propose_containment(
    action: str,
    target_id: str,
    incident_id: str,
) -> str:
    """Propose a containment action (ISOLATE_NODE or REVOKE_ROLE) for policy evaluation and dry-run
    attack path simulation without modifying persistent graph state.

    Use when: evaluating containment options for an incident or preparing an action for approval.
    Do NOT use when: executing approved actions or running read-only blast radius queries.
    """
    if not action or not isinstance(action, str) or not action.strip():
        return format_error(ErrorCode.INVALID_INPUT, "action must be a non-empty string")
    if not target_id or not isinstance(target_id, str) or not target_id.strip():
        return format_error(ErrorCode.INVALID_INPUT, "target_id must be a non-empty string")
    if not incident_id or not isinstance(incident_id, str) or not incident_id.strip():
        return format_error(ErrorCode.INVALID_INPUT, "incident_id must be a non-empty string")

    normalized_action: str = action.strip().upper()
    cleaned_target: str = target_id.strip()
    cleaned_incident: str = incident_id.strip()

    valid_actions = {ContainmentAction.ISOLATE_NODE.value, ContainmentAction.REVOKE_ROLE.value}
    if normalized_action not in valid_actions:
        return format_error(
            ErrorCode.INVALID_INPUT,
            f"action must be 'ISOLATE_NODE' or 'REVOKE_ROLE', got '{action}'",
        )

    if normalized_action == ContainmentAction.REVOKE_ROLE.value and "|" not in cleaned_target:
        return format_error(
            ErrorCode.INVALID_INPUT,
            "target_id for REVOKE_ROLE must be in 'service_id|role_id' format",
        )

    try:
        policy_eval = evaluate_containment_policy(normalized_action, cleaned_target)
        policy_decision = policy_eval["policy"]
        risk_score = float(policy_eval["risk"])

        source_id: str = (
            cleaned_target.split("|", 1)[0]
            if normalized_action == ContainmentAction.REVOKE_ROLE.value
            else cleaned_target
        )

        before_res = execute_find_attack_paths(source_id=source_id, max_hops=6)
        paths_before: int = len(before_res.get("paths", []))
        targets_before: list[str] = sorted({p["target"] for p in before_res.get("paths", [])})

        targets_after: list[str] = targets_before
        paths_after: int = paths_before

        if policy_decision["decision"] != PolicyDecision.DENIED.value:
            async with _CONTAINMENT_LOCK:
                try:
                    if normalized_action == ContainmentAction.ISOLATE_NODE.value:
                        isolate_node(cleaned_target)
                    else:
                        revoke_role(cleaned_target)

                    after_res = execute_find_attack_paths(source_id=source_id, max_hops=6)
                    paths_after = len(after_res.get("paths", []))
                    targets_after = sorted({p["target"] for p in after_res.get("paths", [])})
                finally:
                    if normalized_action == ContainmentAction.ISOLATE_NODE.value:
                        rollback_node(cleaned_target)
                    else:
                        rollback_role(cleaned_target)

        action_id: str = f"act-{uuid.uuid4().hex[:8]}"
        mode: str = "AUTO" if policy_decision["decision"] == PolicyDecision.AUTO.value else "MANUAL"

        record_action(
            incident_id=cleaned_incident,
            action_id=action_id,
            action_type=normalized_action,
            target_id=cleaned_target,
            status="PROPOSED",
            mode=mode,
            policy_decision=policy_decision["decision"],
            policy_reason=policy_decision["reason"],
        )

        data: dict[str, Any] = {
            "action_id": action_id,
            "policy": policy_decision,
            "risk": risk_score,
            "simulation": {
                "targets_before": targets_before,
                "targets_after": targets_after,
                "paths_before": paths_before,
                "paths_after": paths_after,
            },
        }

        edge_keys: list[str] = []
        if normalized_action == ContainmentAction.REVOKE_ROLE.value:
            svc_part, role_part = cleaned_target.split("|", 1)
            edge_keys.append(f"{svc_part}|ASSUMES_ROLE|{role_part}")

        visit = {
            "kind": VisitKind.ACTION.value,
            "node_ids": [source_id],
            "edge_keys": edge_keys,
        }
        evidence = {
            "query_id": "Q-PROPOSE-CONTAINMENT",
            "cypher": "RECORD_ACTION (Incident-[:TOOK]->Action)",
            "params": {"incident_id": cleaned_incident, "action": normalized_action, "target": cleaned_target},
            "ms": 1.0,
            "row_count": 1,
        }
        return format_success(data=data, visit=visit, evidence=evidence)

    except KeyError:
        return format_error(ErrorCode.NOT_FOUND, f"Component '{cleaned_target}' was not found in the graph")
    except Exception as err:
        logger.exception("Error proposing containment for '%s'", cleaned_target)
        return format_error(ErrorCode.DB_ERROR, f"Database error proposing containment: {err}")


@mcp.tool()
async def execute_containment(action_id: str) -> str:
    """Execute a previously proposed containment action following policy validation and approval.

    Use when: executing an AUTO-approved containment action or an action that has received human approval.
    Do NOT use when: proposing actions, simulating containment effects, or executing denied actions.
    """
    if not action_id or not isinstance(action_id, str) or not action_id.strip():
        return format_error(ErrorCode.INVALID_INPUT, "action_id must be a non-empty string")

    cleaned_action_id: str = action_id.strip()
    try:
        action = fetch_action(cleaned_action_id)
        if action is None:
            return format_error(ErrorCode.NOT_FOUND, f"Action '{cleaned_action_id}' not found")

        status: str = action.get("status", "")
        if status == "EXECUTED":
            return format_error(
                ErrorCode.INVALID_INPUT,
                f"Action '{cleaned_action_id}' has already been executed",
            )
        if status == "ROLLED_BACK":
            return format_error(
                ErrorCode.INVALID_INPUT,
                f"Action '{cleaned_action_id}' has already been rolled back",
            )

        policy_decision: str = action.get("policy_decision", "")
        if policy_decision == PolicyDecision.DENIED.value:
            return format_error(
                ErrorCode.POLICY_DENIED,
                f"Cannot execute denied action: {action.get('policy_reason')}",
            )

        approved_by = action.get("approved_by")
        if policy_decision == PolicyDecision.APPROVAL_REQUIRED.value and not approved_by:
            return format_error(
                ErrorCode.APPROVAL_REQUIRED,
                f"Action '{cleaned_action_id}' requires human approval before execution: "
                f"{action.get('policy_reason')}",
            )

        action_type: str = action.get("type", "")
        target_id: str = action.get("target_id", "")
        source_id: str = (
            target_id.split("|", 1)[0]
            if action_type == ContainmentAction.REVOKE_ROLE.value
            else target_id
        )

        async with _CONTAINMENT_LOCK:
            if action_type == ContainmentAction.ISOLATE_NODE.value:
                isolate_node(target_id)
            else:
                revoke_role(target_id)

            post_res = execute_find_attack_paths(source_id=source_id, max_hops=6)
            paths_after: int = len(post_res.get("paths", []))
            targets_after: list[str] = sorted({p["target"] for p in post_res.get("paths", [])})

            set_action_executed(cleaned_action_id)

        data: dict[str, Any] = {
            "action_id": cleaned_action_id,
            "action": action_type,
            "target_id": target_id,
            "status": "EXECUTED",
            "targets_after": targets_after,
            "paths_after": paths_after,
        }

        edge_keys: list[str] = []
        if action_type == ContainmentAction.REVOKE_ROLE.value:
            svc_part, role_part = target_id.split("|", 1)
            edge_keys.append(f"{svc_part}|ASSUMES_ROLE|{role_part}")

        visit = {
            "kind": VisitKind.ACTION.value,
            "node_ids": [source_id],
            "edge_keys": edge_keys,
        }
        evidence = {
            "query_id": "Q-EXECUTE-CONTAINMENT",
            "cypher": "APPLY_CONTAINMENT_WRITE AND SET Action.status = 'EXECUTED'",
            "params": {"action_id": cleaned_action_id},
            "ms": 1.0,
            "row_count": 1,
        }
        return format_success(data=data, visit=visit, evidence=evidence)

    except Exception as err:
        logger.exception("Error executing containment for '%s'", cleaned_action_id)
        return format_error(ErrorCode.DB_ERROR, f"Database error executing containment: {err}")


@mcp.tool()
async def rollback_action(action_id: str) -> str:
    """Roll back a previously executed containment action, restoring the graph to its prior state.

    Use when: containment was mistaken, incident has concluded, or testing containment reversal.
    Do NOT use when: proposing actions or handling non-executed actions.
    """
    if not action_id or not isinstance(action_id, str) or not action_id.strip():
        return format_error(ErrorCode.INVALID_INPUT, "action_id must be a non-empty string")

    cleaned_action_id: str = action_id.strip()
    try:
        action = fetch_action(cleaned_action_id)
        if action is None:
            return format_error(ErrorCode.NOT_FOUND, f"Action '{cleaned_action_id}' not found")

        current_status: str = action.get("status", "")
        if current_status != "EXECUTED":
            return format_error(
                ErrorCode.INVALID_INPUT,
                f"Action '{cleaned_action_id}' cannot be rolled back because status is '{current_status}'",
            )

        action_type: str = action.get("type", "")
        target_id: str = action.get("target_id", "")
        source_id: str = (
            target_id.split("|", 1)[0]
            if action_type == ContainmentAction.REVOKE_ROLE.value
            else target_id
        )

        async with _CONTAINMENT_LOCK:
            if action_type == ContainmentAction.ISOLATE_NODE.value:
                rollback_node(target_id)
            elif action_type == ContainmentAction.REVOKE_ROLE.value:
                rollback_role(target_id)

            post_res = execute_find_attack_paths(source_id=source_id, max_hops=6)
            targets_after: list[str] = sorted({p["target"] for p in post_res.get("paths", [])})

            rollback_action_node(cleaned_action_id)

        data: dict[str, Any] = {
            "action_id": cleaned_action_id,
            "status": "ROLLED_BACK",
            "targets_after": targets_after,
        }

        edge_keys: list[str] = []
        if action_type == ContainmentAction.REVOKE_ROLE.value:
            svc_part, role_part = target_id.split("|", 1)
            edge_keys.append(f"{svc_part}|ASSUMES_ROLE|{role_part}")

        visit = {
            "kind": VisitKind.ACTION.value,
            "node_ids": [source_id],
            "edge_keys": edge_keys,
        }
        evidence = {
            "query_id": "Q-ROLLBACK-ACTION",
            "cypher": "ROLLBACK_CONTAINMENT_WRITE AND SET Action.status = 'ROLLED_BACK'",
            "params": {"action_id": cleaned_action_id},
            "ms": 1.0,
            "row_count": 1,
        }
        return format_success(data=data, visit=visit, evidence=evidence)

    except Exception as err:
        logger.exception("Error rolling back action '%s'", cleaned_action_id)
        return format_error(ErrorCode.DB_ERROR, f"Database error rolling back action: {err}")


@mcp.tool()
def notify_owners(incident_id: str, team_ids: list[str], message: str) -> str:
    """Notify owning teams of impacted components or containment actions via simulated Outbox.

    Use when: alerting service owners about active containment, outages, or security findings.
    Do NOT use when: modifying infrastructure graph topology or computing risk.
    """
    if not incident_id or not isinstance(incident_id, str) or not incident_id.strip():
        return format_error(ErrorCode.INVALID_INPUT, "incident_id must be a non-empty string")
    if not team_ids or not isinstance(team_ids, list):
        return format_error(ErrorCode.INVALID_INPUT, "team_ids must be a non-empty list of strings")
    if not message or not isinstance(message, str) or not message.strip():
        return format_error(ErrorCode.INVALID_INPUT, "message must be a non-empty string")

    cleaned_incident: str = incident_id.strip()
    cleaned_teams: list[str] = [t.strip() for t in team_ids if isinstance(t, str) and t.strip()]
    if not cleaned_teams:
        return format_error(ErrorCode.INVALID_INPUT, "team_ids must contain valid non-empty string team IDs")

    try:
        teams_data = get_teams_by_ids(cleaned_teams)
        notified: list[dict[str, str]] = [
            {"team_id": t["id"], "slack_channel": t["slack_channel"]}
            for t in teams_data
        ]

        found_ids = {t["team_id"] for t in notified}
        for tid in cleaned_teams:
            if tid not in found_ids:
                notified.append({"team_id": tid, "slack_channel": f"#{tid.replace('team-', '')}-alerts"})

        outbox_file: str = os.getenv("OUTBOX_PATH", "./outbox/notifications.jsonl")
        outbox_dir: str = os.path.dirname(os.path.abspath(outbox_file))
        os.makedirs(outbox_dir, exist_ok=True)

        now_ts: str = datetime.datetime.now(datetime.UTC).isoformat()
        with open(outbox_file, "a", encoding="utf-8") as f:
            for item in notified:
                entry = {
                    "timestamp": now_ts,
                    "incident_id": cleaned_incident,
                    "team_id": item["team_id"],
                    "slack_channel": item["slack_channel"],
                    "message": message.strip(),
                }
                f.write(json.dumps(entry) + "\n")

        action_id: str = f"act-{uuid.uuid4().hex[:8]}"
        record_notification_action(
            incident_id=cleaned_incident,
            action_id=action_id,
            target_id=",".join(cleaned_teams),
        )

        data: dict[str, Any] = {"notified": notified}
        visit = {
            "kind": VisitKind.ACTION.value,
            "node_ids": [t["team_id"] for t in notified],
            "edge_keys": [],
        }
        evidence = {
            "query_id": "Q-NOTIFY-OWNERS",
            "cypher": "RECORD_ACTION (Incident-[:TOOK]->Action {type:'NOTIFY_OWNER'})",
            "params": {"incident_id": cleaned_incident, "team_ids": cleaned_teams},
            "ms": 1.0,
            "row_count": len(notified),
        }
        return format_success(data=data, visit=visit, evidence=evidence)

    except Exception as err:
        logger.exception("Error in notify_owners for incident '%s'", cleaned_incident)
        return format_error(ErrorCode.DB_ERROR, f"Database error notifying owners: {err}")


@mcp.tool()
def record_finding(
    incident_id: str,
    kind: str,
    summary: str,
    evidence_ids: list[str] | None = None,
    risk_score: float | None = None,
) -> str:
    """Record an analytical finding with supporting graph evidence linked to an incident audit trail.

    Use when: capturing an investigation finding (e.g., EXPLOITABLE_VULNERABILITY, ATTACK_PATH_DETECTED,
    BLAST_RADIUS_EVALUATED, MITIGATION_STATUS) with evidence IDs.
    Do NOT use when: executing containment actions or notifying teams.
    """
    if not incident_id or not isinstance(incident_id, str) or not incident_id.strip():
        return format_error(ErrorCode.INVALID_INPUT, "incident_id must be a non-empty string")
    if not kind or not isinstance(kind, str) or not kind.strip():
        return format_error(ErrorCode.INVALID_INPUT, "kind must be a non-empty string")
    if not summary or not isinstance(summary, str) or not summary.strip():
        return format_error(ErrorCode.INVALID_INPUT, "summary must be a non-empty string")

    cleaned_incident: str = incident_id.strip()
    cleaned_kind: str = kind.strip().upper()
    cleaned_summary: str = summary.strip()
    evidence_list: list[str] = [e.strip() for e in (evidence_ids or []) if isinstance(e, str) and e.strip()]

    try:
        finding_id: str = f"finding-{uuid.uuid4().hex[:8]}"
        create_finding(
            incident_id=cleaned_incident,
            finding_id=finding_id,
            kind=cleaned_kind,
            summary=cleaned_summary,
            risk_score=risk_score,
            evidence_ids=evidence_list,
        )

        data: dict[str, Any] = {"finding_id": finding_id}
        visit = {
            "kind": VisitKind.INSPECT.value,
            "node_ids": evidence_list,
            "edge_keys": [],
        }
        evidence = {
            "query_id": "Q-CREATE-FINDING",
            "cypher": "CREATE (i)-[:FOUND]->(f:Finding)-[:EVIDENCED_BY]->(e)",
            "params": {"incident_id": cleaned_incident, "finding_id": finding_id},
            "ms": 1.0,
            "row_count": 1,
        }
        return format_success(data=data, visit=visit, evidence=evidence)

    except Exception as err:
        logger.exception("Error recording finding for incident '%s'", cleaned_incident)
        return format_error(ErrorCode.DB_ERROR, f"Database error recording finding: {err}")


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
            "Query contains prohibited mutation or procedure call keywords "
            "(CREATE, MERGE, SET, DELETE, REMOVE, DROP, CALL)",
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
