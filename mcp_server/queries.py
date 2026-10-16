"""Cypher queries and graph traversal routines for incident analysis."""

from __future__ import annotations

import datetime
import logging
from typing import Any

from falkordb import Graph

from mcp_server.db import run_ro, run_rw

logger = logging.getLogger(__name__)

Q_IMPACT_ID = "Q-IMPACT"
Q_CONTEXT_ID = "Q-CONTEXT"
Q_CONTEXT = """
MATCH (n {id: $id})
OPTIONAL MATCH (t:Team)-[:OWNS]->(n)
OPTIONAL MATCH (v:Vulnerability)-[:AFFECTS]->(n)
RETURN labels(n)[0] AS label, properties(n) AS props,
       collect(DISTINCT t.id) AS owners, collect(DISTINCT properties(v)) AS vulns
"""
Q_NEIGHBORS_OUT = (
    "MATCH (n {id: $id})-[r]->(o) RETURN type(r) AS rel, o.id AS other, r.isolated AS isolated"
)
Q_NEIGHBORS_IN = (
    "MATCH (i)-[r]->(n {id: $id}) RETURN type(r) AS rel, i.id AS other, r.isolated AS isolated"
)

Q_OWNERS_ID = "Q-OWNERS"
Q_OWNERS = "MATCH (t:Team)-[:OWNS]->(s:Service) WHERE s.id IN $ids RETURN s.id, t.id, t.name"

Q_ATTACK_ID = "Q-ATTACK"
Q_EDGES_NODES_ID = "Q-EDGES-NODES"
Q_EDGES_NODES = "MATCH (n) RETURN n.id AS id, labels(n)[0] AS label, properties(n) AS props"
Q_EDGES_RELS_ID = "Q-EDGES-RELS"
Q_EDGES_RELS = (
    "MATCH (a)-[r]->(b) WHERE labels(a)[0] IN ['Service','Database','IAMRole','Vulnerability','Team'] "
    "RETURN a.id AS src, type(r) AS rel, b.id AS dst, properties(r) AS props"
)

Q_RANK_ID = "Q-RANK"
Q_RANK = """
MATCH (s:Service)
OPTIONAL MATCH (d:Service)-[:DEPENDS_ON*1..10]->(s)
RETURN s.id AS id, s.name AS name, count(DISTINCT d) AS transitive_dependents
ORDER BY transitive_dependents DESC LIMIT $top_n
"""

Q_DEPENDENTS_COUNT_ID = "Q-DEPENDENTS-COUNT"
Q_DEPENDENTS_COUNT = """
MATCH (target:Service {id: $id})
OPTIONAL MATCH (d:Service)-[:DEPENDS_ON*1..10]->(target)
RETURN count(DISTINCT d) AS transitive_dependents
"""

Q_ISOLATE_NODE_ID = "Q-ISOLATE-NODE"
Q_ISOLATE_NODE = """
MATCH (n {id: $id}) SET n.status = 'ISOLATED'
WITH n MATCH (n)-[r]-() SET r.isolated = true
"""

Q_REVOKE_ROLE_ID = "Q-REVOKE-ROLE"
Q_REVOKE_ROLE = """
MATCH (s:Service {id: $svc})-[r:ASSUMES_ROLE]->(ro:IAMRole {id: $role}) SET r.isolated = true
"""

Q_ROLLBACK_NODE_ID = "Q-ROLLBACK-NODE"
Q_ROLLBACK_NODE = """
MATCH (n {id: $id}) SET n.status = 'HEALTHY'
WITH n MATCH (n)-[r]-() SET r.isolated = false
"""

Q_ROLLBACK_ROLE_ID = "Q-ROLLBACK-ROLE"
Q_ROLLBACK_ROLE = """
MATCH (s:Service {id: $svc})-[r:ASSUMES_ROLE]->(ro:IAMRole {id: $role}) SET r.isolated = false
"""

Q_RECORD_ACTION_ID = "Q-RECORD-ACTION"
Q_RECORD_ACTION = """
MERGE (i:Incident {id: $inc})
CREATE (a:Action {
    id: $aid,
    type: $type,
    target_id: $target,
    status: $status,
    mode: $mode,
    policy_decision: $decision,
    policy_reason: $reason,
    created_at: $ts,
    reversed: false
})
CREATE (i)-[:TOOK]->(a)
RETURN a.id AS aid
"""

Q_GET_ACTION_ID = "Q-GET-ACTION"
Q_GET_ACTION = """
MATCH (a:Action {id: $aid})
RETURN a.id AS id, a.type AS type, a.target_id AS target_id, a.status AS status,
       a.mode AS mode, a.policy_decision AS policy_decision, a.policy_reason AS policy_reason,
       a.created_at AS created_at, a.approved_by AS approved_by, a.approved_at AS approved_at,
       a.executed_at AS executed_at, a.reversed AS reversed
"""

Q_EXECUTE_ACTION_UPDATE_ID = "Q-EXECUTE-ACTION-UPDATE"
Q_EXECUTE_ACTION_UPDATE = """
MATCH (a:Action {id: $aid})
SET a.status = 'EXECUTED', a.executed_at = $ts
"""

Q_APPROVE_ACTION_ID = "Q-APPROVE-ACTION"
Q_APPROVE_ACTION = """
MATCH (a:Action {id: $aid})
SET a.approved_by = $approved_by, a.approved_at = $ts
"""

Q_ROLLBACK_ACTION_ID = "Q-ROLLBACK-ACTION"
Q_ROLLBACK_ACTION = """
MATCH (a:Action {id: $aid})
SET a.status = 'ROLLED_BACK', a.reversed = true, a.rolled_back_at = $ts
"""

Q_GET_TEAMS_ID = "Q-GET-TEAMS"
Q_GET_TEAMS = """
MATCH (t:Team) WHERE t.id IN $ids
RETURN t.id AS id, t.name AS name, t.slack_channel AS slack_channel, t.email AS email
"""

Q_RECORD_NOTIFICATION_ID = "Q-RECORD-NOTIFICATION"
Q_RECORD_NOTIFICATION = """
MERGE (i:Incident {id: $inc})
CREATE (a:Action {
    id: $aid,
    type: 'NOTIFY_OWNER',
    target_id: $target,
    status: 'EXECUTED',
    mode: 'AUTO',
    policy_decision: 'AUTO',
    policy_reason: 'owner notification is always permitted',
    created_at: $ts,
    executed_at: $ts,
    reversed: false
})
CREATE (i)-[:TOOK]->(a)
"""

Q_CREATE_FINDING_ID = "Q-CREATE-FINDING"
Q_CREATE_FINDING = """
MERGE (i:Incident {id: $inc})
CREATE (f:Finding {
    id: $fid,
    kind: $kind,
    summary: $summary,
    risk_score: $risk,
    created_at: $ts
})
CREATE (i)-[:FOUND]->(f)
"""

Q_LINK_FINDING_EVIDENCE_ID = "Q-LINK-FINDING-EVIDENCE"
Q_LINK_FINDING_EVIDENCE = """
MATCH (f:Finding {id: $fid})
UNWIND $evidence_ids AS eid
MATCH (e {id: eid})
CREATE (f)-[:EVIDENCED_BY]->(e)
"""


def build_impact_query(max_hops: int = 3, critical_only: bool = False) -> str:
    """Build the reverse failure impact Cypher query with validated hop bound."""
    if not (1 <= max_hops <= 6):
        raise ValueError(f"max_hops must be between 1 and 6, got {max_hops}")

    where_filter = (
        "WHERE ALL(r IN relationships(p) WHERE type(r) <> 'DEPENDS_ON' OR r.critical = true)"
        if critical_only
        else ""
    )

    query = (
        f"MATCH p = (imp:Service)-[:DEPENDS_ON|CONNECTS_TO*1..{max_hops}]->(f {{id: $id}})\n"
        f"{where_filter}\n"
        "RETURN imp.id AS id, imp.name AS name, imp.tier AS tier, imp.customer_facing AS cf,\n"
        "       length(p) AS hops,\n"
        "       [n IN nodes(p) | n.id] AS node_ids, [r IN relationships(p) | type(r)] AS edge_types\n"
        "LIMIT 500"
    )
    return query.strip()


def get_failure_impact(
    target_id: str,
    max_hops: int = 3,
    critical_only: bool = False,
    graph: Graph | None = None,
) -> dict[str, Any]:
    """Calculate the reverse failure blast radius of a failing service or database."""
    if not target_id or not isinstance(target_id, str):
        raise ValueError("target_id must be a non-empty string")

    cypher_query = build_impact_query(max_hops=max_hops, critical_only=critical_only)
    rows, execution_ms = run_ro(cypher_query, {"id": target_id}, graph=graph)

    impacted_services: dict[str, dict[str, Any]] = {}
    visited_node_ids: set[str] = {target_id}
    visited_edge_keys: set[str] = set()

    for row in rows:
        service_id: str = row[0]
        service_name: str = row[1]
        tier: int = row[2]
        customer_facing: bool = row[3]
        hops: int = row[4]
        node_ids: list[str] = row[5]
        edge_types: list[str] = row[6]

        visited_node_ids.update(node_ids)
        for i in range(len(edge_types)):
            # Edge key: <src>|<REL>|<dst>
            visited_edge_keys.add(f"{node_ids[i]}|{edge_types[i]}|{node_ids[i + 1]}")

        if service_id not in impacted_services or hops < impacted_services[service_id]["hops"]:
            impacted_services[service_id] = {
                "id": service_id,
                "name": service_name,
                "tier": tier,
                "customer_facing": customer_facing,
                "hops": hops,
                "owners": [],
            }

    service_id_list = list(impacted_services.keys())
    team_directory: dict[str, str] = {}

    if service_id_list:
        owner_rows, _ = run_ro(Q_OWNERS, {"ids": service_id_list}, graph=graph)
        for svc_id, team_id, team_name in owner_rows:
            if svc_id in impacted_services and team_id not in impacted_services[svc_id]["owners"]:
                impacted_services[svc_id]["owners"].append(team_id)
            team_directory[team_id] = team_name

    sorted_impacted = sorted(
        impacted_services.values(),
        key=lambda item: (item["hops"], item["id"]),
    )
    customer_facing_count = sum(1 for item in sorted_impacted if item["customer_facing"])
    distinct_owners = [
        {"id": tid, "name": team_name} for tid, team_name in sorted(team_directory.items())
    ]

    return {
        "target": target_id,
        "impacted": sorted_impacted,
        "customer_facing_count": customer_facing_count,
        "owners": distinct_owners,
        "node_ids": sorted(visited_node_ids),
        "edge_keys": sorted(visited_edge_keys),
        "query_id": Q_IMPACT_ID,
        "cypher": cypher_query,
        "params": {"id": target_id},
        "ms": execution_ms,
        "row_count": len(rows),
    }


def build_attack_query(max_hops: int = 6) -> str:
    """Build the Cypher forward attack path query to PII databases."""
    if not (1 <= max_hops <= 6):
        raise ValueError(f"max_hops must be between 1 and 6, got {max_hops}")

    query = (
        "MATCH (src:Service {id: $id}), (db:Database {contains_pii: true})\n"
        f"WITH shortestPath((src)-[:DEPENDS_ON|CONNECTS_TO|ASSUMES_ROLE|CAN_ASSUME|CAN_ACCESS*..{max_hops}]->(db)) AS p, db\n"
        "WHERE p IS NOT NULL AND ALL(r IN relationships(p) WHERE r.isolated = false)\n"
        "RETURN db.id AS target, length(p) AS hops,\n"
        "       [n IN nodes(p) | n.id] AS node_ids, [r IN relationships(p) | type(r)] AS edge_types\n"
        "ORDER BY hops"
    )
    return query.strip()


def find_attack_paths(
    source_id: str,
    max_hops: int = 6,
    engine: str = "fallback",
    graph: Graph | None = None,
) -> dict[str, Any]:
    """Find reachable attack paths from source_id to PII databases honoring edge isolation."""
    if not source_id or not isinstance(source_id, str):
        raise ValueError("source_id must be a non-empty string")
    if not (1 <= max_hops <= 6):
        raise ValueError(f"max_hops must be between 1 and 6, got {max_hops}")

    cypher_text = build_attack_query(max_hops=max_hops)

    if engine == "fallback":
        from mcp_server.pathfinder_fallback import bfs_attack_paths

        paths, visited_nodes, visited_edges, elapsed_ms = bfs_attack_paths(
            source_id=source_id,
            max_hops=max_hops,
            graph=graph,
        )
        return {
            "source": source_id,
            "paths": paths,
            "engine": "fallback",
            "node_ids": sorted(visited_nodes),
            "edge_keys": sorted(visited_edges),
            "query_id": Q_ATTACK_ID,
            "cypher": cypher_text,
            "params": {"id": source_id},
            "ms": elapsed_ms,
            "row_count": len(paths),
        }

    rows, elapsed_ms = run_ro(cypher_text, {"id": source_id}, graph=graph)
    paths = []
    visited_nodes = {source_id}
    visited_edges = set()

    for row in rows:
        target: str = row[0]
        hops: int = row[1]
        node_ids: list[str] = row[2]
        edge_types: list[str] = row[3]

        visited_nodes.update(node_ids)
        edge_keys = [
            f"{node_ids[i]}|{edge_types[i]}|{node_ids[i + 1]}" for i in range(len(edge_types))
        ]
        visited_edges.update(edge_keys)

        paths.append(
            {
                "target": target,
                "hops": hops,
                "node_ids": node_ids,
                "edge_types": edge_types,
                "edge_keys": edge_keys,
            }
        )

    return {
        "source": source_id,
        "paths": paths,
        "engine": "cypher",
        "node_ids": sorted(visited_nodes),
        "edge_keys": sorted(visited_edges),
        "query_id": Q_ATTACK_ID,
        "cypher": cypher_text,
        "params": {"id": source_id},
        "ms": elapsed_ms,
        "row_count": len(paths),
    }


def rank_critical_components(
    top_n: int = 5,
    graph: Graph | None = None,
) -> dict[str, Any]:
    """Rank services by number of transitive incoming dependents, with optional PageRank bonus."""
    if not (1 <= top_n <= 20):
        raise ValueError(f"top_n must be between 1 and 20, got {top_n}")

    rows, elapsed_ms = run_ro(Q_RANK, {"top_n": top_n}, graph=graph)

    pagerank_scores: dict[str, float] = {}
    try:
        pr_rows, _ = run_rw("CALL algo.pageRank('Service', 'DEPENDS_ON')", graph=graph)
        for node, score in pr_rows:
            node_id = getattr(node, "properties", {}).get("id")
            if node_id:
                pagerank_scores[node_id] = round(float(score), 4)
    except Exception as err:  # noqa: BLE001
        logger.debug("PageRank algorithm call skipped or unsupported: %s", err)

    ranking = []
    visited_nodes: set[str] = set()

    for row in rows:
        service_id: str = row[0]
        service_name: str = row[1]
        trans_deps: int = int(row[2])

        visited_nodes.add(service_id)
        item: dict[str, Any] = {
            "id": service_id,
            "name": service_name,
            "transitive_dependents": trans_deps,
        }
        if service_id in pagerank_scores:
            item["pagerank"] = pagerank_scores[service_id]
        ranking.append(item)

    return {
        "ranking": ranking,
        "top_n": top_n,
        "node_ids": sorted(visited_nodes),
        "query_id": Q_RANK_ID,
        "cypher": Q_RANK.strip(),
        "params": {"top_n": top_n},
        "ms": elapsed_ms,
        "row_count": len(ranking),
    }


def count_transitive_dependents(service_id: str, graph: Graph | None = None) -> int:
    """Return the exact count of transitive incoming dependents for a single service."""
    rows, _ = run_ro(Q_DEPENDENTS_COUNT, {"id": service_id}, graph=graph)
    return int(rows[0][0]) if rows else 0


def isolate_node(node_id: str, graph: Graph | None = None) -> dict[str, Any]:
    """Isolate a node by setting status to ISOLATED and marking all connected edges isolated."""
    if not node_id:
        raise ValueError("node_id must be a non-empty string")

    _, elapsed_ms = run_rw(Q_ISOLATE_NODE, {"id": node_id}, graph=graph)
    return {
        "action": "ISOLATE_NODE",
        "target_id": node_id,
        "status": "ISOLATED",
        "query_id": Q_ISOLATE_NODE_ID,
        "ms": elapsed_ms,
    }


def revoke_role(
    service_id: str,
    role_id: str | None = None,
    graph: Graph | None = None,
) -> dict[str, Any]:
    """Revoke an IAM role assumption from a service by marking the ASSUMES_ROLE edge isolated."""
    if role_id is None and "|" in service_id:
        svc, role = service_id.split("|", 1)
    else:
        svc = service_id
        role = role_id or ""

    if not svc or not role:
        raise ValueError("Both service_id and role_id must be provided or formatted as 'svc|role'")

    _, elapsed_ms = run_rw(Q_REVOKE_ROLE, {"svc": svc, "role": role}, graph=graph)
    return {
        "action": "REVOKE_ROLE",
        "target_id": f"{svc}|{role}",
        "status": "REVOKED",
        "query_id": Q_REVOKE_ROLE_ID,
        "ms": elapsed_ms,
    }


def rollback_node(node_id: str, graph: Graph | None = None) -> dict[str, Any]:
    """Roll back node isolation by restoring status to HEALTHY and unisolating connected edges."""
    if not node_id:
        raise ValueError("node_id must be a non-empty string")

    _, elapsed_ms = run_rw(Q_ROLLBACK_NODE, {"id": node_id}, graph=graph)
    return {
        "action": "ROLLBACK_NODE",
        "target_id": node_id,
        "status": "HEALTHY",
        "query_id": Q_ROLLBACK_NODE_ID,
        "ms": elapsed_ms,
    }


def rollback_role(
    service_id: str,
    role_id: str | None = None,
    graph: Graph | None = None,
) -> dict[str, Any]:
    """Roll back IAM role revocation by marking the ASSUMES_ROLE edge active (isolated=false)."""
    if role_id is None and "|" in service_id:
        svc, role = service_id.split("|", 1)
    else:
        svc = service_id
        role = role_id or ""

    if not svc or not role:
        raise ValueError("Both service_id and role_id must be provided or formatted as 'svc|role'")

    _, elapsed_ms = run_rw(Q_ROLLBACK_ROLE, {"svc": svc, "role": role}, graph=graph)
    return {
        "action": "ROLLBACK_ROLE",
        "target_id": f"{svc}|{role}",
        "status": "ACTIVE",
        "query_id": Q_ROLLBACK_ROLE_ID,
        "ms": elapsed_ms,
    }


def get_component_context(
    component_id: str,
    graph: Graph | None = None,
) -> dict[str, Any] | None:
    """Retrieve node properties, owners, vulnerabilities, and adjacent relationships."""
    if not component_id or not isinstance(component_id, str):
        raise ValueError("component_id must be a non-empty string")

    rows, elapsed_ms = run_ro(Q_CONTEXT, {"id": component_id}, graph=graph)
    if not rows or rows[0][0] is None:
        return None

    row = rows[0]
    label = str(row[0])
    raw_props = dict(row[1]) if row[1] else {}
    owners = [str(o) for o in row[2] if o is not None]
    raw_vulns = [dict(v) for v in row[3] if v]

    out_rows, ms_out = run_ro(Q_NEIGHBORS_OUT, {"id": component_id}, graph=graph)
    in_rows, ms_in = run_ro(Q_NEIGHBORS_IN, {"id": component_id}, graph=graph)

    outgoing = [{"rel": str(r[0]), "other": str(r[1]), "isolated": bool(r[2])} for r in out_rows]
    incoming = [{"rel": str(r[0]), "other": str(r[1]), "isolated": bool(r[2])} for r in in_rows]

    visited_nodes = {component_id}
    visited_edges = set()

    for out_item in outgoing:
        visited_nodes.add(out_item["other"])
        visited_edges.add(f"{component_id}|{out_item['rel']}|{out_item['other']}")

    for in_item in incoming:
        visited_nodes.add(in_item["other"])
        visited_edges.add(f"{in_item['other']}|{in_item['rel']}|{component_id}")

    return {
        "id": component_id,
        "label": label,
        "props": raw_props,
        "owners": owners,
        "vulnerabilities": raw_vulns,
        "outgoing": outgoing,
        "incoming": incoming,
        "node_ids": sorted(visited_nodes),
        "edge_keys": sorted(visited_edges),
        "query_id": Q_CONTEXT_ID,
        "cypher": Q_CONTEXT.strip(),
        "params": {"id": component_id},
        "ms": round(elapsed_ms + ms_out + ms_in, 2),
        "row_count": len(rows),
    }


def record_action(
    incident_id: str,
    action_id: str,
    action_type: str,
    target_id: str,
    status: str = "PROPOSED",
    mode: str = "AUTO",
    policy_decision: str = "AUTO",
    policy_reason: str = "",
    graph: Graph | None = None,
) -> dict[str, Any]:
    """Record a containment action node linked to an incident via TOOK relationship."""
    now_ts: str = datetime.datetime.now(datetime.UTC).isoformat()
    params: dict[str, Any] = {
        "inc": incident_id,
        "aid": action_id,
        "type": action_type,
        "target": target_id,
        "status": status,
        "mode": mode,
        "decision": policy_decision,
        "reason": policy_reason,
        "ts": now_ts,
    }
    _, elapsed_ms = run_rw(Q_RECORD_ACTION, params, graph=graph)
    return {
        "action_id": action_id,
        "incident_id": incident_id,
        "type": action_type,
        "target_id": target_id,
        "status": status,
        "mode": mode,
        "policy_decision": policy_decision,
        "policy_reason": policy_reason,
        "created_at": now_ts,
        "ms": elapsed_ms,
    }


def get_action(
    action_id: str,
    graph: Graph | None = None,
) -> dict[str, Any] | None:
    """Retrieve an Action node by ID with current execution and approval status."""
    rows, _ = run_ro(Q_GET_ACTION, {"aid": action_id}, graph=graph)
    if not rows or rows[0][0] is None:
        return None
    r = rows[0]
    return {
        "id": str(r[0]),
        "type": str(r[1]),
        "target_id": str(r[2]),
        "status": str(r[3]),
        "mode": str(r[4]) if r[4] is not None else None,
        "policy_decision": str(r[5]) if r[5] is not None else None,
        "policy_reason": str(r[6]) if r[6] is not None else "",
        "created_at": str(r[7]) if r[7] is not None else None,
        "approved_by": str(r[8]) if r[8] is not None else None,
        "approved_at": str(r[9]) if r[9] is not None else None,
        "executed_at": str(r[10]) if r[10] is not None else None,
        "reversed": bool(r[11]) if r[11] is not None else False,
    }


def set_action_executed(
    action_id: str,
    graph: Graph | None = None,
) -> dict[str, Any]:
    """Mark an Action node as EXECUTED with execution timestamp."""
    now_ts: str = datetime.datetime.now(datetime.UTC).isoformat()
    _, elapsed_ms = run_rw(Q_EXECUTE_ACTION_UPDATE, {"aid": action_id, "ts": now_ts}, graph=graph)
    return {
        "action_id": action_id,
        "status": "EXECUTED",
        "executed_at": now_ts,
        "ms": elapsed_ms,
    }


def approve_action(
    action_id: str,
    approved_by: str = "security-lead",
    graph: Graph | None = None,
) -> dict[str, Any]:
    """Mark an Action node as approved by setting approved_by and approved_at."""
    now_ts: str = datetime.datetime.now(datetime.UTC).isoformat()
    _, elapsed_ms = run_rw(
        Q_APPROVE_ACTION,
        {"aid": action_id, "approved_by": approved_by, "ts": now_ts},
        graph=graph,
    )
    return {
        "action_id": action_id,
        "approved_by": approved_by,
        "approved_at": now_ts,
        "ms": elapsed_ms,
    }


def rollback_action_node(
    action_id: str,
    graph: Graph | None = None,
) -> dict[str, Any]:
    """Mark an Action node as ROLLED_BACK with reversed=true and rolled_back_at timestamp."""
    now_ts: str = datetime.datetime.now(datetime.UTC).isoformat()
    _, elapsed_ms = run_rw(Q_ROLLBACK_ACTION, {"aid": action_id, "ts": now_ts}, graph=graph)
    return {
        "action_id": action_id,
        "status": "ROLLED_BACK",
        "reversed": True,
        "rolled_back_at": now_ts,
        "ms": elapsed_ms,
    }


def get_teams_by_ids(
    team_ids: list[str],
    graph: Graph | None = None,
) -> list[dict[str, Any]]:
    """Retrieve Team nodes by IDs including name and slack_channel."""
    if not team_ids:
        return []
    rows, _ = run_ro(Q_GET_TEAMS, {"ids": team_ids}, graph=graph)
    teams: list[dict[str, Any]] = []
    for r in rows:
        teams.append({
            "id": str(r[0]),
            "name": str(r[1]) if r[1] is not None else "",
            "slack_channel": str(r[2]) if r[2] is not None else "",
            "email": str(r[3]) if r[3] is not None else "",
        })
    return teams


def record_notification_action(
    incident_id: str,
    action_id: str,
    target_id: str,
    graph: Graph | None = None,
) -> dict[str, Any]:
    """Record an Action node of type NOTIFY_OWNER in the audit trail."""
    now_ts: str = datetime.datetime.now(datetime.UTC).isoformat()
    _, elapsed_ms = run_rw(
        Q_RECORD_NOTIFICATION,
        {"inc": incident_id, "aid": action_id, "target": target_id, "ts": now_ts},
        graph=graph,
    )
    return {
        "action_id": action_id,
        "incident_id": incident_id,
        "type": "NOTIFY_OWNER",
        "target_id": target_id,
        "status": "EXECUTED",
        "ms": elapsed_ms,
    }


def create_finding(
    incident_id: str,
    finding_id: str,
    kind: str,
    summary: str,
    risk_score: float | None = None,
    evidence_ids: list[str] | None = None,
    graph: Graph | None = None,
) -> dict[str, Any]:
    """Create a Finding node linked to an Incident and link to supporting evidence nodes."""
    now_ts: str = datetime.datetime.now(datetime.UTC).isoformat()
    params: dict[str, Any] = {
        "inc": incident_id,
        "fid": finding_id,
        "kind": kind,
        "summary": summary,
        "risk": risk_score,
        "ts": now_ts,
    }
    _, elapsed_ms = run_rw(Q_CREATE_FINDING, params, graph=graph)

    valid_evidence: list[str] = [e for e in (evidence_ids or []) if e and isinstance(e, str)]
    if valid_evidence:
        run_rw(
            Q_LINK_FINDING_EVIDENCE,
            {"fid": finding_id, "evidence_ids": valid_evidence},
            graph=graph,
        )

    return {
        "finding_id": finding_id,
        "incident_id": incident_id,
        "kind": kind,
        "summary": summary,
        "risk_score": risk_score,
        "evidence_ids": valid_evidence,
        "ms": elapsed_ms,
    }


Q_HEALTH = "MATCH (n) RETURN count(n) AS count"
Q_GRAPH_NODES = (
    "MATCH (n) WHERE labels(n)[0] IN ['Service', 'Database', 'IAMRole'] "
    "RETURN n.id AS id, labels(n)[0] AS label, properties(n) AS props"
)
Q_GRAPH_EDGES = (
    "MATCH (a)-[r]->(b) "
    "WHERE labels(a)[0] IN ['Service', 'Database', 'IAMRole'] "
    "AND labels(b)[0] IN ['Service', 'Database', 'IAMRole'] "
    "RETURN a.id AS src, type(r) AS rel, b.id AS dst, properties(r) AS props"
)


def get_graph_health(graph: Graph | None = None) -> dict[str, Any]:
    """Check graph connection and return total node count."""
    rows, _ = run_ro(Q_HEALTH, graph=graph)
    node_count = int(rows[0][0]) if rows and rows[0] else 0
    return {"ok": True, "graph": "infra", "nodes": node_count}


def get_ui_graph(graph: Graph | None = None) -> dict[str, Any]:
    """Retrieve UI graph containing Service, Database, and IAMRole nodes and connecting edges."""
    node_rows, _ = run_ro(Q_GRAPH_NODES, graph=graph)
    edge_rows, _ = run_ro(Q_GRAPH_EDGES, graph=graph)

    nodes = [
        {"id": str(row[0]), "label": str(row[1]), "props": dict(row[2])}
        for row in node_rows
    ]
    edges = [
        {
            "id": f"{row[0]}|{row[1]}|{row[2]}",
            "source": str(row[0]),
            "target": str(row[2]),
            "type": str(row[1]),
            "props": dict(row[3]),
        }
        for row in edge_rows
    ]
    return {"nodes": nodes, "edges": edges}



