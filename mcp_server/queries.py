"""Cypher queries and graph traversal routines for incident analysis."""

from __future__ import annotations

from typing import Any

from falkordb import Graph

from mcp_server.db import run_ro

Q_IMPACT_ID = "Q-IMPACT"
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
