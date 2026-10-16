"""Python BFS fallback for attacker path traversal to PII databases honoring containment."""

from __future__ import annotations

import time
from collections import deque
from typing import Any

from falkordb import Graph

from mcp_server.db import run_ro

ALLOWED_ATTACK_EDGES = {
    "DEPENDS_ON",
    "CONNECTS_TO",
    "ASSUMES_ROLE",
    "CAN_ASSUME",
    "CAN_ACCESS",
}

Q_PII_DATABASES = "MATCH (d:Database {contains_pii: true}) RETURN d.id"
Q_EDGES_ACTIVE = """
MATCH (a)-[r]->(b)
WHERE labels(a)[0] IN ['Service','Database','IAMRole','Vulnerability','Team']
RETURN a.id AS src, type(r) AS rel, b.id AS dst, r.isolated AS isolated
"""


def bfs_attack_paths(
    source_id: str,
    max_hops: int = 6,
    graph: Graph | None = None,
) -> tuple[list[dict[str, Any]], set[str], set[str], float]:
    """Execute BFS from source_id to PII databases up to max_hops, returning valid paths and visited sets."""
    if not (1 <= max_hops <= 6):
        raise ValueError(f"max_hops must be between 1 and 6, got {max_hops}")

    start_time = time.perf_counter()

    pii_rows, _ = run_ro(Q_PII_DATABASES, graph=graph)
    pii_target_ids = {row[0] for row in pii_rows}

    edge_rows, _ = run_ro(Q_EDGES_ACTIVE, graph=graph)

    adjacency: dict[str, list[tuple[str, str]]] = {}
    for src, rel, dst, isolated in edge_rows:
        if rel in ALLOWED_ATTACK_EDGES and not isolated:
            adjacency.setdefault(src, []).append((dst, rel))

    visited_nodes: set[str] = {source_id}
    visited_edges: set[str] = set()
    found_paths: dict[str, dict[str, Any]] = {}

    # Queue contains tuples of: (current_node, [node_ids_in_path], [edge_types_in_path])
    queue: deque[tuple[str, list[str], list[str]]] = deque([(source_id, [source_id], [])])

    while queue:
        current_node, path_nodes, path_rels = queue.popleft()

        if len(path_rels) >= max_hops:
            continue

        for neighbor, rel_type in adjacency.get(current_node, []):
            if neighbor in path_nodes:
                continue

            next_nodes = path_nodes + [neighbor]
            next_rels = path_rels + [rel_type]

            edge_key = f"{current_node}|{rel_type}|{neighbor}"
            visited_nodes.add(neighbor)
            visited_edges.add(edge_key)

            if neighbor in pii_target_ids:
                if neighbor not in found_paths:
                    edge_keys = [
                        f"{next_nodes[i]}|{next_rels[i]}|{next_nodes[i + 1]}"
                        for i in range(len(next_rels))
                    ]
                    found_paths[neighbor] = {
                        "target": neighbor,
                        "hops": len(next_rels),
                        "node_ids": next_nodes,
                        "edge_types": next_rels,
                        "edge_keys": edge_keys,
                    }
            else:
                queue.append((neighbor, next_nodes, next_rels))

    sorted_paths = sorted(
        found_paths.values(),
        key=lambda item: (item["hops"], item["target"]),
    )
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return sorted_paths, visited_nodes, visited_edges, elapsed_ms
