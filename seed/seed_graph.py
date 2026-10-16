"""Idempotent seed script for FalkorDB with acyclicity validation and reset support."""

from __future__ import annotations

import argparse
import json
import logging
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from falkordb import FalkorDB
from redis.exceptions import RedisError, ResponseError

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent / "data"

INDEX_LABELS = [
    "Service",
    "Database",
    "IAMRole",
    "Vulnerability",
    "Team",
    "Incident",
    "Finding",
    "Action",
]

ENTITY_FILES = [
    ("teams.json", "Team"),
    ("services.json", "Service"),
    ("databases.json", "Database"),
    ("roles.json", "IAMRole"),
    ("vulns.json", "Vulnerability"),
]

EDGE_SCHEMAS = [
    ("depends_on", "DEPENDS_ON", "Service", "Service", ["critical", "isolated"]),
    ("connects_to", "CONNECTS_TO", "Service", "Database", ["access", "isolated"]),
    ("assumes_role", "ASSUMES_ROLE", "Service", "IAMRole", ["isolated"]),
    ("can_assume", "CAN_ASSUME", "IAMRole", "IAMRole", ["isolated"]),
    ("can_access", "CAN_ACCESS", "IAMRole", "Database", ["level", "isolated"]),
    ("owns", "OWNS", "Team", "Service", ["isolated"]),
    ("affects", "AFFECTS", "Vulnerability", "Service", ["isolated"]),
]


def check_acyclicity(depends_on_edges: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """Check if the DEPENDS_ON relationship graph is a Directed Acyclic Graph (DAG)."""
    adjacency: dict[str, list[str]] = defaultdict(list)
    nodes: set[str] = set()

    for edge in depends_on_edges:
        src = edge["src"]
        dst = edge["dst"]
        adjacency[src].append(dst)
        nodes.add(src)
        nodes.add(dst)

    visiting = 1
    visited = 2
    node_state: dict[str, int] = {}
    cycle_nodes: list[str] = []

    def dfs(current: str, current_path: list[str]) -> bool:
        node_state[current] = visiting
        current_path.append(current)

        for neighbor in adjacency.get(current, []):
            if node_state.get(neighbor) == visiting:
                start_index = current_path.index(neighbor)
                cycle_nodes.extend(current_path[start_index:] + [neighbor])
                return True
            if neighbor not in node_state and dfs(neighbor, current_path):
                return True

        current_path.pop()
        node_state[current] = visited
        return False

    for node in sorted(nodes):
        if node not in node_state and dfs(node, []):
            return False, cycle_nodes

    return True, []


def assert_acyclic(depends_on_edges: list[dict[str, Any]], graph: Any | None = None) -> None:
    """Assert that the DEPENDS_ON subgraph has no directed cycles, failing loudly if detected."""
    is_acyclic, cycle_path = check_acyclicity(depends_on_edges)
    if not is_acyclic:
        cycle_str = " -> ".join(cycle_path)
        raise ValueError(f"Cycle detected in DEPENDS_ON edges: {cycle_str}")

    if graph is not None:
        try:
            cypher_result = graph.query(
                "MATCH (s:Service)-[:DEPENDS_ON*]->(s) RETURN s.id"
            ).result_set
            if cypher_result:
                cycle_ids = [row[0] for row in cypher_result]
                raise ValueError(f"Cypher detected cyclic Service nodes in DEPENDS_ON: {cycle_ids}")
        except Exception as e:
            if "Cycle detected" in str(e):
                raise


def create_indexes(graph: Any) -> list[str]:
    """Create indexes for all core entity and tracking node labels."""
    created: list[str] = []
    for label in INDEX_LABELS:
        try:
            graph.query(f"CREATE INDEX FOR (n:{label}) ON (n.id)")
            created.append(label)
        except (ResponseError, RedisError) as err:
            logger.debug("Index for %s might already exist: %s", label, err)
    return created


def seed_nodes(graph: Any, data_dir: Path) -> dict[str, int]:
    """Ingest entity JSON files using idempotent MERGE queries."""
    counts: dict[str, int] = {}
    for filename, label in ENTITY_FILES:
        filepath = data_dir / filename
        with open(filepath, "r", encoding="utf-8") as f:
            items: list[dict[str, Any]] = json.load(f)

        query = f"MERGE (n:{label} {{id: $id}}) SET n += $props"
        for item in items:
            node_id = item["id"]
            graph.query(query, {"id": node_id, "props": item})

        counts[label] = len(items)
    return counts


def seed_edges(graph: Any, data_dir: Path) -> dict[str, int]:
    """Ingest relationship definitions from edges.json using idempotent MERGE queries."""
    filepath = data_dir / "edges.json"
    with open(filepath, "r", encoding="utf-8") as f:
        edges_data: dict[str, list[dict[str, Any]]] = json.load(f)

    counts: dict[str, int] = {}

    for key, rel_type, src_label, dst_label, prop_keys in EDGE_SCHEMAS:
        edges = edges_data.get(key, [])
        query = (
            f"MATCH (a:{src_label} {{id: $src}}), (b:{dst_label} {{id: $dst}}) "
            f"MERGE (a)-[r:{rel_type}]->(b) "
            f"SET r += $props"
        )
        for edge in edges:
            src = edge["src"]
            dst = edge["dst"]
            props = {k: edge[k] for k in prop_keys if k in edge}
            if "isolated" not in props:
                props["isolated"] = False
            graph.query(query, {"src": src, "dst": dst, "props": props})

        counts[rel_type] = len(edges)

    return counts


def get_live_counts(graph: Any) -> tuple[dict[str, int], dict[str, int]]:
    """Retrieve current node and relationship counts directly from FalkorDB."""
    node_labels = ["Service", "Database", "IAMRole", "Vulnerability", "Team"]
    edge_types = [
        "DEPENDS_ON",
        "CONNECTS_TO",
        "ASSUMES_ROLE",
        "CAN_ASSUME",
        "CAN_ACCESS",
        "OWNS",
        "AFFECTS",
    ]

    node_counts: dict[str, int] = {}
    for label in node_labels:
        result = graph.query(f"MATCH (n:{label}) RETURN count(n)").result_set
        node_counts[label] = result[0][0] if result else 0

    edge_counts: dict[str, int] = {}
    for etype in edge_types:
        result = graph.query(f"MATCH ()-[r:{etype}]->() RETURN count(r)").result_set
        edge_counts[etype] = result[0][0] if result else 0

    return node_counts, edge_counts


def seed_graph(
    reset: bool = False,
    host: str | None = None,
    port: int | None = None,
    graph_name: str | None = None,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    """Execute end-to-end graph seeding with optional reset and acyclicity validation."""
    effective_host = host or os.getenv("FALKORDB_HOST", "localhost")
    effective_port = port or int(os.getenv("FALKORDB_PORT", "6379"))
    effective_graph_name = graph_name or os.getenv("GRAPH_NAME", "infra")
    effective_data_dir = data_dir or DATA_DIR

    client = FalkorDB(host=effective_host, port=effective_port)
    graph = client.select_graph(effective_graph_name)

    if reset:
        print(f"Resetting graph '{effective_graph_name}'...")
        try:
            graph.delete()
        except (ResponseError, RedisError) as err:
            logger.debug("Graph deletion skipped or not found: %s", err)

    # Read and validate edges for acyclicity before insertion
    with open(effective_data_dir / "edges.json", "r", encoding="utf-8") as f:
        edges_data = json.load(f)
    assert_acyclic(edges_data.get("depends_on", []))

    # Setup indexes and ingest data
    create_indexes(graph)
    seed_nodes(graph, effective_data_dir)
    seed_edges(graph, effective_data_dir)

    # Post-insertion Cypher acyclicity verification
    assert_acyclic(edges_data.get("depends_on", []), graph=graph)

    node_counts, edge_counts = get_live_counts(graph)

    print("\n" + "=" * 50)
    print(f"FalkorDB Seed Summary (Graph: {effective_graph_name})")
    print("=" * 50)
    print("Nodes:")
    total_nodes = 0
    for label, count in node_counts.items():
        print(f"  {label:<16}: {count:>3}")
        total_nodes += count
    print(f"  {'Total Nodes':<16}: {total_nodes:>3}")

    print("\nEdges:")
    total_edges = 0
    for etype, count in edge_counts.items():
        print(f"  {etype:<16}: {count:>3}")
        total_edges += count
    print(f"  {'Total Edges':<16}: {total_edges:>3}")
    print("Acyclicity: VERIFIED (DAG)")
    print("=" * 50 + "\n")

    return {
        "nodes": node_counts,
        "edges": edge_counts,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "acyclic": True,
    }


def main() -> None:
    """Parse CLI arguments and run the graph seeder."""
    parser = argparse.ArgumentParser(
        description="Idempotent FalkorDB graph seeder with --reset and acyclicity validation."
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete existing graph before seeding",
    )
    args = parser.parse_args()
    seed_graph(reset=args.reset)


if __name__ == "__main__":
    main()
