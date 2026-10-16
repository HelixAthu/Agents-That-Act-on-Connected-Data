"""Tests for graph seed data, node/edge counts, idempotency, and acyclicity."""

import os
from typing import Any

import pytest
from falkordb import FalkorDB

from seed.seed_graph import assert_acyclic, check_acyclicity, seed_graph


@pytest.fixture(scope="session")
def graph() -> Any:
    """Fixture ensuring the graph is seeded and providing the FalkorDB graph client."""
    seed_graph(reset=False)
    host = os.getenv("FALKORDB_HOST", "localhost")
    port = int(os.getenv("FALKORDB_PORT", "6379"))
    graph_name = os.getenv("GRAPH_NAME", "infra")
    client = FalkorDB(host=host, port=port)
    return client.select_graph(graph_name)


def test_node_counts(graph: Any) -> None:
    """Assert node counts per label match Golden Value G1 (total 41)."""
    expected_node_counts = {
        "Service": 20,
        "Database": 5,
        "IAMRole": 6,
        "Vulnerability": 5,
        "Team": 5,
    }

    for label, expected_count in expected_node_counts.items():
        result = graph.query(f"MATCH (n:{label}) RETURN count(n)").result_set
        actual_count = result[0][0]
        assert actual_count == expected_count, (
            f"Expected {expected_count} {label} nodes, found {actual_count}"
        )

    total_result = graph.query("MATCH (n) RETURN count(n)").result_set
    assert total_result[0][0] == 41, f"Expected 41 total entity nodes, found {total_result[0][0]}"


def test_edge_counts(graph: Any) -> None:
    """Assert relationship counts per type match Golden Value G1 (total 94)."""
    expected_edge_counts = {
        "DEPENDS_ON": 50,
        "CONNECTS_TO": 6,
        "ASSUMES_ROLE": 6,
        "CAN_ASSUME": 2,
        "CAN_ACCESS": 5,
        "OWNS": 20,
        "AFFECTS": 5,
    }

    for etype, expected_count in expected_edge_counts.items():
        result = graph.query(f"MATCH ()-[r:{etype}]->() RETURN count(r)").result_set
        actual_count = result[0][0]
        assert actual_count == expected_count, (
            f"Expected {expected_count} {etype} edges, found {actual_count}"
        )

    total_result = graph.query("MATCH ()-[r]->() RETURN count(r)").result_set
    assert total_result[0][0] == 94, f"Expected 94 total edges, found {total_result[0][0]}"


def test_edges_isolated_property(graph: Any) -> None:
    """Assert every relationship in the seeded graph has isolated=false."""
    invalid_edges = graph.query(
        "MATCH ()-[r]->() WHERE r.isolated IS NULL OR r.isolated <> false RETURN count(r)"
    ).result_set[0][0]
    assert invalid_edges == 0, f"Found {invalid_edges} edges with isolated != false"


def test_each_service_has_exactly_one_owner(graph: Any) -> None:
    """Assert each Service has exactly one owning Team."""
    result = graph.query("""
        MATCH (s:Service)
        OPTIONAL MATCH (t:Team)-[:OWNS]->(s)
        WITH s, count(t) AS owner_count
        WHERE owner_count <> 1
        RETURN s.id, owner_count
    """).result_set
    assert len(result) == 0, f"Services without exactly 1 owner: {result}"


def test_customer_facing_services_count(graph: Any) -> None:
    """Assert exactly 8 services are marked customer_facing (6 tier-1 + recommendation + search)."""
    result = graph.query("MATCH (s:Service {customer_facing: true}) RETURN count(s)").result_set
    assert result[0][0] == 8, f"Expected 8 customer_facing services, found {result[0][0]}"


def test_pii_databases(graph: Any) -> None:
    """Assert exactly 2 databases contain PII (db-user-billing and db-customer-profile)."""
    result = graph.query(
        "MATCH (d:Database {contains_pii: true}) RETURN d.id ORDER BY d.id"
    ).result_set
    pii_ids = [row[0] for row in result]
    assert pii_ids == ["db-customer-profile", "db-user-billing"]


def test_graph_acyclicity(graph: Any) -> None:
    """Assert that the DEPENDS_ON relationship graph in FalkorDB has no cycles."""
    result = graph.query("MATCH (s:Service)-[:DEPENDS_ON*]->(s) RETURN s.id").result_set
    assert len(result) == 0, f"Detected cycles in DEPENDS_ON: {result}"


def test_acyclicity_checker_unit() -> None:
    """Unit test acyclicity detection logic on valid DAG and cyclic edges."""
    dag_edges = [
        {"src": "a", "dst": "b"},
        {"src": "b", "dst": "c"},
        {"src": "a", "dst": "c"},
    ]
    is_dag, cycle = check_acyclicity(dag_edges)
    assert is_dag is True
    assert cycle == []

    cyclic_edges = [
        {"src": "a", "dst": "b"},
        {"src": "b", "dst": "c"},
        {"src": "c", "dst": "a"},
    ]
    is_dag, cycle = check_acyclicity(cyclic_edges)
    assert is_dag is False
    assert len(cycle) > 0

    with pytest.raises(ValueError, match="Cycle detected"):
        assert_acyclic(cyclic_edges)


def test_seed_idempotency(graph: Any) -> None:
    """Assert re-running seed_graph does not duplicate nodes or edges."""
    seed_graph(reset=False)
    nodes_count = graph.query("MATCH (n) RETURN count(n)").result_set[0][0]
    edges_count = graph.query("MATCH ()-[r]->() RETURN count(r)").result_set[0][0]
    assert nodes_count == 41, f"Expected 41 nodes after idempotent seed, found {nodes_count}"
    assert edges_count == 94, f"Expected 94 edges after idempotent seed, found {edges_count}"
