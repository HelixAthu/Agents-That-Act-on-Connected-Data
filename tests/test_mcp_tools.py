"""Tests for MCP graph tools, envelope serialization, and error codes."""

import json

import pytest

from mcp_server.server import (
    compute_risk,
    find_attack_paths,
    get_component_context,
    get_failure_impact,
    rank_critical_components,
    run_readonly_cypher,
)
from seed.seed_graph import seed_graph


@pytest.fixture(scope="session", autouse=True)
def setup_seed_graph() -> None:
    """Ensure graph has fresh canonical seed data before tool tests."""
    seed_graph(reset=True)


def test_get_component_context_success() -> None:
    """Assert Tool 1 get_component_context returns full context with inspect visit."""
    payload = json.loads(get_component_context("svc-payments-gateway"))
    assert payload["ok"] is True
    data = payload["data"]
    assert data["id"] == "svc-payments-gateway"
    assert data["label"] == "Service"
    assert data["owners"] == ["team-payments"]
    assert len(data["vulnerabilities"]) == 1
    assert data["vulnerabilities"][0]["id"] == "vuln-001"
    assert len(data["outgoing"]) >= 5
    assert len(data["incoming"]) >= 3

    visit = payload["visit"]
    assert visit["kind"] == "inspect"
    assert "svc-payments-gateway" in visit["node_ids"]
    assert "svc-payments-gateway|ASSUMES_ROLE|role-storage-manager" in visit["edge_keys"]

    evidence = payload["evidence"]
    assert evidence["query_id"] == "Q-CONTEXT"
    assert evidence["row_count"] == 1


def test_get_component_context_not_found() -> None:
    """Assert Tool 1 returns NOT_FOUND error envelope for unknown component."""
    payload = json.loads(get_component_context("svc-does-not-exist"))
    assert payload["ok"] is False
    assert payload["error"]["code"] == "NOT_FOUND"
    assert "not found" in payload["error"]["message"].lower()


def test_get_component_context_invalid_input() -> None:
    """Assert Tool 1 returns INVALID_INPUT error envelope for empty string."""
    payload = json.loads(get_component_context(""))
    assert payload["ok"] is False
    assert payload["error"]["code"] == "INVALID_INPUT"


def test_get_failure_impact_tool() -> None:
    """Assert Tool 2 get_failure_impact returns reverse impact with impact visit."""
    payload = json.loads(get_failure_impact("svc-config", max_hops=3))
    assert payload["ok"] is True
    data = payload["data"]
    assert data["target"] == "svc-config"
    assert len(data["impacted"]) == 17
    assert data["customer_facing_count"] == 8

    visit = payload["visit"]
    assert visit["kind"] == "impact"
    assert "svc-config" in visit["node_ids"]
    assert len(visit["edge_keys"]) > 0

    evidence = payload["evidence"]
    assert evidence["query_id"] == "Q-IMPACT"


def test_get_failure_impact_invalid_hops() -> None:
    """Assert Tool 2 rejects max_hops out of [1..6] range."""
    payload_low = json.loads(get_failure_impact("svc-config", max_hops=0))
    assert payload_low["ok"] is False
    assert payload_low["error"]["code"] == "INVALID_INPUT"

    payload_high = json.loads(get_failure_impact("svc-config", max_hops=7))
    assert payload_high["ok"] is False
    assert payload_high["error"]["code"] == "INVALID_INPUT"


def test_find_attack_paths_tool() -> None:
    """Assert Tool 3 find_attack_paths returns PII reachability paths with attack_path visit."""
    payload = json.loads(find_attack_paths("svc-payments-gateway", max_hops=6))
    assert payload["ok"] is True
    data = payload["data"]
    assert data["source"] == "svc-payments-gateway"
    assert len(data["paths"]) == 2
    assert data["paths"][0]["target"] == "db-user-billing"
    assert data["paths"][1]["target"] == "db-customer-profile"

    visit = payload["visit"]
    assert visit["kind"] == "attack_path"
    assert "db-user-billing" in visit["node_ids"]
    assert "db-customer-profile" in visit["node_ids"]

    evidence = payload["evidence"]
    assert evidence["query_id"] == "Q-ATTACK"


def test_find_attack_paths_invalid_hops() -> None:
    """Assert Tool 3 rejects invalid max_hops."""
    payload = json.loads(find_attack_paths("svc-payments-gateway", max_hops=10))
    assert payload["ok"] is False
    assert payload["error"]["code"] == "INVALID_INPUT"


def test_rank_critical_components_tool() -> None:
    """Assert Tool 4 rank_critical_components returns ordered ranking."""
    payload = json.loads(rank_critical_components(top_n=5))
    assert payload["ok"] is True
    ranking = payload["data"]["ranking"]
    assert len(ranking) == 5
    assert ranking[0]["id"] == "svc-config"
    assert ranking[0]["transitive_dependents"] == 17

    visit = payload["visit"]
    assert visit["kind"] == "inspect"
    assert "svc-config" in visit["node_ids"]

    evidence = payload["evidence"]
    assert evidence["query_id"] == "Q-RANK"


def test_rank_critical_components_invalid_top_n() -> None:
    """Assert Tool 4 rejects top_n out of range [1..20]."""
    payload = json.loads(rank_critical_components(top_n=25))
    assert payload["ok"] is False
    assert payload["error"]["code"] == "INVALID_INPUT"


def test_run_readonly_cypher_success() -> None:
    """Assert Tool 11 executes valid read-only Cypher query."""
    payload = json.loads(run_readonly_cypher("MATCH (t:Team) RETURN t.id ORDER BY t.id"))
    assert payload["ok"] is True
    data = payload["data"]
    assert data["count"] == 5
    assert data["rows"][0] == ["team-commerce"]

    evidence = payload["evidence"]
    assert evidence["query_id"] == "Q-READONLY"


def test_run_readonly_cypher_policy_denied() -> None:
    """Assert Tool 11 rejects prohibited mutation and procedure keywords."""
    for forbidden in [
        "MATCH (n) DELETE n",
        "CREATE (:Test)",
        "MERGE (:Test)",
        "CALL algo.pageRank()",
    ]:
        payload = json.loads(run_readonly_cypher(forbidden))
        assert payload["ok"] is False
        assert payload["error"]["code"] == "POLICY_DENIED"
        assert "prohibited" in payload["error"]["message"].lower()


def test_compute_risk_tool_payments_gateway_success() -> None:
    """Assert Tool 5 compute_risk computes deterministic score and returns inspect visit for payments gateway."""
    payload = json.loads(compute_risk("svc-payments-gateway"))
    assert payload["ok"] is True
    data = payload["data"]

    # Assert Golden Value G8 within tolerance
    assert abs(data["risk"] - 0.828) <= 0.003
    assert data["attack_target_count"] == 2
    assert data["impacted_cf_count"] == 2
    assert data["vulnerability"]["id"] == "vuln-001"

    components = data["components"]
    assert abs(components["severity"] - 0.98) <= 0.001
    assert components["pii"] == 1.0
    assert abs(components["blast"] - 0.25) <= 0.001
    assert abs(components["central"] - 0.1053) <= 0.001

    visit = payload["visit"]
    assert visit["kind"] == "inspect"
    assert "svc-payments-gateway" in visit["node_ids"]

    evidence = payload["evidence"]
    assert evidence["query_id"] == "Q-RISK-ASSESSMENT"


def test_compute_risk_tool_config_success() -> None:
    """Assert Tool 5 compute_risk computes deterministic score for svc-config."""
    payload = json.loads(compute_risk("svc-config"))
    assert payload["ok"] is True
    data = payload["data"]

    # Assert Golden Value G8 within tolerance
    assert abs(data["risk"] - 0.514) <= 0.003
    assert data["attack_target_count"] == 0
    assert data["impacted_cf_count"] == 8
    assert data["vulnerability"]["id"] == "vuln-005"


def test_compute_risk_tool_not_found() -> None:
    """Assert Tool 5 returns NOT_FOUND error for non-existent component."""
    payload = json.loads(compute_risk("svc-does-not-exist"))
    assert payload["ok"] is False
    assert payload["error"]["code"] == "NOT_FOUND"
    assert "not found" in payload["error"]["message"].lower()


def test_compute_risk_tool_invalid_input() -> None:
    """Assert Tool 5 returns INVALID_INPUT error for empty target ID."""
    payload = json.loads(compute_risk(""))
    assert payload["ok"] is False
    assert payload["error"]["code"] == "INVALID_INPUT"

