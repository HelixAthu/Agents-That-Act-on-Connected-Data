"""Tests asserting deterministic risk scoring logic and Golden Result G8."""

import pytest

from mcp_server.scoring import (
    calculate_risk,
    compute_blast_score,
    compute_centrality_score,
    compute_pii_score,
    compute_severity,
    compute_target_risk,
    evaluate_risk,
)
from seed.seed_graph import seed_graph


@pytest.fixture(scope="session", autouse=True)
def ensure_clean_graph() -> None:
    """Ensure the graph is fresh and populated with canonical seed data before tests run."""
    seed_graph(reset=True)


def test_compute_severity_edge_cases() -> None:
    """Verify severity computation across empty, unexploitable, and multi-vuln cases."""
    # Empty vulnerabilities list or None
    assert compute_severity([]) == (0.0, None)
    assert compute_severity(None) == (0.0, None)

    # Single unexploitable vulnerability: cvss 5.4 * 0.6 / 10 = 0.324
    vuln_unexploitable = [{"id": "v1", "cvss": 5.4, "exploitable": False}]
    score, top_vuln = compute_severity(vuln_unexploitable)
    assert score == 0.324
    assert top_vuln == vuln_unexploitable[0]

    # Single exploitable vulnerability: cvss 9.8 * 1.0 / 10 = 0.98
    vuln_exploitable = [{"id": "v2", "cvss": 9.8, "exploitable": True}]
    score, top_vuln = compute_severity(vuln_exploitable)
    assert score == 0.98
    assert top_vuln == vuln_exploitable[0]

    # Multiple vulnerabilities: picks the highest weighted score
    mixed_vulns = [
        {"id": "v1", "cvss": 8.0, "exploitable": False},  # 8.0 * 0.6 / 10 = 0.48
        {"id": "v2", "cvss": 7.0, "exploitable": True},   # 7.0 * 1.0 / 10 = 0.70
        {"id": "v3", "cvss": 6.0, "exploitable": False},  # 6.0 * 0.6 / 10 = 0.36
    ]
    score, top_vuln = compute_severity(mixed_vulns)
    assert score == 0.7
    assert top_vuln is not None
    assert top_vuln["id"] == "v2"


def test_compute_pii_score_edge_cases() -> None:
    """Verify PII exposure score calculation across hop boundaries."""
    assert compute_pii_score([]) == 0.0
    assert compute_pii_score(None) == 0.0

    # Short paths: 1, 2, or 3 hops -> 1.0
    assert compute_pii_score([{"hops": 1}]) == 1.0
    assert compute_pii_score([{"hops": 2}, {"hops": 4}]) == 1.0
    assert compute_pii_score([{"hops": 3}]) == 1.0

    # Medium paths: 4, 5, or 6 hops -> 0.7
    assert compute_pii_score([{"hops": 4}]) == 0.7
    assert compute_pii_score([{"hops": 5}, {"hops": 6}]) == 0.7
    assert compute_pii_score([{"hops": 6}]) == 0.7

    # Longer paths: > 6 hops -> 0.0
    assert compute_pii_score([{"hops": 7}]) == 0.0


def test_compute_blast_score_edge_cases() -> None:
    """Verify failure blast score calculation, customer-facing filtering, and target exclusion."""
    assert compute_blast_score([]) == (0.0, 0)
    assert compute_blast_score(None) == (0.0, 0)

    # 2 customer-facing services impacted: 2 / 8 = 0.25
    impacted = [
        {"id": "svc-checkout-ui", "customer_facing": True},
        {"id": "svc-web-portal", "customer_facing": True},
        {"id": "svc-internal-worker", "customer_facing": False},
    ]
    score, count = compute_blast_score(impacted, target_id="svc-target")
    assert score == 0.25
    assert count == 2

    # Target itself is customer facing and must be excluded
    impacted_with_target = [
        {"id": "svc-target", "customer_facing": True},
        {"id": "svc-checkout-ui", "customer_facing": True},
    ]
    score, count = compute_blast_score(impacted_with_target, target_id="svc-target")
    assert score == 0.125
    assert count == 1


def test_compute_centrality_score_edge_cases() -> None:
    """Verify centrality score calculation for services and non-services."""
    # Non-service targets always receive 0.0
    assert compute_centrality_score(10, is_service=False) == 0.0
    assert compute_centrality_score(0, is_service=True) == 0.0

    # Service with 2 dependents: 2 / 19 = 0.1053
    assert compute_centrality_score(2, is_service=True) == 0.1053

    # Service with 17 dependents: 17 / 19 = 0.8947
    assert compute_centrality_score(17, is_service=True) == 0.8947


def test_calculate_risk_weights() -> None:
    """Verify deterministic risk combination weights and precision."""
    # All zeros
    assert calculate_risk(0.0, 0.0, 0.0, 0.0) == 0.0

    # All ones: 0.40 + 0.40 + 0.10 + 0.10 = 1.0
    assert calculate_risk(1.0, 1.0, 1.0, 1.0) == 1.0

    # Individual component contributions
    assert calculate_risk(1.0, 0.0, 0.0, 0.0) == 0.400
    assert calculate_risk(0.0, 1.0, 0.0, 0.0) == 0.400
    assert calculate_risk(0.0, 0.0, 1.0, 0.0) == 0.100
    assert calculate_risk(0.0, 0.0, 0.0, 1.0) == 0.100


def test_evaluate_risk_pure_output() -> None:
    """Verify pure evaluation dictionary output schema and sub-scores."""
    result = evaluate_risk(
        target_id="svc-test",
        is_service=True,
        vulnerabilities=[{"id": "v1", "cvss": 9.8, "exploitable": True}],
        attack_paths=[{"target": "db-pii-1", "hops": 2}, {"target": "db-pii-2", "hops": 4}],
        impacted_services=[{"id": "svc-ui", "customer_facing": True}],
        transitive_dependents=2,
    )

    assert result["target_id"] == "svc-test"
    assert result["risk"] > 0.0
    assert result["components"]["severity"] == 0.98
    assert result["components"]["pii"] == 1.0
    assert result["components"]["blast"] == 0.125
    assert result["components"]["central"] == 0.1053
    assert result["attack_target_count"] == 2
    assert result["impacted_cf_count"] == 1
    assert result["vulnerability"]["id"] == "v1"


def test_g8_payments_gateway_risk_score() -> None:
    """Assert Golden Result G8: svc-payments-gateway risk score ≈ 0.828 (tolerance ±0.003)."""
    result = compute_target_risk("svc-payments-gateway")
    data = result["data"]

    # Assert G8 tolerance bounds
    assert abs(data["risk"] - 0.828) <= 0.003, f"Expected risk ≈ 0.828, got {data['risk']}"

    # Verify component scores
    components = data["components"]
    assert abs(components["severity"] - 0.98) <= 0.001
    assert components["pii"] == 1.0
    assert abs(components["blast"] - 0.25) <= 0.001
    assert abs(components["central"] - 0.1053) <= 0.001

    # Verify contextual counts
    assert data["attack_target_count"] == 2
    assert data["impacted_cf_count"] == 2
    assert data["vulnerability"]["id"] == "vuln-001"

    # Verify visit and evidence metadata
    assert result["visit"]["kind"] == "inspect"
    assert "svc-payments-gateway" in result["visit"]["node_ids"]
    assert result["evidence"]["query_id"] == "Q-RISK-ASSESSMENT"


def test_g8_config_service_risk_score() -> None:
    """Assert Golden Result G8: svc-config risk score ≈ 0.514 (tolerance ±0.003)."""
    result = compute_target_risk("svc-config")
    data = result["data"]

    # Assert G8 tolerance bounds (observed: 0.513)
    assert abs(data["risk"] - 0.514) <= 0.003, f"Expected risk ≈ 0.514, got {data['risk']}"

    # Verify component scores
    components = data["components"]
    assert abs(components["severity"] - 0.81) <= 0.001
    assert components["pii"] == 0.0
    assert abs(components["blast"] - 1.0) <= 0.001
    assert abs(components["central"] - 0.8947) <= 0.001

    # Verify contextual counts
    assert data["attack_target_count"] == 0
    assert data["impacted_cf_count"] == 8
    assert data["vulnerability"]["id"] == "vuln-005"


def test_compute_target_risk_error_handling() -> None:
    """Assert validation errors for empty IDs and missing components."""
    with pytest.raises(ValueError, match="target_id must be a non-empty string"):
        compute_target_risk("")

    with pytest.raises(KeyError, match="Component 'svc-unknown' not found"):
        compute_target_risk("svc-unknown")
