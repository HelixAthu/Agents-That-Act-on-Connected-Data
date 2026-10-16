"""Tests asserting golden results G2 through G7 for failure impact, attack paths, and ranking."""

import pytest

from mcp_server.queries import (
    count_transitive_dependents,
    find_attack_paths,
    get_failure_impact,
    isolate_node,
    rank_critical_components,
    revoke_role,
    rollback_node,
    rollback_role,
)
from seed.seed_graph import seed_graph


@pytest.fixture(scope="session", autouse=True)
def ensure_clean_graph() -> None:
    """Ensure the graph is fresh and populated with canonical seed data before tests run."""
    seed_graph(reset=True)


def test_g2_attack_paths_from_payments_gateway_fallback() -> None:
    """Assert G2: exactly 2 attack paths from svc-payments-gateway to PII databases."""
    res = find_attack_paths("svc-payments-gateway", max_hops=6, engine="fallback")
    paths = res["paths"]

    assert len(paths) == 2, f"Expected 2 attack paths, found {len(paths)}"

    # Path 1: db-user-billing, 2 hops
    p1 = paths[0]
    assert p1["target"] == "db-user-billing"
    assert p1["hops"] == 2
    assert p1["node_ids"] == ["svc-payments-gateway", "svc-billing", "db-user-billing"]
    assert p1["edge_types"] == ["DEPENDS_ON", "CONNECTS_TO"]
    assert p1["edge_keys"] == [
        "svc-payments-gateway|DEPENDS_ON|svc-billing",
        "svc-billing|CONNECTS_TO|db-user-billing",
    ]

    # Path 2: db-customer-profile, 3 hops
    p2 = paths[1]
    assert p2["target"] == "db-customer-profile"
    assert p2["hops"] == 3
    assert p2["node_ids"] == [
        "svc-payments-gateway",
        "role-storage-manager",
        "role-data-admin",
        "db-customer-profile",
    ]
    assert p2["edge_types"] == ["ASSUMES_ROLE", "CAN_ASSUME", "CAN_ACCESS"]
    assert p2["edge_keys"] == [
        "svc-payments-gateway|ASSUMES_ROLE|role-storage-manager",
        "role-storage-manager|CAN_ASSUME|role-data-admin",
        "role-data-admin|CAN_ACCESS|db-customer-profile",
    ]


def test_g2_attack_paths_from_payments_gateway_cypher() -> None:
    """Assert G2 via direct Cypher engine matches the golden attack paths."""
    res = find_attack_paths("svc-payments-gateway", max_hops=6, engine="cypher")
    paths = res["paths"]

    assert len(paths) == 2
    assert paths[0]["target"] == "db-user-billing" and paths[0]["hops"] == 2
    assert paths[1]["target"] == "db-customer-profile" and paths[1]["hops"] == 3


def test_g3_containment_effects() -> None:
    """Assert G3: containment actions eliminate specific attack paths and rollback restores them."""
    # 1. Revoke role -> only db-user-billing remains reachable
    revoke_res = revoke_role("svc-payments-gateway|role-storage-manager")
    assert revoke_res["status"] == "REVOKED"

    after_revoke = find_attack_paths("svc-payments-gateway", max_hops=6)
    assert [p["target"] for p in after_revoke["paths"]] == ["db-user-billing"]

    # Roll back role revocation
    rb_role_res = rollback_role("svc-payments-gateway", "role-storage-manager")
    assert rb_role_res["status"] == "ACTIVE"

    after_role_rollback = find_attack_paths("svc-payments-gateway", max_hops=6)
    assert len(after_role_rollback["paths"]) == 2

    # 2. Isolate node -> 0 attack paths remain reachable
    isolate_res = isolate_node("svc-payments-gateway")
    assert isolate_res["status"] == "ISOLATED"

    after_isolate = find_attack_paths("svc-payments-gateway", max_hops=6)
    assert len(after_isolate["paths"]) == 0

    # 3. Roll back node isolation -> targets return to G2 result
    rb_node_res = rollback_node("svc-payments-gateway")
    assert rb_node_res["status"] == "HEALTHY"

    after_node_rollback = find_attack_paths("svc-payments-gateway", max_hops=6)
    assert len(after_node_rollback["paths"]) == 2
    assert [p["target"] for p in after_node_rollback["paths"]] == [
        "db-user-billing",
        "db-customer-profile",
    ]


def test_g4_failure_impact_svc_config() -> None:
    """Assert G4: failure impact of svc-config (reverse, max_hops=3) impacts 17 services (8 customer-facing)."""
    impact_res = get_failure_impact("svc-config", max_hops=3)

    impacted = impact_res["impacted"]
    impacted_ids = {item["id"] for item in impacted}

    assert len(impacted) == 17, f"Expected 17 impacted services, got {len(impacted)}"
    assert impact_res["customer_facing_count"] == 8, (
        f"Expected 8 customer facing, got {impact_res['customer_facing_count']}"
    )

    # Specifically excluded per G4: svc-config, svc-session-cache, svc-audit-log
    assert "svc-config" not in impacted_ids
    assert "svc-session-cache" not in impacted_ids
    assert "svc-audit-log" not in impacted_ids


def test_g5_failure_impact_db_orders() -> None:
    """Assert G5: failure impact of db-orders impacts 8 services, 6 customer-facing, across 4 teams."""
    impact_res = get_failure_impact("db-orders", max_hops=3)

    impacted = impact_res["impacted"]
    assert len(impacted) == 8, f"Expected 8 impacted services, found {len(impacted)}"
    assert impact_res["customer_facing_count"] == 6, (
        f"Expected 6 customer-facing, found {impact_res['customer_facing_count']}"
    )

    hop_map = {item["id"]: item["hops"] for item in impacted}
    assert hop_map["svc-order"] == 1
    assert hop_map["svc-mobile-api"] == 2
    assert hop_map["svc-partner-api"] == 2
    assert hop_map["svc-checkout-ui"] == 2
    assert hop_map["svc-payments-gateway"] == 2
    assert hop_map["svc-reporting"] == 2
    assert hop_map["svc-web-portal"] == 3
    assert hop_map["svc-admin-portal"] == 3

    distinct_team_names = {owner["name"] for owner in impact_res["owners"]}
    assert distinct_team_names == {"Commerce", "Experience", "Payments", "Data"}


def test_g6_attack_paths_from_svc_config() -> None:
    """Assert G6: attack paths from svc-config return exactly 0 rows."""
    res = find_attack_paths("svc-config", max_hops=6)
    assert len(res["paths"]) == 0


def test_g7_criticality_ranking() -> None:
    """Assert G7: top-1 is svc-config (17) and svc-catalog has 11 transitive dependents."""
    res = rank_critical_components(top_n=10)
    ranking = res["ranking"]

    assert len(ranking) >= 4
    # Top-1 svc-config (17)
    assert ranking[0]["id"] == "svc-config"
    assert ranking[0]["transitive_dependents"] == 17

    # svc-catalog has 11 transitive dependents
    catalog_entry = next(r for r in ranking if r["id"] == "svc-catalog")
    assert catalog_entry["transitive_dependents"] == 11

    # Individual helper validation
    assert count_transitive_dependents("svc-config") == 17
    assert count_transitive_dependents("svc-catalog") == 11


def test_query_input_validations() -> None:
    """Assert query builder and execution functions raise ValueError on invalid arguments."""
    with pytest.raises(ValueError, match="max_hops must be between 1 and 6"):
        get_failure_impact("svc-order", max_hops=0)

    with pytest.raises(ValueError, match="max_hops must be between 1 and 6"):
        get_failure_impact("svc-order", max_hops=7)

    with pytest.raises(ValueError, match="target_id must be a non-empty string"):
        get_failure_impact("")

    with pytest.raises(ValueError, match="max_hops must be between 1 and 6"):
        find_attack_paths("svc-order", max_hops=10)

    with pytest.raises(ValueError, match="source_id must be a non-empty string"):
        find_attack_paths("")

    with pytest.raises(ValueError, match="top_n must be between 1 and 20"):
        rank_critical_components(top_n=25)
