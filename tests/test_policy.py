"""Tests asserting policy truth table coverage, Golden Result G9, and score determinism."""

import pytest

from mcp_server.policy import (
    REASON_HIGH_RISK_AUTO,
    REASON_MODERATE_RISK_APPROVAL,
    REASON_NO_ATTACK_PATH,
    REASON_ROLE_HIGH_RISK_AUTO,
    REASON_ROLE_LOW_RISK_APPROVAL,
    REASON_ROLE_NOT_ON_ATTACK_PATH,
    REASON_TIER1_CUSTOMER_FACING,
    ContainmentAction,
    PolicyDecision,
    decide,
    evaluate_containment_policy,
    is_edge_on_attack_paths,
)
from mcp_server.scoring import compute_target_risk
from seed.seed_graph import seed_graph


@pytest.fixture(scope="session", autouse=True)
def ensure_clean_graph() -> None:
    """Ensure the graph is fresh and populated with canonical seed data before tests run."""
    seed_graph(reset=True)


def test_policy_truth_table_isolate_node_no_attack_path() -> None:
    """Row 1: ISOLATE_NODE with no verified attack path -> DENIED."""
    ctx = {
        "target_id": "svc-isolated",
        "attack_paths": [],
        "attack_target_count": 0,
        "tier": 2,
        "customer_facing": False,
        "risk": 0.95,
    }
    outcome = decide(ContainmentAction.ISOLATE_NODE.value, ctx)
    assert outcome["decision"] == PolicyDecision.DENIED.value
    assert outcome["reason"] == REASON_NO_ATTACK_PATH


def test_policy_truth_table_isolate_node_tier1_customer_facing() -> None:
    """Row 2: ISOLATE_NODE with attack path, tier 1 AND customer facing -> APPROVAL_REQUIRED."""
    ctx = {
        "target_id": "svc-payments-gateway",
        "attack_paths": [{"target": "db-customers", "hops": 2}],
        "attack_target_count": 1,
        "tier": 1,
        "customer_facing": True,
        "risk": 0.95,  # Even with risk >= 0.8, tier-1-cf rule takes priority (first match wins)
    }
    outcome = decide(ContainmentAction.ISOLATE_NODE.value, ctx)
    assert outcome["decision"] == PolicyDecision.APPROVAL_REQUIRED.value
    assert outcome["reason"] == REASON_TIER1_CUSTOMER_FACING


def test_policy_truth_table_isolate_node_high_risk_auto() -> None:
    """Row 3: ISOLATE_NODE with attack path, not tier-1 customer facing, risk >= 0.8 -> AUTO."""
    # Case A: Tier 2 service with customer_facing=True
    ctx_tier2 = {
        "target_id": "svc-backend",
        "attack_paths": [{"target": "db-orders", "hops": 3}],
        "attack_target_count": 1,
        "tier": 2,
        "customer_facing": True,
        "risk": 0.82,
    }
    outcome = decide(ContainmentAction.ISOLATE_NODE.value, ctx_tier2)
    assert outcome["decision"] == PolicyDecision.AUTO.value
    assert outcome["reason"] == REASON_HIGH_RISK_AUTO

    # Case B: Tier 1 service with customer_facing=False (internal tier-1)
    ctx_internal = {
        "target_id": "svc-ledger",
        "attack_paths": [{"target": "db-ledger", "hops": 1}],
        "attack_target_count": 1,
        "tier": 1,
        "customer_facing": False,
        "risk": 0.80,
    }
    outcome_internal = decide(ContainmentAction.ISOLATE_NODE.value, ctx_internal)
    assert outcome_internal["decision"] == PolicyDecision.AUTO.value
    assert outcome_internal["reason"] == REASON_HIGH_RISK_AUTO


def test_policy_truth_table_isolate_node_moderate_risk_approval() -> None:
    """Row 4: ISOLATE_NODE with attack path, not tier-1-cf, risk < 0.8 -> APPROVAL_REQUIRED."""
    ctx = {
        "target_id": "svc-inventory",
        "attack_paths": [{"target": "db-inventory", "hops": 4}],
        "attack_target_count": 1,
        "tier": 2,
        "customer_facing": False,
        "risk": 0.55,
    }
    outcome = decide(ContainmentAction.ISOLATE_NODE.value, ctx)
    assert outcome["decision"] == PolicyDecision.APPROVAL_REQUIRED.value
    assert outcome["reason"] == REASON_MODERATE_RISK_APPROVAL


def test_policy_truth_table_revoke_role_not_on_attack_path() -> None:
    """Row 5: REVOKE_ROLE where edge is not on any verified attack path -> DENIED."""
    ctx = {
        "target_id": "svc-payments-gateway|role-unrelated",
        "service_id": "svc-payments-gateway",
        "role_id": "role-unrelated",
        "edge_on_attack_path": False,
        "risk": 0.90,
    }
    outcome = decide(ContainmentAction.REVOKE_ROLE.value, ctx)
    assert outcome["decision"] == PolicyDecision.DENIED.value
    assert outcome["reason"] == REASON_ROLE_NOT_ON_ATTACK_PATH


def test_policy_truth_table_revoke_role_high_risk_auto() -> None:
    """Row 6: REVOKE_ROLE where edge is on attack path, risk >= 0.5 -> AUTO."""
    ctx = {
        "target_id": "svc-payments-gateway|role-storage-manager",
        "service_id": "svc-payments-gateway",
        "role_id": "role-storage-manager",
        "edge_on_attack_path": True,
        "risk": 0.50,
    }
    outcome = decide(ContainmentAction.REVOKE_ROLE.value, ctx)
    assert outcome["decision"] == PolicyDecision.AUTO.value
    assert outcome["reason"] == REASON_ROLE_HIGH_RISK_AUTO


def test_policy_truth_table_revoke_role_low_risk_approval() -> None:
    """Row 7: REVOKE_ROLE where edge is on attack path, risk < 0.5 -> APPROVAL_REQUIRED."""
    ctx = {
        "target_id": "svc-reports|role-analytics",
        "service_id": "svc-reports",
        "role_id": "role-analytics",
        "edge_on_attack_path": True,
        "risk": 0.49,
    }
    outcome = decide(ContainmentAction.REVOKE_ROLE.value, ctx)
    assert outcome["decision"] == PolicyDecision.APPROVAL_REQUIRED.value
    assert outcome["reason"] == REASON_ROLE_LOW_RISK_APPROVAL


def test_is_edge_on_attack_paths_helper() -> None:
    """Verify helper detecting whether a specific role assumption edge resides in attack paths."""
    attack_paths = [
        {
            "target": "db-customer-profile",
            "edge_keys": [
                "svc-payments-gateway|ASSUMES_ROLE|role-storage-manager",
                "role-storage-manager|CAN_ASSUME|role-data-admin",
                "role-data-admin|CAN_ACCESS|db-customer-profile",
            ],
            "node_ids": [
                "svc-payments-gateway",
                "role-storage-manager",
                "role-data-admin",
                "db-customer-profile",
            ],
        }
    ]

    # Present edge
    assert is_edge_on_attack_paths("svc-payments-gateway", "role-storage-manager", attack_paths) is True

    # Absent edge (different service or role)
    assert is_edge_on_attack_paths("svc-payments-gateway", "role-other", attack_paths) is False
    assert is_edge_on_attack_paths("svc-other", "role-storage-manager", attack_paths) is False
    assert is_edge_on_attack_paths("svc-payments-gateway", "role-storage-manager", []) is False


def test_g9_revoke_role_payments_gateway_auto() -> None:
    """Assert Golden Result G9: propose_containment(REVOKE_ROLE, gateway|role-storage) -> AUTO."""
    result = evaluate_containment_policy(
        action=ContainmentAction.REVOKE_ROLE.value,
        target_id="svc-payments-gateway|role-storage-manager",
    )

    policy = result["policy"]
    assert policy["decision"] == PolicyDecision.AUTO.value
    assert policy["reason"] == REASON_ROLE_HIGH_RISK_AUTO
    assert result["risk"] >= 0.5
    assert result["context"]["edge_on_attack_path"] is True


def test_g9_isolate_payments_gateway_approval_required() -> None:
    """Assert Golden Result G9: propose_containment(ISOLATE_NODE, gateway) -> APPROVAL_REQUIRED."""
    result = evaluate_containment_policy(
        action=ContainmentAction.ISOLATE_NODE.value,
        target_id="svc-payments-gateway",
    )

    policy = result["policy"]
    assert policy["decision"] == PolicyDecision.APPROVAL_REQUIRED.value
    assert policy["reason"] == REASON_TIER1_CUSTOMER_FACING
    assert result["context"]["tier"] == 1
    assert result["context"]["customer_facing"] is True
    assert result["context"]["attack_target_count"] > 0


def test_g9_isolate_config_service_denied() -> None:
    """Assert Golden Result G9: propose_containment(ISOLATE_NODE, svc-config) -> DENIED."""
    result = evaluate_containment_policy(
        action=ContainmentAction.ISOLATE_NODE.value,
        target_id="svc-config",
    )

    policy = result["policy"]
    assert policy["decision"] == PolicyDecision.DENIED.value
    assert policy["reason"] == REASON_NO_ATTACK_PATH
    assert result["context"]["attack_target_count"] == 0
    assert len(result["context"]["attack_paths"]) == 0


def test_risk_and_policy_score_determinism_across_3_runs() -> None:
    """Verify scoring and policy evaluation produce identical outputs across 3 consecutive runs."""
    gateway_scores: list[float] = []
    config_scores: list[float] = []
    policy_decisions: list[str] = []

    for _ in range(3):
        gw_risk = compute_target_risk("svc-payments-gateway")
        cfg_risk = compute_target_risk("svc-config")
        policy_res = evaluate_containment_policy(
            ContainmentAction.REVOKE_ROLE.value,
            "svc-payments-gateway|role-storage-manager",
        )

        gateway_scores.append(gw_risk["data"]["risk"])
        config_scores.append(cfg_risk["data"]["risk"])
        policy_decisions.append(policy_res["policy"]["decision"])

    assert len(set(gateway_scores)) == 1, f"Gateway risk scores varied: {gateway_scores}"
    assert len(set(config_scores)) == 1, f"Config risk scores varied: {config_scores}"
    assert len(set(policy_decisions)) == 1, f"Policy decisions varied: {policy_decisions}"
    assert gateway_scores[0] == 0.828
    assert config_scores[0] == 0.513


def test_policy_error_handling() -> None:
    """Assert error handling for unsupported actions, malformed targets, and unknown components."""
    with pytest.raises(ValueError, match="Unknown or unsupported containment action"):
        decide("UNSUPPORTED_ACTION", {})

    with pytest.raises(ValueError, match="target_id for REVOKE_ROLE must be in 'service_id|role_id' format"):
        evaluate_containment_policy(ContainmentAction.REVOKE_ROLE.value, "svc-only-no-pipe")

    with pytest.raises(ValueError, match="target_id must be a non-empty string"):
        evaluate_containment_policy(ContainmentAction.ISOLATE_NODE.value, "")

    with pytest.raises(KeyError, match="Component 'svc-missing' not found"):
        evaluate_containment_policy(ContainmentAction.ISOLATE_NODE.value, "svc-missing")
