"""Tests for MCP graph tools, envelope serialization, and error codes."""

import json
import os

import pytest

from mcp_server.queries import (
    approve_action,
    rollback_node,
    rollback_role,
)
from mcp_server.server import (
    compute_risk,
    execute_containment,
    find_attack_paths,
    get_component_context,
    get_failure_impact,
    notify_owners,
    propose_containment,
    rank_critical_components,
    record_finding,
    rollback_action,
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


@pytest.mark.asyncio
async def test_propose_containment_revoke_role_auto_simulation() -> None:
    """Assert Tool 6 propose_containment evaluates AUTO, runs dry-run simulation, and leaves graph untouched."""
    res = await propose_containment(
        action="REVOKE_ROLE",
        target_id="svc-payments-gateway|role-storage-manager",
        incident_id="inc-test-001",
    )
    payload = json.loads(res)
    assert payload["ok"] is True
    data = payload["data"]

    assert data["policy"]["decision"] == "AUTO"
    assert data["action_id"].startswith("act-")

    sim = data["simulation"]
    assert sim["paths_before"] == 2
    assert sim["paths_after"] == 1
    assert sim["targets_before"] == ["db-customer-profile", "db-user-billing"]
    assert sim["targets_after"] == ["db-user-billing"]

    # Verify simulation was a dry run: graph still has 2 attack paths
    verify_res = json.loads(find_attack_paths("svc-payments-gateway", max_hops=6))
    assert len(verify_res["data"]["paths"]) == 2


@pytest.mark.asyncio
async def test_execute_containment_revoke_role_success() -> None:
    """Assert Tool 7 execute_containment applies write, updates Action to EXECUTED, and post-state matches."""
    res_prop = await propose_containment(
        action="REVOKE_ROLE",
        target_id="svc-payments-gateway|role-storage-manager",
        incident_id="inc-test-002",
    )
    act_id = json.loads(res_prop)["data"]["action_id"]

    try:
        res_exec = await execute_containment(act_id)
        payload = json.loads(res_exec)
        assert payload["ok"] is True
        assert payload["data"]["status"] == "EXECUTED"
        assert payload["data"]["paths_after"] == 1
        assert payload["data"]["targets_after"] == ["db-user-billing"]

        # Verify live graph now reflects the mutation (only 1 attack path left)
        live_paths = json.loads(find_attack_paths("svc-payments-gateway", max_hops=6))
        assert len(live_paths["data"]["paths"]) == 1
    finally:
        # Restore graph to clean state
        rollback_role("svc-payments-gateway|role-storage-manager")
        restored = json.loads(find_attack_paths("svc-payments-gateway", max_hops=6))
        assert len(restored["data"]["paths"]) == 2


@pytest.mark.asyncio
async def test_propose_and_execute_isolate_node_approval_required() -> None:
    """Assert Tool 6/7 enforce APPROVAL_REQUIRED gate and permit execution upon approval."""
    res_prop = await propose_containment(
        action="ISOLATE_NODE",
        target_id="svc-payments-gateway",
        incident_id="inc-test-003",
    )
    payload_prop = json.loads(res_prop)
    assert payload_prop["ok"] is True
    assert payload_prop["data"]["policy"]["decision"] == "APPROVAL_REQUIRED"
    act_id = payload_prop["data"]["action_id"]

    # Execution without approval must fail with APPROVAL_REQUIRED
    res_unapproved = await execute_containment(act_id)
    payload_unapproved = json.loads(res_unapproved)
    assert payload_unapproved["ok"] is False
    assert payload_unapproved["error"]["code"] == "APPROVAL_REQUIRED"

    try:
        # Approve action and execute
        approve_action(act_id, approved_by="sec-admin")
        res_approved = await execute_containment(act_id)
        payload_approved = json.loads(res_approved)
        assert payload_approved["ok"] is True
        assert payload_approved["data"]["status"] == "EXECUTED"
        assert payload_approved["data"]["paths_after"] == 0
        assert payload_approved["data"]["targets_after"] == []
    finally:
        # Rollback node to restore graph
        rollback_node("svc-payments-gateway")
        restored = json.loads(find_attack_paths("svc-payments-gateway", max_hops=6))
        assert len(restored["data"]["paths"]) == 2


@pytest.mark.asyncio
async def test_propose_and_execute_isolate_node_denied() -> None:
    """Assert Tool 6/7 enforce POLICY_DENIED and prevent execution of denied actions."""
    res_prop = await propose_containment(
        action="ISOLATE_NODE",
        target_id="svc-config",
        incident_id="inc-test-004",
    )
    payload_prop = json.loads(res_prop)
    assert payload_prop["ok"] is True
    assert payload_prop["data"]["policy"]["decision"] == "DENIED"
    act_id = payload_prop["data"]["action_id"]

    res_exec = await execute_containment(act_id)
    payload_exec = json.loads(res_exec)
    assert payload_exec["ok"] is False
    assert payload_exec["error"]["code"] == "POLICY_DENIED"


@pytest.mark.asyncio
async def test_containment_invalid_inputs() -> None:
    """Assert validation errors for malformed action names, missing pipes, and unknown actions."""
    # Invalid action
    res_bad_action = await propose_containment("DROP_DATABASE", "svc-config", "inc-005")
    assert json.loads(res_bad_action)["error"]["code"] == "INVALID_INPUT"

    # Revoke role without pipe
    res_bad_target = await propose_containment("REVOKE_ROLE", "svc-config", "inc-005")
    assert json.loads(res_bad_target)["error"]["code"] == "INVALID_INPUT"

    # Execute missing action
    res_missing_action = await execute_containment("act-nonexistent")
    assert json.loads(res_missing_action)["error"]["code"] == "NOT_FOUND"

    # Execute empty string
    res_empty_action = await execute_containment("")
    assert json.loads(res_empty_action)["error"]["code"] == "INVALID_INPUT"


@pytest.mark.asyncio
async def test_rollback_action_tool_success_and_errors() -> None:
    """Assert Tool 8 rollback_action restores graph reachability and prevents double rollbacks."""
    # Setup an executed action
    res_prop = await propose_containment(
        action="REVOKE_ROLE",
        target_id="svc-payments-gateway|role-storage-manager",
        incident_id="inc-test-rb",
    )
    act_id = json.loads(res_prop)["data"]["action_id"]
    await execute_containment(act_id)

    # Roll back the executed action
    res_rb = await rollback_action(act_id)
    payload_rb = json.loads(res_rb)
    assert payload_rb["ok"] is True
    data_rb = payload_rb["data"]
    assert data_rb["status"] == "ROLLED_BACK"
    assert "db-customer-profile" in data_rb["targets_after"]
    assert "db-user-billing" in data_rb["targets_after"]

    # Rolling back an already rolled-back action must fail
    res_rb_again = await rollback_action(act_id)
    payload_rb_again = json.loads(res_rb_again)
    assert payload_rb_again["ok"] is False
    assert payload_rb_again["error"]["code"] == "INVALID_INPUT"

    # Non-existent action ID
    res_missing = await rollback_action("act-missing")
    assert json.loads(res_missing)["error"]["code"] == "NOT_FOUND"


def test_notify_owners_tool_appends_outbox_and_records_action(tmp_path) -> None:
    """Assert Tool 9 notify_owners queries team channels, writes to outbox, and records an action."""
    test_outbox = str(tmp_path / "test_notifications.jsonl")
    os.environ["OUTBOX_PATH"] = test_outbox

    try:
        res = notify_owners(
            incident_id="inc-test-notify-01",
            team_ids=["team-payments", "team-commerce"],
            message="Critical containment action taken on payments gateway",
        )
        payload = json.loads(res)
        assert payload["ok"] is True
        notified = payload["data"]["notified"]
        assert len(notified) == 2
        assert notified[0]["slack_channel"] == "#payments-oncall"
        assert notified[1]["slack_channel"] == "#commerce-oncall"

        # Verify outbox file has appended lines
        assert os.path.exists(test_outbox)
        with open(test_outbox, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
        assert len(lines) == 2
        assert lines[0]["team_id"] == "team-payments"
        assert lines[0]["slack_channel"] == "#payments-oncall"
        assert "payments gateway" in lines[0]["message"]
    finally:
        os.environ.pop("OUTBOX_PATH", None)


def test_record_finding_tool_creates_finding_with_evidence() -> None:
    """Assert Tool 10 record_finding links analytical finding to incident and evidence nodes."""
    res = record_finding(
        incident_id="inc-test-finding-01",
        kind="EXPLOITABLE_VULNERABILITY",
        summary="Remote code execution detected on svc-payments-gateway",
        evidence_ids=["svc-payments-gateway", "vuln-001"],
        risk_score=0.828,
    )
    payload = json.loads(res)
    assert payload["ok"] is True
    data = payload["data"]
    assert data["finding_id"].startswith("finding-")

    visit = payload["visit"]
    assert "svc-payments-gateway" in visit["node_ids"]
    assert "vuln-001" in visit["node_ids"]


def test_notify_and_finding_input_validations() -> None:
    """Assert input validations for notify_owners and record_finding."""
    # Notify owners validations
    assert json.loads(notify_owners("", ["team-payments"], "msg"))["error"]["code"] == "INVALID_INPUT"
    assert json.loads(notify_owners("inc-1", [], "msg"))["error"]["code"] == "INVALID_INPUT"
    assert json.loads(notify_owners("inc-1", ["team-payments"], ""))["error"]["code"] == "INVALID_INPUT"

    # Record finding validations
    assert json.loads(record_finding("", "KIND", "summary"))["error"]["code"] == "INVALID_INPUT"
    assert json.loads(record_finding("inc-1", "", "summary"))["error"]["code"] == "INVALID_INPUT"
    assert json.loads(record_finding("inc-1", "KIND", ""))["error"]["code"] == "INVALID_INPUT"



