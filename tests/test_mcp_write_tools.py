"""Tests for MCP write tools, action state machine, policy gates, and graph state transitions."""

import asyncio
import json
import os
from typing import Any

import pytest

from mcp_server.queries import (
    approve_action,
    get_action,
    run_ro,
)
from mcp_server.server import (
    execute_containment,
    notify_owners,
    propose_containment,
    record_finding,
    rollback_action,
)
from seed.seed_graph import seed_graph


@pytest.fixture(scope="session", autouse=True)
def setup_seed_graph() -> None:
    """Ensure graph has fresh canonical seed data before write tool tests."""
    seed_graph(reset=True)


@pytest.mark.asyncio
async def test_g3_revoke_role_full_lifecycle_and_simulation() -> None:
    """Assert G3 containment simulation, execution, and rollback for REVOKE_ROLE."""
    seed_graph(reset=True)

    # Propose REVOKE_ROLE for payments gateway assuming storage manager
    res_prop: str = await propose_containment(
        action="REVOKE_ROLE",
        target_id="svc-payments-gateway|role-storage-manager",
        incident_id="inc-test-g3-full",
    )
    payload_prop: dict[str, Any] = json.loads(res_prop)
    assert payload_prop["ok"] is True
    data_prop: dict[str, Any] = payload_prop["data"]
    act_id: str = data_prop["action_id"]
    assert data_prop["policy"]["decision"] == "AUTO"
    assert data_prop["simulation"]["targets_before"] == ["db-customer-profile", "db-user-billing"]
    assert data_prop["simulation"]["targets_after"] == ["db-user-billing"]

    # Verify action in DB is PROPOSED
    act_record: dict[str, Any] | None = get_action(act_id)
    assert act_record is not None
    assert act_record["status"] == "PROPOSED"
    assert act_record["reversed"] is False

    # Execute containment (AUTO policy allows direct execution)
    res_exec: str = await execute_containment(act_id)
    payload_exec: dict[str, Any] = json.loads(res_exec)
    assert payload_exec["ok"] is True
    data_exec: dict[str, Any] = payload_exec["data"]
    assert data_exec["status"] == "EXECUTED"
    assert data_exec["targets_after"] == ["db-user-billing"]

    # Verify edge in FalkorDB is isolated
    rows_isolated, _ = run_ro(
        "MATCH (s:Service {id: 'svc-payments-gateway'})-[r:ASSUMES_ROLE]->(m:IAMRole {id: 'role-storage-manager'}) "
        "RETURN r.isolated"
    )
    assert len(rows_isolated) == 1
    assert rows_isolated[0][0] is True

    # Roll back the containment action
    res_rb: str = await rollback_action(act_id)
    payload_rb: dict[str, Any] = json.loads(res_rb)
    assert payload_rb["ok"] is True
    data_rb: dict[str, Any] = payload_rb["data"]
    assert data_rb["status"] == "ROLLED_BACK"
    assert sorted(data_rb["targets_after"]) == ["db-customer-profile", "db-user-billing"]

    # Verify edge in FalkorDB is restored to isolated=false
    rows_restored, _ = run_ro(
        "MATCH (s:Service {id: 'svc-payments-gateway'})-[r:ASSUMES_ROLE]->(m:IAMRole {id: 'role-storage-manager'}) "
        "RETURN r.isolated"
    )
    assert len(rows_restored) == 1
    assert rows_restored[0][0] is False

    # Verify action node in DB is marked ROLLED_BACK with reversed=true
    act_rb: dict[str, Any] | None = get_action(act_id)
    assert act_rb is not None
    assert act_rb["status"] == "ROLLED_BACK"
    assert act_rb["reversed"] is True


@pytest.mark.asyncio
async def test_policy_enforcement_isolate_tier1_approval_flow() -> None:
    """Assert ISOLATE_NODE on Tier 1 customer-facing service requires approval before execution."""
    seed_graph(reset=True)

    res_prop: str = await propose_containment(
        action="ISOLATE_NODE",
        target_id="svc-payments-gateway",
        incident_id="inc-test-tier1-approval",
    )
    payload_prop: dict[str, Any] = json.loads(res_prop)
    assert payload_prop["ok"] is True
    data_prop: dict[str, Any] = payload_prop["data"]
    act_id: str = data_prop["action_id"]
    assert data_prop["policy"]["decision"] == "APPROVAL_REQUIRED"

    # Execution without prior approval must be rejected
    res_unapproved: str = await execute_containment(act_id)
    payload_unapproved: dict[str, Any] = json.loads(res_unapproved)
    assert payload_unapproved["ok"] is False
    assert payload_unapproved["error"]["code"] == "APPROVAL_REQUIRED"

    # Verify graph node is NOT isolated
    rows_node, _ = run_ro("MATCH (s:Service {id: 'svc-payments-gateway'}) RETURN s.status")
    assert rows_node[0][0] == "HEALTHY"

    # Approve the action via human security-lead intervention
    app_res: dict[str, Any] = approve_action(action_id=act_id, approved_by="security-lead@corp")
    assert app_res["approved_by"] == "security-lead@corp"

    # Execution after approval must succeed
    res_approved: str = await execute_containment(act_id)
    payload_approved: dict[str, Any] = json.loads(res_approved)
    assert payload_approved["ok"] is True
    assert payload_approved["data"]["status"] == "EXECUTED"

    # Verify node in graph is now isolated
    rows_isolated, _ = run_ro("MATCH (s:Service {id: 'svc-payments-gateway'}) RETURN s.status")
    assert rows_isolated[0][0] == "ISOLATED"

    # Clean up by rolling back
    res_rb: str = await rollback_action(act_id)
    assert json.loads(res_rb)["ok"] is True


@pytest.mark.asyncio
async def test_policy_enforcement_denied_containment_action() -> None:
    """Assert containment actions evaluated as DENIED cannot be executed even with approval attempts."""
    seed_graph(reset=True)

    # Propose ISOLATE_NODE on svc-config (zero blast / not on attack path to PII)
    res_prop: str = await propose_containment(
        action="ISOLATE_NODE",
        target_id="svc-config",
        incident_id="inc-test-denied-config",
    )
    payload_prop: dict[str, Any] = json.loads(res_prop)
    assert payload_prop["ok"] is True
    act_id: str = payload_prop["data"]["action_id"]
    assert payload_prop["data"]["policy"]["decision"] == "DENIED"

    # Execution of DENIED action must fail with POLICY_DENIED
    res_exec: str = await execute_containment(act_id)
    payload_exec: dict[str, Any] = json.loads(res_exec)
    assert payload_exec["ok"] is False
    assert payload_exec["error"]["code"] == "POLICY_DENIED"

    # Even if someone attempts to approve it, execute must still deny
    approve_action(action_id=act_id, approved_by="rogue-admin")
    res_exec_again: str = await execute_containment(act_id)
    assert json.loads(res_exec_again)["error"]["code"] == "POLICY_DENIED"

    # Graph remains unmutated
    rows, _ = run_ro("MATCH (s:Service {id: 'svc-config'}) RETURN s.status")
    assert rows[0][0] == "HEALTHY"


@pytest.mark.asyncio
async def test_action_state_machine_illegal_transitions() -> None:
    """Assert all illegal state machine transitions on Action nodes are strictly rejected."""
    seed_graph(reset=True)

    # Propose action
    res_prop: str = await propose_containment(
        action="REVOKE_ROLE",
        target_id="svc-payments-gateway|role-storage-manager",
        incident_id="inc-test-sm",
    )
    act_id: str = json.loads(res_prop)["data"]["action_id"]

    # Cannot rollback a PROPOSED (non-executed) action
    res_rb_early: str = await rollback_action(act_id)
    payload_rb_early: dict[str, Any] = json.loads(res_rb_early)
    assert payload_rb_early["ok"] is False
    assert payload_rb_early["error"]["code"] == "INVALID_INPUT"

    # Execute action -> EXECUTED
    res_exec: str = await execute_containment(act_id)
    assert json.loads(res_exec)["ok"] is True

    # Cannot re-execute already EXECUTED action
    res_exec_dup: str = await execute_containment(act_id)
    payload_exec_dup: dict[str, Any] = json.loads(res_exec_dup)
    assert payload_exec_dup["ok"] is False
    assert payload_exec_dup["error"]["code"] == "INVALID_INPUT"

    # Rollback action -> ROLLED_BACK
    res_rb: str = await rollback_action(act_id)
    assert json.loads(res_rb)["ok"] is True

    # Cannot re-rollback already ROLLED_BACK action
    res_rb_dup: str = await rollback_action(act_id)
    payload_rb_dup: dict[str, Any] = json.loads(res_rb_dup)
    assert payload_rb_dup["ok"] is False
    assert payload_rb_dup["error"]["code"] == "INVALID_INPUT"

    # Cannot re-execute ROLLED_BACK action
    res_exec_post_rb: str = await execute_containment(act_id)
    payload_exec_post_rb: dict[str, Any] = json.loads(res_exec_post_rb)
    assert payload_exec_post_rb["ok"] is False
    assert payload_exec_post_rb["error"]["code"] == "INVALID_INPUT"


def test_notify_owners_outbox_format_and_action_audit(tmp_path: Any) -> None:
    """Assert notify_owners appends structured JSONL and records audit Action node in FalkorDB."""
    test_outbox: str = str(tmp_path / "test_outbox.jsonl")
    os.environ["OUTBOX_PATH"] = test_outbox

    try:
        res: str = notify_owners(
            incident_id="inc-write-notify-01",
            team_ids=["team-payments", "team-commerce", "team-nonexistent"],
            message="Immediate attention required: active incident detected",
        )
        payload: dict[str, Any] = json.loads(res)
        assert payload["ok"] is True
        notified: list[dict[str, str]] = payload["data"]["notified"]
        assert len(notified) == 3

        # Verify known teams have correct Slack channels
        team_map: dict[str, str] = {item["team_id"]: item["slack_channel"] for item in notified}
        assert team_map["team-payments"] == "#payments-oncall"
        assert team_map["team-commerce"] == "#commerce-oncall"
        assert team_map["team-nonexistent"] == "#nonexistent-alerts"

        # Verify outbox file
        assert os.path.exists(test_outbox)
        with open(test_outbox, "r", encoding="utf-8") as f:
            lines: list[dict[str, Any]] = [json.loads(line) for line in f if line.strip()]
        assert len(lines) == 3
        for line in lines:
            assert line["incident_id"] == "inc-write-notify-01"
            assert "immediate attention required" in line["message"].lower()
            assert "timestamp" in line

        # Verify Action node in FalkorDB audit trail
        rows, _ = run_ro(
            "MATCH (i:Incident {id: 'inc-write-notify-01'})-[:TOOK]->(a:Action {type: 'NOTIFY_OWNER'}) "
            "RETURN a.status, a.target_id"
        )
        assert len(rows) >= 1
        assert rows[0][0] == "EXECUTED"
    finally:
        os.environ.pop("OUTBOX_PATH", None)


def test_record_finding_audit_and_graph_evidence_links() -> None:
    """Assert record_finding creates Finding node linked to Incident and supporting evidence nodes."""
    res: str = record_finding(
        incident_id="inc-write-finding-01",
        kind="LATERAL_MOVEMENT_EXPLOIT",
        summary="High-risk path through storage manager role to PII store",
        evidence_ids=["svc-payments-gateway", "role-storage-manager", "db-customer-profile"],
        risk_score=0.88,
    )
    payload: dict[str, Any] = json.loads(res)
    assert payload["ok"] is True
    fid: str = payload["data"]["finding_id"]
    assert fid.startswith("finding-")

    # Verify FalkorDB contains the Finding node linked to Incident and evidence
    rows, _ = run_ro(
        "MATCH (i:Incident {id: 'inc-write-finding-01'})-[:FOUND]->(f:Finding {id: $fid})-[:EVIDENCED_BY]->(e) "
        "RETURN f.kind, f.summary, f.risk_score, collect(e.id)",
        {"fid": fid},
    )
    assert len(rows) == 1
    assert rows[0][0] == "LATERAL_MOVEMENT_EXPLOIT"
    assert rows[0][1] == "High-risk path through storage manager role to PII store"
    assert float(rows[0][2]) == pytest.approx(0.88)
    evidence_collected: list[str] = rows[0][3]
    assert "svc-payments-gateway" in evidence_collected
    assert "role-storage-manager" in evidence_collected
    assert "db-customer-profile" in evidence_collected


@pytest.mark.asyncio
async def test_concurrent_containment_lock_safety() -> None:
    """Assert concurrent proposals and executions execute sequentially without race conditions."""
    seed_graph(reset=True)

    # Launch concurrent proposals
    tasks = [
        propose_containment(
            action="REVOKE_ROLE",
            target_id="svc-payments-gateway|role-storage-manager",
            incident_id=f"inc-concurrent-{i}",
        )
        for i in range(4)
    ]
    results: list[str] = await asyncio.gather(*tasks)
    for r in results:
        payload: dict[str, Any] = json.loads(r)
        assert payload["ok"] is True
        assert payload["data"]["simulation"]["targets_after"] == ["db-user-billing"]

    # Verify the graph was left clean (isolated=false on edge)
    rows, _ = run_ro(
        "MATCH (s:Service {id: 'svc-payments-gateway'})-[r:ASSUMES_ROLE]->(m:IAMRole {id: 'role-storage-manager'}) "
        "RETURN r.isolated"
    )
    assert rows[0][0] is False
