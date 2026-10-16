"""Tests for event models, EventBus sequence numbers, subscriber queues, and FinalReport validation."""

from pathlib import Path
from typing import Any

import pytest

from backend.events import (
    ActionData,
    ApprovalRequiredData,
    ErrorData,
    Event,
    EventBus,
    EventType,
    FinalReport,
    GraphVisitData,
    IncidentStartedData,
    RiskUpdateData,
    ThoughtData,
    ToolCallData,
    ToolResultData,
    VerificationData,
    validate_final_report_hallucinations,
)


def test_event_payload_models_serialization() -> None:
    """Assert all typed event data payloads serialize cleanly into valid dictionaries."""
    inc = IncidentStartedData(incident_id="inc-1", alert_text="Alert on gateway", mode="mock")
    assert inc.model_dump()["incident_id"] == "inc-1"

    thought = ThoughtData(text="Investigating attack path to PII")
    assert thought.model_dump()["text"] == "Investigating attack path to PII"

    call = ToolCallData(call_id="call-01", tool="get_component_context", args={"component_id": "svc-payments-gateway"})
    assert call.model_dump()["tool"] == "get_component_context"

    visit = GraphVisitData(
        call_id="call-01",
        kind="inspect",
        node_ids=["svc-payments-gateway"],
        edge_keys=["svc-payments-gateway|ASSUMES_ROLE|role-storage-manager"],
    )
    assert len(visit.model_dump()["node_ids"]) == 1

    result = ToolResultData(
        call_id="call-01",
        ok=True,
        summary="Retrieved component context for svc-payments-gateway",
        query_id="Q-CONTEXT",
        ms=1.5,
    )
    assert result.model_dump()["ok"] is True

    risk = RiskUpdateData(risk=0.828, components={"svc-payments-gateway": 0.828})
    assert risk.model_dump()["risk"] == pytest.approx(0.828)

    appr = ApprovalRequiredData(
        action_id="act-01",
        action="ISOLATE_NODE",
        target_id="svc-payments-gateway",
        reason="Tier 1 customer facing",
    )
    assert appr.model_dump()["action"] == "ISOLATE_NODE"

    act = ActionData(
        action_id="act-01",
        action="REVOKE_ROLE",
        target_id="svc-payments-gateway|role-storage-manager",
        status="EXECUTED",
        policy="AUTO",
    )
    assert act.model_dump()["status"] == "EXECUTED"

    verif = VerificationData(
        action_id="act-01",
        targets_before=["db-customer-profile", "db-user-billing"],
        targets_after=["db-user-billing"],
    )
    assert len(verif.model_dump()["targets_after"]) == 1

    err = ErrorData(message="Execution timed out", recoverable=False)
    assert err.model_dump()["recoverable"] is False


@pytest.mark.asyncio
async def test_event_bus_sequential_numbering_and_subscribers() -> None:
    """Assert EventBus assigns consecutive sequence numbers and broadcasts to subscribers."""
    bus: EventBus = EventBus(incident_id="inc-test-bus")

    # Initial state
    assert bus.current_seq == 0
    assert len(bus.get_events()) == 0

    # Emit first two events synchronously
    e1 = bus.emit_sync(EventType.INCIDENT_STARTED, {"incident_id": "inc-test-bus", "alert_text": "Alert"})
    assert e1.seq == 1
    assert e1.type == "incident_started"
    assert e1.data["incident_id"] == "inc-test-bus"

    e2 = bus.emit_sync(EventType.THOUGHT, {"text": "Thinking about attack paths"})
    assert e2.seq == 2
    assert e2.type == "thought"

    # Subscriber with replay_buffered=True must receive e1 and e2 immediately
    sub_replaying = bus.subscribe(replay_buffered=True)
    assert sub_replaying.qsize() == 2
    assert (await sub_replaying.get()).seq == 1
    assert (await sub_replaying.get()).seq == 2

    # Subscriber with replay_buffered=False must be empty initially
    sub_live_only = bus.subscribe(replay_buffered=False)
    assert sub_live_only.qsize() == 0

    # Emit third event asynchronously
    e3 = await bus.emit(EventType.TOOL_CALL, {"call_id": "c1", "tool": "compute_risk", "args": {}})
    assert e3.seq == 3
    assert bus.current_seq == 3

    # Both active subscribers must receive e3
    rec_replaying = await sub_replaying.get()
    assert rec_replaying.seq == 3
    rec_live = await sub_live_only.get()
    assert rec_live.seq == 3

    # Unsubscribe live subscriber and emit e4
    bus.unsubscribe(sub_live_only)
    e4 = await bus.emit(EventType.TOOL_RESULT, {"call_id": "c1", "ok": True, "summary": "Risk computed"})
    assert e4.seq == 4

    assert sub_live_only.qsize() == 0
    assert (await sub_replaying.get()).seq == 4


def test_event_bus_dump_and_load_jsonl(tmp_path: Path) -> None:
    """Assert EventBus dumps valid JSONL to string and file, and can reload verbatim."""
    bus: EventBus = EventBus(incident_id="inc-jsonl")
    bus.emit_sync(EventType.INCIDENT_STARTED, {"incident_id": "inc-jsonl", "alert_text": "Breach detected"})
    bus.emit_sync(EventType.RISK_UPDATE, {"risk": 0.85, "components": {}})

    # Dump to string
    raw_jsonl: str = bus.dump_jsonl()
    loaded_from_str: list[Event] = EventBus.load_jsonl(raw_jsonl)
    assert len(loaded_from_str) == 2
    assert loaded_from_str[0].seq == 1
    assert loaded_from_str[0].type == "incident_started"
    assert loaded_from_str[1].seq == 2
    assert loaded_from_str[1].type == "risk_update"

    # Dump to file on disk
    file_path: Path = tmp_path / "replay.jsonl"
    bus.dump_jsonl(file_path)
    assert file_path.exists()
    loaded_from_file: list[Event] = EventBus.load_jsonl(file_path)
    assert len(loaded_from_file) == 2
    assert loaded_from_file[0].seq == 1
    assert loaded_from_file[1].seq == 2


def test_final_report_model_and_anti_hallucination_guard() -> None:
    """Assert FinalReport schema parses properly and hallucinated node IDs are stripped from findings."""
    report_dict: dict[str, Any] = {
        "incident_id": "inc-sec-01",
        "summary": "Compromised payments gateway contained successfully.",
        "risk_score": 0.828,
        "findings": [
            {
                "claim": "Vulnerability vuln-001 enables exploit on svc-payments-gateway",
                "evidence_refs": ["call-01"],
            },
            {
                "claim": "Attacker moved laterally to svc-ghost-service without auth",
                "evidence_refs": ["call-02"],
            },
        ],
        "impact": {
            "impacted_services": 4,
            "customer_facing": 1,
            "owner_teams": ["team-payments"],
        },
        "actions": [
            {
                "action_id": "act-01",
                "type": "REVOKE_ROLE",
                "target": "svc-payments-gateway|role-storage-manager",
                "policy": "AUTO",
                "status": "EXECUTED",
            }
        ],
        "verification": {
            "targets_before": ["db-customer-profile", "db-user-billing"],
            "targets_after": ["db-user-billing"],
        },
        "tool_calls": [
            {"call_id": "call-01", "tool": "get_component_context", "ms": 2.1, "query_id": "Q-CONTEXT"}
        ],
    }

    report: FinalReport = FinalReport(**report_dict)
    assert report.incident_id == "inc-sec-01"
    assert len(report.findings) == 2

    # Verified nodes seen during tool calls
    allowed_nodes: set[str] = {"svc-payments-gateway", "vuln-001", "team-payments"}

    sanitized_report = validate_final_report_hallucinations(report, allowed_nodes)
    # The second claim mentions 'svc-ghost-service' which is not in allowed_nodes; must be stripped
    assert len(sanitized_report.findings) == 1
    assert "svc-payments-gateway" in sanitized_report.findings[0].claim
