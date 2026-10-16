"""Tests for scripted MockAgent across Scenarios A, B, and C with event stream verification."""


import pytest

from backend.agent_mock import MockAgent
from backend.events import Event, EventBus, FinalReport
from backend.scenarios import (
    SCENARIO_A_ALERT,
    SCENARIO_B_ALERT,
    SCENARIO_C_ALERT,
)
from mcp_server.queries import run_ro
from seed.seed_graph import seed_graph


@pytest.fixture(scope="session", autouse=True)
def setup_seed_graph() -> None:
    """Ensure graph has fresh canonical seed data before mock agent tests."""
    seed_graph(reset=True)


@pytest.mark.asyncio
async def test_mock_agent_scenario_a_attack_and_containment() -> None:
    """Assert Scenario A eliminates all attack paths, verifies graph visits, and finishes report."""
    seed_graph(reset=True)

    bus = EventBus(incident_id="inc-mock-a")
    agent = MockAgent()

    report: FinalReport = await agent.run(
        incident_id="inc-mock-a",
        alert_text=SCENARIO_A_ALERT,
        emit=bus.emit,
        auto_approve=True,
    )

    # 1. Assert final report verification has eliminated all attack targets
    assert report.incident_id == "inc-mock-a"
    assert report.verification.targets_before == ["db-customer-profile", "db-user-billing"]
    assert report.verification.targets_after == []

    # 2. Assert actions taken
    assert len(report.actions) == 2
    assert report.actions[0].type == "REVOKE_ROLE"
    assert report.actions[0].status == "EXECUTED"
    assert report.actions[1].type == "ISOLATE_NODE"
    assert report.actions[1].status == "EXECUTED"

    # 3. Assert events emitted in order
    events: list[Event] = bus.get_events()
    event_types: list[str] = [e.type for e in events]
    assert event_types[0] == "incident_started"
    assert "thought" in event_types
    assert "tool_call" in event_types
    assert "graph_visit" in event_types
    assert "tool_result" in event_types
    assert "risk_update" in event_types
    assert "approval_required" in event_types
    assert "action" in event_types
    assert "verification" in event_types
    assert event_types[-1] == "final_report"

    # 4. Assert every node ID in graph_visit events exists in the FalkorDB graph
    rows, _ = run_ro("MATCH (n) RETURN n.id")
    graph_node_ids: set[str] = {str(r[0]) for r in rows if r[0]}

    visit_events = [e for e in events if e.type == "graph_visit"]
    assert len(visit_events) > 0
    for v in visit_events:
        for nid in v.data.get("node_ids", []):
            assert nid in graph_node_ids, f"Visited node ID '{nid}' not found in FalkorDB graph"


@pytest.mark.asyncio
async def test_mock_agent_scenario_b_database_outage() -> None:
    """Assert Scenario B alerts 4 owner teams across 8 impacted services without containment actions."""
    seed_graph(reset=True)

    bus = EventBus(incident_id="inc-mock-b")
    agent = MockAgent()

    report: FinalReport = await agent.run(
        incident_id="inc-mock-b",
        alert_text=SCENARIO_B_ALERT,
        emit=bus.emit,
    )

    # Assert 8 impacted services and 4 owner teams
    assert report.impact.impacted_services == 8
    assert len(report.impact.owner_teams) == 4
    expected_teams: set[str] = {"team-commerce", "team-data", "team-experience", "team-payments"}
    assert set(report.impact.owner_teams) == expected_teams

    # Assert no containment actions were taken
    assert len(report.actions) == 0
    assert report.verification.targets_before == []
    assert report.verification.targets_after == []

    # Assert all visited nodes exist in graph
    rows, _ = run_ro("MATCH (n) RETURN n.id")
    graph_node_ids: set[str] = {str(r[0]) for r in rows if r[0]}

    events = bus.get_events()
    for v in [e for e in events if e.type == "graph_visit"]:
        for nid in v.data.get("node_ids", []):
            assert nid in graph_node_ids, f"Visited node ID '{nid}' not found in FalkorDB graph"


@pytest.mark.asyncio
async def test_mock_agent_scenario_c_false_alarm_isolation_denied() -> None:
    """Assert Scenario C containment is DENIED with no graph isolation mutations."""
    seed_graph(reset=True)

    bus = EventBus(incident_id="inc-mock-c")
    agent = MockAgent()

    report: FinalReport = await agent.run(
        incident_id="inc-mock-c",
        alert_text=SCENARIO_C_ALERT,
        emit=bus.emit,
    )

    # Assert action proposed was DENIED
    assert len(report.actions) == 1
    assert report.actions[0].type == "ISOLATE_NODE"
    assert report.actions[0].policy == "DENIED"
    assert report.actions[0].status == "PROPOSED"

    # Assert no node in the graph was isolated
    rows, _ = run_ro("MATCH (s:Service {id: 'svc-config'}) RETURN s.status")
    assert rows[0][0] == "HEALTHY"

    # Assert all visited nodes exist in graph
    rows_all, _ = run_ro("MATCH (n) RETURN n.id")
    graph_node_ids: set[str] = {str(r[0]) for r in rows_all if r[0]}

    events = bus.get_events()
    for v in [e for e in events if e.type == "graph_visit"]:
        for nid in v.data.get("node_ids", []):
            assert nid in graph_node_ids, f"Visited node ID '{nid}' not found in FalkorDB graph"


@pytest.mark.asyncio
async def test_mock_agent_scenario_a_approval_handler_flow() -> None:
    """Assert Scenario A pauses for approval_handler callback and resumes upon approval."""
    seed_graph(reset=True)

    bus = EventBus(incident_id="inc-mock-approval")
    agent = MockAgent()

    approval_called: bool = False

    async def mock_human_approval(action_id: str) -> bool:
        nonlocal approval_called
        approval_called = True
        assert len(action_id) > 0
        return True

    report: FinalReport = await agent.run(
        incident_id="inc-mock-approval",
        alert_text=SCENARIO_A_ALERT,
        emit=bus.emit,
        auto_approve=False,
        approval_handler=mock_human_approval,
    )

    assert approval_called is True
    assert report.verification.targets_after == []
