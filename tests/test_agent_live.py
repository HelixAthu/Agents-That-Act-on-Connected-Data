"""Unit tests for LiveAgent tool loop using FakeSession asserting T8b requirements."""


import pytest

from backend.agent_live import LiveAgent
from backend.events import Event, EventBus, FinalReport
from backend.llm.base import LLMTurn, ToolCall, ToolResult
from backend.llm.fake_client import FakeSession
from seed.seed_graph import seed_graph


@pytest.fixture(scope="session", autouse=True)
def setup_seed_graph() -> None:
    """Ensure graph has fresh canonical seed data before live agent tests."""
    seed_graph(reset=True)


@pytest.mark.asyncio
async def test_agent_live_12_call_cap_aborts() -> None:
    """Assert tool calling loop aborts with non-recoverable error when exceeding 12 calls."""
    # Script a turn with 13 tool calls
    turns: list[LLMTurn] = [
        LLMTurn(
            text="Calling many tools",
            tool_calls=[
                ToolCall(id=f"c-{i}", name="get_component_context", args={"id": f"svc-{i}"})
                for i in range(13)
            ],
        )
    ]
    fake_session = FakeSession(turns=turns)
    bus = EventBus(incident_id="inc-test-cap")
    agent = LiveAgent(session=fake_session)

    report: FinalReport = await agent.run(
        incident_id="inc-test-cap",
        alert_text="Test alert",
        emit=bus.emit,
    )

    events: list[Event] = bus.get_events()
    err_events = [e for e in events if e.type == "error"]
    assert len(err_events) == 1
    assert "cap of 12 calls reached" in err_events[0].data["message"]
    assert err_events[0].data["recoverable"] is False
    assert report.incident_id == "inc-test-cap"


@pytest.mark.asyncio
async def test_agent_live_repeated_call_abort() -> None:
    """Assert loop aborts when the same identical tool call is repeated more than twice."""
    call = ToolCall(id="c-rep", name="get_component_context", args={"id": "svc-config"})
    turns: list[LLMTurn] = [
        LLMTurn(text="Call 1", tool_calls=[call]),
        LLMTurn(text="Call 2", tool_calls=[call]),
        LLMTurn(text="Call 3", tool_calls=[call]),
    ]
    fake_session = FakeSession(turns=turns)
    bus = EventBus(incident_id="inc-test-repeat")
    agent = LiveAgent(session=fake_session)

    report: FinalReport = await agent.run(
        incident_id="inc-test-repeat",
        alert_text="Test alert",
        emit=bus.emit,
    )

    events: list[Event] = bus.get_events()
    err_events = [e for e in events if e.type == "error"]
    assert len(err_events) == 1
    assert "repeated identical call" in err_events[0].data["message"]
    assert report.incident_id == "inc-test-repeat"


@pytest.mark.asyncio
async def test_agent_live_tool_error_fed_back_as_is_error() -> None:
    """Assert tool errors are returned to the model with is_error=True and hint without crashing."""
    turns: list[LLMTurn] = [
        LLMTurn(
            text="Querying missing service",
            tool_calls=[ToolCall(id="c-err", name="get_component_context", args={"id": "svc-nonexistent"})],
        ),
        LLMTurn(
            text="Received error and concluding investigation",
            tool_calls=[],
        ),
    ]
    fake_session = FakeSession(turns=turns)
    bus = EventBus(incident_id="inc-test-err")
    agent = LiveAgent(session=fake_session)

    await agent.run(
        incident_id="inc-test-err",
        alert_text="Test alert",
        emit=bus.emit,
    )

    # History entry 1 is tool_results sent back to model
    tool_results_history = [h for h in fake_session.history if h.get("role") == "tool_results"]
    assert len(tool_results_history) == 1
    tool_results: list[ToolResult] = tool_results_history[0]["results"]
    assert len(tool_results) == 1
    assert tool_results[0].is_error is True
    assert "hint" in tool_results[0].content
    assert "Check the ID spelling" in tool_results[0].content["hint"]


@pytest.mark.asyncio
async def test_agent_live_approval_pause_and_report_parse_retry() -> None:
    """Assert approval pauses and report parsing retries on invalid first output."""
    seed_graph(reset=True)

    approval_invoked: bool = False

    async def mock_approval(action_id: str) -> bool:
        nonlocal approval_invoked
        approval_invoked = True
        return True

    turns: list[LLMTurn] = [
        # Turn 1: Propose isolation
        LLMTurn(
            text="Proposing node isolation",
            tool_calls=[
                ToolCall(
                    id="c-prop",
                    name="propose_containment",
                    args={"action": "ISOLATE_NODE", "target_id": "svc-payments-gateway", "incident_id": "inc-live-appr"},
                )
            ],
        ),
        # Turn 2: Execute containment
        LLMTurn(
            text="Executing containment after approval",
            tool_calls=[
                ToolCall(
                    id="c-exec",
                    name="execute_containment",
                    args={"action_id": ""},  # Dynamically resolved in callback or test
                )
            ],
        ),
        # Turn 3: Model returns plain text instead of json report
        LLMTurn(text="Here is your final answer: everything looks resolved.", tool_calls=[]),
        # Turn 4: Model returns valid json report after retry prompt
        LLMTurn(
            text="""```json
{
  "incident_id": "inc-live-appr",
  "summary": "Gateway isolated successfully.",
  "risk_score": 0.828,
  "findings": [{"claim": "Isolated svc-payments-gateway safely", "evidence_refs": ["c-exec"]}],
  "impact": {"impacted_services": 4, "customer_facing": 1, "owner_teams": ["team-payments"]},
  "actions": [{"action_id": "act-test", "type": "ISOLATE_NODE", "target": "svc-payments-gateway", "policy": "APPROVAL_REQUIRED", "status": "EXECUTED"}],
  "verification": {"targets_before": ["db-customer-profile"], "targets_after": []},
  "tool_calls": []
}
```""",
            tool_calls=[],
        ),
    ]

    # Dynamically inject the proposed action_id into turn 2
    def dynamic_turn_generator(results: list[ToolResult]) -> LLMTurn:
        if results and results[0].name == "propose_containment":
            act_id = results[0].content.get("data", {}).get("action_id", "")
            return LLMTurn(
                text="Executing approved containment",
                tool_calls=[ToolCall(id="c-exec", name="execute_containment", args={"action_id": act_id})],
            )
        return turns.pop(0)

    fake_session = FakeSession(turns=[turns[0], dynamic_turn_generator, turns[2], turns[3]])
    bus = EventBus(incident_id="inc-live-appr")
    agent = LiveAgent(session=fake_session)

    report: FinalReport = await agent.run(
        incident_id="inc-live-appr",
        alert_text="Payment exploit alert",
        emit=bus.emit,
        auto_approve=False,
        approval_handler=mock_approval,
    )

    assert approval_invoked is True
    assert report.incident_id == "inc-live-appr"
    assert report.summary == "Gateway isolated successfully."

    # Assert verification event emitted during execute_containment
    events: list[Event] = bus.get_events()
    verif_events = [e for e in events if e.type == "verification"]
    assert len(verif_events) >= 1
    assert "targets_after" in verif_events[0].data
