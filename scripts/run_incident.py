"""Incident runner CLI for running autonomous incident response scenarios and recording replays."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import uuid
from pathlib import Path
from typing import Any

# Ensure repository root is on sys.path for direct script execution
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.agent_mock import MockAgent
from backend.events import Event, EventBus, EventType, FinalReport
from backend.scenarios import get_scenario
from seed.seed_graph import seed_graph

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger: logging.Logger = logging.getLogger(__name__)


def format_cli_event(event: Event) -> str:
    """Format an event envelope into a human-readable CLI log line."""
    etype: str = event.type
    data: dict[str, Any] = event.data

    if etype == EventType.INCIDENT_STARTED.value:
        return f"[START] Incident {data.get('incident_id')} | Alert: {data.get('alert_text')}"
    if etype == EventType.THOUGHT.value:
        return f"[THOUGHT] {data.get('text')}"
    if etype == EventType.TOOL_CALL.value:
        return f"[TOOL CALL] {data.get('tool')}({data.get('args')})"
    if etype == EventType.GRAPH_VISIT.value:
        return f"[GRAPH VISIT] ({data.get('kind')}) nodes={data.get('node_ids')} edges={data.get('edge_keys')}"
    if etype == EventType.TOOL_RESULT.value:
        status = "OK" if data.get("ok") else "FAILED"
        return f"[TOOL RESULT] [{status}] {data.get('summary')} ({data.get('ms', 0):.1f}ms)"
    if etype == EventType.RISK_UPDATE.value:
        return f"[RISK UPDATE] Deterministic score: {data.get('risk', 0.0):.3f}"
    if etype == EventType.APPROVAL_REQUIRED.value:
        return f"[APPROVAL REQUIRED] Action {data.get('action_id')}: {data.get('action')} on {data.get('target_id')}"
    if etype == EventType.ACTION.value:
        return f"[ACTION] {data.get('action_id')} ({data.get('action')}) -> {data.get('status')} [{data.get('policy')}]"
    if etype == EventType.VERIFICATION.value:
        return f"[VERIFICATION] Targets before: {data.get('targets_before')} -> After: {data.get('targets_after')}"
    if etype == EventType.FINAL_REPORT.value:
        return f"[REPORT] Final report generated with {len(data.get('findings', []))} findings."
    if etype == EventType.ERROR.value:
        return f"[ERROR] {data.get('message')}"
    return f"[{etype.upper()}] {data}"


async def run_scenario(
    scenario_id: str,
    mode: str = "mock",
    auto_approve: bool = True,
    replay_out: Path | None = None,
    reset_graph: bool = True,
) -> FinalReport:
    """Execute scenario with chosen agent mode, print events live, and save replay JSONL."""
    if reset_graph:
        logger.info("Resetting graph 'infra' to canonical baseline...")
        seed_graph(reset=True)

    scenario_def = get_scenario(scenario_id)
    incident_id: str = f"inc-{scenario_id.lower()}-{uuid.uuid4().hex[:6]}"

    print("\n" + "=" * 80)
    print(f"INCIDENT RESPONSE RUNNER | Scenario {scenario_def.id}: {scenario_def.title}")
    print(f"Incident ID : {incident_id}")
    print(f"Alert       : {scenario_def.alert_text}")
    print(f"Agent Mode  : {mode.upper()} (Auto-Approve={auto_approve})")
    print("=" * 80 + "\n")

    bus: EventBus = EventBus(incident_id=incident_id)

    async def emit_and_log(event: Event) -> None:
        emitted = await bus.emit(event)
        print(format_cli_event(emitted))

    if mode == "mock":
        agent = MockAgent()
        report = await agent.run(
            incident_id=incident_id,
            alert_text=scenario_def.alert_text,
            emit=emit_and_log,
            auto_approve=auto_approve,
        )
    else:
        raise NotImplementedError("Live mode is implemented in T8b; use --mode mock.")

    # Save replay JSONL
    if replay_out is not None:
        replay_out.parent.mkdir(parents=True, exist_ok=True)
        bus.dump_jsonl(replay_out)
        print(f"\n[REPLAY] Recorded {len(bus.get_events())} events saved to: {replay_out}")

    print("\n" + "=" * 80)
    print("FINAL INCIDENT REPORT SUMMARY")
    print("=" * 80)
    print(f"Summary         : {report.summary}")
    print(f"Risk Score      : {report.risk_score:.3f}")
    print(f"Impacted Svc    : {report.impact.impacted_services} ({report.impact.customer_facing} customer-facing)")
    print(f"Owner Teams     : {', '.join(report.impact.owner_teams)}")
    print(f"Actions Taken   : {len(report.actions)}")
    for a in report.actions:
        print(f"  - [{a.status}] {a.type} -> {a.target} (policy={a.policy})")
    print(f"Verification    : {report.verification.targets_before} -> {report.verification.targets_after}")
    print(f"Tool Calls      : {len(report.tool_calls)} calls recorded")
    print("=" * 80 + "\n")

    return report


def parse_args() -> argparse.Namespace:
    """Parse command line arguments for incident runner CLI."""
    parser = argparse.ArgumentParser(description="Graph Incident Response Agent Runner")
    parser.add_argument(
        "--scenario",
        "-s",
        type=str,
        default="A",
        choices=["A", "B", "C", "a", "b", "c"],
        help="Scenario identifier to execute (A, B, or C)",
    )
    parser.add_argument(
        "--mode",
        "-m",
        type=str,
        default="mock",
        choices=["mock", "live"],
        help="Agent mode: mock (deterministic script) or live (LLM tool loop)",
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        default=True,
        help="Automatically approve containment actions requiring human intervention",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Custom path to save recorded events replay JSONL",
    )
    parser.add_argument(
        "--no-reset",
        action="store_true",
        default=False,
        help="Skip resetting graph to canonical seed data before run",
    )
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""
    args = parse_args()
    sid = args.scenario.upper()
    replay_file = (
        Path(args.output)
        if args.output
        else Path(f"replays/scenario_{sid.lower()}.jsonl")
    )

    try:
        asyncio.run(
            run_scenario(
                scenario_id=sid,
                mode=args.mode,
                auto_approve=args.auto_approve,
                replay_out=replay_file,
                reset_graph=not args.no_reset,
            )
        )
    except Exception:
        logger.exception("Incident runner failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
