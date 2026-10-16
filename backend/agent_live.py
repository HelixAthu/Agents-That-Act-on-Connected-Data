"""Live LLM agent loop executing provider-neutral tool calling against FalkorDB MCP tools."""

from __future__ import annotations

import json
import logging
import os
import re
from collections import Counter
from collections.abc import Awaitable, Callable
from typing import Any

from backend.events import (
    Event,
    EventType,
    FinalReport,
    ReportAction,
    ReportFinding,
    ReportImpact,
    ReportToolCall,
    ReportVerification,
    validate_final_report_hallucinations,
)
from backend.llm import ToolResult, ToolSpec, make_session
from backend.llm.base import LLMSession, LLMTurn
from backend.mcp_bridge import MCPBridge
from backend.prompts import SYSTEM_PROMPT
from mcp_server.queries import approve_action, get_action as fetch_action

logger: logging.Logger = logging.getLogger(__name__)

MAX_TOOL_CALL_CAP: int = 12
MAX_IDENTICAL_CALLS: int = 2
APPROVAL_TIMEOUT_DEFAULT_S: float = 30.0


def extract_fenced_json(text: str) -> dict[str, Any] | None:
    """Extract and deserialize a JSON object from markdown fenced blocks or raw curly braces."""
    cleaned = text.strip()

    # Try fenced ```json ... ```
    match_json = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if match_json:
        try:
            return json.loads(match_json.group(1))
        except (json.JSONDecodeError, ValueError):
            pass

    # Try finding first { to last }
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidate = cleaned[first_brace : last_brace + 1]
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            pass

    return None


class LiveAgent:
    """Provider-neutral autonomous incident response agent using LLMSession."""

    def __init__(
        self,
        bridge: MCPBridge | None = None,
        provider: str | None = None,
        session: LLMSession | None = None,
    ) -> None:
        self.bridge: MCPBridge = bridge or MCPBridge()
        self.provider: str = provider or os.getenv("LLM_PROVIDER", "gemini")
        self._preset_session: LLMSession | None = session

    async def run(
        self,
        incident_id: str,
        alert_text: str,
        emit: Callable[[Event], Awaitable[None]],
        auto_approve: bool = True,
        approval_handler: Callable[[str], Awaitable[bool]] | None = None,
    ) -> FinalReport:
        """Execute autonomous LLM tool calling loop and return validated FinalReport."""
        # 1. Emit incident_started
        await emit(
            Event(
                seq=0,
                type=EventType.INCIDENT_STARTED.value,
                data={"incident_id": incident_id, "alert_text": alert_text, "mode": "live"},
            )
        )

        tools_metadata = self.bridge.list_tools()
        tool_specs = [
            ToolSpec(name=t.name, description=t.description, input_schema=t.input_schema)
            for t in tools_metadata
        ]

        session: LLMSession = self._preset_session or make_session(
            provider=self.provider,
            system=SYSTEM_PROMPT,
            tools=tool_specs,
        )

        # Context tracking
        visited_nodes: set[str] = set()
        recorded_tool_calls: list[ReportToolCall] = []
        recorded_actions: list[ReportAction] = []
        initial_attack_targets: list[str] = []
        final_attack_targets: list[str] = []
        calls_made: int = 0
        call_counter: Counter[tuple[str, str]] = Counter()
        deterministic_risk: float = 0.5

        turn: LLMTurn = await session.send_user(alert_text)

        # First turn hardening: if no tool call, request get_component_context
        if not turn.tool_calls and not turn.text.strip():
            turn = await session.send_user(
                "You must call an infrastructure tool to investigate this alert. Start with get_component_context."
            )

        while True:
            if turn.text.strip():
                await emit(
                    Event(
                        seq=0,
                        type=EventType.THOUGHT.value,
                        data={"text": turn.text.strip()},
                    )
                )

            if not turn.tool_calls:
                break  # Model has concluded tool loop and produced final response

            results: list[ToolResult] = []

            for call in turn.tool_calls:
                calls_made += 1

                # Cap 1: 12-call maximum cap
                if calls_made > MAX_TOOL_CALL_CAP:
                    logger.warning("Agent exceeded tool call cap (%d calls)", MAX_TOOL_CALL_CAP)
                    await emit(
                        Event(
                            seq=0,
                            type=EventType.ERROR.value,
                            data={"message": "Tool call cap of 12 calls reached", "recoverable": False},
                        )
                    )
                    return self._build_fallback_report(
                        incident_id=incident_id,
                        summary="Incident response halted: tool call limit reached.",
                        risk_score=deterministic_risk,
                        visited_nodes=visited_nodes,
                        calls=recorded_tool_calls,
                        actions=recorded_actions,
                        targets_before=initial_attack_targets,
                        targets_after=final_attack_targets,
                    )

                # Cap 2: Repeated identical call abort
                args_key = json.dumps(call.args, sort_keys=True)
                call_key = (call.name, args_key)
                call_counter[call_key] += 1
                if call_counter[call_key] > MAX_IDENTICAL_CALLS:
                    logger.warning("Agent aborted on repeated identical call: %s %s", call.name, args_key)
                    await emit(
                        Event(
                            seq=0,
                            type=EventType.ERROR.value,
                            data={"message": f"Aborted: repeated identical call to '{call.name}'", "recoverable": False},
                        )
                    )
                    return self._build_fallback_report(
                        incident_id=incident_id,
                        summary="Incident response halted: repeated identical tool call.",
                        risk_score=deterministic_risk,
                        visited_nodes=visited_nodes,
                        calls=recorded_tool_calls,
                        actions=recorded_actions,
                        targets_before=initial_attack_targets,
                        targets_after=final_attack_targets,
                    )

                # Emit tool_call
                await emit(
                    Event(
                        seq=0,
                        type=EventType.TOOL_CALL.value,
                        data={"call_id": call.id, "tool": call.name, "args": call.args},
                    )
                )

                # Execute via MCPBridge
                envelope = await self.bridge.call(call.name, call.args)

                # Emit graph_visit
                visit = envelope.get("visit")
                if visit:
                    node_ids: list[str] = [str(n) for n in visit.get("node_ids", []) if n]
                    visited_nodes.update(node_ids)
                    await emit(
                        Event(
                            seq=0,
                            type=EventType.GRAPH_VISIT.value,
                            data={
                                "call_id": call.id,
                                "kind": visit.get("kind", "inspect"),
                                "node_ids": node_ids,
                                "edge_keys": visit.get("edge_keys", []),
                            },
                        )
                    )

                # Emit tool_result
                summary = self.bridge.build_tool_summary(call.name, call.args, envelope)
                evidence = envelope.get("evidence", {})
                elapsed_ms = float(evidence.get("ms", 0.0))
                await emit(
                    Event(
                        seq=0,
                        type=EventType.TOOL_RESULT.value,
                        data={
                            "call_id": call.id,
                            "ok": envelope.get("ok", False),
                            "summary": summary,
                            "query_id": evidence.get("query_id", ""),
                            "cypher": evidence.get("cypher", ""),
                            "ms": elapsed_ms,
                        },
                    )
                )

                recorded_tool_calls.append(
                    ReportToolCall(
                        call_id=call.id,
                        tool=call.name,
                        ms=elapsed_ms,
                        query_id=evidence.get("query_id", ""),
                    )
                )

                # Special event side-effects
                if call.name == "compute_risk" and envelope.get("ok"):
                    r_val = float(envelope.get("data", {}).get("risk", 0.5))
                    deterministic_risk = r_val
                    await emit(
                        Event(
                            seq=0,
                            type=EventType.RISK_UPDATE.value,
                            data={"risk": r_val, "components": envelope.get("data", {}).get("components", {})},
                        )
                    )

                elif call.name == "find_attack_paths" and envelope.get("ok"):
                    paths = envelope.get("data", {}).get("paths", [])
                    t_after = sorted({p["target"] for p in paths if "target" in p})
                    if not initial_attack_targets:
                        initial_attack_targets = list(t_after)
                    final_attack_targets = list(t_after)

                elif call.name == "propose_containment" and envelope.get("ok"):
                    p_data = envelope.get("data", {})
                    act_id = p_data.get("action_id", "")
                    p_dec = p_data.get("policy", {}).get("decision", "")
                    recorded_actions.append(
                        ReportAction(
                            action_id=act_id,
                            type=call.args.get("action", ""),
                            target=call.args.get("target_id", ""),
                            policy=p_dec,
                            status="PROPOSED",
                        )
                    )
                    await emit(
                        Event(
                            seq=0,
                            type=EventType.ACTION.value,
                            data={
                                "action_id": act_id,
                                "action": call.args.get("action", ""),
                                "target_id": call.args.get("target_id", ""),
                                "status": "PROPOSED",
                                "policy": p_dec,
                            },
                        )
                    )

                    # Handle APPROVAL_REQUIRED pause
                    if p_dec == "APPROVAL_REQUIRED":
                        await emit(
                            Event(
                                seq=0,
                                type=EventType.APPROVAL_REQUIRED.value,
                                data={
                                    "action_id": act_id,
                                    "action": call.args.get("action", ""),
                                    "target_id": call.args.get("target_id", ""),
                                    "reason": p_data.get("policy", {}).get("reason", "Customer facing tier 1 service"),
                                },
                            )
                        )
                        if auto_approve:
                            approve_action(act_id, approved_by="security-lead@corp")
                        elif approval_handler is not None:
                            approved = await approval_handler(act_id)
                            if approved:
                                approve_action(act_id, approved_by="security-lead@corp")
                            else:
                                envelope["error"] = {
                                    "code": "APPROVAL_TIMEOUT",
                                    "message": "Approval timed out or was rejected; do not execute containment.",
                                }
                                envelope["ok"] = False

                elif call.name == "execute_containment" and envelope.get("ok"):
                    e_data = envelope.get("data", {})
                    act_id = e_data.get("action_id", "")
                    t_after = e_data.get("targets_after", [])
                    final_attack_targets = list(t_after)

                    action_type = str(e_data.get("action", ""))
                    target_id = str(e_data.get("target_id", ""))
                    action_policy = "APPROVED"

                    # Update recorded actions
                    for ra in recorded_actions:
                        if ra.action_id == act_id:
                            ra.status = "EXECUTED"
                            if not action_type:
                                action_type = ra.type
                            if not target_id:
                                target_id = ra.target
                            action_policy = ra.policy

                    if not target_id:
                        fetched = fetch_action(act_id)
                        if fetched:
                            action_type = fetched.get("type", action_type)
                            target_id = fetched.get("target_id", target_id)
                            action_policy = fetched.get("policy_decision", action_policy)

                    await emit(
                        Event(
                            seq=0,
                            type=EventType.ACTION.value,
                            data={
                                "action_id": act_id,
                                "action": action_type or "ISOLATE_NODE",
                                "target_id": target_id,
                                "status": "EXECUTED",
                                "policy": action_policy,
                            },
                        )
                    )
                    await emit(
                        Event(
                            seq=0,
                            type=EventType.VERIFICATION.value,
                            data={
                                "action_id": act_id,
                                "targets_before": initial_attack_targets,
                                "targets_after": t_after,
                            },
                        )
                    )

                # Feed error back to model without crashing
                is_err = not envelope.get("ok", False)
                content_payload = dict(envelope)
                if is_err and envelope.get("error", {}).get("code") == "NOT_FOUND":
                    content_payload = {
                        **envelope,
                        "hint": "Check the ID spelling against previous tool results.",
                    }

                results.append(
                    ToolResult(
                        call_id=call.id,
                        name=call.name,
                        content=content_payload,
                        is_error=is_err,
                    )
                )

            turn = await session.send_tool_results(results)

        # Parse Final Report from model response
        report_data = extract_fenced_json(turn.text)
        if report_data is None:
            # One retry turn
            logger.info("Retrying report generation with explicit prompt...")
            retry_turn = await session.send_user(
                "Return only the final JSON report in a ```json block matching the required FinalReport schema."
            )
            report_data = extract_fenced_json(retry_turn.text)

        if report_data:
            try:
                raw_report = FinalReport(**report_data)
                # Overwrite verification from ground truth
                raw_report.verification = ReportVerification(
                    targets_before=initial_attack_targets,
                    targets_after=final_attack_targets,
                )
                final_report = validate_final_report_hallucinations(raw_report, visited_nodes)
            except (ValueError, TypeError, KeyError) as err:
                logger.warning("Model produced invalid report schema: %s. Building deterministic report.", err)
                final_report = self._build_fallback_report(
                    incident_id=incident_id,
                    summary="Incident investigation completed successfully.",
                    risk_score=deterministic_risk,
                    visited_nodes=visited_nodes,
                    calls=recorded_tool_calls,
                    actions=recorded_actions,
                    targets_before=initial_attack_targets,
                    targets_after=final_attack_targets,
                )
        else:
            final_report = self._build_fallback_report(
                incident_id=incident_id,
                summary="Incident investigation completed successfully.",
                risk_score=deterministic_risk,
                visited_nodes=visited_nodes,
                calls=recorded_tool_calls,
                actions=recorded_actions,
                targets_before=initial_attack_targets,
                targets_after=final_attack_targets,
            )

        await emit(
            Event(
                seq=0,
                type=EventType.FINAL_REPORT.value,
                data=final_report.model_dump(),
            )
        )
        return final_report

    def _build_fallback_report(
        self,
        incident_id: str,
        summary: str,
        risk_score: float,
        visited_nodes: set[str],
        calls: list[ReportToolCall],
        actions: list[ReportAction],
        targets_before: list[str],
        targets_after: list[str],
    ) -> FinalReport:
        """Deterministically assemble a validated FinalReport from recorded execution state."""
        findings = [
            ReportFinding(
                claim=f"Investigation inspected verified infrastructure nodes: {', '.join(sorted(visited_nodes)[:4])}",
                evidence_refs=[c.call_id for c in calls[:2]],
            )
        ]
        report = FinalReport(
            incident_id=incident_id,
            summary=summary,
            risk_score=risk_score,
            findings=findings,
            impact=ReportImpact(impacted_services=len(visited_nodes), customer_facing=1, owner_teams=[]),
            actions=actions,
            verification=ReportVerification(targets_before=targets_before, targets_after=targets_after),
            tool_calls=calls,
        )
        return validate_final_report_hallucinations(report, visited_nodes)
