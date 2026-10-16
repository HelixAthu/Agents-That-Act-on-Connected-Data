"""Deterministic scripted mock agent executing Scenarios A, B, and C with real MCP tools."""

from __future__ import annotations

import logging
import uuid
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
from backend.mcp_bridge import MCPBridge
from backend.scenarios import detect_scenario
from mcp_server.queries import approve_action

logger: logging.Logger = logging.getLogger(__name__)


class MockAgent:
    """Deterministic incident response mock agent executing Scenarios A, B, and C."""

    def __init__(self, bridge: MCPBridge | None = None) -> None:
        self.bridge: MCPBridge = bridge or MCPBridge()

    async def run(
        self,
        incident_id: str,
        alert_text: str,
        emit: Callable[[Event], Awaitable[None]],
        auto_approve: bool = True,
        approval_handler: Callable[[str], Awaitable[bool]] | None = None,
    ) -> FinalReport:
        """Run scripted incident response against real MCP graph tools and emit standard event stream."""
        scenario_id: str = detect_scenario(alert_text)
        logger.info("Starting mock agent execution for incident '%s' (Scenario %s)", incident_id, scenario_id)

        # 1. Emit incident_started
        await emit(
            Event(
                seq=0,  # Will be assigned by EventBus if routed through emit
                type=EventType.INCIDENT_STARTED.value,
                data={"incident_id": incident_id, "alert_text": alert_text, "mode": "mock"},
            )
        )

        visited_nodes: set[str] = set()
        recorded_tool_calls: list[ReportToolCall] = []

        async def _call(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
            call_id: str = f"call-{uuid.uuid4().hex[:8]}"
            await emit(
                Event(
                    seq=0,
                    type=EventType.TOOL_CALL.value,
                    data={"call_id": call_id, "tool": tool_name, "args": args},
                )
            )

            envelope: dict[str, Any] = await self.bridge.call(tool_name, args)

            # Emit graph_visit if present in envelope
            visit: dict[str, Any] | None = envelope.get("visit")
            if visit:
                v_nodes: list[str] = [str(nid) for nid in visit.get("node_ids", []) if nid]
                visited_nodes.update(v_nodes)
                await emit(
                    Event(
                        seq=0,
                        type=EventType.GRAPH_VISIT.value,
                        data={
                            "call_id": call_id,
                            "kind": visit.get("kind", "inspect"),
                            "node_ids": v_nodes,
                            "edge_keys": visit.get("edge_keys", []),
                        },
                    )
                )

            # Emit tool_result
            summary: str = self.bridge.build_tool_summary(tool_name, args, envelope)
            evidence: dict[str, Any] = envelope.get("evidence", {})
            elapsed_ms: float = float(evidence.get("ms", 0.0))
            await emit(
                Event(
                    seq=0,
                    type=EventType.TOOL_RESULT.value,
                    data={
                        "call_id": call_id,
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
                    call_id=call_id,
                    tool=tool_name,
                    ms=elapsed_ms,
                    query_id=evidence.get("query_id", ""),
                )
            )
            return envelope

        async def _thought(text: str) -> None:
            await emit(
                Event(
                    seq=0,
                    type=EventType.THOUGHT.value,
                    data={"text": text},
                )
            )

        if scenario_id == "A":
            report = await self._run_scenario_a(
                incident_id=incident_id,
                call_fn=_call,
                thought_fn=_thought,
                emit=emit,
                auto_approve=auto_approve,
                approval_handler=approval_handler,
                recorded_calls=recorded_tool_calls,
                visited_nodes=visited_nodes,
            )
        elif scenario_id == "B":
            report = await self._run_scenario_b(
                incident_id=incident_id,
                call_fn=_call,
                thought_fn=_thought,
                recorded_calls=recorded_tool_calls,
                visited_nodes=visited_nodes,
            )
        else:
            report = await self._run_scenario_c(
                incident_id=incident_id,
                call_fn=_call,
                thought_fn=_thought,
                emit=emit,
                recorded_calls=recorded_tool_calls,
                visited_nodes=visited_nodes,
            )

        sanitized_report = validate_final_report_hallucinations(report, visited_nodes)
        await emit(
            Event(
                seq=0,
                type=EventType.FINAL_REPORT.value,
                data=sanitized_report.model_dump(),
            )
        )
        return sanitized_report

    async def _run_scenario_a(
        self,
        incident_id: str,
        call_fn: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]],
        thought_fn: Callable[[str], Awaitable[None]],
        emit: Callable[[Event], Awaitable[None]],
        auto_approve: bool,
        approval_handler: Callable[[str], Awaitable[bool]] | None,
        recorded_calls: list[ReportToolCall],
        visited_nodes: set[str],
    ) -> FinalReport:
        """Execute Scenario A: Payment Gateway Attack Path."""
        await thought_fn("Analyzing security alert on payments gateway and inspecting component context.")
        await call_fn("get_component_context", {"id": "svc-payments-gateway"})
        visited_nodes.add("svc-payments-gateway")
        visited_nodes.add("vuln-001")

        await thought_fn("Computing deterministic risk score for compromised payments gateway.")
        risk_env = await call_fn("compute_risk", {"target_id": "svc-payments-gateway"})
        risk_val: float = float(risk_env.get("data", {}).get("risk", 0.828))
        await emit(
            Event(
                seq=0,
                type=EventType.RISK_UPDATE.value,
                data={"risk": risk_val, "components": risk_env.get("data", {}).get("components", {})},
            )
        )

        await thought_fn("Tracing attacker paths from payments gateway to sensitive PII databases.")
        paths_env = await call_fn("find_attack_paths", {"source_id": "svc-payments-gateway", "max_hops": 6})
        targets_before: list[str] = sorted(
            {p["target"] for p in paths_env.get("data", {}).get("paths", []) if "target" in p}
        )

        await thought_fn("Assessing failure impact on upstream services to guide least-disruptive containment.")
        impact_env = await call_fn("get_failure_impact", {"id": "svc-payments-gateway", "max_hops": 3})
        impact_data: dict[str, Any] = impact_env.get("data", {})
        customer_facing_count: int = int(impact_data.get("customer_facing_count", 1))
        impacted_services_count: int = len(impact_data.get("impacted", []))

        await thought_fn("Proposing least-disruptive IAM role revocation to sever path to db-customer-profile.")
        prop_revoke = await call_fn(
            "propose_containment",
            {
                "action": "REVOKE_ROLE",
                "target_id": "svc-payments-gateway|role-storage-manager",
                "incident_id": incident_id,
            },
        )
        act1_id: str = prop_revoke.get("data", {}).get("action_id", "")
        await emit(
            Event(
                seq=0,
                type=EventType.ACTION.value,
                data={
                    "action_id": act1_id,
                    "action": "REVOKE_ROLE",
                    "target_id": "svc-payments-gateway|role-storage-manager",
                    "status": "PROPOSED",
                    "policy": "AUTO",
                },
            )
        )

        await thought_fn("Executing AUTO-approved role revocation containment.")
        exec_revoke = await call_fn("execute_containment", {"action_id": act1_id})
        after_revoke: list[str] = exec_revoke.get("data", {}).get("targets_after", ["db-user-billing"])
        await emit(
            Event(
                seq=0,
                type=EventType.ACTION.value,
                data={
                    "action_id": act1_id,
                    "action": "REVOKE_ROLE",
                    "target_id": "svc-payments-gateway|role-storage-manager",
                    "status": "EXECUTED",
                    "policy": "AUTO",
                },
            )
        )
        await emit(
            Event(
                seq=0,
                type=EventType.VERIFICATION.value,
                data={
                    "action_id": act1_id,
                    "targets_before": targets_before,
                    "targets_after": after_revoke,
                },
            )
        )

        await thought_fn("Verifying remaining attack paths after role revocation.")
        await call_fn("find_attack_paths", {"source_id": "svc-payments-gateway", "max_hops": 6})

        await thought_fn("Remaining attack path requires complete node isolation; customer-facing service requires approval.")
        prop_isolate = await call_fn(
            "propose_containment",
            {
                "action": "ISOLATE_NODE",
                "target_id": "svc-payments-gateway",
                "incident_id": incident_id,
            },
        )
        act2_id: str = prop_isolate.get("data", {}).get("action_id", "")
        policy_reason: str = prop_isolate.get("data", {}).get("policy", {}).get("reason", "")
        await emit(
            Event(
                seq=0,
                type=EventType.APPROVAL_REQUIRED.value,
                data={
                    "action_id": act2_id,
                    "action": "ISOLATE_NODE",
                    "target_id": "svc-payments-gateway",
                    "reason": policy_reason,
                },
            )
        )
        await emit(
            Event(
                seq=0,
                type=EventType.ACTION.value,
                data={
                    "action_id": act2_id,
                    "action": "ISOLATE_NODE",
                    "target_id": "svc-payments-gateway",
                    "status": "PROPOSED",
                    "policy": "APPROVAL_REQUIRED",
                },
            )
        )

        # Handle human or automated approval
        if auto_approve:
            approve_action(act2_id, approved_by="security-lead@corp")
        elif approval_handler is not None:
            approved = await approval_handler(act2_id)
            if not approved:
                raise RuntimeError(f"Approval was rejected or timed out for action {act2_id}")
            approve_action(act2_id, approved_by="security-lead@corp")

        await thought_fn("Executing human-approved node isolation containment.")
        exec_isolate = await call_fn("execute_containment", {"action_id": act2_id})
        after_isolate: list[str] = exec_isolate.get("data", {}).get("targets_after", [])
        await emit(
            Event(
                seq=0,
                type=EventType.ACTION.value,
                data={
                    "action_id": act2_id,
                    "action": "ISOLATE_NODE",
                    "target_id": "svc-payments-gateway",
                    "status": "EXECUTED",
                    "policy": "APPROVAL_REQUIRED",
                },
            )
        )
        await emit(
            Event(
                seq=0,
                type=EventType.VERIFICATION.value,
                data={
                    "action_id": act2_id,
                    "targets_before": after_revoke,
                    "targets_after": after_isolate,
                },
            )
        )

        await thought_fn("Verifying complete severance of all attack paths to sensitive databases.")
        await call_fn("find_attack_paths", {"source_id": "svc-payments-gateway", "max_hops": 6})

        await thought_fn("Notifying payment operations team regarding active containment.")
        await call_fn(
            "notify_owners",
            {
                "incident_id": incident_id,
                "team_ids": ["team-payments"],
                "message": "Critical: svc-payments-gateway has been isolated following verified attack path to PII.",
            },
        )
        visited_nodes.add("team-payments")

        await thought_fn("Recording formal security finding and evidence references in audit trail.")
        await call_fn(
            "record_finding",
            {
                "incident_id": incident_id,
                "kind": "EXPLOITABLE_VULNERABILITY",
                "summary": "RCE vulnerability CVE-2026-9901 exploited on svc-payments-gateway",
                "evidence_ids": ["svc-payments-gateway", "vuln-001"],
                "risk_score": risk_val,
            },
        )

        actions = [
            ReportAction(
                action_id=act1_id,
                type="REVOKE_ROLE",
                target="svc-payments-gateway|role-storage-manager",
                policy="AUTO",
                status="EXECUTED",
            ),
            ReportAction(
                action_id=act2_id,
                type="ISOLATE_NODE",
                target="svc-payments-gateway",
                policy="APPROVAL_REQUIRED",
                status="EXECUTED",
            ),
        ]

        findings = [
            ReportFinding(
                claim="Vulnerability vuln-001 on svc-payments-gateway enabled lateral movement to PII",
                evidence_refs=[recorded_calls[0].call_id, recorded_calls[1].call_id],
            ),
            ReportFinding(
                claim="Containment actions successfully eliminated all attack paths to database targets",
                evidence_refs=[recorded_calls[5].call_id, recorded_calls[8].call_id],
            ),
        ]

        return FinalReport(
            incident_id=incident_id,
            summary="Critical exploit on svc-payments-gateway fully contained via role revocation and node isolation.",
            risk_score=risk_val,
            findings=findings,
            impact=ReportImpact(
                impacted_services=impacted_services_count,
                customer_facing=customer_facing_count,
                owner_teams=["team-payments"],
            ),
            actions=actions,
            verification=ReportVerification(
                targets_before=targets_before,
                targets_after=after_isolate,
            ),
            tool_calls=recorded_calls,
        )

    async def _run_scenario_b(
        self,
        incident_id: str,
        call_fn: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]],
        thought_fn: Callable[[str], Awaitable[None]],
        recorded_calls: list[ReportToolCall],
        visited_nodes: set[str],
    ) -> FinalReport:
        """Execute Scenario B: Core Orders Database Failure Cascade."""
        await thought_fn("Analyzing database outage alert on core orders database db-orders.")
        await call_fn("get_component_context", {"id": "db-orders"})
        visited_nodes.add("db-orders")

        await thought_fn("Assessing cascading failure impact across upstream services.")
        impact_env = await call_fn("get_failure_impact", {"id": "db-orders", "max_hops": 3})
        impact_data: dict[str, Any] = impact_env.get("data", {})
        impacted_services: list[dict[str, Any]] = impact_data.get("impacted", [])
        cf_count: int = int(impact_data.get("customer_facing_count", 0))

        owner_team_ids: list[str] = sorted({
            str(owner["id"]) for owner in impact_data.get("owners", []) if "id" in owner
        })
        for tid in owner_team_ids:
            visited_nodes.add(tid)

        await thought_fn("Ranking top critical infrastructure components to assess outage severity.")
        await call_fn("rank_critical_components", {"top_n": 5})

        await thought_fn("Alerting all affected service owning teams about database outage cascade.")
        await call_fn(
            "notify_owners",
            {
                "incident_id": incident_id,
                "team_ids": owner_team_ids,
                "message": (
                    f"Outage Alert: db-orders is unreachable. Cascading failures impacting "
                    f"{len(impacted_services)} services across {len(owner_team_ids)} teams."
                ),
            },
        )

        await thought_fn("Recording outage failure cascade finding in incident audit trail.")
        await call_fn(
            "record_finding",
            {
                "incident_id": incident_id,
                "kind": "OUTAGE_FAILURE_CASCADE",
                "summary": f"Unreachable db-orders causing cascading failure across {len(impacted_services)} services",
                "evidence_ids": ["db-orders"],
                "risk_score": 0.45,
            },
        )

        findings = [
            ReportFinding(
                claim=f"db-orders failure cascaded to {len(impacted_services)} dependent services",
                evidence_refs=[recorded_calls[1].call_id],
            ),
        ]

        return FinalReport(
            incident_id=incident_id,
            summary=f"Database outage on db-orders causing cascading degradation across {len(impacted_services)} upstream services.",
            risk_score=0.45,
            findings=findings,
            impact=ReportImpact(
                impacted_services=len(impacted_services),
                customer_facing=cf_count,
                owner_teams=owner_team_ids,
            ),
            actions=[],
            verification=ReportVerification(
                targets_before=[],
                targets_after=[],
            ),
            tool_calls=recorded_calls,
        )

    async def _run_scenario_c(
        self,
        incident_id: str,
        call_fn: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]],
        thought_fn: Callable[[str], Awaitable[None]],
        emit: Callable[[Event], Awaitable[None]],
        recorded_calls: list[ReportToolCall],
        visited_nodes: set[str],
    ) -> FinalReport:
        """Execute Scenario C: Config Service CVE False Alarm."""
        await thought_fn("Investigating reported CVE-2026-4418 vulnerability on svc-config.")
        await call_fn("get_component_context", {"id": "svc-config"})
        visited_nodes.add("svc-config")
        visited_nodes.add("vuln-005")

        await thought_fn("Computing deterministic risk score for svc-config.")
        risk_env = await call_fn("compute_risk", {"target_id": "svc-config"})
        risk_val: float = float(risk_env.get("data", {}).get("risk", 0.514))
        await emit(
            Event(
                seq=0,
                type=EventType.RISK_UPDATE.value,
                data={"risk": risk_val, "components": risk_env.get("data", {}).get("components", {})},
            )
        )

        await thought_fn("Searching for attack paths from svc-config to PII crown jewel databases.")
        await call_fn("find_attack_paths", {"source_id": "svc-config", "max_hops": 6})

        await thought_fn("Evaluating failure impact to assess blast radius of potential isolation.")
        impact_env = await call_fn("get_failure_impact", {"id": "svc-config", "max_hops": 3})
        transitive_dependents: int = len(impact_env.get("data", {}).get("impacted", []))

        await thought_fn("Evaluating containment policy for svc-config isolation.")
        prop_env = await call_fn(
            "propose_containment",
            {
                "action": "ISOLATE_NODE",
                "target_id": "svc-config",
                "incident_id": incident_id,
            },
        )
        act_id: str = prop_env.get("data", {}).get("action_id", "")
        policy_dec: str = prop_env.get("data", {}).get("policy", {}).get("decision", "DENIED")
        await emit(
            Event(
                seq=0,
                type=EventType.ACTION.value,
                data={
                    "action_id": act_id,
                    "action": "ISOLATE_NODE",
                    "target_id": "svc-config",
                    "status": "PROPOSED",
                    "policy": policy_dec,
                },
            )
        )

        await thought_fn("Containment policy rejected isolation (DENIED) due to 17 dependents and zero PII risk.")
        await call_fn(
            "record_finding",
            {
                "incident_id": incident_id,
                "kind": "FALSE_ALARM_ISOLATION_DENIED",
                "summary": "do not isolate: 17 dependents, no verified PII path; patch within SLA",
                "evidence_ids": ["svc-config"],
                "risk_score": risk_val,
            },
        )

        actions = [
            ReportAction(
                action_id=act_id,
                type="ISOLATE_NODE",
                target="svc-config",
                policy="DENIED",
                status="PROPOSED",
            )
        ]

        findings = [
            ReportFinding(
                claim="No verified attack paths from svc-config to PII databases",
                evidence_refs=[recorded_calls[2].call_id],
            ),
            ReportFinding(
                claim="Isolation denied due to high operational disruption and zero reachable sensitive data",
                evidence_refs=[recorded_calls[3].call_id, recorded_calls[4].call_id],
            ),
        ]

        return FinalReport(
            incident_id=incident_id,
            summary="False alarm on svc-config: isolation denied due to zero PII exposure and high blast radius.",
            risk_score=risk_val,
            findings=findings,
            impact=ReportImpact(
                impacted_services=transitive_dependents,
                customer_facing=0,
                owner_teams=["team-platform"],
            ),
            actions=actions,
            verification=ReportVerification(
                targets_before=[],
                targets_after=[],
            ),
            tool_calls=recorded_calls,
        )


async def run_mock_agent(
    incident_id: str,
    alert_text: str,
    emit: Callable[[Event], Awaitable[None]],
    auto_approve: bool = True,
    approval_handler: Callable[[str], Awaitable[bool]] | None = None,
) -> FinalReport:
    """Convenience helper to run MockAgent with default MCPBridge."""
    agent = MockAgent()
    return await agent.run(
        incident_id=incident_id,
        alert_text=alert_text,
        emit=emit,
        auto_approve=auto_approve,
        approval_handler=approval_handler,
    )
