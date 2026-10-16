"""Scenario definitions and detection for Incident Response agent."""

from __future__ import annotations

import re
from dataclasses import dataclass

SCENARIO_A_ALERT = "CRITICAL: CVE-2026-9901 (CVSS 9.8, exploit available) detected on svc-payments-gateway."
SCENARIO_B_ALERT = "ALERT: db-orders is unreachable; connection timeouts reported across services."
SCENARIO_C_ALERT = "HIGH: CVE-2026-4418 (CVSS 8.1, exploit available) detected on svc-config."
SCENARIO_A2_ALERT = "HIGH: suspicious activity on svc-web-portal"


@dataclass(frozen=True)
class ScenarioDefinition:
    """Specification of an incident scenario including canonical alert text and target component."""

    id: str
    title: str
    alert_text: str
    target_id: str
    description: str


SCENARIOS: dict[str, ScenarioDefinition] = {
    "A": ScenarioDefinition(
        id="A",
        title="Payment Gateway Exploitable CVE with Attack Paths to PII",
        alert_text=SCENARIO_A_ALERT,
        target_id="svc-payments-gateway",
        description="Exploitable RCE vulnerability detected on payments gateway with lateral movement to PII stores.",
    ),
    "B": ScenarioDefinition(
        id="B",
        title="Core Orders Database Failure Cascade",
        alert_text=SCENARIO_B_ALERT,
        target_id="db-orders",
        description="Database outage causing cascading failure impact across multiple dependent upstream services.",
    ),
    "C": ScenarioDefinition(
        id="C",
        title="Config Service Vulnerability False Alarm",
        alert_text=SCENARIO_C_ALERT,
        target_id="svc-config",
        description="Reported CVE on internal config service with zero reachable PII paths and high blast radius.",
    ),
    "A2": ScenarioDefinition(
        id="A2",
        title="Vague Suspicious Activity Alert on Web Portal",
        alert_text=SCENARIO_A2_ALERT,
        target_id="svc-web-portal",
        description="Vague activity alert evaluating tool selection without unwarranted containment isolation.",
    ),
}


def list_scenarios() -> list[ScenarioDefinition]:
    """Return all supported canonical incident response scenarios."""
    return list(SCENARIOS.values())


def get_scenario(scenario_id: str) -> ScenarioDefinition:
    """Retrieve scenario definition by ID ('A', 'B', or 'C')."""
    sid = scenario_id.strip().upper()
    if sid not in SCENARIOS:
        raise ValueError(f"Unknown scenario ID '{scenario_id}'. Supported scenarios are A, B, C.")
    return SCENARIOS[sid]


def detect_scenario(alert_text: str) -> str:
    """Detect scenario identifier ('A', 'B', 'C', or 'A2') from incident alert text."""
    text_lower = alert_text.lower()
    if "suspicious activity" in text_lower or "svc-web-portal" in text_lower:
        return "A2"
    if "svc-payments-gateway" in text_lower or "cve-2026-9901" in text_lower:
        return "A"
    if "db-orders" in text_lower or "unreachable" in text_lower:
        return "B"
    if "svc-config" in text_lower or "cve-2026-4418" in text_lower:
        return "C"

    # Fallback to regex ID matching
    match_a2 = re.search(r"\b(?:suspicious|web-portal)\b", text_lower)
    if match_a2:
        return "A2"
    match_a = re.search(r"\b(?:payments|gateway)\b", text_lower)
    if match_a:
        return "A"
    match_b = re.search(r"\b(?:orders|order-db)\b", text_lower)
    if match_b:
        return "B"
    match_c = re.search(r"\b(?:config|configuration)\b", text_lower)
    if match_c:
        return "C"

    return "A"
