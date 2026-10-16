"""Containment policy decision engine for graph containment actions.

Implements the deterministic policy decision rules defined in Spec 02 Section 8.2:
  - ISOLATE_NODE:
      1. No verified attack path to a PII DB from target -> DENIED
      2. Target is tier 1 AND customer_facing -> APPROVAL_REQUIRED
      3. risk >= 0.8 -> AUTO
      4. else -> APPROVAL_REQUIRED
  - REVOKE_ROLE:
      1. Edge not on any verified attack path -> DENIED
      2. risk >= 0.5 -> AUTO, else APPROVAL_REQUIRED
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from falkordb import Graph

from mcp_server.queries import find_attack_paths, get_component_context
from mcp_server.scoring import MAX_ATTACK_HOPS, compute_target_risk

logger = logging.getLogger(__name__)


class ContainmentAction(str, Enum):
    """Supported containment actions defined in Spec 02 Section 8.2."""

    ISOLATE_NODE = "ISOLATE_NODE"
    REVOKE_ROLE = "REVOKE_ROLE"


class PolicyDecision(str, Enum):
    """Possible policy gate outcomes."""

    AUTO = "AUTO"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    DENIED = "DENIED"


# Decision reason strings (Spec 02 Section 8.2)
REASON_NO_ATTACK_PATH: str = "no verified attack path; isolation would cause outage without evidence"
REASON_TIER1_CUSTOMER_FACING: str = "tier-1 customer-facing service requires human approval"
REASON_HIGH_RISK_AUTO: str = "high risk threshold met (risk >= 0.8); automatic isolation permitted"
REASON_MODERATE_RISK_APPROVAL: str = "moderate risk containment requires human approval"

REASON_ROLE_NOT_ON_ATTACK_PATH: str = "edge not on any verified attack path"
REASON_ROLE_HIGH_RISK_AUTO: str = "risk threshold met (risk >= 0.5); automatic role revocation permitted"
REASON_ROLE_LOW_RISK_APPROVAL: str = "low risk role revocation requires human approval"

# Risk threshold constants
ISOLATE_HIGH_RISK_THRESHOLD: float = 0.8
REVOKE_HIGH_RISK_THRESHOLD: float = 0.5


def is_edge_on_attack_paths(
    service_id: str,
    role_id: str,
    attack_paths: list[dict[str, Any]] | None,
) -> bool:
    """Check if the ASSUMES_ROLE edge between service_id and role_id appears in any attack path."""
    if not attack_paths:
        return False

    expected_edge_key: str = f"{service_id}|ASSUMES_ROLE|{role_id}"

    for path in attack_paths:
        edge_keys: list[str] = path.get("edge_keys", [])
        if expected_edge_key in edge_keys:
            return True

        node_ids: list[str] = path.get("node_ids", [])
        for i in range(len(node_ids) - 1):
            if node_ids[i] == service_id and node_ids[i + 1] == role_id:
                return True

    return False


def decide(action: str, ctx: dict[str, Any]) -> dict[str, str]:
    """Pure policy decision function evaluating containment requests against context.

    Evaluates policy rules sequentially (first match wins) per Spec 02 Section 8.2.
    Returns a dict with 'decision' and 'reason'.
    """
    normalized_action: str = action.strip().upper() if isinstance(action, str) else ""

    if normalized_action == ContainmentAction.ISOLATE_NODE.value:
        return _decide_isolate_node(ctx)

    if normalized_action == ContainmentAction.REVOKE_ROLE.value:
        return _decide_revoke_role(ctx)

    raise ValueError(f"Unknown or unsupported containment action: '{action}'")


def _decide_isolate_node(ctx: dict[str, Any]) -> dict[str, str]:
    """Evaluate ISOLATE_NODE rules in order of priority (first match wins)."""
    attack_paths: list[dict[str, Any]] = ctx.get("attack_paths", [])
    has_attack_path: bool = bool(attack_paths) or (int(ctx.get("attack_target_count", 0)) > 0)

    # Rule 1: No verified attack path to a PII DB from target -> DENIED
    if not has_attack_path:
        return {
            "decision": PolicyDecision.DENIED.value,
            "reason": REASON_NO_ATTACK_PATH,
        }

    tier: int = int(ctx.get("tier", 0))
    customer_facing: bool = bool(ctx.get("customer_facing", False))

    # Rule 2: Target is tier 1 AND customer_facing -> APPROVAL_REQUIRED
    if tier == 1 and customer_facing:
        return {
            "decision": PolicyDecision.APPROVAL_REQUIRED.value,
            "reason": REASON_TIER1_CUSTOMER_FACING,
        }

    risk: float = float(ctx.get("risk", 0.0))

    # Rule 3: risk >= 0.8 -> AUTO
    if risk >= ISOLATE_HIGH_RISK_THRESHOLD:
        return {
            "decision": PolicyDecision.AUTO.value,
            "reason": REASON_HIGH_RISK_AUTO,
        }

    # Rule 4: else -> APPROVAL_REQUIRED
    return {
        "decision": PolicyDecision.APPROVAL_REQUIRED.value,
        "reason": REASON_MODERATE_RISK_APPROVAL,
    }


def _decide_revoke_role(ctx: dict[str, Any]) -> dict[str, str]:
    """Evaluate REVOKE_ROLE rules in order of priority (first match wins)."""
    edge_on_path: bool = bool(ctx.get("edge_on_attack_path", False))
    attack_paths: list[dict[str, Any]] = ctx.get("attack_paths", [])
    service_id: str = str(ctx.get("service_id", ""))
    role_id: str = str(ctx.get("role_id", ""))

    if not edge_on_path and service_id and role_id:
        edge_on_path = is_edge_on_attack_paths(service_id, role_id, attack_paths)

    # Rule 1: Edge not on any verified attack path -> DENIED
    if not edge_on_path:
        return {
            "decision": PolicyDecision.DENIED.value,
            "reason": REASON_ROLE_NOT_ON_ATTACK_PATH,
        }

    risk: float = float(ctx.get("risk", 0.0))

    # Rule 2: risk >= 0.5 -> AUTO, else APPROVAL_REQUIRED
    if risk >= REVOKE_HIGH_RISK_THRESHOLD:
        return {
            "decision": PolicyDecision.AUTO.value,
            "reason": REASON_ROLE_HIGH_RISK_AUTO,
        }

    return {
        "decision": PolicyDecision.APPROVAL_REQUIRED.value,
        "reason": REASON_ROLE_LOW_RISK_APPROVAL,
    }


def evaluate_containment_policy(
    action: str,
    target_id: str,
    graph: Graph | None = None,
) -> dict[str, Any]:
    """Query graph context and evaluate policy decision for a containment candidate.

    For ISOLATE_NODE: target_id is the node ID (e.g., 'svc-payments-gateway').
    For REVOKE_ROLE: target_id is 'service_id|role_id' (e.g., 'svc-payments-gateway|role-storage-manager').
    """
    if not target_id or not isinstance(target_id, str):
        raise ValueError("target_id must be a non-empty string")

    normalized_action: str = action.strip().upper() if isinstance(action, str) else ""

    if normalized_action == ContainmentAction.ISOLATE_NODE.value:
        risk_result = compute_target_risk(target_id, graph=graph)
        ctx = get_component_context(target_id, graph=graph)
        if ctx is None:
            raise KeyError(f"Component '{target_id}' not found in graph")

        props = ctx.get("props", {})
        attack_paths = find_attack_paths(target_id, max_hops=MAX_ATTACK_HOPS, graph=graph).get("paths", [])

        eval_ctx: dict[str, Any] = {
            "target_id": target_id,
            "tier": props.get("tier", 0),
            "customer_facing": props.get("customer_facing", False),
            "risk": risk_result["data"]["risk"],
            "attack_paths": attack_paths,
            "attack_target_count": len({p["target"] for p in attack_paths if "target" in p}),
        }

        policy_decision = decide(ContainmentAction.ISOLATE_NODE.value, eval_ctx)
        return {
            "action": ContainmentAction.ISOLATE_NODE.value,
            "target_id": target_id,
            "policy": policy_decision,
            "risk": risk_result["data"]["risk"],
            "context": eval_ctx,
        }

    if normalized_action == ContainmentAction.REVOKE_ROLE.value:
        if "|" not in target_id:
            raise ValueError("target_id for REVOKE_ROLE must be in 'service_id|role_id' format")

        service_id, role_id = target_id.split("|", 1)
        risk_result = compute_target_risk(service_id, graph=graph)
        attack_paths = find_attack_paths(service_id, max_hops=MAX_ATTACK_HOPS, graph=graph).get("paths", [])

        edge_on_path = is_edge_on_attack_paths(service_id, role_id, attack_paths)

        eval_ctx = {
            "target_id": target_id,
            "service_id": service_id,
            "role_id": role_id,
            "risk": risk_result["data"]["risk"],
            "attack_paths": attack_paths,
            "edge_on_attack_path": edge_on_path,
        }

        policy_decision = decide(ContainmentAction.REVOKE_ROLE.value, eval_ctx)
        return {
            "action": ContainmentAction.REVOKE_ROLE.value,
            "target_id": target_id,
            "policy": policy_decision,
            "risk": risk_result["data"]["risk"],
            "context": eval_ctx,
        }

    raise ValueError(f"Unknown or unsupported containment action: '{action}'")
