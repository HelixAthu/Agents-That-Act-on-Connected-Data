"""Deterministic risk scoring engine for graph-resident components.

Implements the deterministic risk formula defined in Spec 02 Section 8.1:
  severity   = max over vulns affecting target of (cvss/10) * (1.0 if exploitable else 0.6); 0 if none
  pii        = 0 if no attack path; 1.0 if min_hops <= 3; 0.7 if 4..6
  blast      = (# customer-facing services impacted, reverse, hops<=3, target excluded) / 8
  central    = transitive_dependents(target) / 19      (0 if target is not a Service)
  risk       = round(0.40*severity + 0.40*pii + 0.10*blast + 0.10*central, 3)
"""

from __future__ import annotations

import logging
from typing import Any

from falkordb import Graph

from mcp_server.queries import (
    count_transitive_dependents,
    find_attack_paths,
    get_component_context,
    get_failure_impact,
)

logger = logging.getLogger(__name__)

# Weight coefficients defined in Spec 02 Section 8.1
SEVERITY_WEIGHT: float = 0.40
PII_WEIGHT: float = 0.40
BLAST_WEIGHT: float = 0.10
CENTRAL_WEIGHT: float = 0.10

# Normalization factors and domain constants
TOTAL_CUSTOMER_FACING_SERVICES: int = 8
MAX_POSSIBLE_DEPENDENTS: int = 19
EXPLOITABLE_MULTIPLIER: float = 1.0
UNEXPLOITABLE_MULTIPLIER: float = 0.6
CVSS_BASE_SCALE: float = 10.0

MAX_ATTACK_HOPS: int = 6
MAX_IMPACT_HOPS: int = 3
SERVICE_LABEL: str = "Service"


def compute_severity(
    vulnerabilities: list[dict[str, Any]] | None,
) -> tuple[float, dict[str, Any] | None]:
    """Calculate the normalized vulnerability severity component.

    Takes the maximum across all vulnerabilities affecting the target:
    (cvss / 10) * (1.0 if exploitable else 0.6). Returns 0.0 if no vulnerabilities exist.
    """
    if not vulnerabilities:
        return 0.0, None

    highest_score: float = -1.0
    primary_vulnerability: dict[str, Any] | None = None

    for vuln in vulnerabilities:
        cvss_score: float = float(vuln.get("cvss", 0.0))
        is_exploitable: bool = bool(vuln.get("exploitable", False))
        multiplier: float = EXPLOITABLE_MULTIPLIER if is_exploitable else UNEXPLOITABLE_MULTIPLIER
        normalized_score: float = (cvss_score / CVSS_BASE_SCALE) * multiplier

        if normalized_score > highest_score:
            highest_score = normalized_score
            primary_vulnerability = vuln

    if highest_score < 0.0:
        return 0.0, None

    return round(highest_score, 4), primary_vulnerability


def compute_pii_score(attack_paths: list[dict[str, Any]] | None) -> float:
    """Calculate the PII exposure score component based on shortest attack path hops.

    Returns 0.0 if no attack paths exist, 1.0 if min_hops <= 3, and 0.7 if 4 <= min_hops <= 6.
    """
    if not attack_paths:
        return 0.0

    min_hops: int = min(int(p.get("hops", 999)) for p in attack_paths)
    if min_hops <= 3:
        return 1.0
    if 4 <= min_hops <= 6:
        return 0.7
    return 0.0


def compute_blast_score(
    impacted_services: list[dict[str, Any]] | None,
    target_id: str | None = None,
) -> tuple[float, int]:
    """Calculate the failure blast radius score component.

    Counts distinct customer-facing services impacted within hops <= 3, excluding the target itself,
    normalized by dividing by 8 (the total count of customer-facing services in the cluster).
    """
    if not impacted_services:
        return 0.0, 0

    cf_services: list[dict[str, Any]] = [
        s
        for s in impacted_services
        if bool(s.get("customer_facing")) and (target_id is None or s.get("id") != target_id)
    ]
    cf_count: int = len(cf_services)
    blast_score: float = min(1.0, cf_count / float(TOTAL_CUSTOMER_FACING_SERVICES))
    return round(blast_score, 4), cf_count


def compute_centrality_score(
    transitive_dependents: int,
    is_service: bool = True,
) -> float:
    """Calculate architectural centrality component based on transitive incoming dependents.

    Non-service targets return 0.0. Services return dependents normalized by 19.
    """
    if not is_service or transitive_dependents <= 0:
        return 0.0

    centrality_score: float = min(1.0, transitive_dependents / float(MAX_POSSIBLE_DEPENDENTS))
    return round(centrality_score, 4)


def calculate_risk(
    severity: float,
    pii: float,
    blast: float,
    central: float,
) -> float:
    """Combine components into a deterministic composite risk score.

    Formula: round(0.40*severity + 0.40*pii + 0.10*blast + 0.10*central, 3).
    """
    composite_risk: float = (
        (SEVERITY_WEIGHT * severity)
        + (PII_WEIGHT * pii)
        + (BLAST_WEIGHT * blast)
        + (CENTRAL_WEIGHT * central)
    )
    return round(composite_risk, 3)


def evaluate_risk(
    target_id: str,
    is_service: bool = True,
    vulnerabilities: list[dict[str, Any]] | None = None,
    attack_paths: list[dict[str, Any]] | None = None,
    impacted_services: list[dict[str, Any]] | None = None,
    transitive_dependents: int = 0,
) -> dict[str, Any]:
    """Pure evaluation function that computes deterministic risk scores and components.

    Accepts raw pre-fetched data structures to support offline testing and deterministic verification.
    """
    severity, primary_vuln = compute_severity(vulnerabilities)
    pii = compute_pii_score(attack_paths)
    blast, cf_count = compute_blast_score(impacted_services, target_id=target_id)
    central = compute_centrality_score(transitive_dependents, is_service=is_service)
    risk = calculate_risk(severity, pii, blast, central)

    target_dbs: set[str] = {
        str(path["target"])
        for path in (attack_paths or [])
        if path.get("target")
    }

    return {
        "target_id": target_id,
        "risk": risk,
        "components": {
            "severity": severity,
            "pii": pii,
            "blast": blast,
            "central": central,
        },
        "vulnerability": primary_vuln,
        "attack_target_count": len(target_dbs),
        "impacted_cf_count": cf_count,
    }


def compute_target_risk(
    target_id: str,
    graph: Graph | None = None,
) -> dict[str, Any]:
    """Retrieve graph context for a target component and compute its authoritative risk profile.

    Gathers component context, reachable attack paths, failure blast radius, and transitive dependents,
    returning structured data, visit tracking metadata, and query execution evidence.
    """
    if not target_id or not isinstance(target_id, str):
        raise ValueError("target_id must be a non-empty string")

    ctx: dict[str, Any] | None = get_component_context(target_id, graph=graph)
    if ctx is None:
        raise KeyError(f"Component '{target_id}' not found in graph")

    is_service: bool = (ctx.get("label") == SERVICE_LABEL)
    vulnerabilities: list[dict[str, Any]] = ctx.get("vulnerabilities", [])

    attack_res: dict[str, Any] = find_attack_paths(
        source_id=target_id,
        max_hops=MAX_ATTACK_HOPS,
        graph=graph,
    )
    attack_paths: list[dict[str, Any]] = attack_res.get("paths", [])

    impact_res: dict[str, Any] = get_failure_impact(
        target_id=target_id,
        max_hops=MAX_IMPACT_HOPS,
        graph=graph,
    )
    impacted_services: list[dict[str, Any]] = impact_res.get("impacted", [])

    transitive_deps: int = (
        count_transitive_dependents(target_id, graph=graph) if is_service else 0
    )

    eval_data: dict[str, Any] = evaluate_risk(
        target_id=target_id,
        is_service=is_service,
        vulnerabilities=vulnerabilities,
        attack_paths=attack_paths,
        impacted_services=impacted_services,
        transitive_dependents=transitive_deps,
    )

    visited_nodes: set[str] = {target_id}
    visited_nodes.update(ctx.get("node_ids", []))
    visited_nodes.update(attack_res.get("node_ids", []))
    visited_nodes.update(impact_res.get("node_ids", []))

    visited_edges: set[str] = set()
    visited_edges.update(ctx.get("edge_keys", []))
    visited_edges.update(attack_res.get("edge_keys", []))
    visited_edges.update(impact_res.get("edge_keys", []))

    total_execution_ms: float = round(
        float(ctx.get("ms", 0.0))
        + float(attack_res.get("ms", 0.0))
        + float(impact_res.get("ms", 0.0)),
        2,
    )

    return {
        "data": eval_data,
        "visit": {
            "kind": "inspect",
            "node_ids": sorted(visited_nodes),
            "edge_keys": sorted(visited_edges),
        },
        "evidence": {
            "query_id": "Q-RISK-ASSESSMENT",
            "cypher": "MULTIPLE_RO_QUERIES (CONTEXT, ATTACK, IMPACT, DEPENDENTS)",
            "params": {"id": target_id},
            "ms": total_execution_ms,
            "row_count": len(attack_paths) + len(impacted_services),
        },
    }
