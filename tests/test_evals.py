"""Test suite for evaluation scenario harness and results table generation."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from evals.eval_harness import load_scenarios_spec, run_scenario_eval, generate_markdown_results


@pytest.mark.asyncio
async def test_scenarios_spec_loading() -> None:
    """Verify scenarios.yaml loads valid definitions for scenarios A, B, C, and A2."""
    spec_path = Path("evals/scenarios.yaml")
    scenarios = load_scenarios_spec(spec_path)
    assert len(scenarios) == 4
    scenario_ids = [s["id"] for s in scenarios]
    assert scenario_ids == ["A", "B", "C", "A2"]


@pytest.mark.asyncio
async def test_eval_harness_execution(tmp_path: Path) -> None:
    """Verify eval harness runs all scenarios with 100% pass rate and produces markdown output."""
    spec_path = Path("evals/scenarios.yaml")
    scenarios = load_scenarios_spec(spec_path)

    results = []
    for spec in scenarios:
        res = await run_scenario_eval(spec, mode="mock")
        assert res.passed is True
        assert res.tool_calls_within_budget is True
        assert res.no_hallucinations is True
        assert res.policy_compliance is True
        results.append(res)

    assert len(results) == 4

    out_file = tmp_path / "results.md"
    content = generate_markdown_results(results, out_file)
    assert "# Incident Response Agent Evaluation Benchmark Results" in content
    assert "100.0%" in content
    assert "G2: Reachable PII Databases" in content
