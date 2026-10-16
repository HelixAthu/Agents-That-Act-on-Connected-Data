"""Tests for FastAPI backend endpoints, graph model, replays, and SSE stream."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx
import pytest

from backend.main import app
from seed.seed_graph import seed_graph


@pytest.fixture(scope="module", autouse=True)
def setup_test_graph() -> None:
    """Ensure clean seeded graph state before running API tests."""
    seed_graph(reset=True)


@pytest.mark.asyncio
async def test_health_endpoint() -> None:
    """Assert GET /health reports database connection and 41 total graph nodes."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["graph"] == "infra"
        assert data["nodes"] == 41


@pytest.mark.asyncio
async def test_graph_endpoint_filtered_counts_and_edge_format() -> None:
    """Assert GET /graph returns 31 nodes (41 minus Team/Vuln) and 69 validly formatted edges."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/graph")
        assert resp.status_code == 200
        data = resp.json()

        nodes = data["nodes"]
        edges = data["edges"]

        # Exactly 31 nodes: 20 Service + 5 Database + 6 IAMRole
        assert len(nodes) == 31, f"Expected 31 nodes in UI graph, got {len(nodes)}"

        label_counts: dict[str, int] = {}
        for n in nodes:
            lbl = n["label"]
            label_counts[lbl] = label_counts.get(lbl, 0) + 1
            assert lbl in {"Service", "Database", "IAMRole"}, f"Unexpected node label: {lbl}"

        assert label_counts.get("Service") == 20
        assert label_counts.get("Database") == 5
        assert label_counts.get("IAMRole") == 6
        assert "Team" not in label_counts
        assert "Vulnerability" not in label_counts

        # Exactly 69 edges: 50 DEPENDS_ON + 6 CONNECTS_TO + 6 ASSUMES_ROLE + 2 CAN_ASSUME + 5 CAN_ACCESS
        assert len(edges) == 69, f"Expected 69 edges in UI graph, got {len(edges)}"

        edge_id_regex = re.compile(r"^[a-z0-9-]+\|[A-Z_]+\|[a-z0-9-]+$")
        for e in edges:
            edge_id = e["id"]
            assert edge_id_regex.match(edge_id), f"Edge id '{edge_id}' violates required pattern."
            assert e["source"]
            assert e["target"]
            assert e["type"]
            assert "isolated" in e["props"]


@pytest.mark.asyncio
async def test_scenarios_listing() -> None:
    """Assert GET /scenarios lists all three canonical incident scenarios."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/scenarios")
        assert resp.status_code == 200
        scenarios = resp.json()
        assert len(scenarios) == 3
        ids = [s["id"] for s in scenarios]
        assert ids == ["A", "B", "C"]


@pytest.mark.asyncio
async def test_replays_endpoints() -> None:
    """Assert GET /replays serves recorded jsonl files and rejects unknown scenarios."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/replays/a")
        assert resp.status_code == 200
        lines = [line for line in resp.text.splitlines() if line.strip()]
        assert len(lines) > 0

        # Assert 404 for invalid replay
        bad_resp = await client.get("/replays/nonexistent")
        assert bad_resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_reset_endpoint() -> None:
    """Assert POST /admin/reset successfully resets the graph and returns ok."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/admin/reset")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}


@pytest.mark.asyncio
async def test_incident_lifecycle_mock_scenario_c_and_events() -> None:
    """Assert creating an incident executes scenario C and exposes events via GET /incidents/{id}/events."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        create_resp = await client.post(
            "/incidents",
            json={"scenario": "C", "mode": "mock", "auto_approve": True},
        )
        assert create_resp.status_code == 200
        inc_id: str = create_resp.json()["incident_id"]
        assert inc_id.startswith("inc-")

        # Allow background execution to finish
        await asyncio.sleep(2.0)

        events_resp = await client.get(f"/incidents/{inc_id}/events")
        assert events_resp.status_code == 200
        lines = [line for line in events_resp.text.splitlines() if line.strip()]
        assert len(lines) > 0

        events = [json.loads(line) for line in lines]
        event_types = [e["type"] for e in events]
        assert "incident_started" in event_types
        assert "tool_call" in event_types
        assert "final_report" in event_types


@pytest.mark.asyncio
async def test_incident_sse_stream() -> None:
    """Assert GET /incidents/{id}/stream delivers events via SSE and terminates upon final_report."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        create_resp = await client.post(
            "/incidents",
            json={"scenario": "C", "mode": "mock", "auto_approve": True},
        )
        assert create_resp.status_code == 200
        inc_id: str = create_resp.json()["incident_id"]

        received_events: list[dict[str, Any]] = []
        async with client.stream("GET", f"/incidents/{inc_id}/stream") as stream_resp:
            assert stream_resp.status_code == 200
            current_event_type: str = ""
            async for raw_line in stream_resp.aiter_lines():
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("event:"):
                    current_event_type = line[len("event:") :].strip()
                elif line.startswith("data:"):
                    payload_raw = line[len("data:") :].strip()
                    payload = json.loads(payload_raw)
                    received_events.append({"event": current_event_type, "payload": payload})
                    if current_event_type == "final_report":
                        break

        assert len(received_events) > 0
        event_names = [ev["event"] for ev in received_events]
        assert "incident_started" in event_names
        assert "final_report" in event_names
