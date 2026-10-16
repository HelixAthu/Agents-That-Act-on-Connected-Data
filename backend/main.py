"""FastAPI application exposing graph data, scenario runner, SSE streaming, and approval endpoints."""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from backend.agent_mock import MockAgent
from backend.events import Event, EventBus, EventType
from backend.scenarios import get_scenario, list_scenarios
from mcp_server.queries import get_graph_health, get_ui_graph
from seed.seed_graph import seed_graph

logger: logging.Logger = logging.getLogger(__name__)

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
REPLAYS_DIR: Path = REPO_ROOT / "replays"


class HealthResponse(BaseModel):
    """Health check response schema."""

    ok: bool
    graph: str
    nodes: int


class GraphNode(BaseModel):
    """UI graph node schema."""

    id: str
    label: str
    props: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """UI graph edge schema."""

    id: str
    source: str
    target: str
    type: str
    props: dict[str, Any] = Field(default_factory=dict)


class GraphResponse(BaseModel):
    """UI graph payload schema."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]


class ScenarioResponse(BaseModel):
    """Incident response scenario metadata."""

    id: str
    title: str
    alert_text: str


class IncidentCreateRequest(BaseModel):
    """Request payload to initiate a new incident response run."""

    scenario: str | None = None
    text: str | None = None
    mode: str = "mock"
    auto_approve: bool = True


class IncidentCreateResponse(BaseModel):
    """Response payload returned upon incident creation."""

    incident_id: str


class IncidentRecord:
    """Internal tracker for an active or completed incident."""

    def __init__(
        self,
        incident_id: str,
        alert_text: str,
        mode: str,
        bus: EventBus,
        task: asyncio.Task[Any] | None = None,
    ) -> None:
        self.incident_id: str = incident_id
        self.alert_text: str = alert_text
        self.mode: str = mode
        self.bus: EventBus = bus
        self.task: asyncio.Task[Any] | None = task


incidents_registry: dict[str, IncidentRecord] = {}
pending_approvals: dict[str, asyncio.Future[bool]] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan by closing background tasks gracefully."""
    logger.info("Initializing Incident Response API...")
    yield
    logger.info("Shutting down Incident Response API...")
    for rec in incidents_registry.values():
        if rec.task and not rec.task.done():
            rec.task.cancel()


app: FastAPI = FastAPI(
    title="Blast Radius Incident Response Agent API",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Check service health and database node count."""
    data = get_graph_health()
    return HealthResponse(**data)


@app.get("/graph", response_model=GraphResponse)
async def graph() -> GraphResponse:
    """Fetch filtered infrastructure graph excluding Team and Vulnerability nodes."""
    data = get_ui_graph()
    return GraphResponse(**data)


@app.get("/scenarios", response_model=list[ScenarioResponse])
async def scenarios() -> list[ScenarioResponse]:
    """List canonical incident response scenarios."""
    all_scenarios = list_scenarios()
    return [
        ScenarioResponse(id=s.id, title=s.title, alert_text=s.alert_text)
        for s in all_scenarios
    ]


async def _run_agent_task(
    incident_id: str,
    alert_text: str,
    mode: str,
    bus: EventBus,
    auto_approve: bool,
) -> None:
    """Execute the incident agent in a background task and route events through the incident bus."""
    async def emit_wrapper(event: Event) -> None:
        await bus.emit(event)

    async def approval_handler(action_id: str) -> bool:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[bool] = loop.create_future()
        pending_approvals[action_id] = future
        try:
            return await asyncio.wait_for(future, timeout=60.0)
        except TimeoutError:
            return False
        finally:
            pending_approvals.pop(action_id, None)

    try:
        if mode == "mock":
            agent = MockAgent()
        else:
            from backend.agent_live import LiveAgent

            agent = LiveAgent()

        await agent.run(
            incident_id=incident_id,
            alert_text=alert_text,
            emit=emit_wrapper,
            auto_approve=auto_approve,
            approval_handler=approval_handler,
        )
    except Exception as err:
        logger.exception("Incident execution error in background task for %s", incident_id)
        await bus.emit(
            EventType.ERROR.value,
            {"message": str(err), "recoverable": False},
        )


@app.post("/incidents", response_model=IncidentCreateResponse)
async def create_incident(req: IncidentCreateRequest) -> IncidentCreateResponse:
    """Create a new incident and launch autonomous agent execution as a background task."""
    alert_text: str
    if req.scenario:
        scenario_def = get_scenario(req.scenario)
        alert_text = scenario_def.alert_text
    elif req.text:
        alert_text = req.text
    else:
        alert_text = get_scenario("A").alert_text

    incident_id: str = f"inc-{uuid.uuid4().hex[:8]}"
    bus: EventBus = EventBus(incident_id=incident_id)

    task: asyncio.Task[Any] = asyncio.create_task(
        _run_agent_task(
            incident_id=incident_id,
            alert_text=alert_text,
            mode=req.mode,
            bus=bus,
            auto_approve=req.auto_approve,
        )
    )

    incidents_registry[incident_id] = IncidentRecord(
        incident_id=incident_id,
        alert_text=alert_text,
        mode=req.mode,
        bus=bus,
        task=task,
    )

    return IncidentCreateResponse(incident_id=incident_id)


@app.get("/incidents/{incident_id}/stream")
async def stream_incident(incident_id: str) -> EventSourceResponse:
    """Stream incident events via Server-Sent Events (SSE), closing upon completion or fatal error."""
    rec = incidents_registry.get(incident_id)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )

    queue = rec.bus.subscribe(replay_buffered=True)

    async def event_generator() -> AsyncGenerator[dict[str, str], None]:
        try:
            while True:
                event: Event = await queue.get()
                yield {
                    "event": event.type,
                    "data": event.model_dump_json(),
                    "id": str(event.seq),
                }
                if event.type == EventType.FINAL_REPORT.value:
                    break
                if event.type == EventType.ERROR.value and not event.data.get("recoverable", False):
                    break
        finally:
            rec.bus.unsubscribe(queue)

    return EventSourceResponse(event_generator())


@app.get("/incidents/{incident_id}/events")
async def get_incident_events(incident_id: str) -> Response:
    """Retrieve full history of events for an incident formatted as newline-delimited JSON."""
    rec = incidents_registry.get(incident_id)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )

    jsonl_content: str = rec.bus.dump_jsonl()
    return Response(content=jsonl_content, media_type="application/x-ndjson")


@app.get("/replays/{scenario}")
async def get_replay(scenario: str) -> Response:
    """Serve recorded scenario replay JSONL file."""
    clean_name = scenario.strip().lower()
    if clean_name.startswith("scenario_"):
        clean_name = clean_name.replace("scenario_", "")
    if clean_name.endswith(".jsonl"):
        clean_name = clean_name.replace(".jsonl", "")

    file_path = REPLAYS_DIR / f"scenario_{clean_name}.jsonl"
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Replay file for scenario '{scenario}' not found.",
        )

    content = file_path.read_text(encoding="utf-8")
    return Response(content=content, media_type="application/x-ndjson")


@app.post("/admin/reset")
async def admin_reset() -> dict[str, bool]:
    """Reset graph to initial seed state and clear in-memory incident tracking."""
    seed_graph(reset=True)
    incidents_registry.clear()
    pending_approvals.clear()
    return {"ok": True}
