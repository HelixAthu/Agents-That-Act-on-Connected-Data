"""Event models, FinalReport schema, anti-hallucination validation, and in-memory EventBus."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

logger: logging.Logger = logging.getLogger(__name__)

NODE_ID_PATTERN: re.Pattern[str] = re.compile(r"\b(?:svc|db|role|team)-[a-z0-9-]+\b")


class EventType(str, Enum):
    """Enumeration of all incident response agent lifecycle event types."""

    INCIDENT_STARTED = "incident_started"
    THOUGHT = "thought"
    TOOL_CALL = "tool_call"
    GRAPH_VISIT = "graph_visit"
    TOOL_RESULT = "tool_result"
    RISK_UPDATE = "risk_update"
    APPROVAL_REQUIRED = "approval_required"
    ACTION = "action"
    VERIFICATION = "verification"
    FINAL_REPORT = "final_report"
    ERROR = "error"


class IncidentStartedData(BaseModel):
    """Payload for incident_started event."""

    incident_id: str
    alert_text: str
    mode: str = "mock"


class ThoughtData(BaseModel):
    """Payload for thought event."""

    text: str


class ToolCallData(BaseModel):
    """Payload for tool_call event."""

    call_id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class GraphVisitData(BaseModel):
    """Payload for graph_visit event extracted strictly from MCP tool envelopes."""

    call_id: str
    kind: str
    node_ids: list[str] = Field(default_factory=list)
    edge_keys: list[str] = Field(default_factory=list)


class ToolResultData(BaseModel):
    """Payload for tool_result event with code-generated summary."""

    call_id: str
    ok: bool
    summary: str
    query_id: str = ""
    cypher: str = ""
    ms: float = 0.0


class RiskUpdateData(BaseModel):
    """Payload for risk_update event."""

    risk: float
    components: dict[str, float] = Field(default_factory=dict)


class ApprovalRequiredData(BaseModel):
    """Payload for approval_required event."""

    action_id: str
    action: str
    target_id: str
    reason: str


class ActionData(BaseModel):
    """Payload for action event."""

    action_id: str
    action: str
    target_id: str
    status: str
    policy: str


class VerificationData(BaseModel):
    """Payload for verification event built from execute/rollback results."""

    action_id: str
    targets_before: list[str] = Field(default_factory=list)
    targets_after: list[str] = Field(default_factory=list)


class ErrorData(BaseModel):
    """Payload for error event."""

    message: str
    recoverable: bool = False


class ReportFinding(BaseModel):
    """Analytical finding item inside FinalReport."""

    claim: str
    evidence_refs: list[str] = Field(default_factory=list)


class ReportImpact(BaseModel):
    """Blast radius impact summary inside FinalReport."""

    impacted_services: int = 0
    customer_facing: int = 0
    owner_teams: list[str] = Field(default_factory=list)


class ReportAction(BaseModel):
    """Action item record inside FinalReport."""

    action_id: str
    type: str
    target: str
    policy: str
    status: str


class ReportVerification(BaseModel):
    """Pre- and post-containment target verification inside FinalReport."""

    targets_before: list[str] = Field(default_factory=list)
    targets_after: list[str] = Field(default_factory=list)


class ReportToolCall(BaseModel):
    """Tool invocation summary record inside FinalReport."""

    call_id: str
    tool: str
    ms: float = 0.0
    query_id: str = ""


class FinalReport(BaseModel):
    """Strict final incident response report schema matching Spec 04 Section 10.5."""

    model_config = ConfigDict(extra="ignore")

    incident_id: str
    summary: str
    risk_score: float = 0.0
    findings: list[ReportFinding] = Field(default_factory=list)
    impact: ReportImpact = Field(default_factory=ReportImpact)
    actions: list[ReportAction] = Field(default_factory=list)
    verification: ReportVerification = Field(default_factory=ReportVerification)
    tool_calls: list[ReportToolCall] = Field(default_factory=list)


def validate_final_report_hallucinations(
    report: FinalReport,
    allowed_node_ids: set[str],
) -> FinalReport:
    """Strip findings citing node IDs not present in any tool result of this incident."""
    valid_findings: list[ReportFinding] = []
    for finding in report.findings:
        mentioned_ids: set[str] = set(NODE_ID_PATTERN.findall(finding.claim))
        hallucinated_ids: set[str] = mentioned_ids - allowed_node_ids
        if hallucinated_ids:
            logger.warning(
                "Stripping hallucinated finding citing unverified nodes %s: %s",
                hallucinated_ids,
                finding.claim,
            )
            continue
        valid_findings.append(finding)

    return report.model_copy(update={"findings": valid_findings})


class Event(BaseModel):
    """Standard SSE and audit event envelope matching Spec 04 Section 11."""

    seq: int
    ts: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    type: str
    data: dict[str, Any]


class EventBus:
    """In-memory event bus with sequence numbering, async streaming queues, and JSONL persistence."""

    def __init__(self, incident_id: str = "") -> None:
        self.incident_id: str = incident_id
        self._seq: int = 0
        self._events: list[Event] = []
        self._subscribers: list[asyncio.Queue[Event]] = []
        self._lock: asyncio.Lock = asyncio.Lock()

    @property
    def current_seq(self) -> int:
        """Return the highest assigned sequence number."""
        return self._seq

    def _prepare_event(
        self,
        event_or_type: Event | EventType | str,
        data: dict[str, Any] | BaseModel | None = None,
    ) -> Event:
        """Internal helper to assign sequence number, timestamp, and envelope structure."""
        self._seq += 1
        if isinstance(event_or_type, Event):
            type_str: str = event_or_type.type
            data_dict: dict[str, Any] = dict(event_or_type.data)
        else:
            type_str = event_or_type.value if isinstance(event_or_type, EventType) else str(event_or_type)
            if data is None:
                data_dict = {}
            elif isinstance(data, BaseModel):
                data_dict = data.model_dump()
            else:
                data_dict = dict(data)

        now_ts: str = datetime.now(UTC).isoformat()
        return Event(seq=self._seq, ts=now_ts, type=type_str, data=data_dict)

    async def emit(
        self,
        event_or_type: Event | EventType | str,
        data: dict[str, Any] | BaseModel | None = None,
    ) -> Event:
        """Emit an event asynchronously, assign sequence number, and broadcast to active subscriber queues."""
        async with self._lock:
            event = self._prepare_event(event_or_type, data)
            self._events.append(event)
            for queue in self._subscribers:
                await queue.put(event)
            return event

    def emit_sync(
        self,
        event_or_type: Event | EventType | str,
        data: dict[str, Any] | BaseModel | None = None,
    ) -> Event:
        """Synchronous emit for non-async contexts or unit testing."""
        event = self._prepare_event(event_or_type, data)
        self._events.append(event)
        for queue in self._subscribers:
            queue.put_nowait(event)
        return event

    def subscribe(self, replay_buffered: bool = True) -> asyncio.Queue[Event]:
        """Subscribe to the event bus, optionally pre-populating queue with prior buffered events."""
        queue: asyncio.Queue[Event] = asyncio.Queue()
        if replay_buffered:
            for event in self._events:
                queue.put_nowait(event)
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        """Remove a subscriber queue from the active broadcast list."""
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    def get_events(self) -> list[Event]:
        """Return an immutable snapshot copy of all recorded events in sequential order."""
        return list(self._events)

    def dump_jsonl(self, filepath: str | Path | None = None) -> str:
        """Serialize all recorded events to newline-delimited JSON, optionally writing to file."""
        lines: list[str] = [event.model_dump_json() for event in self._events]
        content: str = "\n".join(lines) + ("\n" if lines else "")
        if filepath is not None:
            target_path = Path(filepath)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(content, encoding="utf-8")
        return content

    @classmethod
    def load_jsonl(cls, source: str | Path) -> list[Event]:
        """Deserialize events from a JSONL file path or raw JSONL string."""
        raw_text: str
        source_path = Path(source)
        if source_path.exists() and source_path.is_file():
            raw_text = source_path.read_text(encoding="utf-8")
        else:
            raw_text = str(source)

        events: list[Event] = []
        for line in raw_text.splitlines():
            cleaned = line.strip()
            if not cleaned:
                continue
            payload = json.loads(cleaned)
            events.append(Event(**payload))
        return events
