"""Pydantic models and envelope formatting helpers for the MCP server."""

from __future__ import annotations

import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ErrorCode(str, Enum):
    """Canonical error codes defined in Spec 03 Section 9."""

    NOT_FOUND = "NOT_FOUND"
    INVALID_INPUT = "INVALID_INPUT"
    POLICY_DENIED = "POLICY_DENIED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    DB_ERROR = "DB_ERROR"


class VisitKind(str, Enum):
    """Kinds of graph traversal or inspection visits for the UI feed."""

    INSPECT = "inspect"
    IMPACT = "impact"
    ATTACK_PATH = "attack_path"
    ACTION = "action"


class Visit(BaseModel):
    """Sub-envelope capturing node and edge visits for UI path highlighting."""

    kind: VisitKind | str
    node_ids: list[str] = Field(default_factory=list)
    edge_keys: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    """Sub-envelope capturing Cypher execution evidence and timing."""

    query_id: str
    cypher: str
    params: dict[str, Any] = Field(default_factory=dict)
    ms: float
    row_count: int


class ErrorDetails(BaseModel):
    """Standard error payload for failed MCP tool executions."""

    code: ErrorCode | str
    message: str


class ResponseEnvelope(BaseModel):
    """Canonical MCP tool response envelope returning data, visit, evidence, or error."""

    ok: bool
    data: dict[str, Any] | None = None
    visit: Visit | None = None
    evidence: Evidence | None = None
    error: ErrorDetails | None = None

    def to_json(self) -> str:
        """Serialize envelope to standard JSON string omitting null optional blocks."""
        return self.model_dump_json(exclude_none=True)


def format_success(
    data: dict[str, Any],
    visit: Visit | dict[str, Any] | None = None,
    evidence: Evidence | dict[str, Any] | None = None,
) -> str:
    """Construct and serialize a successful MCP response envelope JSON string."""
    visit_obj = Visit(**visit) if isinstance(visit, dict) else visit
    evidence_obj = Evidence(**evidence) if isinstance(evidence, dict) else evidence

    envelope = ResponseEnvelope(
        ok=True,
        data=data,
        visit=visit_obj,
        evidence=evidence_obj,
    )
    return envelope.to_json()


def format_error(code: ErrorCode | str, message: str) -> str:
    """Construct and serialize a standard MCP error envelope JSON string."""
    error_code = code.value if isinstance(code, ErrorCode) else code
    envelope = ResponseEnvelope(
        ok=False,
        error=ErrorDetails(code=error_code, message=message),
    )
    return envelope.to_json()


def parse_envelope(payload_json: str) -> dict[str, Any]:
    """Parse an envelope JSON string into a validated Python dict."""
    return json.loads(payload_json)
