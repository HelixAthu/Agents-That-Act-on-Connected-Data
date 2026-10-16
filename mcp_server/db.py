"""FalkorDB connection, query execution helpers, and execution timing."""

from __future__ import annotations

import os
import time
from typing import Any

from falkordb import FalkorDB, Graph

_client: FalkorDB | None = None


def get_client() -> FalkorDB:
    """Return a cached or newly initialized FalkorDB client connection."""
    global _client
    if _client is None:
        host = os.getenv("FALKORDB_HOST", "localhost")
        port = int(os.getenv("FALKORDB_PORT", "6379"))
        _client = FalkorDB(host=host, port=port)
    return _client


def get_graph(graph_name: str | None = None) -> Graph:
    """Select and return a FalkorDB graph instance."""
    name = graph_name or os.getenv("GRAPH_NAME", "infra")
    client = get_client()
    return client.select_graph(name)


def run_ro(
    query: str,
    params: dict[str, Any] | None = None,
    graph: Graph | None = None,
) -> tuple[list[list[Any]], float]:
    """Execute a read-only Cypher query and return (result_set, elapsed_ms)."""
    target_graph = graph or get_graph()
    start_time = time.perf_counter()
    response = target_graph.ro_query(query, params)
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
    return response.result_set, elapsed_ms


def run_rw(
    query: str,
    params: dict[str, Any] | None = None,
    graph: Graph | None = None,
) -> tuple[list[list[Any]], float]:
    """Execute a read-write Cypher query and return (result_set, elapsed_ms)."""
    target_graph = graph or get_graph()
    start_time = time.perf_counter()
    response = target_graph.query(query, params)
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
    return response.result_set, elapsed_ms
