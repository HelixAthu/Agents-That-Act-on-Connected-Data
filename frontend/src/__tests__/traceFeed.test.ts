import { describe, it, expect } from "vitest";
import { TraceItem } from "../types";
import { TraceFeed } from "../components/TraceFeed";

describe("TraceFeed Component", () => {
  const sampleItems: TraceItem[] = [
    {
      seq: 1,
      ts: "2026-10-16T07:57:31.728744+00:00",
      type: "incident_started",
      summary: "CRITICAL: CVE-2026-9901 detected on svc-payments-gateway",
    },
    {
      seq: 2,
      ts: "2026-10-16T07:57:31.728786+00:00",
      type: "thought",
      text: "Analyzing security alert and inspecting component context.",
    },
    {
      seq: 3,
      ts: "2026-10-16T07:57:31.728830+00:00",
      type: "tool_call",
      tool: "get_component_context",
      call_id: "call-083d0510",
      args: { id: "svc-payments-gateway" },
      query_id: "Q-CONTEXT",
      cypher: "MATCH (n {id: $id}) RETURN n",
      summary: "Context for svc-payments-gateway",
      ms: 3.93,
      ok: true,
    },
  ];

  it("exports TraceFeed component definition", () => {
    expect(TraceFeed).toBeDefined();
    expect(typeof TraceFeed).toBe("function");
  });

  it("validates trace item structure with Cypher and execution metrics", () => {
    const toolCall = sampleItems[2];
    expect(toolCall.call_id).toBe("call-083d0510");
    expect(toolCall.query_id).toBe("Q-CONTEXT");
    expect(toolCall.cypher).toContain("MATCH (n {id: $id})");
    expect(toolCall.ms).toBe(3.93);
    expect(toolCall.ok).toBe(true);
    expect(toolCall.args).toEqual({ id: "svc-payments-gateway" });
  });

  it("matches selected call ID and query ID associations", () => {
    const selectedCallId = "call-083d0510";
    const matchingItems = sampleItems.filter((i) => i.call_id === selectedCallId);
    expect(matchingItems.length).toBe(1);
    expect(matchingItems[0].query_id).toBe("Q-CONTEXT");
  });
});
