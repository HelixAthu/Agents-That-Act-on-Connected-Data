import fs from "fs";
import path from "path";
import { describe, it, expect } from "vitest";
import {
  createInitialIncidentState,
  reduceAgentEvent,
} from "../lib/eventReducer";
import { AgentEvent, IncidentState } from "../types";

describe("Agent Event Reducer", () => {
  it("initializes clean incident state", () => {
    const state = createInitialIncidentState();
    expect(state.status).toBe("idle");
    expect(state.riskScore).toBe(0);
    expect(state.isolatedNodes.size).toBe(0);
    expect(state.seenApprovalRequired).toBe(false);
    expect(state.pendingApproval).toBeNull();
  });

  it("processes scenario_a.jsonl replay to exact acceptance criteria", () => {
    // Read the canonical recorded scenario A events
    const replayPath = path.resolve(__dirname, "../../../replays/scenario_a.jsonl");
    const fileContent = fs.readFileSync(replayPath, "utf-8");
    const lines = fileContent
      .trim()
      .split("\n")
      .filter((line) => line.trim().length > 0);

    const events: AgentEvent[] = lines.map((line) => JSON.parse(line));
    expect(events.length).toBeGreaterThan(0);

    // Feed all events sequentially through the pure state reducer
    let state: IncidentState = createInitialIncidentState();
    for (const event of events) {
      state = reduceAgentEvent(state, event);
    }

    // Acceptance criterion 1: Final risk score ≈ 0.828
    expect(state.riskScore).toBeCloseTo(0.828, 3);

    // Acceptance criterion 2: Final isolated node set = {"svc-payments-gateway"}
    const isolatedArray = Array.from(state.isolatedNodes);
    expect(isolatedArray).toEqual(["svc-payments-gateway"]);

    // Acceptance criterion 3: approval_required was seen
    expect(state.seenApprovalRequired).toBe(true);

    // Additional state integrity assertions
    expect(state.status).toBe("completed");
    expect(state.finalReport).toBeDefined();
    expect(state.finalReport?.incident_id).toBe("inc-a-19aad7");
    expect(state.executedActions.length).toBeGreaterThan(0);
    expect(state.traceItems.length).toBeGreaterThan(0);
  });

  it("handles error events gracefully", () => {
    let state = createInitialIncidentState();
    const errorEvent: AgentEvent = {
      seq: 1,
      ts: new Date().toISOString(),
      type: "error",
      data: { message: "FalkorDB connection timeout" },
    };
    state = reduceAgentEvent(state, errorEvent);
    expect(state.status).toBe("error");
    expect(state.error).toBe("FalkorDB connection timeout");
  });

  it("prunes attack_path highlight on verification event with reduced targets", () => {
    let state = createInitialIncidentState();
    state.highlightedNodes["db-customer-profile"] = "attack_path";
    state.highlightedNodes["db-user-billing"] = "attack_path";

    const verificationEvent: AgentEvent = {
      seq: 29,
      ts: new Date().toISOString(),
      type: "verification",
      data: {
        action_id: "act-1a2b56bf",
        targets_before: ["db-customer-profile", "db-user-billing"],
        targets_after: ["db-user-billing"],
      },
    };

    state = reduceAgentEvent(state, verificationEvent);
    // db-customer-profile was in targets_before but not targets_after, should be pruned
    expect(state.highlightedNodes["db-customer-profile"]).toBeUndefined();
    // db-user-billing remains in targets_after
    expect(state.highlightedNodes["db-user-billing"]).toBe("attack_path");
  });

  it("falls back to pendingApproval target and clears all attack paths when targets_after is empty", () => {
    let state = createInitialIncidentState();
    state.highlightedNodes["svc-payments-gateway"] = "attack_path";
    state.highlightedNodes["db-user-billing"] = "attack_path";
    state.highlightedEdges["svc-payments-gateway->db-user-billing"] = "attack_path";

    // Propose containment requiring approval
    const approvalReqEvent: AgentEvent = {
      seq: 10,
      ts: new Date().toISOString(),
      type: "approval_required",
      data: {
        action_id: "act-test-fallback",
        action: "ISOLATE_NODE",
        target_id: "svc-payments-gateway",
        reason: "Customer facing tier 1 service",
      },
    };
    state = reduceAgentEvent(state, approvalReqEvent);
    expect(state.status).toBe("waiting_approval");
    expect(state.pendingApproval?.target_id).toBe("svc-payments-gateway");

    // Action executed event with generic action and empty target_id
    const executedEvent: AgentEvent = {
      seq: 11,
      ts: new Date().toISOString(),
      type: "action",
      data: {
        action_id: "act-test-fallback",
        action: "CONTAINMENT",
        target_id: "",
        status: "EXECUTED",
      },
    };
    state = reduceAgentEvent(state, executedEvent);
    expect(state.isolatedNodes.has("svc-payments-gateway")).toBe(true);
    expect(state.nodeStatuses["svc-payments-gateway"]).toBe("ISOLATED");

    // Verification event indicating zero attack targets left
    const verificationEvent: AgentEvent = {
      seq: 12,
      ts: new Date().toISOString(),
      type: "verification",
      data: {
        action_id: "act-test-fallback",
        targets_before: ["db-user-billing"],
        targets_after: [],
      },
    };
    state = reduceAgentEvent(state, verificationEvent);
    expect(Object.keys(state.highlightedEdges).length).toBe(0);
    expect(state.highlightedNodes["db-user-billing"]).toBeUndefined();
  });
});
