import { describe, it, expect } from "vitest";
import {
  createInitialIncidentState,
  reduceAgentEvent,
} from "../lib/eventReducer";
import { getHighlightClasses, getNodeStatusClasses } from "../lib/constants";
import { AgentEvent, IncidentState } from "../types";

describe("Live Path Highlighting from Graph Visit Events", () => {
  it("applies inspect pulse ring styling from inspect visit event", () => {
    let state: IncidentState = createInitialIncidentState();

    const inspectEvent: AgentEvent = {
      seq: 4,
      ts: new Date().toISOString(),
      type: "graph_visit",
      data: {
        kind: "inspect",
        node_ids: ["svc-payments-gateway", "role-storage-manager"],
        edge_keys: ["svc-payments-gateway|ASSUMES_ROLE|role-storage-manager"],
      },
    };

    state = reduceAgentEvent(state, inspectEvent);

    expect(state.highlightedNodes["svc-payments-gateway"]).toBe("inspect");
    expect(state.highlightedNodes["role-storage-manager"]).toBe("inspect");
    expect(state.highlightedEdges["svc-payments-gateway|ASSUMES_ROLE|role-storage-manager"]).toBe(
      "inspect"
    );

    const ringClass = getHighlightClasses(state.highlightedNodes["svc-payments-gateway"]);
    expect(ringClass).toContain("ring-sky-400");
    expect(ringClass).toContain("animate-pulse");
  });

  it("applies attack path highlighting and edge animation from attack_path event", () => {
    let state: IncidentState = createInitialIncidentState();

    const attackPathEvent: AgentEvent = {
      seq: 15,
      ts: new Date().toISOString(),
      type: "graph_visit",
      data: {
        kind: "attack_path",
        node_ids: ["svc-payments-gateway", "db-customer-profile"],
        edge_keys: ["role-storage-manager|CAN_ASSUME|role-data-admin"],
      },
    };

    state = reduceAgentEvent(state, attackPathEvent);

    expect(state.highlightedNodes["db-customer-profile"]).toBe("attack_path");
    expect(state.highlightedEdges["role-storage-manager|CAN_ASSUME|role-data-admin"]).toBe(
      "attack_path"
    );

    const attackRing = getHighlightClasses(state.highlightedNodes["db-customer-profile"]);
    expect(attackRing).toContain("ring-rose-500");
  });

  it("applies isolated styling to node and edges upon action execution", () => {
    let state: IncidentState = createInitialIncidentState();

    const actionEvent: AgentEvent = {
      seq: 44,
      ts: new Date().toISOString(),
      type: "action",
      data: {
        action_id: "act-c361ea6a",
        action: "ISOLATE_NODE",
        target_id: "svc-payments-gateway",
        status: "EXECUTED",
        policy: "APPROVAL_REQUIRED",
      },
    };

    state = reduceAgentEvent(state, actionEvent);

    expect(state.isolatedNodes.has("svc-payments-gateway")).toBe(true);
    expect(state.nodeStatuses["svc-payments-gateway"]).toBe("ISOLATED");

    const isolatedClass = getNodeStatusClasses(state.nodeStatuses["svc-payments-gateway"]);
    expect(isolatedClass).toContain("border-dashed");
    expect(isolatedClass).toContain("border-slate-600");
  });

  it("fades out attack path highlighting for targets removed during verification", () => {
    let state: IncidentState = createInitialIncidentState();

    // Initially highlight two targets on attack path
    state.highlightedNodes["db-customer-profile"] = "attack_path";
    state.highlightedNodes["db-user-billing"] = "attack_path";

    // Verification event: db-customer-profile is contained, only db-user-billing remains
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

    // Contained target must be pruned from active attack path highlights
    expect(state.highlightedNodes["db-customer-profile"]).toBeUndefined();
    // Remaining target stays highlighted
    expect(state.highlightedNodes["db-user-billing"]).toBe("attack_path");
  });
});
