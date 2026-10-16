import fs from "fs";
import path from "path";
import { describe, it, expect } from "vitest";
import { createInitialIncidentState, reduceAgentEvent } from "../lib/eventReducer";
import { AgentEvent, IncidentState } from "../types";

describe("Scenario Replay Mode", () => {
  const replaysDir = path.resolve(__dirname, "../../../replays");

  it("loads and verifies scenario_a replay events", () => {
    const filePath = path.join(replaysDir, "scenario_a.jsonl");
    const raw = fs.readFileSync(filePath, "utf-8");
    const events: AgentEvent[] = raw
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));

    expect(events.length).toBe(58);
    expect(events[0].type).toBe("incident_started");
    expect(events[events.length - 1].type).toBe("final_report");

    let state: IncidentState = createInitialIncidentState();
    for (const ev of events) {
      state = reduceAgentEvent(state, ev);
    }

    expect(state.riskScore).toBeCloseTo(0.828, 3);
    expect(Array.from(state.isolatedNodes)).toEqual(["svc-payments-gateway"]);
    expect(state.status).toBe("completed");
  });

  it("loads and verifies scenario_b replay events", () => {
    const filePath = path.join(replaysDir, "scenario_b.jsonl");
    if (!fs.existsSync(filePath)) return;

    const raw = fs.readFileSync(filePath, "utf-8");
    const events: AgentEvent[] = raw
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));

    expect(events.length).toBeGreaterThan(0);
    expect(events[0].type).toBe("incident_started");

    let state: IncidentState = createInitialIncidentState();
    for (const ev of events) {
      state = reduceAgentEvent(state, ev);
    }
    expect(state.status).toBe("completed");
  });

  it("loads and verifies scenario_c replay events", () => {
    const filePath = path.join(replaysDir, "scenario_c.jsonl");
    if (!fs.existsSync(filePath)) return;

    const raw = fs.readFileSync(filePath, "utf-8");
    const events: AgentEvent[] = raw
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));

    expect(events.length).toBeGreaterThan(0);
    expect(events[0].type).toBe("incident_started");

    let state: IncidentState = createInitialIncidentState();
    for (const ev of events) {
      state = reduceAgentEvent(state, ev);
    }
    expect(state.status).toBe("completed");
  });
});
