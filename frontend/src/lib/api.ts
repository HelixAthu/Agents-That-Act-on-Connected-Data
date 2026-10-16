import { GraphPayload, Scenario, AgentEvent } from "@/types";

const BASE_URL = "";

/**
 * Fetches the infrastructure graph filtered for UI presentation.
 */
export async function fetchGraph(): Promise<GraphPayload> {
  const response = await fetch(`${BASE_URL}/graph`);
  if (!response.ok) {
    throw new Error(`Failed to fetch graph: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

/**
 * Fetches the canonical incident response scenarios.
 */
export async function fetchScenarios(): Promise<Scenario[]> {
  const response = await fetch(`${BASE_URL}/scenarios`);
  if (!response.ok) {
    throw new Error(`Failed to fetch scenarios: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

/**
 * Initiates an incident run for a given scenario.
 */
export async function createIncident(
  scenarioId: string,
  mode = "mock",
  autoApprove = false
): Promise<{ incident_id: string }> {
  const response = await fetch(`${BASE_URL}/incidents`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      scenario: scenarioId,
      mode,
      auto_approve: autoApprove,
    }),
  });
  if (!response.ok) {
    throw new Error(`Failed to create incident: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

/**
 * Approves a pending containment action by ID.
 */
export async function approveAction(
  actionId: string,
  approvedBy = "security-lead@corp"
): Promise<{ ok: boolean; action_id: string; approved_by?: string }> {
  const response = await fetch(`${BASE_URL}/actions/${actionId}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ approved_by: approvedBy }),
  });
  if (!response.ok) {
    throw new Error(`Failed to approve action: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

/**
 * Rolls back an executed action by ID.
 */
export async function rollbackAction(
  actionId: string
): Promise<{ status: string; action_id: string; target_id?: string; action?: string }> {
  const response = await fetch(`${BASE_URL}/actions/${actionId}/rollback`, {
    method: "POST",
  });
  if (!response.ok) {
    throw new Error(`Failed to rollback action: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

/**
 * Resets the FalkorDB graph back to clean seed state.
 */
export async function resetGraph(): Promise<{ status: string }> {
  const response = await fetch(`${BASE_URL}/admin/reset`, {
    method: "POST",
  });
  if (!response.ok) {
    throw new Error(`Failed to reset graph: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

/**
 * Fetches recorded event replay for a given scenario name.
 */
export async function fetchReplay(scenario: string): Promise<AgentEvent[]> {
  const clean = scenario.toLowerCase().replace("scenario_", "").replace(".jsonl", "");
  const response = await fetch(`${BASE_URL}/replays/${clean}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch replay for ${scenario}: ${response.statusText}`);
  }
  const text = await response.text();
  return text
    .trim()
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line));
}
