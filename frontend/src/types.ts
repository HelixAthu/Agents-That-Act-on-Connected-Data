/**
 * Core type definitions for Blast Radius Agent UI matching Spec 04 Section 11 and Spec 05.
 */

export interface GraphNodeProps {
  name?: string;
  tier?: number;
  customer_facing?: boolean;
  contains_pii?: boolean;
  technology?: string;
  max_session_hours?: number;
  admin_privileges?: boolean;
  status?: string;
  cvss?: number;
  exploit_available?: boolean;
  [key: string]: unknown;
}

export interface GraphNode {
  id: string;
  label: "Service" | "Database" | "IAMRole" | "Vulnerability" | "Team" | string;
  props: GraphNodeProps;
}

export interface GraphEdgeProps {
  isolated?: boolean;
  [key: string]: unknown;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  props: GraphEdgeProps;
}

export interface GraphPayload {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Scenario {
  id: "A" | "B" | "C" | string;
  title: string;
  alert_text: string;
}

export interface ReportFinding {
  claim: string;
  evidence_refs: string[];
}

export interface ReportImpact {
  impacted_services: number;
  customer_facing: number;
  owner_teams: string[];
}

export interface ReportAction {
  action_id: string;
  type: string;
  target: string;
  policy: string;
  status: string;
}

export interface ReportVerification {
  targets_before: string[];
  targets_after: string[];
}

export interface ReportToolCall {
  call_id: string;
  tool: string;
  ms: number;
  query_id: string;
}

export interface FinalReport {
  incident_id: string;
  summary: string;
  risk_score: number;
  findings: ReportFinding[];
  impact: ReportImpact;
  actions: ReportAction[];
  verification: ReportVerification;
  tool_calls: ReportToolCall[];
}

export interface AgentEvent {
  seq: number;
  ts: string;
  type:
    | "incident_started"
    | "thought"
    | "tool_call"
    | "graph_visit"
    | "tool_result"
    | "risk_update"
    | "approval_required"
    | "action"
    | "verification"
    | "final_report"
    | "error"
    | string;
  data: Record<string, any>;
}

export type NodeVisualStatus = "HEALTHY" | "DEGRADED" | "FAILED" | "ISOLATED";

export interface TraceItem {
  seq: number;
  ts: string;
  type: string;
  tool?: string;
  call_id?: string;
  query_id?: string;
  cypher?: string;
  args?: Record<string, unknown>;
  summary?: string;
  ok?: boolean;
  text?: string;
  ms?: number;
}

export interface PendingApproval {
  action_id: string;
  action: string;
  target_id: string;
  reason?: string;
  policy?: string;
  targets_before?: string[];
  targets_after?: string[];
}

export interface IncidentState {
  incidentId: string | null;
  alertText: string | null;
  status: "idle" | "running" | "waiting_approval" | "completed" | "error";
  events: AgentEvent[];
  traceItems: TraceItem[];
  riskScore: number;
  riskComponents: Record<string, number>;
  highlightedNodes: Record<string, string>;
  highlightedEdges: Record<string, string>;
  nodeStatuses: Record<string, string>;
  isolatedNodes: Set<string>;
  revokedRoles: Set<string>;
  seenApprovalRequired: boolean;
  pendingApproval: PendingApproval | null;
  executedActions: ReportAction[];
  verification: ReportVerification | null;
  finalReport: FinalReport | null;
  error: string | null;
}
