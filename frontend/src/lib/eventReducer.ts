import { AgentEvent, IncidentState, ReportAction } from "@/types";

/**
 * Creates the clean initial state for an incident response run.
 */
export function createInitialIncidentState(): IncidentState {
  return {
    incidentId: null,
    alertText: null,
    status: "idle",
    events: [],
    traceItems: [],
    riskScore: 0,
    riskComponents: {},
    highlightedNodes: {},
    highlightedEdges: {},
    nodeStatuses: {},
    isolatedNodes: new Set<string>(),
    revokedRoles: new Set<string>(),
    seenApprovalRequired: false,
    pendingApproval: null,
    executedActions: [],
    verification: null,
    finalReport: null,
    error: null,
  };
}

/**
 * Pure state reducer applying agent events sequentially to maintain UI graph and incident state.
 */
export function reduceAgentEvent(
  state: IncidentState,
  event: AgentEvent
): IncidentState {
  const events = [...state.events, event];
  const highlightedNodes = { ...state.highlightedNodes };
  const highlightedEdges = { ...state.highlightedEdges };
  const nodeStatuses = { ...state.nodeStatuses };
  const isolatedNodes = new Set(state.isolatedNodes);
  const revokedRoles = new Set(state.revokedRoles);
  const executedActions = [...state.executedActions];
  const traceItems = [...state.traceItems];

  let incidentId = state.incidentId;
  let alertText = state.alertText;
  let status = state.status;
  let riskScore = state.riskScore;
  let riskComponents = { ...state.riskComponents };
  let seenApprovalRequired = state.seenApprovalRequired;
  let pendingApproval = state.pendingApproval;
  let verification = state.verification;
  let finalReport = state.finalReport;
  let error = state.error;

  switch (event.type) {
    case "incident_started": {
      incidentId = event.data?.incident_id || incidentId;
      alertText = event.data?.alert_text || alertText;
      status = "running";
      traceItems.push({
        seq: event.seq,
        ts: event.ts,
        type: "incident_started",
        summary: event.data?.alert_text,
      });
      break;
    }

    case "thought": {
      traceItems.push({
        seq: event.seq,
        ts: event.ts,
        type: "thought",
        text: event.data?.text,
      });
      break;
    }

    case "tool_call": {
      traceItems.push({
        seq: event.seq,
        ts: event.ts,
        type: "tool_call",
        tool: event.data?.tool,
        call_id: event.data?.call_id,
        args: event.data?.args,
      });
      break;
    }

    case "graph_visit": {
      const kind = String(event.data?.kind || "inspect");
      const nodeIds: string[] = event.data?.node_ids || [];
      const edgeKeys: string[] = event.data?.edge_keys || [];

      for (const nid of nodeIds) {
        highlightedNodes[nid] = kind;
      }
      for (const ek of edgeKeys) {
        highlightedEdges[ek] = kind;
      }
      break;
    }

    case "tool_result": {
      const callId = event.data?.call_id;
      let existingIdx = -1;
      for (let i = traceItems.length - 1; i >= 0; i--) {
        if (traceItems[i].type === "tool_call" && traceItems[i].call_id === callId) {
          existingIdx = i;
          break;
        }
      }

      if (existingIdx !== -1) {
        traceItems[existingIdx] = {
          ...traceItems[existingIdx],
          ok: event.data?.ok,
          summary: event.data?.summary,
          query_id: event.data?.query_id,
          cypher: event.data?.cypher,
          ms: event.data?.ms,
        };
      } else {
        traceItems.push({
          seq: event.seq,
          ts: event.ts,
          type: "tool_result",
          call_id: callId,
          ok: event.data?.ok,
          summary: event.data?.summary,
          query_id: event.data?.query_id,
          cypher: event.data?.cypher,
          ms: event.data?.ms,
        });
      }
      break;
    }

    case "risk_update": {
      const parsedRisk = event.data?.risk ?? event.data?.risk_score;
      if (parsedRisk !== undefined && parsedRisk !== null) {
        riskScore = Number(parsedRisk);
      }
      if (event.data?.components) {
        riskComponents = { ...riskComponents, ...event.data.components };
      }
      break;
    }

    case "approval_required": {
      seenApprovalRequired = true;
      pendingApproval = {
        action_id: event.data?.action_id,
        action: event.data?.action,
        target_id: event.data?.target_id,
        reason: event.data?.reason,
        policy: event.data?.policy,
        targets_before: event.data?.dry_run?.targets_before,
        targets_after: event.data?.dry_run?.targets_after,
      };
      status = "waiting_approval";
      break;
    }

    case "action": {
      pendingApproval = null;
      status = "running";

      const actionData = event.data || {};
      const actionType = String(actionData.action || actionData.type || "");
      const targetId = String(actionData.target_id || actionData.target || "");
      const actionStatus = String(actionData.status || "");

      if (actionStatus === "EXECUTED") {
        if (actionType === "ISOLATE_NODE" || actionType.includes("ISOLATE")) {
          isolatedNodes.add(targetId);
          nodeStatuses[targetId] = "ISOLATED";
        } else if (actionType === "REVOKE_ROLE" || actionType.includes("REVOKE")) {
          revokedRoles.add(targetId);
          highlightedEdges[targetId] = "action";
        }

        const existingActionIdx = executedActions.findIndex(
          (a) => a.action_id === actionData.action_id
        );
        const actionRecord: ReportAction = {
          action_id: actionData.action_id,
          type: actionType,
          target: targetId,
          policy: actionData.policy || "AUTO",
          status: actionStatus,
        };

        if (existingActionIdx !== -1) {
          executedActions[existingActionIdx] = actionRecord;
        } else {
          executedActions.push(actionRecord);
        }
      }
      break;
    }

    case "verification": {
      verification = {
        targets_before: event.data?.targets_before || [],
        targets_after: event.data?.targets_after || [],
      };

      const beforeList: string[] = event.data?.targets_before || [];
      const afterList: string[] = event.data?.targets_after || [];

      // Remove attack path highlight for removed targets
      for (const target of beforeList) {
        if (!afterList.includes(target) && highlightedNodes[target] === "attack_path") {
          delete highlightedNodes[target];
        }
      }
      break;
    }

    case "final_report": {
      finalReport = event.data as any;
      if (finalReport && finalReport.risk_score !== undefined) {
        riskScore = Number(finalReport.risk_score);
      }
      status = "completed";
      break;
    }

    case "error": {
      error = event.data?.message || "Incident run encountered an error.";
      status = "error";
      break;
    }

    default:
      break;
  }

  return {
    incidentId,
    alertText,
    status,
    events,
    traceItems,
    riskScore,
    riskComponents,
    highlightedNodes,
    highlightedEdges,
    nodeStatuses,
    isolatedNodes,
    revokedRoles,
    seenApprovalRequired,
    pendingApproval,
    executedActions,
    verification,
    finalReport,
    error,
  };
}
