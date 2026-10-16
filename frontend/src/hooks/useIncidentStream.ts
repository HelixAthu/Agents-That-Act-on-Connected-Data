import { useState, useCallback, useRef, useEffect } from "react";
import { AgentEvent, IncidentState } from "@/types";
import { createInitialIncidentState, reduceAgentEvent } from "@/lib/eventReducer";
import {
  createIncident,
  approveAction as apiApproveAction,
  rollbackAction as apiRollbackAction,
  fetchReplay,
} from "@/lib/api";

/**
 * Custom hook managing real-time SSE event consumption and incident response state.
 */
export function useIncidentStream() {
  const [state, setState] = useState<IncidentState>(createInitialIncidentState);
  const eventSourceRef = useRef<EventSource | null>(null);
  const replayTimerRef = useRef<NodeJS.Timeout | null>(null);

  const cleanupStream = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    if (replayTimerRef.current) {
      clearInterval(replayTimerRef.current);
      replayTimerRef.current = null;
    }
  }, []);

  useEffect(() => {
    return () => {
      cleanupStream();
    };
  }, [cleanupStream]);

  const dispatchEvent = useCallback((event: AgentEvent) => {
    setState((prevState) => reduceAgentEvent(prevState, event));
  }, []);

  const startIncident = useCallback(
    async (scenarioId: string, mode = "mock", autoApprove = false) => {
      cleanupStream();
      setState(createInitialIncidentState());

      try {
        const { incident_id } = await createIncident(scenarioId, mode, autoApprove);
        const eventSource = new EventSource(`/incidents/${incident_id}/events`);
        eventSourceRef.current = eventSource;

        eventSource.onmessage = (msgEvent) => {
          try {
            const agentEvent: AgentEvent = JSON.parse(msgEvent.data);
            dispatchEvent(agentEvent);
            if (agentEvent.type === "final_report" || agentEvent.type === "error") {
              cleanupStream();
            }
          } catch (err) {
            console.error("Failed to parse SSE event message:", err);
          }
        };

        eventSource.onerror = (err) => {
          console.error("SSE stream encountered an error:", err);
          cleanupStream();
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Failed to start incident";
        setState((prevState) => ({
          ...prevState,
          status: "error",
          error: message,
        }));
      }
    },
    [cleanupStream, dispatchEvent]
  );

  const approve = useCallback(async (actionId: string) => {
    await apiApproveAction(actionId);
  }, []);

  const rollback = useCallback(async (actionId: string) => {
    await apiRollbackAction(actionId);
    setState((prevState) => ({
      ...prevState,
      executedActions: prevState.executedActions.map((act) =>
        act.action_id === actionId ? { ...act, status: "ROLLED_BACK" } : act
      ),
    }));
  }, []);

  const reset = useCallback(() => {
    cleanupStream();
    setState(createInitialIncidentState());
  }, [cleanupStream]);

  const replayEvents = useCallback(
    (events: AgentEvent[], intervalMs = 600) => {
      cleanupStream();
      setState(createInitialIncidentState());

      let currentIndex = 0;
      replayTimerRef.current = setInterval(() => {
        if (currentIndex < events.length) {
          dispatchEvent(events[currentIndex]);
          currentIndex++;
        } else {
          cleanupStream();
        }
      }, intervalMs);
    },
    [cleanupStream, dispatchEvent]
  );

  const startReplay = useCallback(
    async (scenario: string, intervalMs = 600) => {
      cleanupStream();
      setState(createInitialIncidentState());
      try {
        const events = await fetchReplay(scenario);
        replayEvents(events, intervalMs);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Failed to load replay";
        setState((prevState) => ({
          ...prevState,
          status: "error",
          error: message,
        }));
      }
    },
    [cleanupStream, replayEvents]
  );

  return {
    state,
    startIncident,
    startReplay,
    approve,
    rollback,
    reset,
    replayEvents,
    dispatchEvent,
  };
}
