import { useState } from "react";
import { Film } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { GraphCanvas } from "@/components/GraphCanvas";
import { TraceFeed } from "@/components/TraceFeed";
import { RiskPanel } from "@/components/panels/RiskPanel";
import { ApprovalCard } from "@/components/panels/ApprovalCard";
import { FinalReportPanel } from "@/components/panels/FinalReportPanel";
import { useIncidentStream } from "@/hooks/useIncidentStream";
import { resetGraph } from "@/lib/api";

/**
 * Root component rendering the incident response workspace with live graph highlighting, replays and reporting.
 */
export default function App(): JSX.Element {
  const {
    state: incidentState,
    startIncident,
    startReplay,
    approve,
    rollback,
    reset: resetStream,
  } = useIncidentStream();

  const [resetting, setResetting] = useState<boolean>(false);
  const [selectedCallId, setSelectedCallId] = useState<string | null>(null);
  const [isReplayMode, setIsReplayMode] = useState<boolean>(false);

  const handleReset = async () => {
    try {
      setResetting(true);
      await resetGraph();
      resetStream();
      setSelectedCallId(null);
    } catch (err) {
      console.error("Failed to reset graph:", err);
    } finally {
      setResetting(false);
    }
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-background text-foreground">
      {/* Left Column: Scenarios, Replay Toggle & Trace Feed */}
      <aside className="w-96 flex-shrink-0 border-r border-border p-4 flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold tracking-tight">Blast Radius</h1>
            <Badge variant="outline" className="text-[10px]">v0.3-ui</Badge>
          </div>
          <Badge variant={incidentState.status === "running" ? "default" : "outline"}>
            {incidentState.status.toUpperCase()}
          </Badge>
        </div>

        {/* Replay Mode Toggle */}
        <div className="flex items-center justify-between p-2 rounded-lg bg-muted/40 border border-border">
          <div className="flex items-center gap-1.5 text-xs font-medium">
            <Film className="h-3.5 w-3.5 text-purple-400" />
            <span>Replay Mode (600ms)</span>
          </div>
          <Button
            variant={isReplayMode ? "default" : "outline"}
            size="sm"
            className="h-6 text-[10px] px-2.5 font-semibold"
            onClick={() => setIsReplayMode((prev) => !prev)}
            disabled={incidentState.status === "running"}
          >
            {isReplayMode ? "ON" : "OFF"}
          </Button>
        </div>

        {/* Scenario execution triggers */}
        <div className="grid grid-cols-3 gap-2">
          {(["A", "B", "C"] as const).map((scId) => (
            <Button
              key={scId}
              variant="outline"
              size="sm"
              onClick={() => {
                if (isReplayMode) {
                  startReplay(scId.toLowerCase());
                } else {
                  startIncident(scId, "mock", false);
                }
              }}
              disabled={incidentState.status === "running"}
            >
              {isReplayMode ? `Replay ${scId}` : `Scenario ${scId}`}
            </Button>
          ))}
        </div>

        <Button
          variant="secondary"
          size="sm"
          onClick={handleReset}
          disabled={resetting || incidentState.status === "running"}
        >
          {resetting ? "Resetting..." : "Reset Graph"}
        </Button>

        <Card className="flex-1 overflow-hidden flex flex-col">
          <CardHeader className="py-2 px-3 border-b border-border">
            <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">
              Trace Feed ({incidentState.traceItems.length})
            </CardTitle>
          </CardHeader>
          <div className="flex-1 overflow-hidden">
            <TraceFeed
              items={incidentState.traceItems}
              selectedCallId={selectedCallId}
              onSelectCallId={setSelectedCallId}
            />
          </div>
        </Card>
      </aside>

      {/* Center Column: Graph Canvas with Live Path Highlighting */}
      <main className="flex-1 relative h-full w-full overflow-hidden bg-background">
        <GraphCanvas
          highlightedNodes={incidentState.highlightedNodes}
          highlightedEdges={incidentState.highlightedEdges}
          nodeStatuses={incidentState.nodeStatuses}
          isolatedNodes={incidentState.isolatedNodes}
          revokedRoles={incidentState.revokedRoles}
        />
      </main>

      {/* Right Column: Risk, Approval and Final Report Panels */}
      <aside className="w-80 flex-shrink-0 border-l border-border p-4 flex flex-col gap-4 overflow-y-auto">
        <RiskPanel
          score={incidentState.riskScore}
          components={incidentState.riskComponents}
        />

        <ApprovalCard
          approval={incidentState.pendingApproval}
          onApprove={approve}
        />

        {incidentState.finalReport && (
          <FinalReportPanel
            report={incidentState.finalReport}
            actions={incidentState.executedActions}
            onRollback={rollback}
            onSelectCallId={setSelectedCallId}
          />
        )}

        <Card className="flex-1">
          <CardHeader className="py-2 px-3 border-b border-border">
            <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">
              Incident Context
            </CardTitle>
          </CardHeader>
          <CardContent className="p-3 text-xs text-muted-foreground">
            {incidentState.alertText || "No active incident loaded."}
            {incidentState.isolatedNodes.size > 0 && (
              <div className="mt-2 text-xs text-amber-400 font-semibold">
                Isolated: {Array.from(incidentState.isolatedNodes).join(", ")}
              </div>
            )}
          </CardContent>
        </Card>
      </aside>
    </div>
  );
}
