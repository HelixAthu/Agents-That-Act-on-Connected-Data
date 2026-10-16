import { useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { GraphCanvas } from "@/components/GraphCanvas";
import { TraceFeed } from "@/components/TraceFeed";
import { useIncidentStream } from "@/hooks/useIncidentStream";
import { resetGraph } from "@/lib/api";

/**
 * Root component rendering the incident response workspace with live graph highlighting.
 */
export default function App(): JSX.Element {
  const {
    state: incidentState,
    startIncident,
    reset: resetStream,
  } = useIncidentStream();

  const [resetting, setResetting] = useState<boolean>(false);

  const handleReset = async () => {
    try {
      setResetting(true);
      await resetGraph();
      resetStream();
    } catch (err) {
      console.error("Failed to reset graph:", err);
    } finally {
      setResetting(false);
    }
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-background text-foreground">
      {/* Left Column: Scenarios & Trace Feed */}
      <aside className="w-96 flex-shrink-0 border-r border-border p-4 flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-bold tracking-tight">Blast Radius</h1>
          <Badge variant={incidentState.status === "running" ? "default" : "outline"}>
            {incidentState.status.toUpperCase()}
          </Badge>
        </div>

        <div className="grid grid-cols-3 gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => startIncident("A", "mock", false)}
            disabled={incidentState.status === "running"}
          >
            Scenario A
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => startIncident("B", "mock", false)}
            disabled={incidentState.status === "running"}
          >
            Scenario B
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => startIncident("C", "mock", false)}
            disabled={incidentState.status === "running"}
          >
            Scenario C
          </Button>
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
            <TraceFeed items={incidentState.traceItems} />
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

      {/* Right Column: Risk & Approval Panels */}
      <aside className="w-80 flex-shrink-0 border-l border-border p-4 flex flex-col gap-4">
        <Card>
          <CardHeader className="py-2 px-3 border-b border-border">
            <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">
              Risk Score
            </CardTitle>
          </CardHeader>
          <CardContent className="p-3 text-sm">
            <div className="text-3xl font-mono font-bold text-primary">
              {incidentState.riskScore.toFixed(3)}
            </div>
            {incidentState.isolatedNodes.size > 0 && (
              <div className="mt-2 text-xs text-muted-foreground">
                Isolated: {Array.from(incidentState.isolatedNodes).join(", ")}
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="flex-1">
          <CardHeader className="py-2 px-3 border-b border-border">
            <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">
              Incident Context
            </CardTitle>
          </CardHeader>
          <CardContent className="p-3 text-xs text-muted-foreground">
            {incidentState.alertText || "No active incident loaded."}
          </CardContent>
        </Card>
      </aside>
    </div>
  );
}
