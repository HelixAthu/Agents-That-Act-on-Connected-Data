import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

/**
 * Root component rendering the three-column incident response layout skeleton.
 */
export default function App(): JSX.Element {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-background text-foreground">
      {/* Left Column: Scenarios & Trace Feed */}
      <aside className="w-96 flex-shrink-0 border-r border-border p-4 flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-bold tracking-tight">Blast Radius</h1>
          <Badge variant="outline">v0.1-scaffold</Badge>
        </div>
        <div className="grid grid-cols-3 gap-2">
          <Button variant="outline" size="sm">
            Scenario A
          </Button>
          <Button variant="outline" size="sm">
            Scenario B
          </Button>
          <Button variant="outline" size="sm">
            Scenario C
          </Button>
        </div>
        <Card className="flex-1 overflow-hidden">
          <CardHeader className="py-2 px-3 border-b border-border">
            <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">
              Trace Feed
            </CardTitle>
          </CardHeader>
          <CardContent className="p-3 text-xs text-muted-foreground">
            Awaiting agent execution...
          </CardContent>
        </Card>
      </aside>

      {/* Center Column: Graph Canvas */}
      <main className="flex-1 relative flex flex-col items-center justify-center p-4">
        <div className="text-center space-y-2">
          <p className="text-sm text-muted-foreground">Graph Canvas (React Flow + Dagre)</p>
          <Badge variant="secondary">Ready to mount</Badge>
        </div>
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
            <div className="text-2xl font-bold">0.000</div>
          </CardContent>
        </Card>

        <Card className="flex-1">
          <CardHeader className="py-2 px-3 border-b border-border">
            <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">
              Incident Details
            </CardTitle>
          </CardHeader>
          <CardContent className="p-3 text-xs text-muted-foreground">
            No active incident loaded.
          </CardContent>
        </Card>
      </aside>
    </div>
  );
}
