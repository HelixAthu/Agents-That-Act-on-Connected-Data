import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export interface RiskPanelProps {
  score: number;
  components?: Record<string, number>;
  className?: string;
}

/**
 * Maps risk score to descriptive severity level and Tailwind color classes.
 */
function getRiskSeverity(score: number): { label: string; textClass: string; bgClass: string } {
  if (score >= 0.7) {
    return {
      label: "CRITICAL",
      textClass: "text-rose-400",
      bgClass: "bg-rose-500",
    };
  }
  if (score >= 0.4) {
    return {
      label: "ELEVATED",
      textClass: "text-amber-400",
      bgClass: "bg-amber-500",
    };
  }
  return {
    label: "LOW",
    textClass: "text-emerald-400",
    bgClass: "bg-emerald-500",
  };
}

/**
 * Normalizes component key names for display in the risk factor bars.
 */
function formatComponentLabel(key: string): string {
  switch (key.toLowerCase()) {
    case "severity":
    case "cvss_severity":
      return "Exploit Severity";
    case "pii":
    case "data_sensitivity":
      return "PII Sensitivity";
    case "blast":
    case "blast_radius":
      return "Blast Radius";
    case "central":
    case "centrality":
      return "Graph Centrality";
    default:
      return key;
  }
}

/**
 * RiskPanel renders a risk score gauge and detailed breakdown bars for all four risk components.
 */
export function RiskPanel({ score, components = {}, className }: RiskPanelProps): JSX.Element {
  const { label, textClass, bgClass } = getRiskSeverity(score);

  // Component breakdown keys
  const componentEntries = Object.entries(components);

  return (
    <Card className={cn("overflow-hidden border-border", className)}>
      <CardHeader className="py-2.5 px-3 border-b border-border flex flex-row items-center justify-between">
        <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground font-semibold">
          Risk Assessment
        </CardTitle>
        <Badge
          variant="outline"
          className={cn("text-[10px] px-1.5 py-0 font-bold", textClass)}
        >
          {label}
        </Badge>
      </CardHeader>

      <CardContent className="p-3 space-y-4">
        {/* Score Display */}
        <div className="flex items-baseline justify-between">
          <div>
            <div className={cn("text-3xl font-mono font-bold tracking-tight", textClass)}>
              {score.toFixed(3)}
            </div>
            <div className="text-[10px] text-muted-foreground mt-0.5">
              Composite graph containment risk
            </div>
          </div>
          <div className="text-right">
            <span className="text-xs font-mono text-muted-foreground">/ 1.000</span>
          </div>
        </div>

        {/* Component breakdown bars */}
        <div className="space-y-2 pt-1 border-t border-border/40">
          <div className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider mb-1.5">
            Risk Components
          </div>

          {componentEntries.length === 0 ? (
            <div className="text-[11px] text-muted-foreground">
              Awaiting risk computation...
            </div>
          ) : (
            componentEntries.map(([key, val]) => {
              const percentage = Math.min(100, Math.max(0, val * 100));
              return (
                <div key={key} className="space-y-1">
                  <div className="flex justify-between text-[11px]">
                    <span className="text-muted-foreground">{formatComponentLabel(key)}</span>
                    <span className="font-mono text-foreground">{val.toFixed(2)}</span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
                    <div
                      className={cn("h-full rounded-full transition-all duration-500", bgClass)}
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              );
            })
          )}
        </div>
      </CardContent>
    </Card>
  );
}
