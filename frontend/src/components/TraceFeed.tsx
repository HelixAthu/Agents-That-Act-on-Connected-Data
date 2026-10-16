import { useState, useEffect, useRef } from "react";
import {
  Terminal,
  Brain,
  Shield,
  Activity,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Database,
} from "lucide-react";
import { TraceItem } from "@/types";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";

export interface TraceFeedProps {
  items: TraceItem[];
  selectedCallId?: string | null;
  onSelectCallId?: (callId: string | null) => void;
  className?: string;
}

/**
 * Returns a contextual icon component for an event type.
 */
function getEventIcon(type: string, tool?: string): JSX.Element {
  if (type === "thought") {
    return <Brain className="h-3.5 w-3.5 text-purple-400" />;
  }
  if (type === "risk_update") {
    return <Activity className="h-3.5 w-3.5 text-amber-400" />;
  }
  if (type === "action" || type === "approval_required") {
    return <Shield className="h-3.5 w-3.5 text-emerald-400" />;
  }
  if (type === "verification") {
    return <CheckCircle2 className="h-3.5 w-3.5 text-sky-400" />;
  }
  if (tool?.includes("database") || tool?.includes("query")) {
    return <Database className="h-3.5 w-3.5 text-blue-400" />;
  }
  if (type === "error") {
    return <AlertTriangle className="h-3.5 w-3.5 text-rose-400" />;
  }
  return <Terminal className="h-3.5 w-3.5 text-emerald-400" />;
}

/**
 * Formats ISO timestamp to short HH:mm:ss representation.
 */
function formatTime(isoString: string): string {
  try {
    return isoString.slice(11, 19);
  } catch {
    return "";
  }
}

/**
 * TraceFeed displays an autoscrolling audit log of all agent thoughts, tool calls, and Cypher queries.
 */
export function TraceFeed({
  items,
  selectedCallId,
  onSelectCallId,
  className,
}: TraceFeedProps): JSX.Element {
  const [expandedCallIds, setExpandedCallIds] = useState<Set<string>>(new Set());
  const endRef = useRef<HTMLDivElement | null>(null);

  // Autoscroll to bottom when new events arrive
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [items.length]);

  const toggleExpand = (callId: string) => {
    setExpandedCallIds((prev) => {
      const next = new Set(prev);
      if (next.has(callId)) {
        next.delete(callId);
      } else {
        next.add(callId);
      }
      return next;
    });
  };

  if (items.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-muted-foreground p-4">
        Awaiting agent execution...
      </div>
    );
  }

  return (
    <div className={cn("flex flex-col h-full overflow-y-auto space-y-2 p-2", className)}>
      {items.map((item, index) => {
        const itemKey = item.call_id || `${item.seq}-${index}`;
        const isExpandable = Boolean(item.cypher || item.args);
        const isExpanded = item.call_id ? expandedCallIds.has(item.call_id) : false;
        const isSelected = item.call_id && selectedCallId === item.call_id;

        return (
          <div
            key={itemKey}
            className={cn(
              "rounded-lg border border-border/60 bg-card/60 p-2 text-xs transition-colors",
              isSelected && "border-primary bg-primary/10 shadow-sm",
              isExpandable && "cursor-pointer hover:bg-card/90"
            )}
            onClick={() => {
              if (item.call_id) {
                toggleExpand(item.call_id);
                if (onSelectCallId) {
                  onSelectCallId(isSelected ? null : item.call_id);
                }
              }
            }}
          >
            {/* Header row */}
            <div className="flex items-center justify-between gap-1.5">
              <div className="flex items-center gap-1.5 min-w-0">
                {isExpandable ? (
                  isExpanded ? (
                    <ChevronDown className="h-3 w-3 text-muted-foreground shrink-0" />
                  ) : (
                    <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />
                  )
                ) : (
                  <span className="w-3 shrink-0" />
                )}

                {getEventIcon(item.type, item.tool)}

                <span className="font-semibold text-foreground truncate">
                  {item.tool || item.type}
                </span>

                {item.query_id && (
                  <Badge
                    variant="outline"
                    className="text-[9px] px-1 py-0 font-mono bg-blue-950/30 text-blue-300 border-blue-800"
                  >
                    {item.query_id}
                  </Badge>
                )}
              </div>

              <div className="flex items-center gap-1 shrink-0 text-[10px] text-muted-foreground">
                {item.ms !== undefined && (
                  <span className="font-mono text-emerald-400">{item.ms.toFixed(1)}ms</span>
                )}
                <span>{formatTime(item.ts)}</span>
              </div>
            </div>

            {/* One line summary or thought text */}
            <div className="mt-1 pl-4 text-muted-foreground line-clamp-2">
              {item.summary || item.text || (item.args ? JSON.stringify(item.args) : "")}
            </div>

            {/* Expandable Cypher and tool arguments */}
            {isExpanded && (
              <div className="mt-2 pl-4 pt-2 border-t border-border/40 space-y-2 text-[11px]">
                {item.call_id && (
                  <div className="font-mono text-[10px] text-muted-foreground">
                    call_id: <span className="text-foreground">{item.call_id}</span>
                  </div>
                )}

                {item.args && Object.keys(item.args).length > 0 && (
                  <div>
                    <div className="text-[10px] uppercase font-bold text-muted-foreground mb-0.5">
                      Arguments
                    </div>
                    <pre className="p-2 rounded bg-muted/60 font-mono text-[10px] overflow-x-auto text-foreground">
                      {JSON.stringify(item.args, null, 2)}
                    </pre>
                  </div>
                )}

                {item.cypher && (
                  <div>
                    <div className="text-[10px] uppercase font-bold text-muted-foreground mb-0.5">
                      Executed Cypher
                    </div>
                    <pre className="p-2 rounded bg-black/80 font-mono text-[10px] overflow-x-auto text-emerald-300 border border-emerald-950">
                      {item.cypher}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
      <div ref={endRef} />
    </div>
  );
}
