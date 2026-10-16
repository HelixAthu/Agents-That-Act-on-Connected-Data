import React from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { getNodeStatusClasses, getHighlightClasses } from "@/lib/constants";

export interface DatabaseNodeData {
  label: string;
  nodeType: string;
  status?: string;
  highlightKind?: string;
  props?: {
    name?: string;
    contains_pii?: boolean;
    technology?: string;
    status?: string;
    [key: string]: unknown;
  };
}

/**
 * DatabaseNode displays a database entity in the bottom rank with technology and PII indicators.
 */
export const DatabaseNode = React.memo(({ data, selected }: NodeProps) => {
  const nodeData = data as unknown as DatabaseNodeData;
  const props = nodeData.props || {};
  const status = props.status || nodeData.status || "HEALTHY";
  const containsPii = Boolean(props.contains_pii);

  const statusClass = getNodeStatusClasses(status);
  const highlightClass = getHighlightClasses(nodeData.highlightKind);

  return (
    <div
      className={cn(
        "rounded-xl border bg-card p-3 shadow-md transition-all duration-300 min-w-[210px] max-w-[240px]",
        statusClass,
        highlightClass,
        selected && "ring-2 ring-primary ring-offset-2"
      )}
    >
      <Handle
        type="target"
        position={Position.Top}
        className="!h-2 !w-2 !border-2 !border-background !bg-muted-foreground"
      />

      <div className="flex items-center justify-between gap-1 mb-1.5">
        <span className="text-[10px] uppercase font-semibold tracking-wider text-muted-foreground">
          Database
        </span>
        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-background/60 border border-border">
          {status}
        </span>
      </div>

      <div className="text-xs font-semibold text-foreground truncate mb-2">
        {props.name || nodeData.label}
      </div>

      <div className="flex items-center justify-between gap-1">
        {containsPii ? (
          <Badge
            variant="outline"
            className="text-[9px] px-1 py-0 bg-purple-950/40 text-purple-300 border-purple-700/60"
          >
            PII
          </Badge>
        ) : (
          <span />
        )}
        {props.technology && (
          <span className="text-[9px] text-muted-foreground truncate max-w-[100px]">
            {String(props.technology)}
          </span>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Bottom}
        className="!h-2 !w-2 !border-2 !border-background !bg-muted-foreground"
      />
    </div>
  );
});
DatabaseNode.displayName = "DatabaseNode";
