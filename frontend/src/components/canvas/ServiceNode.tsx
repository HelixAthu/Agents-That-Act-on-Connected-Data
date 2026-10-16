import React from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { getNodeStatusClasses, getHighlightClasses } from "@/lib/constants";

export interface ServiceNodeData {
  label: string;
  nodeType: string;
  status?: string;
  highlightKind?: string;
  props?: {
    name?: string;
    tier?: number;
    customer_facing?: boolean;
    contains_pii?: boolean;
    technology?: string;
    cvss?: number;
    status?: string;
    [key: string]: unknown;
  };
}

/**
 * ServiceNode displays a microservice entity with status styling, tier, and capability badges.
 */
export const ServiceNode = React.memo(({ data, selected }: NodeProps) => {
  const nodeData = data as unknown as ServiceNodeData;
  const props = nodeData.props || {};
  const status = nodeData.status || props.status || "HEALTHY";
  const tier = props.tier ?? 2;
  const isCustomerFacing = Boolean(props.customer_facing);
  const containsPii = Boolean(props.contains_pii);
  const hasVuln = Boolean(props.cvss && props.cvss > 0);

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
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-muted/80 text-foreground">
            T{tier}
          </span>
          <span className="text-[10px] uppercase font-semibold tracking-wider text-muted-foreground">
            Service
          </span>
        </div>
        <span
          className={cn(
            "text-[10px] font-mono px-1.5 py-0.2 rounded bg-background/60 border border-border",
            status === "ISOLATED" && "border-rose-500/80 bg-rose-950/50 text-rose-300 font-bold"
          )}
        >
          {status}
        </span>
      </div>

      {status === "ISOLATED" && (
        <div
          className={
            "mb-1.5 rounded bg-rose-950/70 border border-rose-500/80 px-2 py-0.5 " +
            "text-center text-[10px] font-bold text-rose-300 uppercase tracking-wider animate-pulse"
          }
        >
          ISOLATED
        </div>
      )}

      <div className="text-xs font-semibold text-foreground truncate mb-2">
        {props.name || nodeData.label}
      </div>

      <div className="flex flex-wrap items-center gap-1">
        {isCustomerFacing && (
          <Badge
            variant="outline"
            className="text-[9px] px-1 py-0 bg-sky-950/40 text-sky-300 border-sky-700/60"
          >
            CF
          </Badge>
        )}
        {containsPii && (
          <Badge
            variant="outline"
            className="text-[9px] px-1 py-0 bg-purple-950/40 text-purple-300 border-purple-700/60"
          >
            PII
          </Badge>
        )}
        {hasVuln && (
          <Badge
            variant="outline"
            className="text-[9px] px-1 py-0 bg-rose-950/40 text-rose-300 border-rose-700/60"
          >
            VULN
          </Badge>
        )}
        {props.technology && (
          <span className="text-[9px] text-muted-foreground ml-auto truncate max-w-[80px]">
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
ServiceNode.displayName = "ServiceNode";
