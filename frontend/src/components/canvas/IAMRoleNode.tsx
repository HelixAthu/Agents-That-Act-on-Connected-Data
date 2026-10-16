import React from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { getNodeStatusClasses, getHighlightClasses } from "@/lib/constants";

export interface IAMRoleNodeData {
  label: string;
  nodeType: string;
  status?: string;
  highlightKind?: string;
  props?: {
    name?: string;
    admin_privileges?: boolean;
    max_session_hours?: number;
    status?: string;
    [key: string]: unknown;
  };
}

/**
 * IAMRoleNode displays an AWS IAM role node with admin privileges badge and session duration.
 */
export const IAMRoleNode = React.memo(({ data, selected }: NodeProps) => {
  const nodeData = data as unknown as IAMRoleNodeData;
  const props = nodeData.props || {};
  const status = nodeData.status || props.status || "HEALTHY";
  const isAdmin = Boolean(props.admin_privileges);

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
          IAM Role
        </span>
        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-background/60 border border-border">
          {status}
        </span>
      </div>

      <div className="text-xs font-semibold text-foreground truncate mb-2">
        {props.name || nodeData.label}
      </div>

      <div className="flex items-center justify-between gap-1">
        {isAdmin ? (
          <Badge
            variant="outline"
            className="text-[9px] px-1 py-0 bg-amber-950/40 text-amber-300 border-amber-700/60"
          >
            ADMIN
          </Badge>
        ) : (
          <span />
        )}
        {props.max_session_hours !== undefined && (
          <span className="text-[9px] text-muted-foreground">
            {props.max_session_hours}h max
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
IAMRoleNode.displayName = "IAMRoleNode";
