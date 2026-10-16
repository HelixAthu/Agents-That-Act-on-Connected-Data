import React from "react";
import {
  BaseEdge,
  EdgeLabelRenderer,
  getSmoothStepPath,
  type EdgeProps,
} from "@xyflow/react";
import { cn } from "@/lib/utils";

export interface CustomEdgeData {
  relType?: string;
  isAttackPath?: boolean;
  isIsolated?: boolean;
  props?: Record<string, unknown>;
}

/**
 * CustomEdge renders smooth-step curved connections with type badges and dynamic incident highlight states.
 */
export const CustomEdge = React.memo(
  ({
    id,
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    data,
    label,
    markerEnd,
  }: EdgeProps) => {
    const edgeData = data as unknown as CustomEdgeData | undefined;
    const isAttackPath = Boolean(edgeData?.isAttackPath);
    const isIsolated = Boolean(edgeData?.isIsolated || edgeData?.props?.isolated);

    const [edgePath, labelX, labelY] = getSmoothStepPath({
      sourceX,
      sourceY,
      sourcePosition,
      targetPosition,
      targetX,
      targetY,
      borderRadius: 16,
    });

    let strokeColor = "#475569";
    let strokeWidth = 1.5;
    let strokeDasharray: string | undefined;

    if (isIsolated) {
      strokeColor = "#64748b";
      strokeWidth = 1.5;
      strokeDasharray = "5 5";
    } else if (isAttackPath) {
      strokeColor = "#f43f5e";
      strokeWidth = 2.5;
      strokeDasharray = "6 4";
    }

    const displayLabel = label || edgeData?.relType;

    return (
      <>
        <BaseEdge
          id={id}
          path={edgePath}
          markerEnd={markerEnd}
          style={{
            stroke: strokeColor,
            strokeWidth,
            strokeDasharray,
            opacity: isIsolated ? 0.45 : 1,
            transition: "all 0.3s ease",
          }}
          className={cn(!isIsolated && isAttackPath && "animate-pulse")}
        />
        {displayLabel && (
          <EdgeLabelRenderer>
            <div
              style={{
                position: "absolute",
                transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
                pointerEvents: "all",
              }}
              className={cn(
                "nodrag nopan rounded px-1.5 py-0.5 text-[9px] font-mono font-medium " +
                  "border border-border/80 bg-background/90 text-muted-foreground shadow-sm",
                !isIsolated && isAttackPath && "border-rose-500 text-rose-300 bg-rose-950/80",
                isIsolated && "border-slate-700 text-slate-500 opacity-60"
              )}
            >
              {String(displayLabel)}
            </div>
          </EdgeLabelRenderer>
        )}
      </>
    );
  }
);
CustomEdge.displayName = "CustomEdge";
