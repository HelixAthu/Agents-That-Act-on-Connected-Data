import React, { useEffect, useState, useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node as FlowNode,
  type Edge as FlowEdge,
  type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { fetchGraph } from "@/lib/api";
import { getLayoutedElements } from "@/lib/layout";
import { GraphPayload } from "@/types";

interface SimpleNodeProps {
  data: {
    label: string;
    nodeType: string;
    status?: string;
    props?: Record<string, unknown>;
  };
}

/**
 * Default memoized node renderer for graph elements.
 */
const DefaultGraphNode = React.memo(({ data }: SimpleNodeProps) => {
  return (
    <div className="rounded-lg border border-border bg-card p-3 shadow-md min-w-[200px]">
      <div className="flex items-center justify-between text-xs text-muted-foreground mb-1">
        <span className="font-semibold uppercase">{data.nodeType}</span>
        <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted">
          {data.status || "HEALTHY"}
        </span>
      </div>
      <div className="text-sm font-medium text-foreground truncate">
        {data.label}
      </div>
    </div>
  );
});
DefaultGraphNode.displayName = "DefaultGraphNode";

// Define nodeTypes OUTSIDE the component to prevent re-creation on every render
const nodeTypes: NodeTypes = {
  service: DefaultGraphNode,
  database: DefaultGraphNode,
  iamrole: DefaultGraphNode,
  default: DefaultGraphNode,
};

export interface GraphCanvasProps {
  onGraphLoaded?: (payload: GraphPayload) => void;
  className?: string;
}

/**
 * Canvas component that loads and renders the infrastructure graph using React Flow and Dagre.
 */
export function GraphCanvas({ onGraphLoaded, className }: GraphCanvasProps): JSX.Element {
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<FlowEdge>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    async function loadGraphData(): Promise<void> {
      try {
        setLoading(true);
        const data = await fetchGraph();
        if (!isMounted) return;
        const layouted = getLayoutedElements(data.nodes, data.edges);
        setNodes(layouted.nodes);
        setEdges(layouted.edges);
        if (onGraphLoaded) {
          onGraphLoaded(data);
        }
      } catch (err: unknown) {
        if (!isMounted) return;
        const message = err instanceof Error ? err.message : "Failed to load graph";
        setError(message);
      } finally {
        if (isMounted) setLoading(false);
      }
    }
    loadGraphData();
    return () => {
      isMounted = false;
    };
  }, [onGraphLoaded, setNodes, setEdges]);

  const memoizedNodeTypes = useMemo(() => nodeTypes, []);

  if (loading) {
    return (
      <div className="flex h-full w-full items-center justify-center text-sm text-muted-foreground">
        Loading infrastructure graph...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex h-full w-full items-center justify-center text-sm text-destructive">
        Error: {error}
      </div>
    );
  }

  return (
    <div className={className || "h-full w-full relative"}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={memoizedNodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.2}
        maxZoom={2.0}
      >
        <Background color="#334155" gap={16} />
        <Controls className="bg-card border-border fill-foreground" />
        <MiniMap
          nodeStrokeWidth={3}
          zoomable
          pannable
          className="bg-card border-border"
        />
      </ReactFlow>
    </div>
  );
}
