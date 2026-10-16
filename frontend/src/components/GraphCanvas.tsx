import { useEffect, useState, useMemo } from "react";
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
  type EdgeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { fetchGraph } from "@/lib/api";
import { getLayoutedElements } from "@/lib/layout";
import { GraphPayload } from "@/types";
import { ServiceNode } from "@/components/canvas/ServiceNode";
import { DatabaseNode } from "@/components/canvas/DatabaseNode";
import { IAMRoleNode } from "@/components/canvas/IAMRoleNode";
import { CustomEdge } from "@/components/canvas/CustomEdge";

// Define nodeTypes and edgeTypes OUTSIDE the component to prevent re-creation
const nodeTypes: NodeTypes = {
  service: ServiceNode,
  database: DatabaseNode,
  iamrole: IAMRoleNode,
};

const edgeTypes: EdgeTypes = {
  custom: CustomEdge,
  smoothstep: CustomEdge,
  default: CustomEdge,
};

export interface GraphCanvasProps {
  initialNodes?: FlowNode[];
  initialEdges?: FlowEdge[];
  onGraphLoaded?: (payload: GraphPayload) => void;
  className?: string;
}

/**
 * Canvas component that loads and renders the infrastructure graph using React Flow and Dagre.
 */
export function GraphCanvas({
  initialNodes,
  initialEdges,
  onGraphLoaded,
  className,
}: GraphCanvasProps): JSX.Element {
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>(initialNodes || []);
  const [edges, setEdges, onEdgesChange] = useEdgesState<FlowEdge>(initialEdges || []);
  const [loading, setLoading] = useState<boolean>(!initialNodes || initialNodes.length === 0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialNodes && initialNodes.length > 0) {
      setNodes(initialNodes);
      setLoading(false);
      return;
    }

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
  }, [initialNodes, onGraphLoaded, setNodes, setEdges]);

  useEffect(() => {
    if (initialEdges && initialEdges.length > 0) {
      setEdges(initialEdges);
    }
  }, [initialEdges, setEdges]);

  const memoizedNodeTypes = useMemo(() => nodeTypes, []);
  const memoizedEdgeTypes = useMemo(() => edgeTypes, []);

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
        edgeTypes={memoizedEdgeTypes}
        fitView
        fitViewOptions={{ padding: 0.15 }}
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
