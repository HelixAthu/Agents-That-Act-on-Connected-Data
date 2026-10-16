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
import { CustomEdge, CustomEdgeData } from "@/components/canvas/CustomEdge";

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
  highlightedNodes?: Record<string, string>;
  highlightedEdges?: Record<string, string>;
  nodeStatuses?: Record<string, string>;
  isolatedNodes?: Set<string>;
  revokedRoles?: Set<string>;
  onGraphLoaded?: (payload: GraphPayload) => void;
  className?: string;
}

/**
 * Canvas component that loads and renders the infrastructure graph using React Flow and Dagre.
 */
export function GraphCanvas({
  initialNodes,
  initialEdges,
  highlightedNodes,
  highlightedEdges,
  nodeStatuses,
  isolatedNodes,
  revokedRoles,
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

  // Synchronize live highlight and isolation states to canvas nodes
  useEffect(() => {
    if (!highlightedNodes && !nodeStatuses && !isolatedNodes) return;
    setNodes((prevNodes) =>
      prevNodes.map((node) => {
        const highlightKind = highlightedNodes ? highlightedNodes[node.id] : undefined;
        const currentStatus =
          isolatedNodes && isolatedNodes.has(node.id)
            ? "ISOLATED"
            : (nodeStatuses && nodeStatuses[node.id]) || node.data.status;

        if (
          node.data.highlightKind === highlightKind &&
          node.data.status === currentStatus
        ) {
          return node;
        }

        return {
          ...node,
          data: {
            ...node.data,
            highlightKind,
            status: currentStatus,
          },
        };
      })
    );
  }, [highlightedNodes, nodeStatuses, isolatedNodes, setNodes]);

  // Synchronize live attack path animations and edge isolation to canvas edges
  useEffect(() => {
    if (!highlightedEdges && !isolatedNodes && !revokedRoles) return;
    setEdges((prevEdges) =>
      prevEdges.map((edge) => {
        const isAttackPath = Boolean(
          highlightedEdges && highlightedEdges[edge.id] === "attack_path"
        );
        const edgeProps = (edge.data?.props as Record<string, unknown> | undefined);
        const isIsolated = Boolean(
          edgeProps?.isolated ||
            (isolatedNodes && (isolatedNodes.has(edge.source) || isolatedNodes.has(edge.target))) ||
            (revokedRoles && (revokedRoles.has(edge.target) || revokedRoles.has(edge.id)))
        );

        const currentData = edge.data as CustomEdgeData | undefined;
        if (
          currentData?.isAttackPath === isAttackPath &&
          currentData?.isIsolated === isIsolated &&
          edge.animated === isAttackPath
        ) {
          return edge;
        }

        return {
          ...edge,
          animated: isAttackPath,
          data: {
            ...edge.data,
            isAttackPath,
            isIsolated,
          },
        };
      })
    );
  }, [highlightedEdges, isolatedNodes, revokedRoles, setEdges]);

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
