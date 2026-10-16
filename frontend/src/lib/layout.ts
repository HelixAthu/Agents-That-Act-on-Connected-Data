import dagre from "@dagrejs/dagre";
import { type Node as FlowNode, type Edge as FlowEdge } from "@xyflow/react";
import { GraphNode, GraphEdge } from "@/types";

export const NODE_WIDTH = 220;
export const NODE_HEIGHT = 80;
export const RANK_SEP = 80;
export const NODE_SEP = 40;

/**
 * Maps a graph node to its hierarchical layout rank index.
 * Services are ordered by tier, IAM roles share a unified rank, and databases occupy the last rank.
 */
export function getRankIndex(node: GraphNode): number {
  if (node.label === "Service") {
    const tier = node.props.tier ?? 2;
    if (tier === 1) return 0;
    if (tier === 2) return 1;
    return 2;
  }
  if (node.label === "IAMRole") {
    return 3;
  }
  if (node.label === "Database") {
    return 4;
  }
  return 0;
}

/**
 * Converts domain graph nodes and edges into React Flow elements laid out via Dagre.
 */
export function getLayoutedElements(
  nodes: GraphNode[],
  edges: GraphEdge[]
): { nodes: FlowNode[]; edges: FlowEdge[] } {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setGraph({
    rankdir: "TB",
    ranksep: RANK_SEP,
    nodesep: NODE_SEP,
  });
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  for (const node of nodes) {
    dagreGraph.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  }

  for (const edge of edges) {
    dagreGraph.setEdge(edge.source, edge.target);
  }

  dagre.layout(dagreGraph);

  // Group nodes by their semantic rank index
  const rankBuckets: Array<Array<{ node: GraphNode; dagreX: number }>> = [
    [],
    [],
    [],
    [],
    [],
  ];

  for (const node of nodes) {
    const rank = getRankIndex(node);
    const layoutNode = dagreGraph.node(node.id);
    const dagreX = layoutNode ? layoutNode.x : 0;
    rankBuckets[rank].push({ node, dagreX });
  }

  // Calculate clean non-overlapping coordinates preserving Dagre relative horizontal ordering
  const flowNodes: FlowNode[] = [];

  rankBuckets.forEach((bucket, rankIndex) => {
    bucket.sort((a, b) => a.dagreX - b.dagreX);
    const count = bucket.length;
    const totalSpan = count * NODE_WIDTH + Math.max(0, count - 1) * NODE_SEP;
    let startX = -totalSpan / 2 + NODE_WIDTH / 2;
    const yPos = rankIndex * (NODE_HEIGHT + RANK_SEP);

    bucket.forEach(({ node }) => {
      flowNodes.push({
        id: node.id,
        type: node.label.toLowerCase(),
        position: { x: startX, y: yPos },
        data: {
          label: node.props.name || node.id,
          nodeType: node.label,
          props: node.props,
          status: node.props.status || "HEALTHY",
        },
      });
      startX += NODE_WIDTH + NODE_SEP;
    });
  });

  const flowEdges: FlowEdge[] = edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    type: "smoothstep",
    animated: false,
    label: edge.type,
    style: { stroke: "#64748b", strokeWidth: 1.5 },
    data: {
      relType: edge.type,
      props: edge.props,
    },
  }));

  return { nodes: flowNodes, edges: flowEdges };
}
