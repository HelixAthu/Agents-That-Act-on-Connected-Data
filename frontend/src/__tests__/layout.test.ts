import { describe, it, expect } from "vitest";
import {
  getRankIndex,
  getLayoutedElements,
  NODE_WIDTH,
  NODE_SEP,
} from "../lib/layout";
import { GraphNode, GraphEdge } from "../types";

describe("Graph Layout (Dagre + Semantic Ranks)", () => {
  const mockNodes: GraphNode[] = [
    {
      id: "svc-web",
      label: "Service",
      props: { name: "Web Portal", tier: 1, status: "HEALTHY" },
    },
    {
      id: "svc-api",
      label: "Service",
      props: { name: "Mobile API", tier: 1, status: "HEALTHY" },
    },
    {
      id: "svc-order",
      label: "Service",
      props: { name: "Order Service", tier: 2, status: "HEALTHY" },
    },
    {
      id: "svc-billing",
      label: "Service",
      props: { name: "Billing Service", tier: 2, status: "HEALTHY" },
    },
    {
      id: "svc-auth",
      label: "Service",
      props: { name: "Auth Service", tier: 3, status: "HEALTHY" },
    },
    {
      id: "role-admin",
      label: "IAMRole",
      props: { name: "Data Admin", admin_privileges: true },
    },
    {
      id: "db-orders",
      label: "Database",
      props: { name: "Orders DB", technology: "postgres" },
    },
  ];

  const mockEdges: GraphEdge[] = [
    {
      id: "svc-web|DEPENDS_ON|svc-order",
      source: "svc-web",
      target: "svc-order",
      type: "DEPENDS_ON",
      props: {},
    },
    {
      id: "svc-api|DEPENDS_ON|svc-billing",
      source: "svc-api",
      target: "svc-billing",
      type: "DEPENDS_ON",
      props: {},
    },
    {
      id: "svc-order|DEPENDS_ON|svc-auth",
      source: "svc-order",
      target: "svc-auth",
      type: "DEPENDS_ON",
      props: {},
    },
    {
      id: "svc-order|CONNECTS_TO|db-orders",
      source: "svc-order",
      target: "db-orders",
      type: "CONNECTS_TO",
      props: {},
    },
    {
      id: "svc-billing|ASSUMES_ROLE|role-admin",
      source: "svc-billing",
      target: "role-admin",
      type: "ASSUMES_ROLE",
      props: {},
    },
  ];

  it("maps node types and tiers to correct rank indices", () => {
    expect(getRankIndex(mockNodes[0])).toBe(0); // Tier 1 Service
    expect(getRankIndex(mockNodes[2])).toBe(1); // Tier 2 Service
    expect(getRankIndex(mockNodes[4])).toBe(2); // Tier 3 Service
    expect(getRankIndex(mockNodes[5])).toBe(3); // IAMRole
    expect(getRankIndex(mockNodes[6])).toBe(4); // Database (last rank)
  });

  it("computes non-overlapping positions obeying semantic rank hierarchy", () => {
    const layout = getLayoutedElements(mockNodes, mockEdges);
    expect(layout.nodes.length).toBe(mockNodes.length);
    expect(layout.edges.length).toBe(mockEdges.length);

    const nodeMap = new Map(layout.nodes.map((n) => [n.id, n]));

    const web = nodeMap.get("svc-web")!;
    const api = nodeMap.get("svc-api")!;
    const order = nodeMap.get("svc-order")!;
    const billing = nodeMap.get("svc-billing")!;
    const auth = nodeMap.get("svc-auth")!;
    const role = nodeMap.get("role-admin")!;
    const db = nodeMap.get("db-orders")!;

    // Services Tier 1 share rank 0 Y position
    expect(web.position.y).toBe(api.position.y);

    // Services Tier 2 share rank 1 Y position
    expect(order.position.y).toBe(billing.position.y);

    // Strict vertical ranking hierarchy: Tier 1 < Tier 2 < Tier 3 < IAMRole < Database
    expect(web.position.y).toBeLessThan(order.position.y);
    expect(order.position.y).toBeLessThan(auth.position.y);
    expect(auth.position.y).toBeLessThan(role.position.y);
    expect(role.position.y).toBeLessThan(db.position.y);

    // Nodes within the same rank must not overlap horizontally
    const tier1Diff = Math.abs(web.position.x - api.position.x);
    expect(tier1Diff).toBeGreaterThanOrEqual(NODE_WIDTH + NODE_SEP - 1);

    const tier2Diff = Math.abs(order.position.x - billing.position.x);
    expect(tier2Diff).toBeGreaterThanOrEqual(NODE_WIDTH + NODE_SEP - 1);
  });

  it("preserves edge IDs, types and smoothstep configuration", () => {
    const layout = getLayoutedElements(mockNodes, mockEdges);
    for (const edge of layout.edges) {
      expect(edge.id).toMatch(/^[a-z0-9-]+\|[A-Z_]+\|[a-z0-9-]+$/);
      expect(edge.type).toBe("smoothstep");
    }
  });
});
