import { describe, it, expect } from "vitest";
import {
  getNodeStatusClasses,
  getHighlightClasses,
  NODE_STATUS,
  HIGHLIGHT_KIND,
} from "../lib/constants";
import { ServiceNode } from "../components/canvas/ServiceNode";
import { DatabaseNode } from "../components/canvas/DatabaseNode";
import { IAMRoleNode } from "../components/canvas/IAMRoleNode";
import { CustomEdge } from "../components/canvas/CustomEdge";

describe("Custom Nodes and Status Styling", () => {
  it("maps node visual statuses to correct Tailwind color classes", () => {
    const healthyClass = getNodeStatusClasses(NODE_STATUS.HEALTHY);
    expect(healthyClass).toContain("border-emerald-500");
    expect(healthyClass).toContain("text-emerald-200");

    const degradedClass = getNodeStatusClasses(NODE_STATUS.DEGRADED);
    expect(degradedClass).toContain("border-amber-500");
    expect(degradedClass).toContain("text-amber-200");

    const failedClass = getNodeStatusClasses(NODE_STATUS.FAILED);
    expect(failedClass).toContain("border-rose-500");
    expect(failedClass).toContain("text-rose-200");

    const isolatedClass = getNodeStatusClasses(NODE_STATUS.ISOLATED);
    expect(isolatedClass).toContain("border-dashed");
    expect(isolatedClass).toContain("border-slate-600");
    expect(isolatedClass).toContain("opacity-60");
  });

  it("maps highlight kinds to distinct ring and animation classes", () => {
    const inspectClass = getHighlightClasses(HIGHLIGHT_KIND.INSPECT);
    expect(inspectClass).toContain("ring-sky-400");
    expect(inspectClass).toContain("animate-pulse");

    const impactClass = getHighlightClasses(HIGHLIGHT_KIND.IMPACT);
    expect(impactClass).toContain("ring-amber-500");

    const attackClass = getHighlightClasses(HIGHLIGHT_KIND.ATTACK_PATH);
    expect(attackClass).toContain("ring-rose-500");

    const actionClass = getHighlightClasses(HIGHLIGHT_KIND.ACTION);
    expect(actionClass).toContain("ring-slate-400");

    expect(getHighlightClasses(undefined)).toBe("");
  });

  it("exports memoized custom node and edge components", () => {
    expect(ServiceNode).toBeDefined();
    expect(ServiceNode.displayName).toBe("ServiceNode");

    expect(DatabaseNode).toBeDefined();
    expect(DatabaseNode.displayName).toBe("DatabaseNode");

    expect(IAMRoleNode).toBeDefined();
    expect(IAMRoleNode.displayName).toBe("IAMRoleNode");

    expect(CustomEdge).toBeDefined();
    expect(CustomEdge.displayName).toBe("CustomEdge");
  });
});
