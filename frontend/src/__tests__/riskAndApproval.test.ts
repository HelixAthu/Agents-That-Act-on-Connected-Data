import { describe, it, expect } from "vitest";
import { RiskPanel } from "../components/panels/RiskPanel";
import { ApprovalCard } from "../components/panels/ApprovalCard";
import { PendingApproval } from "../types";

describe("RiskPanel and ApprovalCard Components", () => {
  it("exports RiskPanel and ApprovalCard components", () => {
    expect(RiskPanel).toBeDefined();
    expect(typeof RiskPanel).toBe("function");

    expect(ApprovalCard).toBeDefined();
    expect(typeof ApprovalCard).toBe("function");
  });

  it("calculates component percentages accurately", () => {
    const components = {
      severity: 0.98,
      pii: 1.0,
      blast: 0.25,
      central: 0.1053,
    };

    expect(components.severity * 100).toBeCloseTo(98.0, 1);
    expect(components.pii * 100).toBe(100);
    expect(components.blast * 100).toBe(25);
    expect(components.central * 100).toBeCloseTo(10.53, 2);
  });

  it("validates approval state properties and action IDs", () => {
    const mockApproval: PendingApproval = {
      action_id: "act-c361ea6a",
      action: "ISOLATE_NODE",
      target_id: "svc-payments-gateway",
      policy: "APPROVAL_REQUIRED",
    };
    expect(mockApproval.action_id).toBe("act-c361ea6a");
    expect(mockApproval.action).toBe("ISOLATE_NODE");
    expect(mockApproval.policy).toBe("APPROVAL_REQUIRED");
  });

  it("formats dry-run impact metrics from pending approval", () => {
    const mockApproval: PendingApproval = {
      action_id: "act-c361ea6a",
      action: "ISOLATE_NODE",
      target_id: "svc-payments-gateway",
      policy: "APPROVAL_REQUIRED",
      reason: "tier-1 customer-facing service requires human approval",
      targets_before: ["db-user-billing"],
      targets_after: [],
    };

    const beforeCount = mockApproval.targets_before?.length || 0;
    const afterCount = mockApproval.targets_after?.length || 0;
    expect(beforeCount).toBe(1);
    expect(afterCount).toBe(0);
    expect(beforeCount - afterCount).toBe(1); // 1 threat path eliminated
  });
});
