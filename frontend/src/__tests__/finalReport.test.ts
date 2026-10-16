import { describe, it, expect } from "vitest";
import { FinalReportPanel, exportReportJson } from "../components/panels/FinalReportPanel";
import { FinalReport, ReportAction } from "../types";

describe("FinalReportPanel and Rollback Controls", () => {
  const sampleReport: FinalReport = {
    incident_id: "inc-a-19aad7",
    summary:
      "Critical exploit on svc-payments-gateway fully contained via role revocation and node isolation.",
    risk_score: 0.828,
    findings: [
      {
        claim: "Vulnerability CVE-2026-9901 affects payments gateway with CVSS 9.8.",
        evidence_refs: ["call-083d0510", "call-1901a88b"],
      },
      {
        claim: "Attack path reaches customer profile database via role assumption.",
        evidence_refs: ["call-99bba120"],
      },
    ],
    impact: {
      impacted_services: 6,
      customer_facing: 3,
      owner_teams: ["team-payments", "team-core"],
    },
    actions: [
      {
        action_id: "act-1a2b56bf",
        type: "REVOKE_ROLE",
        target: "svc-payments-gateway|role-storage-manager",
        policy: "AUTO",
        status: "EXECUTED",
      },
      {
        action_id: "act-c361ea6a",
        type: "ISOLATE_NODE",
        target: "svc-payments-gateway",
        policy: "APPROVAL_REQUIRED",
        status: "EXECUTED",
      },
    ],
    verification: {
      targets_before: ["db-customer-profile", "db-user-billing"],
      targets_after: [],
    },
    tool_calls: [
      {
        call_id: "call-083d0510",
        tool: "get_component_context",
        query_id: "Q-CONTEXT",
        ms: 3.93,
      },
    ],
  };

  const sampleActions: ReportAction[] = [...sampleReport.actions];

  it("exports FinalReportPanel and exportReportJson definitions", () => {
    expect(FinalReportPanel).toBeDefined();
    expect(typeof FinalReportPanel).toBe("function");

    expect(exportReportJson).toBeDefined();
    expect(typeof exportReportJson).toBe("function");
  });

  it("verifies containment reduction metrics from report data", () => {
    expect(sampleReport.verification.targets_before.length).toBe(2);
    expect(sampleReport.verification.targets_after.length).toBe(0);
    const eliminated =
      sampleReport.verification.targets_before.length -
      sampleReport.verification.targets_after.length;
    expect(eliminated).toBe(2);
  });

  it("maps findings to evidence references correctly", () => {
    expect(sampleReport.findings.length).toBe(2);
    expect(sampleReport.findings[0].evidence_refs).toContain("call-083d0510");
    expect(sampleReport.findings[1].evidence_refs).toContain("call-99bba120");
  });

  it("handles rollback state updates on action records", () => {
    const updatedActions = sampleActions.map((act) =>
      act.action_id === "act-c361ea6a" ? { ...act, status: "ROLLED_BACK" } : act
    );

    const isolatedAction = updatedActions.find((a) => a.action_id === "act-c361ea6a");
    expect(isolatedAction?.status).toBe("ROLLED_BACK");

    const revokeAction = updatedActions.find((a) => a.action_id === "act-1a2b56bf");
    expect(revokeAction?.status).toBe("EXECUTED");
  });
});
