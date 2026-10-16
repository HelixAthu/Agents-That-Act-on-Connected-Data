import { useState } from "react";
import {
  FileText,
  RotateCcw,
  Download,
  CheckCircle,
  ExternalLink,
  ShieldCheck,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { FinalReport, ReportAction } from "@/types";
import { cn } from "@/lib/utils";

export interface FinalReportPanelProps {
  report: FinalReport | null;
  actions: ReportAction[];
  onRollback: (actionId: string) => Promise<void> | void;
  onSelectCallId?: (callId: string) => void;
  className?: string;
}

/**
 * Downloads incident report data as a formatted JSON document.
 */
export function exportReportJson(report: FinalReport, actions: ReportAction[]): void {
  const payload = {
    ...report,
    executed_actions: actions,
    exported_at: new Date().toISOString(),
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `incident_${report.incident_id}_report.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * FinalReportPanel displays incident findings, containment verification, action rollback controls, and JSON export.
 */
export function FinalReportPanel({
  report,
  actions,
  onRollback,
  onSelectCallId,
  className,
}: FinalReportPanelProps): JSX.Element | null {
  const [rollingBackId, setRollingBackId] = useState<string | null>(null);

  if (!report) {
    return null;
  }

  const handleRollback = async (actionId: string) => {
    try {
      setRollingBackId(actionId);
      await onRollback(actionId);
    } catch (err) {
      console.error("Failed to rollback action:", err);
    } finally {
      setRollingBackId(null);
    }
  };

  const findings = report.findings || [];
  const actionList = actions.length > 0 ? actions : report.actions || [];
  const verification = report.verification || { targets_before: [], targets_after: [] };

  return (
    <Card className={cn("border-emerald-600/70 bg-card shadow-lg animate-in fade-in duration-300", className)}>
      <CardHeader className="py-2.5 px-3 border-b border-border flex flex-row items-center justify-between">
        <div className="flex items-center gap-1.5">
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
          <CardTitle className="text-xs uppercase font-bold tracking-wider text-emerald-300">
            Final Incident Report
          </CardTitle>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="h-7 text-[10px] px-2"
          onClick={() => exportReportJson(report, actionList)}
        >
          <Download className="h-3 w-3 mr-1" />
          Export JSON
        </Button>
      </CardHeader>

      <CardContent className="p-3 space-y-3.5 text-xs">
        {/* Executive Summary */}
        <div className="rounded-lg bg-muted/40 p-2.5 border border-border/60">
          <div className="flex items-center justify-between text-[10px] text-muted-foreground mb-1 font-mono">
            <span>{report.incident_id}</span>
            <span className="text-emerald-400 font-semibold">CONTAINED</span>
          </div>
          <p className="text-foreground text-[11px] leading-relaxed font-medium">
            {report.summary}
          </p>
        </div>

        {/* Findings with Evidence References */}
        {findings.length > 0 && (
          <div className="space-y-1.5">
            <div className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider flex items-center gap-1">
              <FileText className="h-3 w-3 text-muted-foreground" />
              Key Findings & Evidence
            </div>
            <div className="space-y-1.5">
              {findings.map((finding, idx) => (
                <div key={idx} className="rounded bg-background/80 border border-border/80 p-2 text-[11px]">
                  <div className="text-foreground leading-snug">{finding.claim}</div>
                  {finding.evidence_refs && finding.evidence_refs.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1 mt-1.5">
                      <span className="text-[9px] text-muted-foreground">Evidence:</span>
                      {finding.evidence_refs.map((refId) => (
                        <button
                          key={refId}
                          type="button"
                          onClick={() => onSelectCallId && onSelectCallId(refId)}
                          className={cn(
                            "inline-flex items-center gap-0.5 rounded px-1.5 py-0.2 font-mono text-[9px]",
                            "bg-primary/10 text-primary border border-primary/30 hover:bg-primary/20 transition-colors"
                          )}
                        >
                          <span>{refId}</span>
                          <ExternalLink className="h-2.5 w-2.5" />
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Verification Before / After */}
        <div className="rounded bg-background/80 border border-border/80 p-2 space-y-1">
          <div className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider flex items-center gap-1">
            <CheckCircle className="h-3 w-3 text-emerald-400" />
            Verification Delta
          </div>
          <div className="flex justify-between items-center font-mono text-[11px]">
            <div>
              <span className="text-rose-400 font-bold">{verification.targets_before.length}</span>
              <span className="text-muted-foreground ml-1">targets exposed</span>
            </div>
            <span className="text-muted-foreground">→</span>
            <div>
              <span className="text-emerald-400 font-bold">{verification.targets_after.length}</span>
              <span className="text-muted-foreground ml-1">remaining</span>
            </div>
          </div>
        </div>

        {/* Actions Table & Rollback Controls */}
        <div className="space-y-1.5">
          <div className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider">
            Executed Containment Actions
          </div>
          <div className="space-y-1.5">
            {actionList.map((action) => {
              const isRolledBack = action.status === "ROLLED_BACK";
              return (
                <div
                  key={action.action_id}
                  className="flex items-center justify-between rounded bg-background/80 border border-border/80 p-2 text-[11px]"
                >
                  <div className="min-w-0 pr-2">
                    <div className="font-semibold text-foreground truncate">
                      {action.type}
                    </div>
                    <div className="font-mono text-[10px] text-muted-foreground truncate">
                      {action.target}
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    <Badge
                      variant="outline"
                      className={cn(
                        "text-[9px] px-1 py-0",
                        isRolledBack
                          ? "border-slate-600 text-slate-400"
                          : "border-emerald-700 bg-emerald-950/40 text-emerald-300"
                      )}
                    >
                      {action.status}
                    </Badge>

                    {!isRolledBack && (
                      <Button
                        variant="destructive"
                        size="sm"
                        className="h-6 text-[10px] px-2"
                        disabled={rollingBackId === action.action_id}
                        onClick={() => handleRollback(action.action_id)}
                      >
                        <RotateCcw className="h-2.5 w-2.5 mr-1" />
                        {rollingBackId === action.action_id ? "Rolling back..." : "Rollback"}
                      </Button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
