import { useState } from "react";
import { ShieldAlert, Check, ArrowRight } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { PendingApproval } from "@/types";
import { cn } from "@/lib/utils";

export interface ApprovalCardProps {
  approval: PendingApproval | null;
  onApprove: (actionId: string) => Promise<void> | void;
  className?: string;
}

/**
 * ApprovalCard prompts human operators for critical containment actions and displays dry-run blast radius impact.
 */
export function ApprovalCard({ approval, onApprove, className }: ApprovalCardProps): JSX.Element | null {
  const [submitting, setSubmitting] = useState<boolean>(false);

  if (!approval) {
    return null;
  }

  const handleApprove = async () => {
    try {
      setSubmitting(true);
      await onApprove(approval.action_id);
    } catch (err) {
      console.error("Failed to approve action:", err);
    } finally {
      setSubmitting(false);
    }
  };

  const beforeTargets = approval.targets_before || [];
  const afterTargets = approval.targets_after || [];

  return (
    <Card className={cn("border-amber-500/80 bg-amber-950/20 shadow-lg animate-in fade-in duration-300", className)}>
      <CardHeader className="py-2.5 px-3 border-b border-amber-500/40 flex flex-row items-center justify-between">
        <div className="flex items-center gap-1.5">
          <ShieldAlert className="h-4 w-4 text-amber-400 animate-pulse" />
          <CardTitle className="text-xs uppercase font-bold tracking-wider text-amber-300">
            Approval Required
          </CardTitle>
        </div>
        <Badge
          variant="outline"
          className="text-[10px] px-1.5 py-0 border-amber-600 bg-amber-950/60 text-amber-300"
        >
          {approval.policy || "GATE"}
        </Badge>
      </CardHeader>

      <CardContent className="p-3 space-y-3 text-xs">
        <div>
          <div className="font-semibold text-foreground text-sm flex items-center gap-1.5">
            <span>{approval.action}</span>
            <span className="font-mono text-xs text-amber-300">({approval.target_id})</span>
          </div>
          {approval.reason && (
            <p className="text-muted-foreground mt-1 text-[11px] leading-relaxed">
              {approval.reason}
            </p>
          )}
        </div>

        {/* Dry-run result */}
        <div className="rounded-lg bg-background/80 border border-border/80 p-2.5 space-y-1.5">
          <div className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider">
            Dry-Run Containment Impact
          </div>
          <div className="flex items-center justify-between text-[11px] font-mono">
            <div>
              <span className="text-rose-400 font-semibold">{beforeTargets.length}</span>
              <span className="text-muted-foreground ml-1">threat paths before</span>
            </div>
            <ArrowRight className="h-3 w-3 text-muted-foreground" />
            <div>
              <span className="text-emerald-400 font-semibold">{afterTargets.length}</span>
              <span className="text-muted-foreground ml-1">targets after</span>
            </div>
          </div>
          {beforeTargets.length > afterTargets.length && (
            <div className="text-[10px] text-emerald-400">
              Mitigates exposure to {beforeTargets.length - afterTargets.length} critical data target(s)
            </div>
          )}
        </div>

        {/* Action button */}
        <Button
          variant="default"
          size="sm"
          className="w-full bg-amber-600 hover:bg-amber-500 text-black font-semibold shadow"
          onClick={handleApprove}
          disabled={submitting}
        >
          <Check className="h-3.5 w-3.5 mr-1" />
          {submitting ? "Approving Action..." : "Approve Containment"}
        </Button>
      </CardContent>
    </Card>
  );
}
