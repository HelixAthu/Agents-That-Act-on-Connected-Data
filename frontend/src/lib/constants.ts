/**
 * Constants and visual mapping definitions for Graph canvas and components.
 */

export const NODE_STATUS = {
  HEALTHY: "HEALTHY",
  DEGRADED: "DEGRADED",
  FAILED: "FAILED",
  ISOLATED: "ISOLATED",
} as const;

export const HIGHLIGHT_KIND = {
  INSPECT: "inspect",
  IMPACT: "impact",
  ATTACK_PATH: "attack_path",
  ACTION: "action",
} as const;

export const NODE_TYPES = {
  SERVICE: "service",
  DATABASE: "database",
  IAMROLE: "iamrole",
} as const;

export const EDGE_TYPES = {
  DEPENDS_ON: "DEPENDS_ON",
  CONNECTS_TO: "CONNECTS_TO",
  ASSUMES_ROLE: "ASSUMES_ROLE",
  CAN_ASSUME: "CAN_ASSUME",
  CAN_ACCESS: "CAN_ACCESS",
} as const;

/**
 * Returns Tailwind class string for a node visual status.
 */
export function getNodeStatusClasses(status?: string): string {
  switch (status) {
    case NODE_STATUS.DEGRADED:
      return "border-amber-500/70 bg-amber-950/20 text-amber-200";
    case NODE_STATUS.FAILED:
      return "border-rose-500/80 bg-rose-950/30 text-rose-200";
    case NODE_STATUS.ISOLATED:
      return "border-dashed border-slate-600 bg-slate-900/60 text-slate-400 opacity-60";
    case NODE_STATUS.HEALTHY:
    default:
      return "border-emerald-500/60 bg-emerald-950/20 text-emerald-200";
  }
}

/**
 * Returns Tailwind class string for node highlight kind.
 */
export function getHighlightClasses(kind?: string): string {
  switch (kind) {
    case HIGHLIGHT_KIND.INSPECT:
      return "ring-2 ring-sky-400 ring-offset-1 ring-offset-background animate-pulse";
    case HIGHLIGHT_KIND.IMPACT:
      return "ring-2 ring-amber-500 ring-offset-1 ring-offset-background";
    case HIGHLIGHT_KIND.ATTACK_PATH:
      return "ring-2 ring-rose-500 ring-offset-1 ring-offset-background shadow-lg shadow-rose-950";
    case HIGHLIGHT_KIND.ACTION:
      return "ring-2 ring-slate-400 ring-offset-1 ring-offset-background opacity-75";
    default:
      return "";
  }
}
