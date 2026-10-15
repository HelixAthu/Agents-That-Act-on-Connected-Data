# Spec 05: Frontend

- **Purpose:** Defines the React UI: layout, canvas behavior, panels, types and acceptance.
- **Read this when:** working on T10, T11, T12.

> **File map note:** section numbers (for example "Section 5.6", "G2", "Q-ATTACK") keep the numbering of the original single-file spec. `AGENTS.md` has the index that says which file holds which section.

---

## 12. Frontend Spec

**Types** (`src/types.ts`): `GraphNode`, `GraphEdge`, `AgentEvent` mirroring Section 11 exactly.

**Layout:** three columns, dark mode. Left (w-96): scenario buttons (A/B/C + "Reset graph") and the **Trace feed**. Center: React Flow canvas. Right (w-80): **Risk panel**, **Impact table**, **Approval card**, **Final report**.

**Canvas:**
- Load `GET /graph`; layout with dagre `rankdir=TB`, rank by type: services by tier, roles in one rank, databases in the last rank (use `ranksep=80`, `nodesep=40`).
- Define `nodeTypes`/`edgeTypes` **outside** the component; memoize node components. Four node components (Service, Database, IAMRole, Team/Vuln may render as small badges on service nodes instead of nodes; **do not render Team/Vulnerability as nodes**; hide those edges).
- Node status colors: HEALTHY green, DEGRADED amber, FAILED red, ISOLATED grey with dashed border. Badges: `PII`, `VULN`, `CF`.
- Highlight states driven only by `graph_visit.kind`: `inspect` → pulse ring; `impact` → orange, with a delay proportional to hop distance (use the hop data from the matching `tool_result`/`graph_visit` order); `attack_path` → red animated edges, edge dashed-animated; `action` → ISOLATED styling. Edges identified by the edge key `src|REL|dst`.
- After a `verification` event with `targets_after` shorter than before: remove red path highlighting for removed targets (fade out).
- Isolated/revoked edges render dashed grey.

**Panels:**
- Trace feed: each event as a row (icon, tool name, one-line summary, timestamp); `tool_call`/`tool_result` rows expandable to show args and the **Cypher** (monospace). Autoscroll.
- Risk panel: score gauge + the four components as bars.
- Approval card: appears on `approval_required`, with **Approve** (calls `/actions/{id}/approve`) and a "Dry-run result" summary (targets before/after); disappears on `action` event.
- Final report: summary, findings with evidence refs (click highlights the associated `call_id` rows in the trace), actions table, verification before/after, **Rollback** button per executed action, **Export JSON**.
- **Replay toggle:** loads `/replays/{scenario}` and feeds the same reducer at 600 ms per event.

**Acceptance (no manual browser needed):** `npm run build` and `npx tsc --noEmit` succeed; a Vitest unit test feeds the recorded `scenario_a.jsonl` to the state reducer and asserts: final risk ≈ 0.828, final isolated node set = {`svc-payments-gateway`}, and an `approval_required` was seen.

---

