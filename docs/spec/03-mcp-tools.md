# Spec 03: MCP tools

- **Purpose:** Defines the 11 MCP tools: names, inputs, outputs, the response envelope and error codes.
- **Read this when:** working on T5, T6, T7 or T8.

> **File map note:** section numbers (for example "Section 5.6", "G2", "Q-ATTACK") keep the numbering of the original single-file spec. `AGENTS.md` has the index that says which file holds which section.

---

## 9. MCP Tools (exact contracts)

**Response envelope (all tools):**
```json
{"ok": true, "data": {...},
 "visit": {"kind": "inspect|impact|attack_path|action", "node_ids": [...], "edge_keys": [...]},
 "evidence": {"query_id": "Q-ATTACK", "cypher": "<executed text>", "params": {...}, "ms": 12.3, "row_count": 2}}
```
Error: `{"ok": false, "error": {"code": "NOT_FOUND|INVALID_INPUT|POLICY_DENIED|APPROVAL_REQUIRED|DB_ERROR", "message": "..."}}`.
Tools return the envelope as a **JSON string** in a single text content item. Tool descriptions must say **when to use** and **when not to use** (this drives tool selection accuracy).

| # | Tool | Input (Pydantic) | `data` contents |
|---|---|---|---|
| 1 | `get_component_context` | `id: str` | `{label, props, owners[], vulnerabilities[], outgoing[{rel,other,isolated}], incoming[...]}` |
| 2 | `get_failure_impact` | `id: str`, `max_hops: int=3 (1..6)`, `critical_only: bool=false` | `{target, impacted:[{id,name,tier,customer_facing,hops,owners[]}], customer_facing_count, owners:[{id,name}]}` |
| 3 | `find_attack_paths` | `source_id: str`, `max_hops: int=6 (1..6)` | `{source, paths:[{target,hops,node_ids,edge_types,edge_keys}], engine:"cypher"\|"fallback"}` |
| 4 | `rank_critical_components` | `top_n: int=5 (1..20)` | `{ranking:[{id,name,transitive_dependents,pagerank?,betweenness?}]}` |
| 5 | `compute_risk` | `target_id: str` | `{risk, components:{severity,pii,blast,central}, vulnerability?, attack_target_count, impacted_cf_count}` |
| 6 | `propose_containment` | `action: ISOLATE_NODE\|REVOKE_ROLE`, `target_id: str` (`"svc|role"` for REVOKE_ROLE), `incident_id: str` | `{action_id, policy:{decision,reason}, risk, simulation:{targets_before[],targets_after[],paths_before,paths_after}}` |
| 7 | `execute_containment` | `action_id: str` | `{action_id, status:"EXECUTED", targets_after[], paths_after}` (authoritative post-state computed server-side) |
| 8 | `rollback_action` | `action_id: str` | `{action_id, status:"ROLLED_BACK", targets_after[]}` |
| 9 | `notify_owners` | `incident_id: str`, `team_ids: [str]`, `message: str` | `{notified:[{team_id, slack_channel}]}`; appends JSON lines to `OUTBOX_PATH` and writes an Action node of type `NOTIFY_OWNER` |
| 10 | `record_finding` | `incident_id: str`, `kind: str`, `summary: str`, `evidence_ids: [str]`, `risk_score: float?` | `{finding_id}` |
| 11 | `run_readonly_cypher` | `query: str` | rows (cap 200); rejects queries containing `CREATE|MERGE|SET|DELETE|REMOVE|DROP|CALL` (case-insensitive); uses `ro_query` with timeout 2000 ms |

`propose_containment` **simulation** = apply the write, run Q-ATTACK, revert the write, all inside one global `asyncio.Lock` in `try/finally`, and record only the Action node (status `PROPOSED`). Document this non-transactional approach in `DECISIONS.md`.

All inputs validated by Pydantic; unknown IDs return `NOT_FOUND`; out-of-range hops return `INVALID_INPUT`.

---

