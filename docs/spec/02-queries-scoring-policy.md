# Spec 02: Cypher queries, scoring, policy

- **Purpose:** Defines every Cypher query, the risk formula, the policy table and the action state machine.
- **Read this when:** working on T1, T3, T4, T5, T6.

> **File map note:** section numbers (for example "Section 5.6", "G2", "Q-ATTACK") keep the numbering of the original single-file spec. `AGENTS.md` has the index that says which file holds which section.

---

## 7. Cypher Library (`mcp_server/queries.py`)

Every query is a module constant (or builder function) with an `id` used in evidence (`Q-CONTEXT`, `Q-IMPACT`, `Q-ATTACK`, `Q-RANK`, `Q-DEPENDENTS-COUNT`, `Q-ISOLATE`, ...). **Interpolate only validated integers** (hops). Everything else uses parameters.

### 7.1 Q-CONTEXT
```cypher
MATCH (n {id: $id})
OPTIONAL MATCH (t:Team)-[:OWNS]->(n)
OPTIONAL MATCH (v:Vulnerability)-[:AFFECTS]->(n)
RETURN labels(n)[0] AS label, properties(n) AS props,
       collect(DISTINCT t.id) AS owners, collect(DISTINCT properties(v)) AS vulns
```
Neighbors in a second query (avoid cartesian products):
```cypher
MATCH (n {id: $id})-[r]->(o) RETURN type(r) AS rel, o.id AS other, r.isolated AS isolated
```
and
```cypher
MATCH (i)-[r]->(n {id: $id}) RETURN type(r) AS rel, i.id AS other, r.isolated AS isolated
```

### 7.2 Q-IMPACT (reverse traversal; works for Service or Database targets)
```cypher
MATCH p = (imp:Service)-[:DEPENDS_ON|CONNECTS_TO*1..{HOPS}]->(f {id: $id})
RETURN imp.id AS id, imp.name AS name, imp.tier AS tier, imp.customer_facing AS cf,
       length(p) AS hops,
       [n IN nodes(p) | n.id] AS node_ids, [r IN relationships(p) | type(r)] AS edge_types
LIMIT 500
```
Python post-processing: group by `id` taking **min hops**; derive edge keys from consecutive `node_ids` + `edge_types` (path runs impacted to failing, so edge `i` is `node_ids[i] | edge_types[i] | node_ids[i+1]`); look up owners with a separate query: `MATCH (t:Team)-[:OWNS]->(s:Service) WHERE s.id IN $ids RETURN s.id, t.id, t.name`.
`critical_only=true`: add `WHERE ALL(r IN relationships(p) WHERE type(r) <> 'DEPENDS_ON' OR r.critical = true)` if probe F6 passes; otherwise filter in Python using edge props fetched from `Q-EDGES`.

### 7.3 Q-ATTACK (forward, directed, bounded, honors containment)
```cypher
MATCH (src:Service {id: $id}), (db:Database {contains_pii: true})
MATCH p = shortestPath((src)-[:DEPENDS_ON|CONNECTS_TO|ASSUMES_ROLE|CAN_ASSUME|CAN_ACCESS*..{HOPS}]->(db))
WHERE ALL(r IN relationships(p) WHERE r.isolated = false)
RETURN db.id AS target, length(p) AS hops,
       [n IN nodes(p) | n.id] AS node_ids, [r IN relationships(p) | type(r)] AS edge_types
ORDER BY hops
```
**Critical semantics caveat:** in some FalkorDB versions, a `WHERE` after `shortestPath` is a *post-filter* (it can discard the shortest path without searching for a longer valid one). Probe F5 (T1) tests this. Decision tree:
- F5 passes (filter acts as a constraint) → use as above.
- F5 fails but F4 passes → use `pathfinder_fallback.py` (Python BFS over the edge list from `Q-EDGES`, honoring `isolated`) for **attack paths only**, and record it prominently in `DECISIONS.md` and README ("graph-resident edge list, traversal in Python because of version limitation"). All other queries stay in Cypher.
- Note: with the seed in Section 5, G2/G3 hold even under post-filter semantics, but the fallback is needed for correctness in general.

### 7.4 Q-EDGES / Q-GRAPH (for `GET /graph` and fallback)
```cypher
MATCH (n) RETURN n.id AS id, labels(n)[0] AS label, properties(n) AS props
```
```cypher
MATCH (a)-[r]->(b) WHERE labels(a)[0] IN ['Service','Database','IAMRole','Vulnerability','Team']
RETURN a.id AS src, type(r) AS rel, b.id AS dst, properties(r) AS props
```
(Exclude audit labels `Incident|Finding|Action` from the UI graph.)

### 7.5 Q-RANK
```cypher
MATCH (s:Service)
OPTIONAL MATCH (d:Service)-[:DEPENDS_ON*1..10]->(s)
RETURN s.id AS id, s.name AS name, count(DISTINCT d) AS transitive_dependents
ORDER BY transitive_dependents DESC LIMIT $top_n
```
**Optional bonus** (only if probe F7/F8 pass): also call `algo.pageRank` / `algo.betweenness` (exact procedure signatures come from the probe output, not from memory) and include as extra fields `pagerank`, `betweenness`. The golden test asserts only `transitive_dependents`.

### 7.6 Containment writes (all reversible)
```cypher
// Q-ISOLATE-NODE
MATCH (n {id: $id}) SET n.status = 'ISOLATED'
WITH n MATCH (n)-[r]-() SET r.isolated = true
```
```cypher
// Q-REVOKE-ROLE
MATCH (s:Service {id: $svc})-[r:ASSUMES_ROLE]->(ro:IAMRole {id: $role}) SET r.isolated = true
```
```cypher
// Q-ROLLBACK-NODE
MATCH (n {id: $id}) SET n.status = 'HEALTHY'
WITH n MATCH (n)-[r]-() SET r.isolated = false
```
```cypher
// Q-ROLLBACK-ROLE  (same as revoke with false)
```
(Rollback of node isolation must not re-enable an edge that was separately revoked by another active action; for the hackathon, rollback in reverse chronological order is the documented constraint.)

### 7.7 Audit trail writes
```cypher
MERGE (i:Incident {id:$id}) SET i.title=$title, i.type=$type, i.status=$status, i.created_at=$ts
```
```cypher
MATCH (i:Incident {id:$inc}) CREATE (f:Finding {id:$fid, kind:$kind, summary:$summary, risk_score:$risk, created_at:$ts})
CREATE (i)-[:FOUND]->(f)
WITH f UNWIND $evidence_ids AS eid MATCH (e {id: eid}) CREATE (f)-[:EVIDENCED_BY]->(e)
```
```cypher
MATCH (i:Incident {id:$inc}) CREATE (a:Action {id:$aid, type:$type, target_id:$target, status:$status, mode:$mode, policy_decision:$decision, created_at:$ts, reversed:false})
CREATE (i)-[:TOOK]->(a)
```

---

## 8. Scoring and Policy (`scoring.py`, `policy.py`; pure functions, fully unit-tested)

### 8.1 Risk score (deterministic)
```
severity   = max over vulns affecting target of (cvss/10) * (1.0 if exploitable else 0.6); 0 if none
pii        = 0 if no attack path; 1.0 if min_hops <= 3; 0.7 if 4..6
blast      = (# customer-facing services impacted, reverse, hops<=3, target excluded) / 8
central    = transitive_dependents(target) / 19      (0 if target is not a Service)
risk       = round(0.40*severity + 0.40*pii + 0.10*blast + 0.10*central, 3)
```
Return all components alongside the score. The LLM never computes a score.

### 8.2 Policy decisions (`decide(action, ctx) -> {decision, reason}`)

| Action | Rule (first match wins) |
|---|---|
| `ISOLATE_NODE` | No verified attack path to a PII DB from target → **DENIED** ("no verified attack path; isolation would cause outage without evidence") |
| `ISOLATE_NODE` | Target is tier 1 AND customer_facing → **APPROVAL_REQUIRED** |
| `ISOLATE_NODE` | risk >= 0.8 → **AUTO** |
| `ISOLATE_NODE` | else → **APPROVAL_REQUIRED** |
| `REVOKE_ROLE` | Edge not on any verified attack path → **DENIED** |
| `REVOKE_ROLE` | risk >= 0.5 → **AUTO**, else **APPROVAL_REQUIRED** |

`NOTIFY_OWNER` is not a containment action; `notify_owners` is always allowed.

### 8.3 Action state machine
`PROPOSED` → (`AUTO` or approved) → `EXECUTED` → (`ROLLED_BACK`)
`PROPOSED` + `APPROVAL_REQUIRED` + not approved → `execute_containment` returns error `APPROVAL_REQUIRED`.
`DENIED` actions can never be executed (`POLICY_DENIED`).
Approval is stored on the Action node (`approved_by`, `approved_at`) via the backend endpoint, not by the LLM.

---

