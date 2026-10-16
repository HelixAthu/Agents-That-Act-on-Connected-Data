# Cypher Query Reference and Golden Results

This document serves as the canonical reference for all FalkorDB Cypher queries, graph traversal algorithms,
and golden benchmark validation results powering the **Blast Radius Incident Response Agent**.

---

## 1. Design Principles & Query Standards

1. **Parameterized Queries:** All user and agent inputs (`$id`, `$source_id`, `$incident_id`, etc.) are passed
   strictly as query parameters to guarantee safety against Cypher injection.
2. **Validated Bounds:** Dynamic integer bounds (e.g. traversal hops `$max_hops` constrained to `1..6`) are
   strictly validated in application logic before Cypher template interpolation.
3. **Traversal Directions:**
   - **Forward Traversals (`Q-ATTACK`):** Follow directed paths from an attacker's entrypoint through dependencies,
     IAM role assumptions (`ASSUMES_ROLE`, `CAN_ASSUME`), and access grants (`CAN_ACCESS`) down to sensitive data stores.
   - **Reverse Traversals (`Q-IMPACT`):** Follow upstream dependencies (`DEPENDS_ON`, `CONNECTS_TO`) backward from a failing
     component to determine who breaks when that component fails.
4. **Boundary Filtering:** All active traversals enforce `WHERE ALL(r IN relationships(p) WHERE r.isolated = false)`
   to respect containment firewalls and revoked access credentials in real time.
5. **Read/Write Segregation:** Read queries execute via read-only transactions, while containment mutations run under
   an explicit asynchronous mutex lock (`_CONTAINMENT_LOCK`) to guarantee consistency.

---

## 2. Core Cypher Query Catalog

### 2.1 `Q-CONTEXT`: Component Deep Inspection
Fetches immediate properties, owning engineering teams, vulnerabilities, and direct incoming/outgoing edges.
Cartesian products are strictly avoided by splitting attribute collection and edge discovery.

```cypher
// Part 1: Node labels, properties, owners, and vulnerabilities
MATCH (n {id: $id})
OPTIONAL MATCH (t:Team)-[:OWNS]->(n)
OPTIONAL MATCH (v:Vulnerability)-[:AFFECTS]->(n)
RETURN labels(n)[0] AS label,
       properties(n) AS props,
       collect(DISTINCT t.id) AS owners,
       collect(DISTINCT properties(v)) AS vulns;

// Part 2: Outgoing neighbors
MATCH (n {id: $id})-[r]->(o)
RETURN type(r) AS rel, o.id AS other, r.isolated AS isolated;

// Part 3: Incoming neighbors
MATCH (i)-[r]->(n {id: $id})
RETURN type(r) AS rel, i.id AS other, r.isolated AS isolated;
```

---

### 2.2 `Q-ATTACK`: Lateral Attack Paths to PII Crown Jewels
Traces the shortest uncontained paths from a compromised service to databases containing sensitive PII
(`contains_pii: true`) across arbitrary hybrid topology (services, IAM role delegations, database connections).

```cypher
MATCH (src:Service {id: $source_id}), (db:Database {contains_pii: true})
MATCH p = shortestPath((src)-[:DEPENDS_ON|CONNECTS_TO|ASSUMES_ROLE|CAN_ASSUME|CAN_ACCESS*..{HOPS}]->(db))
WHERE ALL(r IN relationships(p) WHERE r.isolated = false)
RETURN db.id AS target,
       length(p) AS hops,
       [n IN nodes(p) | n.id] AS node_ids,
       [r IN relationships(p) | type(r)] AS edge_types
ORDER BY hops ASC;
```

> **Implementation Note on Traversal Semantics:**
> In topologies where `shortestPath()` filters post-discovery, the system provides a transparent fallback
> (`mcp_server.pathfinder_fallback.bfs_attack_paths`) running breadth-first search directly on the graph's
> edge list to guarantee shortest unisolated path discovery.

---

### 2.3 `Q-IMPACT`: Reverse Failure Blast Radius
Traverses incoming `DEPENDS_ON` and `CONNECTS_TO` edges to identify all upstream services transitively
affected by a service or database failure.

```cypher
MATCH p = (imp:Service)-[:DEPENDS_ON|CONNECTS_TO*1..{HOPS}]->(f {id: $id})
RETURN imp.id AS id,
       imp.name AS name,
       imp.tier AS tier,
       imp.customer_facing AS cf,
       length(p) AS hops,
       [n IN nodes(p) | n.id] AS node_ids,
       [r IN relationships(p) | type(r)] AS edge_types
LIMIT 500;
```

**Post-Processing:**
- Services are aggregated by `id` taking the minimum hop distance.
- Owner teams are fetched via batch lookup:
  ```cypher
  MATCH (t:Team)-[:OWNS]->(s:Service)
  WHERE s.id IN $service_ids
  RETURN s.id AS service_id, t.id AS team_id, t.name AS team_name;
  ```

---

### 2.4 `Q-RANK`: Criticality Ranking (Transitive Dependents)
Ranks services by infrastructure criticality based on total transitive upstream dependents.

```cypher
MATCH (s:Service)
OPTIONAL MATCH (d:Service)-[:DEPENDS_ON*1..10]->(s)
RETURN s.id AS id,
       s.name AS name,
       count(DISTINCT d) AS transitive_dependents
ORDER BY transitive_dependents DESC
LIMIT $top_n;
```

---

### 2.5 Containment Mutation Queries (Reversible)

#### Node Isolation (`Q-ISOLATE-NODE`)
Marks the target component as isolated and severs all connected edges:
```cypher
MATCH (n {id: $id})
SET n.status = 'ISOLATED'
WITH n
MATCH (n)-[r]-()
SET r.isolated = true;
```

#### IAM Role Revocation (`Q-REVOKE-ROLE`)
Surgically revokes a specific IAM role assumption without disrupting the underlying service:
```cypher
MATCH (s:Service {id: $service_id})-[r:ASSUMES_ROLE]->(ro:IAMRole {id: $role_id})
SET r.isolated = true;
```

#### Rollback Node Isolation (`Q-ROLLBACK-NODE`)
Restores healthy operational state and reactivates incident-isolated edges:
```cypher
MATCH (n {id: $id})
SET n.status = 'HEALTHY'
WITH n
MATCH (n)-[r]-()
SET r.isolated = false;
```

#### Rollback Role Revocation (`Q-ROLLBACK-ROLE`)
Restores role assumption authorization:
```cypher
MATCH (s:Service {id: $service_id})-[r:ASSUMES_ROLE]->(ro:IAMRole {id: $role_id})
SET r.isolated = false;
```

---

### 2.6 Incident Audit Trail Queries

#### Incident Creation / Update
```cypher
MERGE (i:Incident {id: $id})
SET i.title = $title,
    i.type = $type,
    i.status = $status,
    i.created_at = $ts;
```

#### Analytical Finding Recording
```cypher
MATCH (i:Incident {id: $incident_id})
CREATE (f:Finding {
    id: $finding_id,
    kind: $kind,
    summary: $summary,
    risk_score: $risk,
    created_at: $ts
})
CREATE (i)-[:FOUND]->(f)
WITH f
UNWIND $evidence_ids AS eid
MATCH (e {id: eid})
CREATE (f)-[:EVIDENCED_BY]->(e);
```

#### Action Audit Trail Recording
```cypher
MATCH (i:Incident {id: $incident_id})
CREATE (a:Action {
    id: $action_id,
    type: $action_type,
    target_id: $target,
    status: $status,
    policy_decision: $decision,
    created_at: $ts,
    reversed: false
})
CREATE (i)-[:TOOK]->(a);
```

---

## 3. Golden Results Reference (G1 to G9)

The following benchmark outputs are verified by automated test suites in `tests/test_queries.py`,
`tests/test_scoring.py`, and `tests/test_policy.py`.

### G1: Seed Entity and Edge Counts
- **Total Entities (41 nodes):**
  - 20 `Service`
  - 5 `Database`
  - 6 `IAMRole`
  - 5 `Vulnerability`
  - 5 `Team`
- **Total Relationships:**
  - 49 `DEPENDS_ON`
  - 6 `CONNECTS_TO`
  - 6 `ASSUMES_ROLE`
  - 2 `CAN_ASSUME`
  - 5 `CAN_ACCESS`
  - 5 `AFFECTS`
  - 20 `OWNS`

---

### G2: Attack Paths from `svc-payments-gateway`
- **Source:** `svc-payments-gateway` (`CVSS 9.8` RCE vulnerability)
- **Target Databases with PII:** Exactly **2** targets found:
  1. `db-user-billing` (Hops: **2**)
     - Path: `svc-payments-gateway` → `svc-billing` → `db-user-billing`
     - Edge types: `[DEPENDS_ON, CONNECTS_TO]`
  2. `db-customer-profile` (Hops: **3** — *The Hidden IAM Lateral Path*)
     - Path: `svc-payments-gateway` → `role-storage-manager` → `role-data-admin` → `db-customer-profile`
     - Edge types: `[ASSUMES_ROLE, CAN_ASSUME, CAN_ACCESS]`

---

### G3: Containment Effects on Attack Paths
- **Initial Clean State:** 2 reachable PII targets (`db-user-billing`, `db-customer-profile`).
- **After Revoking Role (`svc-payments-gateway|role-storage-manager`):**
  - Reachable targets: `[db-user-billing]` (1 target remaining).
  - Lateral IAM attack path severed.
- **After Full Node Isolation (`svc-payments-gateway`):**
  - Reachable targets: `[]` (0 targets remaining).
  - All ingress and egress edges severed (`r.isolated = true`).
- **After Rollback:**
  - Graph returns exactly to the clean state (2 reachable targets).

---

### G4: Failure Blast Radius of `svc-config`
- **Query:** Reverse failure impact on `svc-config` (`max_hops=3`).
- **Transitive Impacted Services:** **17** services (all services in graph except `svc-config`, `svc-session-cache`, and `svc-audit-log`).
- **Customer-Facing Impacted Services:** **8** customer-facing services.
- **Significance:** Explains why `ISOLATE_NODE svc-config` is strictly **DENIED** by policy gate.

---

### G5: Failure Blast Radius of `db-orders` Outage
- **Query:** Reverse failure impact on `db-orders` (`max_hops=3`).
- **Total Impacted Services:** **8** services:
  - Hop 1: `svc-order`
  - Hop 2: `svc-mobile-api`, `svc-partner-api`, `svc-checkout-ui`, `svc-payments-gateway`, `svc-reporting`
  - Hop 3: `svc-web-portal`, `svc-admin-portal`
- **Customer-Facing Services Impacted:** **6** services.
- **Distinct Owning Teams:** **4** teams (`team-commerce`, `team-experience`, `team-payments`, `team-data`).

---

### G6: Attack Paths from `svc-config`
- **Query:** Lateral attack paths from `svc-config` to PII databases (`max_hops=6`).
- **Result:** **0 rows** (no outgoing connections to databases or IAM roles).
- **Security Implication:** Confirming vulnerability CVE-2026-4418 on `svc-config` has zero lateral exposure to crown jewel data.

---

### G7: Structural Criticality Ranking
- **Query:** `rank_critical_components(top_n=5)`
- **Top Rankings:**
  1. `svc-config` — **17** transitive dependents
  2. `svc-catalog` — **11** transitive dependents

---

### G8: Deterministic Risk Scores
Calculated using formula:
$$\text{Risk} = \text{round}(0.40 \times \text{Severity} + 0.40 \times \text{PII} + 0.10 \times \text{Blast} + 0.10 \times \text{Centrality}, 3)$$

- `svc-payments-gateway`:
  - $\text{Severity} = 0.98$ ($9.8/10 \times 1.0$)
  - $\text{PII} = 1.0$ (min hops = 2 $\le$ 3)
  - $\text{Blast} = 1/8 = 0.125$
  - $\text{Centrality} = 5/19 = 0.263$
  - **Composite Risk Score:** **0.828** ($\pm 0.003$)
- `svc-config`:
  - $\text{Severity} = 0.81$ ($8.1/10 \times 1.0$)
  - $\text{PII} = 0.0$ (no attack path)
  - $\text{Blast} = 8/8 = 1.0$
  - $\text{Centrality} = 17/19 = 0.895$
  - **Composite Risk Score:** **0.514** ($\pm 0.003$)

---

### G9: Containment Policy Decisions
- **`REVOKE_ROLE svc-payments-gateway|role-storage-manager`:**
  - Decision: **`AUTO`**
  - Rationale: Role edge lies on verified attack path to PII and composite risk $\ge 0.5$.
- **`ISOLATE_NODE svc-payments-gateway`:**
  - Decision: **`APPROVAL_REQUIRED`**
  - Rationale: Target is a Tier 1 customer-facing service requiring human sign-off before disruption.
- **`ISOLATE_NODE svc-config`:**
  - Decision: **`DENIED`**
  - Rationale: Zero verified attack paths to PII databases; isolating 17 dependents would trigger catastrophic platform outage without evidence.
