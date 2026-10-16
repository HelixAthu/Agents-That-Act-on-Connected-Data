# Technical Explainer: The Blast Radius Architecture

This document provides a comprehensive technical deep-dive into the architectural mechanics,
graph algorithms, safety policies, and design decisions underpinning the **Blast Radius Incident Response Agent**.

---

## 1. Executive Problem Statement

Enterprise cloud platforms are not isolated inventories; they are dense, heterogeneous dependency graphs.
Security and reliability teams are confronted with two structural dilemmas:

1. **The Lateral Movement Blindspot:** An attacker who compromises a perimeter service does not follow direct
   database connections. Instead, they exploit cross-account IAM delegations, role chaining, and service meshes
   to pivot laterally toward crown jewel assets.
2. **The Remediation Paradox:** Prematurely shutting down a suspected service often inflicts far greater financial
   and operational disruption than the vulnerability itself. Without instantaneous reverse dependency intelligence,
   incident responders risk collapsing downstream systems.

The **Blast Radius Incident Response Agent** resolves this paradox by grounding LLM reasoning directly in
**FalkorDB's** graph-native linear algebra engine, bounded by a strict **Model Context Protocol (MCP)** safety gate.

---

## 2. GraphBLAS & The FalkorDB Advantage

Traditional relational databases represent graphs using adjacency lists or recursive Common Table Expressions (CTEs).
Under deep multi-hop traversals, relational query optimizers suffer from **exponential join explosion**:

$$\mathcal{O}(V + E) \quad \text{vs} \quad \mathcal{O}(N^k \text{ joins})$$

FalkorDB stores the graph as a sparse adjacency matrix in memory and maps Cypher pattern matching directly to
**GraphBLAS linear algebra operations** (semiring matrix-vector and matrix-matrix multiplications):

$$\mathbf{A}_{\text{hop}} = \mathbf{A}_{\text{depends}} \cdot \mathbf{A}_{\text{assumes}} \cdot \mathbf{A}_{\text{access}}$$

- **Performance:** Multi-hop path calculations across 6 hops evaluate in `<3ms`, regardless of overall graph scale.
- **Dynamic Boundary Filtering:** FalkorDB evaluates edge properties (`WHERE r.isolated = false`) during traversal
  matrix operations, instantly pruning paths when containment actions sever an edge.

---

## 3. Forward vs. Reverse Traversal Mechanics

The agent utilizes two complementary graph traversal algorithms:

### 3.1 Forward Directed Attack Pathfinding (`Q-ATTACK`)
- **Objective:** Discover all reachable databases flagged with `contains_pii: true` from a compromised entrypoint.
- **Edge Traversal Sequence:**
  $$\text{Service} \xrightarrow{\text{DEPENDS\_ON}} \text{Service} \xrightarrow{\text{ASSUMES\_ROLE}} \text{IAMRole} \xrightarrow{\text{CAN\_ASSUME}} \text{IAMRole} \xrightarrow{\text{CAN\_ACCESS}} \text{Database}$$
- **Containment Invariant:** Only traverses edges where `r.isolated = false`. Once an edge or node is contained,
  subsequent traversals instantly reflect the pruned topology.

### 3.2 Reverse Dependency Blast Radius (`Q-IMPACT`)
- **Objective:** Determine who depends on a failing or compromised component.
- **Traversal Mechanics:** Traverses `DEPENDS_ON` and `CONNECTS_TO` relationships backward from the target node
  up to 3 hops, aggregating all impacted services and grouping them by tier and customer-facing status.
- **Ownership Resolution:** Maps impacted services to owning engineering teams via `Team -[:OWNS]-> Service`
  for automated notification dispatch.

---

## 4. Deterministic Risk Scoring Formula (G8)

Large Language Models should never guess or hallucinate numerical risk scores.
The agent delegates risk calculation to a pure, deterministic mathematical function in `mcp_server/scoring.py`:

$$\text{Risk} = \text{round}(0.40 \times \text{Severity} + 0.40 \times \text{PII} + 0.10 \times \text{Blast} + 0.10 \times \text{Centrality}, 3)$$

Where:
- $\text{Severity} = \max_{v \in \text{vulns}} \left( \frac{\text{CVSS}}{10} \times [1.0 \text{ if exploitable else } 0.6] \right)$
- $\text{PII} = \begin{cases} 0.0 & \text{if no reachable attack path to PII} \\ 1.0 & \text{if shortest path hops } \le 3 \\ 0.7 & \text{if shortest path hops } \in [4, 6] \end{cases}$
- $\text{Blast} = \frac{\text{Count of customer-facing services impacted (hops} \le 3\text{)}}{8}$
- $\text{Centrality} = \frac{\text{Transitive upstream dependents count}}{19}$

---

## 5. Model Context Protocol (MCP) as a Safety Boundary

The LLM is treated as an untrusted reasoning engine. It has **no direct database write credentials** and cannot
execute arbitrary shell or network commands. It interacts exclusively through 11 strictly typed MCP tools.

### 5.1 The Containment Policy Gate (`mcp_server/policy.py`)
Every containment proposal (`propose_containment`) is evaluated by a hardcoded deterministic truth table:

```
                      [ Containment Action Proposed ]
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
          [ ISOLATE_NODE ]                        [ REVOKE_ROLE ]
                 │                                       │
         Has PII Path?                           On Attack Path?
         ├─ NO  ──> [ DENIED ]                   ├─ NO  ──> [ DENIED ]
         └─ YES ──> Is Tier-1 CF?                └─ YES ──> Risk >= 0.5?
                    ├─ YES ──> [ APPROVAL_REQ ]             ├─ YES ──> [ AUTO ]
                    └─ NO  ──> Risk >= 0.8?                 └─ NO  ──> [ APPROVAL_REQ ]
                               ├─ YES ──> [ AUTO ]
                               └─ NO  ──> [ APPROVAL_REQ ]
```

### 5.2 Action State Machine
```
[ PROPOSED ] ──(Policy: AUTO or Human Approval)──> [ EXECUTED ] ──(1-Click Rollback)──> [ ROLLED_BACK ]
      │
      └──(Policy: DENIED)──> [ BLOCKED / CANNOT EXECUTE ]
```

---

## 6. Frontend Streaming Architecture & Canvas Rendering

- **React Flow & Dagre:** Nodes are automatically laid out hierarchically based on architectural tiers:
  Tier 1 Services → Tier 2 Services → Tier 3 Services → IAM Roles → Databases.
- **Server-Sent Events (SSE):** The backend streams granular agent thoughts, tool calls, graph visits,
  risk updates, and verification events over a persistent HTTP/1.1 SSE stream (`/incidents/{id}/stream`).
- **Live Path Highlighting:** When an attack path or failure ripple is traversed, the frontend dynamically
  updates edge renderers with animated SVG glow effects (`stroke: #ef4444`).
- **Interactive Replay Mode:** Allows security auditors to step through past incident logs frame-by-frame
  at 600ms intervals to inspect historical reasoning.
