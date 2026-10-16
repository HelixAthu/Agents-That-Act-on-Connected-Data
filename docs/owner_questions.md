# Owner & Judge Evaluation FAQ: Critical Architectural Questions

This document answers the foundational technical and design questions regarding the architecture,
safety boundaries, performance limits, and operational viability of the **Blast Radius Incident Response Agent**.

---

### Q1: Why couldn't you just use PostgreSQL with recursive Common Table Expressions (CTEs)?

**Answer:**
While recursive CTEs can traverse single-table hierarchies (e.g. employee-manager trees), infrastructure topology
is **heterogeneous**: it spans services, databases, IAM roles, delegation edges, and access policies.

1. **Join Explosion:** A 5-hop path spanning `Service -> IAMRole -> IAMRole -> Database` requires joining across
   4 separate relational tables. In PostgreSQL, computing all paths under dynamic boundary filtering
   (`r.isolated = false`) degrades exponentially ($\mathcal{O}(N^k)$). Under load, this triggers statement timeouts.
2. **Sub-5ms In-Memory Matrix Traversal:** FalkorDB maps this graph to sparse adjacency matrices. A multi-hop
   traversal is executed as a series of GraphBLAS matrix multiplications in `<3ms`, regardless of depth.
3. **Cypher Expressiveness:** Expressing multi-hop heterogeneous path matching in Cypher requires one line:
   ```cypher
   MATCH p = shortestPath((src)-[:DEPENDS_ON|ASSUMES_ROLE|CAN_ASSUME|CAN_ACCESS*..6]->(db))
   ```
   Doing this in SQL requires over 80 lines of nested recursive CTEs with custom union logic.

---

### Q2: Why not just use Vector Search or RAG on infrastructure documentation?

**Answer:**
Vector embeddings capture semantic similarity, not **topological reachability**:
- A vector similarity search can tell you that `svc-payments-gateway` and `db-customer-profile` are both "payment-related".
- However, vector search **cannot determine whether a valid, unisolated path exists** between them through an obscure
  cross-account IAM delegation chain (`role-storage-manager` → `role-data-admin`).
- An incident response agent relying on RAG will hallucinate connectivity based on textual mentions, leading to
  unwarranted service shutdowns or missed breaches. FalkorDB provides exact mathematical reachability proofs.

---

### Q3: How do you prevent LLM hallucinations during containment actions?

**Answer:**
We implement a multi-layered verification barrier:
1. **No Hallucinated Node IDs:** The `validate_final_report_hallucinations` validator checks every node ID mentioned
   in findings and actions against `visited_nodes` (the strict set of nodes returned by verified tool calls).
   Any unvisited ID is stripped or flagged.
2. **Deterministic Risk Scoring:** The LLM is never allowed to calculate or guess risk scores. It must invoke the
   `compute_risk` tool, which executes a deterministic mathematical formula (G8).
3. **Hard Policy Gates:** An LLM cannot execute containment directly. It calls `propose_containment`, which passes
   through an immutable Python truth table (`mcp_server/policy.py`). Even if an LLM is prompted to "isolate immediately",
   the policy gate blocks execution with `APPROVAL_REQUIRED` or `DENIED`.

---

### Q4: What happens if an attacker or rogue prompt attempts to isolate a mission-critical service?

**Answer:**
Our policy truth table enforces hard operational boundaries:
1. **Tier 1 Customer-Facing Exemption:** Any service marked `tier: 1` and `customer_facing: true` can **never** be
   isolated automatically. It strictly returns `APPROVAL_REQUIRED`, halting execution until a human clicks "Approve".
2. **False Alarm Protection (Scenario C):** If a service has vulnerabilities but **zero reachable paths to PII**,
   node isolation is strictly **`DENIED`**. The agent cannot isolate the node under any circumstances.

---

### Q5: How do you handle write concurrency and simulation safety in FalkorDB?

**Answer:**
Graph databases lack multi-table rollback snapshots found in traditional RDBMSs. We resolve this via:
1. **Asynchronous Containment Lock:** All containment mutations (`ISOLATE_NODE`, `REVOKE_ROLE`, `ROLLBACK`) acquire
   a global asynchronous mutex lock (`_CONTAINMENT_LOCK`) in `mcp_server/server.py`, ensuring sequential consistency.
2. **Symmetrical Reversibility:** Every mutating Cypher query (`Q-ISOLATE-NODE`, `Q-REVOKE-ROLE`) has an exact,
   symmetrical inverse (`Q-ROLLBACK-NODE`, `Q-ROLLBACK-ROLE`).
3. **Reverse Chronological Rollback:** Rollbacks are applied in LIFO (last-in, first-out) sequence to prevent
   re-enabling an edge that was deliberately isolated by another concurrent rule.

---

### Q6: How does this architecture scale to an enterprise graph with 100,000+ nodes?

**Answer:**
1. **Graph Partitioning:** In production, infrastructure graphs are naturally segmented by VPCs, cloud accounts,
   or Kubernetes clusters.
2. **Bounded Hops:** All pathfinding and blast radius queries enforce strict hop limits (`max_hops: 1..6`). Because
   microservice architectures rarely feature valid dependency chains beyond 6 hops, graph exploration is tightly bounded.
3. **Read-Only Replicas:** Read-heavy investigative queries (`Q-CONTEXT`, `Q-IMPACT`, `Q-ATTACK`) run against
   read-only graph replicas, while containment writes commit to the primary instance.

---

### Q7: How would this integrate with real-world infrastructure (AWS, Kubernetes, PagerDuty)?

**Answer:**
The MCP server architecture was chosen specifically for real-world pluggability:
- **Topology Ingestion:** A background worker syncs AWS CloudTrail/IAM, Kubernetes CRDs, and Datadog service dependencies
  into FalkorDB every 60 seconds.
- **Real Containment Execution:** The `execute_containment` MCP tool can be swapped to invoke:
  - AWS IAM API: `aws iam detach-role-policy` or `aws iam put-role-permissions-boundary`
  - Kubernetes API: `kubectl apply -f networkpolicy-deny-all.yaml`
  - Cloudflare/WAF: Block incoming IP CIDRs or route traffic to honeypots.
- **Incident Escalation:** `notify_owners` dispatches webhooks directly to PagerDuty services and Slack incident channels.

---

### Q8: What happens if an API key is missing or the external LLM is down?

**Answer:**
The system is built with **zero-cost resilience**:
1. **Scripted Mock Mode:** If no `ANTHROPIC_API_KEY` or `GEMINI_API_KEY` is present, the agent automatically falls back
   to the deterministic `MockAgent` (`backend/agent_mock.py`). This allows complete CI/CD testing, evaluation benchmarks,
   and demo presentations without external API dependencies or costs.
2. **Multi-Model Support:** The LLM abstraction layer (`backend/llm/base.py`) supports hot-swapping between Anthropic Claude
   and Google Gemini seamlessly via environment variables (`LLM_PROVIDER=gemini|anthropic`).
