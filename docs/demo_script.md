# Video & Live Presentation Demo Script (~2:30)

This script outlines the exact timing, visual cues, speaker narration, and screen actions for presenting
the **Blast Radius Incident Response Agent** to judges, security leads, and hackathon evaluators.

---

## Timeline Breakdown

```
[0:00 - 0:20] Hook & Problem ──> [0:20 - 1:40] Scenario A (Deep Dive) ──> [1:40 - 2:00] Verification
                                                                               │
[2:25 - 2:30] Conclusion <────── [2:15 - 2:25] Scenario B <────── [2:00 - 2:15] Scenario C
```

---

### [0:00 - 0:20] Introduction & Topology: "Who Can Reach PII?"

- **Screen Action:**
  - Browser opens to `http://localhost:5173`.
  - The React Flow dark-mode canvas renders the 31 visible services, databases, and IAM roles arranged in Dagre hierarchical tiers (Tier 1 on top, Tier 2, Tier 3, IAM roles, and Databases on the bottom).
  - Hover over `db-customer-profile` and `svc-payments-gateway`.
- **Narrator:**
  > *"In modern microservice architectures, security alerts rarely show the full picture. Looking at this topology: if an attacker compromises our payment gateway, can they reach sensitive customer PII? A traditional flat inventory says 'No direct database edge exists.' But infrastructure is connected data."*

---

### [0:20 - 0:35] Trigger Scenario A: The Hidden Lateral IAM Path

- **Screen Action:**
  - Click the **"Scenario A: Payment Gateway Attack Path"** card in the left control panel.
  - The live trace feed begins streaming events via Server-Sent Events (SSE).
  - `svc-payments-gateway` pulses in yellow (`INSPECT`).
  - Right panel displays the computed **Risk Gauge: 0.828** (Critical).
  - On the canvas, **two red animated attack paths** illuminate simultaneously.
- **Narrator:**
  > *"We trigger Scenario A—a critical CVSS 9.8 vulnerability on `svc-payments-gateway`. The agent inspects component context and computes a deterministic risk score of 0.828. Notice the red paths: one goes through billing, but the second path jumps from the service into `role-storage-manager`, assumes `role-data-admin`, and reaches `db-customer-profile`. No service-to-database connection exists—only a graph traversal over heterogeneous edges reveals this lateral attack vector."*

---

### [0:35 - 1:05] Impact Ripple & Surgical Least-Disruptive Containment

- **Screen Action:**
  - Trace feed displays `get_failure_impact(svc-payments-gateway, max_hops=3)`.
  - Upstream dependent nodes pulse with blue boundary rings.
  - Trace feed displays `propose_containment(REVOKE_ROLE)` evaluated against the policy engine.
- **Narrator:**
  > *"Before acting, the agent evaluates the blast radius. Isolating the entire gateway immediately would break checkout. Instead, the agent selects the least disruptive mitigation: surgical IAM role revocation. Because the role edge lies on an active attack path and risk exceeds 0.5, our policy gate flags this as `AUTO`."*

---

### [1:05 - 1:20] Auto-Execution & Verification Event (2 → 1 Paths)

- **Screen Action:**
  - Trace feed emits `execute_containment`.
  - The canvas updates: the `ASSUMES_ROLE` edge turns dashed grey (`ISOLATED`).
  - A `VERIFICATION` event fires: the hidden IAM lateral path vanishes.
  - The active path count drops from **2 to 1**.
- **Narrator:**
  > *"The agent executes the role revocation in FalkorDB. Watch the canvas in real time: the IAM delegation edge is severed, and an automated verification query confirms that reachable PII targets have dropped from 2 down to 1. The hidden path is eliminated."*

---

### [1:20 - 1:40] Human-in-the-Loop Policy Gate & Node Isolation

- **Screen Action:**
  - The agent evaluates remaining risk for `svc-payments-gateway`.
  - An **Approval Card** slides into the right-hand panel with amber warning styling:
    - Target: `svc-payments-gateway` (Tier 1 Customer-Facing).
    - Policy Reason: *"Target is tier 1 and customer-facing; requires human sign-off before disruption."*
    - Dry-Run Delta: 1 affected customer-facing service.
  - Narrator clicks the blue **"Approve Containment"** button.
- **Narrator:**
  > *"One path remains via billing. The agent proposes full node isolation. But because `svc-payments-gateway` is a Tier 1 customer-facing service, our hard safety policy gate halts execution and demands human approval. The UI displays the exact blast radius delta. We click Approve."*

---

### [1:40 - 2:00] Complete Containment & Final Audit Report

- **Screen Action:**
  - Gateway node turns red with an `ISOLATED` badge; connected edges turn grey.
  - Verification fires: **targets_after = 0**. The remaining red path vanishes.
  - Notification sent to `team-payments` via Outbox.
  - Final Incident Report renders with summary, findings, and 1-click **Rollback** button.
- **Narrator:**
  > *"With approval received, FalkorDB severs all ingress and egress edges. Verification confirms zero reachable targets remain. The agent notifies team payments and generates an immutable audit trail with evidence-linked findings. If needed, the entire containment is fully reversible with one click."*

---

### [2:00 - 2:15] Scenario C: The False Alarm (Safety Gate Rejection)

- **Screen Action:**
  - Click **"Scenario C: Config Service CVE False Alarm"**.
  - Canvas resets. High-severity CVE-2026-4418 appears on `svc-config`.
  - Trace feed evaluates `find_attack_paths` (0 paths) and `get_failure_impact` (17 dependents).
  - Trace feed displays `propose_containment(ISOLATE_NODE)` -> **`DENIED`**.
- **Narrator:**
  > *"Now observe safety in action with Scenario C: a CVSS 8.1 CVE on `svc-config`. A naive agent might panic and isolate it. But FalkorDB reveals zero paths to PII, and reverse traversal shows 17 dependent services. Our policy gate strictly DENIES isolation. No outage occurs. The agent recommends standard in-place patching."*

---

### [2:15 - 2:25] Scenario B: Outage Ripple & Team Alerting

- **Screen Action:**
  - Click **"Scenario B: Orders DB Outage"**.
  - `db-orders` pulses red. Reverse failure ripple cascades across 8 services.
  - Trace feed shows 4 owning teams identified and notified in the Outbox log.
- **Narrator:**
  > *"Finally, Scenario B handles operational cascades: when `db-orders` fails, the agent traverses reverse dependencies, maps all 8 impacted services and 4 owning teams, dispatches targeted PagerDuty notifications, and refrains from unwarranted containment."*

---

### [2:25 - 2:30] Conclusion

- **Screen Action:**
  - Zoom out to view full canvas with clean, resilient graph state.
- **Narrator:**
  > *"The Blast Radius Agent demonstrates why graphs are load-bearing for AI systems: **FalkorDB is the engine**, **MCP is the safety boundary**, and **connected data is the explanation**."*
