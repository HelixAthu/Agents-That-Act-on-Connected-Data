# Spec 06: Evals, README requirements, demo script

- **Purpose:** Defines evaluation metrics, README content and the demo script.
- **Read this when:** working on T13, T14, T16.

> **File map note:** section numbers (for example "Section 5.6", "G2", "Q-ATTACK") keep the numbering of the original single-file spec. `AGENTS.md` has the index that says which file holds which section.

---

## 14. Evals (`evals/`)

`scenarios.yaml` entries: `id, alert_text, expected_tools_called (set, order-insensitive), forbidden_tools, expected: {...}`. Scenarios: A, B, C plus **A2** (`HIGH: suspicious activity on svc-web-portal`, a vague alert to test tool selection; expected: calls `compute_risk`/`find_attack_paths` and does **not** isolate without a verified path).
Metrics per run (default 5 runs in live mode, 1 in mock mode): tool-selection set match · no hallucinated IDs (all IDs in report exist in tool results) · policy compliance (never executes `DENIED`; never executes `APPROVAL_REQUIRED` without approval) · containment effectiveness (`targets_after==[]` for A) · tool calls ≤12 · total latency. Output a Markdown table to `evals/results.md`.

**Graph-vs-no-graph baseline** (`evals/baseline_no_graph.py`, optional but valuable; needs an API key): feed an LLM a flat JSON dump of services+dependency lists (no tools) and ask: "From svc-payments-gateway, which PII databases can an attacker reach and through what path?" and "Who is impacted if db-orders fails?" Compare against G2 and G5. Record results honestly in `evals/results.md` (including if the baseline gets it right).

---

## 15. README Requirements (T14)

Sections in order: pitch + screenshot/GIF placeholder · **Why the graph is load-bearing** (table: capability / FalkorDB feature / why a flat store fails) · architecture diagram · **graph data model** (node/edge tables from Section 4/5) · **queries and algorithms the product depends on** (all `Q-*` queries inlined or linked to `docs/queries.md`) · MCP tools table (with when-to-use) · safety model (policy table, reversibility, read-only escape hatch, non-transactional simulation caveat) · setup (exact commands) · demo scenarios · eval results · **AI assistance disclosure** · limitations (synthetic data, simulated actions only, mock mode, whichever fallbacks were used) · track entered: *Agents That Act on Connected Data*.

---

## 16. Demo Script (for `docs/demo_script.md`, ~2:30)

0:00 topology and the question "who can reach PII?" → 0:20 trigger Scenario A → 0:35 trace shows risk 0.828, red path through the IAM chain to `db-customer-profile` ("no direct DB edge: only the graph shows this") → 1:05 impact ripple → 1:20 agent auto-revokes the role link (path count 2→1, verification event) → 1:40 proposes full isolation, approval card, click Approve, verification 1→0, red path vanishes → 2:00 Scenario C: same severity class but isolation DENIED, with the 17-dependent explanation → 2:15 Scenario B ripple and owners notified → 2:25 close: graph is the engine, MCP is the safety boundary, evidence trail is the explanation.

---

