# BUILD_LOG.md

Log of task execution, command outputs, and commit hashes for verification.

---

## T0. Bootstrap

- **Commits:**
  - `59556fd`: `chore: initialize repo with README stub, license and .gitignore`
  - `250e37f`: `docs: add problem statement and initial graph schema`
  - `7339f6c`: `chore: add docker-compose for pinned FalkorDB`
  - `d998fb3`: `chore: scaffold python project, requirements and Makefile`
- **Acceptance Output:**
  ```bash
  $ make up
  docker compose up -d
  [+] Running 3/3
   ✔ Volume agents-that-act-on-connected-data_falkordb_data Created
   ✔ Network agents-that-act-on-connected-data_default      Created
   ✔ Container blast-radius-falkordb                        Started

  $ python -c "from falkordb import FalkorDB; print(FalkorDB().select_graph('t').query('RETURN 1').result_set)"
  [[1]]
  ```
- **Status:** DONE

---

## T1. Capability Probe

- **Commits:**
  - `4338816`: `chore: add falkordb capability probe`
  - Current: `docs: record probe results and pinned image tag`
- **Acceptance Output:**
  ```bash
  $ python scripts/probe_falkordb.py

  ================================================================================
  Probe ID   | Status | Capability Description                 | Details
  ================================================================================
  F1         | PASS   | ro_query works                         | Result: [[1]]
  F2         | PASS   | CREATE INDEX FOR (n:X) ON (n.id)       | Index created
  F3         | PASS   | var-length with relationship-type union | Found 2 path(s)
  F4         | PASS   | shortestPath directed with type union and bound | Shortest path length: 1
  F5         | FAIL   | shortestPath constraint semantics      | Post-filter semantics detected (returned: empty)
  F6         | PASS   | ALL() over relationships in WHERE      | Found 1 valid non-isolated path(s)
  F7         | PASS   | CALL algo.pageRank                     | Returned 3 row(s)
  F8         | PASS   | CALL algo.betweenness                  | Returned 0 row(s)
  F9         | PASS   | startNode / endNode                    | Supported
  F10        | PASS   | min(length(p)) with grouping           | Returned 3 group(s)
  ================================================================================
  ```
- **Engine Decisions Recorded in DECISIONS.md:**
  - Pinned FalkorDB tag: `v4.22.1`
  - Attack path engine: `fallback` (`pathfinder_fallback.py` BFS) due to F5 post-filter semantics
  - Algorithms bonus: `pageRank` enabled, `betweenness` disabled
- **Status:** DONE

---

## T2. Seed Ingestion & Validation

- **Commits:**
  - `17305d6`: `feat(seed): add entity data for services, databases, roles, teams`
  - `26ac028`: `feat(seed): add dependency, access and vulnerability edges`
  - `4c885af`: `feat(seed): idempotent seed script with --reset and acyclicity check`
  - `23323cf`: `test(seed): assert node/edge counts and acyclicity`
- **Acceptance Output:**
  ```bash
  $ python -m seed.seed_graph --reset
  Resetting graph 'infra'...

  ==================================================
  FalkorDB Seed Summary (Graph: infra)
  ==================================================
  Nodes:
    Service         :  20
    Database        :   5
    IAMRole         :   6
    Vulnerability   :   5
    Team            :   5
    Total Nodes     :  41

  Edges:
    DEPENDS_ON      :  50
    CONNECTS_TO     :   6
    ASSUMES_ROLE    :   6
    CAN_ASSUME      :   2
    CAN_ACCESS      :   5
    OWNS            :  20
    AFFECTS         :   5
    Total Edges     :  94
  Acyclicity: VERIFIED (DAG)
  ==================================================

  $ pytest -v tests
  ============================= test session starts ==============================
  collected 9 items

  tests/test_seed.py::test_node_counts PASSED                              [ 11%]
  tests/test_seed.py::test_edge_counts PASSED                              [ 22%]
  tests/test_seed.py::test_edges_isolated_property PASSED                  [ 33%]
  tests/test_seed.py::test_each_service_has_exactly_one_owner PASSED       [ 44%]
  tests/test_seed.py::test_customer_facing_services_count PASSED           [ 55%]
  tests/test_seed.py::test_pii_databases PASSED                            [ 66%]
  tests/test_seed.py::test_graph_acyclicity PASSED                         [ 77%]
  tests/test_seed.py::test_acyclicity_checker_unit PASSED                  [ 88%]
  tests/test_seed.py::test_seed_idempotency PASSED                         [100%]

  ============================== 9 passed in 0.33s ===============================
  ```
- **Status:** DONE

---

## T3. Query Layer

- **Commits:**
  - `12ef917`: `feat(queries): failure impact traversal`
  - `561cbe7`: `feat(queries): attacker paths to PII databases`
  - `ff186b2`: `feat(queries): criticality ranking and containment writes`
  - `612d176`: `test(queries): golden results G2 to G7`
- **Acceptance Output:**
  ```bash
  $ pytest -v tests/test_queries.py
  ============================= test session starts ==============================
  collected 8 items

  tests/test_queries.py::test_g2_attack_paths_from_payments_gateway_fallback PASSED [ 12%]
  tests/test_queries.py::test_g2_attack_paths_from_payments_gateway_cypher PASSED [ 25%]
  tests/test_queries.py::test_g3_containment_effects PASSED                [ 37%]
  tests/test_queries.py::test_g4_failure_impact_svc_config PASSED          [ 50%]
  tests/test_queries.py::test_g5_failure_impact_db_orders PASSED           [ 62%]
  tests/test_queries.py::test_g6_attack_paths_from_svc_config PASSED       [ 75%]
  tests/test_queries.py::test_g7_criticality_ranking PASSED                [ 87%]
  tests/test_queries.py::test_query_input_validations PASSED               [100%]

  ============================== 8 passed in 0.52s ===============================
  ```
- **Golden Values Asserted:** G2 (attack paths), G3 (containment & rollback), G4 (svc-config blast radius), G5 (db-orders failure impact), G6 (svc-config attack paths), G7 (criticality ranking).
- **Status:** DONE

---

## T5. MCP Read Tools

- **Commits:**
  - `dcd9c62`: `feat(mcp): server skeleton with component context tool`
  - `c072971`: `feat(mcp): impact, attack-path, ranking and read-only cypher tools`
  - Tag: `v0.1-graph`
- **Acceptance Output:**
  ```bash
  $ pytest -v tests/test_mcp_tools.py
  ============================= test session starts ==============================
  collected 11 items

  tests/test_mcp_tools.py::test_get_component_context_success PASSED       [  9%]
  tests/test_mcp_tools.py::test_get_component_context_not_found PASSED     [ 18%]
  tests/test_mcp_tools.py::test_get_component_context_invalid_input PASSED [ 27%]
  tests/test_mcp_tools.py::test_get_failure_impact_tool PASSED             [ 36%]
  tests/test_mcp_tools.py::test_get_failure_impact_invalid_hops PASSED     [ 45%]
  tests/test_mcp_tools.py::test_find_attack_paths_tool PASSED              [ 54%]
  tests/test_mcp_tools.py::test_find_attack_paths_invalid_hops PASSED      [ 63%]
  tests/test_mcp_tools.py::test_rank_critical_components_tool PASSED       [ 72%]
  tests/test_mcp_tools.py::test_rank_critical_components_invalid_top_n PASSED [ 81%]
  tests/test_mcp_tools.py::test_run_readonly_cypher_success PASSED         [ 90%]
  tests/test_mcp_tools.py::test_run_readonly_cypher_policy_denied PASSED   [100%]

  ============================== 11 passed in 0.88s ==============================
  ```
- **Status:** DONE

---

## T4. Scoring and Policy

- **Commits:**
  - `43338c2`: `feat: deterministic risk scoring with tests`
  - `e498c66`: `feat: containment policy gate with tests`
- **Acceptance Output:**
  ```bash
  $ pytest -v tests/test_scoring.py tests/test_policy.py
  ============================= test session starts ==============================
  collected 22 items

  tests/test_scoring.py::test_compute_severity_edge_cases PASSED           [  4%]
  tests/test_scoring.py::test_compute_pii_score_edge_cases PASSED          [  9%]
  tests/test_scoring.py::test_compute_blast_score_edge_cases PASSED        [ 13%]
  tests/test_scoring.py::test_compute_centrality_score_edge_cases PASSED   [ 18%]
  tests/test_scoring.py::test_calculate_risk_weights PASSED                [ 22%]
  tests/test_scoring.py::test_evaluate_risk_pure_output PASSED             [ 27%]
  tests/test_scoring.py::test_g8_payments_gateway_risk_score PASSED        [ 31%]
  tests/test_scoring.py::test_g8_config_service_risk_score PASSED          [ 36%]
  tests/test_scoring.py::test_compute_target_risk_error_handling PASSED    [ 40%]
  tests/test_policy.py::test_policy_truth_table_isolate_node_no_attack_path PASSED [ 45%]
  tests/test_policy.py::test_policy_truth_table_isolate_node_tier1_customer_facing PASSED [ 50%]
  tests/test_policy.py::test_policy_truth_table_isolate_node_high_risk_auto PASSED [ 54%]
  tests/test_policy.py::test_policy_truth_table_isolate_node_moderate_risk_approval PASSED [ 59%]
  tests/test_policy.py::test_policy_truth_table_revoke_role_not_on_attack_path PASSED [ 63%]
  tests/test_policy.py::test_policy_truth_table_revoke_role_high_risk_auto PASSED [ 68%]
  tests/test_policy.py::test_policy_truth_table_revoke_role_low_risk_approval PASSED [ 72%]
  tests/test_policy.py::test_is_edge_on_attack_paths_helper PASSED         [ 77%]
  tests/test_policy.py::test_g9_revoke_role_payments_gateway_auto PASSED   [ 81%]
  tests/test_policy.py::test_g9_isolate_payments_gateway_approval_required PASSED [ 86%]
  tests/test_policy.py::test_g9_isolate_config_service_denied PASSED       [ 90%]
  tests/test_policy.py::test_risk_and_policy_score_determinism_across_3_runs PASSED [ 95%]
  tests/test_policy.py::test_policy_error_handling PASSED                  [100%]

  ============================== 22 passed in 1.17s ==============================
  ```
- **Golden Values Asserted:**
  - G8: Risk scores (`svc-payments-gateway` ≈ 0.828, `svc-config` ≈ 0.514, within ±0.003).
  - G9: Policy outcomes (`REVOKE_ROLE` gateway/storage-manager -> `AUTO`, `ISOLATE_NODE` gateway -> `APPROVAL_REQUIRED`, `ISOLATE_NODE` config -> `DENIED`).
  - Determinism: 3 consecutive runs produce identical scores and decisions.
- **Status:** DONE

---

## T5. MCP Tool 5: Compute Risk

- **Commits:**
  - `feat(mcp): compute_risk tool`
- **Acceptance Output:**
  ```bash
  $ pytest -v tests/test_mcp_tools.py
  ============================= test session starts ==============================
  collected 15 items

  tests/test_mcp_tools.py::test_get_component_context_success PASSED       [  6%]
  tests/test_mcp_tools.py::test_get_component_context_not_found PASSED     [ 13%]
  tests/test_mcp_tools.py::test_get_component_context_invalid_input PASSED [ 20%]
  tests/test_mcp_tools.py::test_get_failure_impact_tool PASSED             [ 26%]
  tests/test_mcp_tools.py::test_get_failure_impact_invalid_hops PASSED     [ 33%]
  tests/test_mcp_tools.py::test_find_attack_paths_tool PASSED              [ 40%]
  tests/test_mcp_tools.py::test_find_attack_paths_invalid_hops PASSED      [ 46%]
  tests/test_mcp_tools.py::test_rank_critical_components_tool PASSED       [ 53%]
  tests/test_mcp_tools.py::test_rank_critical_components_invalid_top_n PASSED [ 60%]
  tests/test_mcp_tools.py::test_run_readonly_cypher_success PASSED         [ 66%]
  tests/test_mcp_tools.py::test_run_readonly_cypher_policy_denied PASSED   [ 73%]
  tests/test_mcp_tools.py::test_compute_risk_tool_payments_gateway_success PASSED [ 80%]
  tests/test_mcp_tools.py::test_compute_risk_tool_config_success PASSED   [ 86%]
  tests/test_mcp_tools.py::test_compute_risk_tool_not_found PASSED        [ 93%]
  tests/test_mcp_tools.py::test_compute_risk_tool_invalid_input PASSED    [100%]

  ============================== 15 passed in 0.95s ==============================
  ```
- **Status:** DONE

---

## T6. MCP Write Tools & Containment

- **Commits:**
  - `8165796`: `feat(mcp): propose and execute containment with action state machine`
  - `eaea214`: `feat(mcp): rollback, notify-owners and record-finding tools`
  - `test(mcp): write-tool and policy enforcement tests`
- **Acceptance Output:**
  ```bash
  $ pytest -v tests/test_mcp_write_tools.py
  ============================= test session starts ==============================
  collected 7 items

  tests/test_mcp_write_tools.py::test_g3_revoke_role_full_lifecycle_and_simulation PASSED [ 14%]
  tests/test_mcp_write_tools.py::test_policy_enforcement_isolate_tier1_approval_flow PASSED [ 28%]
  tests/test_mcp_write_tools.py::test_policy_enforcement_denied_containment_action PASSED [ 42%]
  tests/test_mcp_write_tools.py::test_action_state_machine_illegal_transitions PASSED [ 57%]
  tests/test_mcp_write_tools.py::test_notify_owners_outbox_format_and_action_audit PASSED [ 71%]
  tests/test_mcp_write_tools.py::test_record_finding_audit_and_graph_evidence_links PASSED [ 85%]
  tests/test_mcp_write_tools.py::test_concurrent_containment_lock_safety PASSED [100%]

  ============================== 7 passed in 1.48s ===============================
  ```
- **Golden Values Asserted:**
  - G3: Revoke role containment cuts attack path to `db-customer-profile` leaving only `db-user-billing`, and rollback completely restores attack path reachability.
  - Policy Truth Table: `REVOKE_ROLE` on attack path -> `AUTO`, `ISOLATE_NODE` on Tier 1 customer-facing -> `APPROVAL_REQUIRED`, `ISOLATE_NODE` on `svc-config` -> `DENIED`.
  - Action State Machine: `PROPOSED` -> `EXECUTED` -> `ROLLED_BACK`. Rejection of illegal transitions (cannot rollback unexecuted, cannot execute rolled-back, cannot re-execute).
  - Concurrency: `_CONTAINMENT_LOCK` guarantees race-free sequential evaluation under concurrent simulation requests.
- **Status:** DONE

---

## T7. Mock Agent, Event Bus, and CLI

- **Commits:**
  - `21ff5a7`: `feat(agent): event models and in-memory event bus`
  - `ac23e23`: `feat(agent): mcp bridge client`
  - `22e31db`: `feat(agent): scripted mock agent for scenarios A, B and C`
  - `feat: incident runner CLI and recorded replays`
- **Acceptance Output:**
  ```bash
  $ python scripts/run_incident.py --scenario A --mode mock --auto-approve
  ================================================================================
  FINAL INCIDENT REPORT SUMMARY
  ================================================================================
  Summary         : Critical exploit on svc-payments-gateway fully contained via role revocation and node isolation.
  Risk Score      : 0.828
  Impacted Svc    : 4 (1 customer-facing)
  Owner Teams     : team-payments
  Actions Taken   : 2
    - [EXECUTED] REVOKE_ROLE -> svc-payments-gateway|role-storage-manager (policy=AUTO)
    - [EXECUTED] ISOLATE_NODE -> svc-payments-gateway (policy=APPROVAL_REQUIRED)
  Verification    : ['db-customer-profile', 'db-user-billing'] -> []
  Tool Calls      : 12 calls recorded
  ================================================================================
  [REPLAY] Recorded 58 events saved to: replays/scenario_a.jsonl

  $ python scripts/run_incident.py --scenario B --mode mock --auto-approve
  ================================================================================
  FINAL INCIDENT REPORT SUMMARY
  ================================================================================
  Summary         : Database outage on db-orders causing cascading degradation across 8 upstream services.
  Risk Score      : 0.450
  Impacted Svc    : 8 (6 customer-facing)
  Owner Teams     : team-commerce, team-data, team-experience, team-payments
  Actions Taken   : 0
  Verification    : [] -> []
  Tool Calls      : 5 calls recorded
  ================================================================================
  [REPLAY] Recorded 22 events saved to: replays/scenario_b.jsonl

  $ python scripts/run_incident.py --scenario C --mode mock --auto-approve
  ================================================================================
  FINAL INCIDENT REPORT SUMMARY
  ================================================================================
  Summary         : False alarm on svc-config: isolation denied due to zero PII exposure and high blast radius.
  Risk Score      : 0.513
  Impacted Svc    : 17 (0 customer-facing)
  Owner Teams     : team-platform
  Actions Taken   : 1
    - [PROPOSED] ISOLATE_NODE -> svc-config (policy=DENIED)
  Verification    : [] -> []
  Tool Calls      : 6 calls recorded
  ================================================================================
  [REPLAY] Recorded 28 events saved to: replays/scenario_c.jsonl

  $ pytest -v tests/test_agent_mock.py
  ============================= test session starts ==============================
  collected 4 items

  tests/test_agent_mock.py::test_mock_agent_scenario_a_attack_and_containment PASSED [ 25%]
  tests/test_agent_mock.py::test_mock_agent_scenario_b_database_outage PASSED [ 50%]
  tests/test_agent_mock.py::test_mock_agent_scenario_c_false_alarm_isolation_denied PASSED [ 75%]
  tests/test_agent_mock.py::test_mock_agent_scenario_a_approval_handler_flow PASSED [100%]

  ============================== 4 passed in 2.05s ===============================
  ```
- **Golden Values Asserted:**
  - Scenario A: Containment eliminates all attack paths (`verification.targets_after == []`), recorded in `replays/scenario_a.jsonl`.
  - Scenario B: Correctly identifies cascading outage (8 impacted services, 4 owner teams) without taking containment actions, recorded in `replays/scenario_b.jsonl`.
  - Scenario C: Propose containment evaluates to `DENIED`; no graph mutations except audit records, recorded in `replays/scenario_c.jsonl`.
  - Graph Integrity: Every single node ID emitted in `graph_visit` events is verified to exist in the FalkorDB graph.
- **Status:** DONE

---

## T8. LLM Adapter (Gemini & Anthropic) and Live Agent Loop

- **Commits:**
  - `feat(agent): live anthropic tool-calling loop`
- **Acceptance Output:**
  ```bash
  $ python scripts/probe_gemini.py
  ======================================================================
  GEMINI SDK INTROSPECTION PROBE
  ======================================================================
  AutomaticFunctionCallingConfig fields: ['disable', 'ignore_call_history', 'maximum_remote_calls']
  ThinkingConfig fields                : ['include_thoughts', 'thinking_budget', 'thinking_level']
  FunctionDeclaration fields           : ['behavior', 'description', 'name', 'parameters', 'parameters_json_schema', 'response', 'response_json_schema']
  ALL INTROSPECTION RECIPE CHECKS: PASS

  SKIPPED live checks (no key)

  $ pytest -v tests/test_schema_simple.py tests/test_llm_gemini.py tests/test_agent_live.py
  ============================= test session starts ==============================
  collected 11 items

  tests/test_schema_simple.py::test_simplify_schema_handles_titles_defaults_and_defs PASSED [  9%]
  tests/test_schema_simple.py::test_assert_simple_schema_raises_on_illegal_keys PASSED [ 18%]
  tests/test_schema_simple.py::test_all_11_mcp_tools_simplify_and_pass_assert_simple_schema PASSED [ 27%]
  tests/test_llm_gemini.py::test_gemini_content_verbatim_identity_check PASSED [ 36%]
  tests/test_llm_gemini.py::test_gemini_multiple_function_calls_produce_single_content_same_order PASSED [ 45%]
  tests/test_llm_gemini.py::test_gemini_retries_on_429_and_aborts_immediately_on_400 PASSED [ 54%]
  tests/test_llm_gemini.py::test_thinking_level_minimal_rejected_by_config_validation PASSED [ 63%]
  tests/test_agent_live.py::test_agent_live_12_call_cap_aborts PASSED      [ 72%]
  tests/test_agent_live.py::test_agent_live_repeated_call_abort PASSED     [ 81%]
  tests/test_agent_live.py::test_agent_live_tool_error_fed_back_as_is_error PASSED [ 90%]
  tests/test_agent_live.py::test_agent_live_approval_pause_and_report_parse_retry PASSED [100%]

  ============================== 11 passed in 2.01s ==============================
  ```
- **Live Run Status:** live Gemini run not verified (GEMINI_API_KEY not configured in local environment; scripted turns verified 100%).
- **Status:** DONE

---

## T9. FastAPI + SSE + Approval

- **Commits:**
  - `5f61864`: `feat(api): fastapi routes, graph endpoint and SSE stream`
  - `b505174`: `feat(api): approval endpoint with pause and resume`
  - `test(api): approval flow end to end`
- **Acceptance Output:**
  ```bash
  $ pytest -v tests/test_api.py
  ============================= test session starts ==============================
  collected 10 items

  tests/test_api.py::test_health_endpoint PASSED                           [ 10%]
  tests/test_api.py::test_graph_endpoint_filtered_counts_and_edge_format PASSED [ 20%]
  tests/test_api.py::test_scenarios_listing PASSED                         [ 30%]
  tests/test_api.py::test_replays_endpoints PASSED                         [ 40%]
  tests/test_api.py::test_admin_reset_endpoint PASSED                      [ 50%]
  tests/test_api.py::test_incident_lifecycle_mock_scenario_c_and_events PASSED [ 60%]
  tests/test_api.py::test_incident_sse_stream PASSED                       [ 70%]
  tests/test_api.py::test_approve_nonexistent_action_returns_404 PASSED    [ 80%]
  tests/test_api.py::test_rollback_nonexistent_action_returns_404 PASSED   [ 90%]
  tests/test_api.py::test_approval_flow_pause_resume_and_rollback PASSED   [100%]

  ============================= 10 passed in 2.35s ==============================
  ```
- **Graph Node / Edge Counts:**
  - Total nodes in DB: 41
  - Nodes in UI graph (/graph): 31 (20 Service, 5 Database, 6 IAMRole; Team and Vulnerability excluded)
  - Edges in UI graph (/graph): 69 (50 DEPENDS_ON, 6 CONNECTS_TO, 6 ASSUMES_ROLE, 2 CAN_ASSUME, 5 CAN_ACCESS)
  - Edge ID format: `src|REL|dst` verified against `^[a-z0-9-]+\|[A-Z_]+\|[a-z0-9-]+$`
- **Tag:** `v0.2-agent`
- **Status:** DONE

---

## T10 to T12. Day 3 Frontend (UI, Canvas, Events & Replay)

- **Commits:**
  - `chore(web): scaffold vite, tailwind and shadcn`
  - `feat(web): load graph and lay out with dagre`
  - `feat(web): custom node components with status styling`
  - `feat(web): event reducer and SSE hook with tests`
  - `feat(web): live path highlighting from graph_visit events`
  - `feat(web): trace feed with expandable cypher`
  - `feat(web): risk panel and approval card`
  - `feat(web): final report, rollback and export`
  - `feat(web): replay mode`
- **Frontend Architecture & Features:**
  - Three-column dark mode layout: Scenarios/Trace feed (left), React Flow canvas (center), Risk/Approval/Report (right)
  - Semantic ranking layout: Tier 1 -> Tier 2 -> Tier 3 -> IAMRole -> Database (last rank) with Dagre layout
  - Custom memoized node components: ServiceNode (T1-T3, CF, PII, VULN), DatabaseNode (PII, technology), IAMRoleNode (ADMIN, max session)
  - Custom smoothstep edge component with dynamic attack-path (red animated), isolated (dashed grey) and normal states
  - Pure state reducer `reduceAgentEvent` handling real-time SSE stream events and replay feeds
  - Live path highlighting: inspect pulse rings, attack path red animated edges, action node isolation, verification pruning
  - Trace feed: autoscrolling audit log, contextual icons, latency metrics, and expandable Cypher query drawers
  - Risk assessment: composite risk gauge + breakdown bars for all 4 components (Severity, PII, Blast Radius, Centrality)
  - Human-in-the-loop: ApprovalCard with dry-run blast radius delta and `/actions/{id}/approve` execution
  - Final report: executive summary, findings with clickable evidence refs, rollback controls, and JSON report export
  - Replay mode: toggle loading `/replays/{scenario}` and stepping through reducer at 600ms per event
- **Acceptance Tests (Vitest):**
  - All 8 unit test suites (28 tests) passing 100%
  - Pure reducer assertion against canonical `scenario_a.jsonl`: final risk = 0.828, final isolated = {svc-payments-gateway}, seen approval_required = true
  - TypeScript strict compilation (`tsc`) and production Vite build verified
- **Tag:** `v0.3-ui`
- **Status:** DONE

---

## T13. Day 4 Evaluation Benchmark and Scenarios Harness

- **Commits:**
  - `feat(evals): scenario harness and results table`
- **Acceptance Output:**
  ```bash
  $ pytest -v tests/test_evals.py
  ============================= test session starts ==============================
  collected 2 items

  tests/test_evals.py::test_scenarios_spec_loading PASSED                  [ 50%]
  tests/test_evals.py::test_eval_harness_execution PASSED                  [100%]

  ============================== 2 passed in 1.28s ===============================
  ```
- **Evaluation Benchmark Summary:**
  - 4 canonical scenarios evaluated: A, B, C, and A2 (vague alert on `svc-web-portal`).
  - Pass Rate: 100% (4/4 passed).
  - Quantitative metrics asserted: Tool match, zero hallucinated IDs, 100% policy compliance, containment effectiveness, tool calls <= 12, low latency.
  - Baseline comparison documented in `evals/results.md`: G2 and G5 against flat JSON representations.
- **Status:** DONE

---

## T14. Day 4 Documentation and Operational Polish

- **Commits:**
  - `docs: query reference with golden results`
  - `docs: readme with graph model, setup and ai disclosure`
  - `chore: github actions ci for backend and frontend`
  - `chore: dockerfiles and full-stack compose`
  - `docs: explainer, owner questions and demo script`
  - `docs: add demo video link`
  - `fix(web): unignore frontend lib modules and add missing utilities`
  - `fix(web): use /stream endpoint for live SSE and register event listeners`
  - `fix(web): preserve pendingApproval when action is PROPOSED`
  - `fix(api): accept optional body in approve endpoint and send json payload from web`
  - `fix(graph): propagate containment isolation and clear attack paths on canvas`
  - `fix(app): restore graph and report on action rollback and jump to trace evidence`
  - `fix(live): load dotenv, format LLM errors gracefully, and surface execution error alerts in UI`
  - `fix(llm): support gemini-2.5-flash thinking budget, parse retry delays, and handle turn errors`
- **Reference Deliverables:**
  - `docs/queries.md`: Complete Cypher query catalog (Q-CONTEXT, Q-IMPACT, Q-ATTACK, Q-RANK, containment mutations, audit trail), traversal mechanics, and golden results reference (G1 to G9).
  - `README.md`: Full architectural overview, graph load-bearing analysis, data model tables, MCP tools catalog, safety policy truth table, exact setup commands, benchmark eval results, AI assistance disclosure, and limitations.
  - `.github/workflows/ci.yml`: GitHub Actions CI workflow executing FalkorDB service container, pytest test suite, eval harness, and frontend vitest/typecheck/build.
  - `backend/Dockerfile`, `frontend/Dockerfile`, `frontend/nginx.conf`, `docker-compose.yml`: Multi-stage Docker deployment with reverse proxying and SSE support.
  - `docs/demo_script.md`: Detailed 2:30 presentation and recording walkthrough with second-by-second narration and visual cues.
  - `docs/explainer.md`: Comprehensive technical explainer detailing FalkorDB GraphBLAS linear algebra, topological traversals, and deterministic safety gates.
  - `docs/owner_questions.md`: Thorough FAQ answering key architectural questions (Graph vs Relational/RAG, hallucination prevention, safety boundaries, real-world integrations).
- **Tag:** `v1.0`
- **Status:** DONE





