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
  - `feat(agent): mcp bridge client`
- **Acceptance Output:**
  ```bash
  $ pytest -v tests/test_events.py tests/test_mcp_bridge.py
  ============================= test session starts ==============================
  collected 8 items

  tests/test_events.py::test_event_payload_models_serialization PASSED     [ 12%]
  tests/test_events.py::test_event_bus_sequential_numbering_and_subscribers PASSED [ 25%]
  tests/test_events.py::test_event_bus_dump_and_load_jsonl PASSED          [ 37%]
  tests/test_events.py::test_final_report_model_and_anti_hallucination_guard PASSED [ 50%]
  tests/test_mcp_bridge.py::test_bridge_list_tools_returns_all_11_spec_tools PASSED [ 62%]
  tests/test_mcp_bridge.py::test_bridge_get_tool_lookup PASSED             [ 75%]
  tests/test_mcp_bridge.py::test_bridge_call_with_argument_normalization PASSED [ 87%]
  tests/test_mcp_bridge.py::test_bridge_build_tool_summary_formatting PASSED [100%]

  ============================== 8 passed in 0.58s ===============================
  ```
- **Status:** IN PROGRESS (Commits 23, 24 completed; mock agent scenarios and CLI next)







