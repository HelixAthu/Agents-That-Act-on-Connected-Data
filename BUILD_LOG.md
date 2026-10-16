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
  - Current: `test(seed): assert node/edge counts and acyclicity`
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

