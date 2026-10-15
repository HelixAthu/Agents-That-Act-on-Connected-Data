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
