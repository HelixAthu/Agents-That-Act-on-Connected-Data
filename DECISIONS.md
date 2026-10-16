# DECISIONS.md

Log of architecture, engine, and design decisions. Format: `date | decision | reason`.

---

- 2026-10-15 | pinned FalkorDB image tag to falkordb/falkordb:v4.22.1 (digest sha256:b0bdcac2cbaff989e77cb0610439b7a9289e86de033ccbbd4368b66fb680ae7a) | Spec 00 requirement to pin exact image tag instead of latest for reproducible engine behavior.
- 2026-10-15 | attack paths engine = fallback (pathfinder_fallback.py BFS over graph-resident edge list from Q-EDGES) | Probe F5 revealed post-filter semantics on shortestPath WHERE clause in FalkorDB v4.22.1; per Spec 02 Section 7.3 decision tree, attack path queries require Python BFS honoring isolated edge property while all other queries remain in Cypher.
- 2026-10-15 | algorithms bonus = pagerank enabled via algo.pageRank, betweenness disabled | Probe F7 succeeded returning 3 rows on Service/DEPENDS_ON; probe F8 returned 0 rows.
- 2026-10-16 | propose_containment simulation uses write-then-revert inside global asyncio.Lock | Spec 03 Section 9 mandates simulation via apply-write, run Q-ATTACK, revert-write in try/finally under global lock because FalkorDB does not support rollbacks of nested interactive transactions.
- 2026-10-16 | google-genai introspection confirmed field names match recipe (disable, thinking_level, parameters_json_schema, system_instruction, automatic_function_calling, thinking_config) | Verified against google-genai installed types for T8a.
