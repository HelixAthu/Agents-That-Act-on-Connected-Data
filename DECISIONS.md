# DECISIONS.md

Log of architecture, engine, and design decisions. Format: `date | decision | reason`.

---

- 2026-10-15 | pinned FalkorDB image tag to falkordb/falkordb:v4.22.1 (digest sha256:b0bdcac2cbaff989e77cb0610439b7a9289e86de033ccbbd4368b66fb680ae7a) | Spec 00 requirement to pin exact image tag instead of latest for reproducible engine behavior.
- 2026-10-15 | attack paths engine = fallback (pathfinder_fallback.py BFS over graph-resident edge list from Q-EDGES) | Probe F5 revealed post-filter semantics on shortestPath WHERE clause in FalkorDB v4.22.1; per Spec 02 Section 7.3 decision tree, attack path queries require Python BFS honoring isolated edge property while all other queries remain in Cypher.
- 2026-10-15 | algorithms bonus = pagerank enabled via algo.pageRank, betweenness disabled | Probe F7 succeeded returning 3 rows on Service/DEPENDS_ON; probe F8 returned 0 rows.
