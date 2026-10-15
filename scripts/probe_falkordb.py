#!/usr/bin/env python3
"""FalkorDB capability probe testing engine constraints and query features."""

import json
import os
import sys
from falkordb import FalkorDB


def run_probe():
    host = os.getenv("FALKORDB_HOST", "localhost")
    port = int(os.getenv("FALKORDB_PORT", "6379"))

    try:
        client = FalkorDB(host=host, port=port)
    except Exception as e:
        print(f"Error connecting to FalkorDB at {host}:{port}: {e}")
        sys.exit(1)

    graph_name = "probe"
    graph = client.select_graph(graph_name)

    # Clean existing scratch graph if any
    try:
        graph.delete()
    except Exception:
        pass

    results = {}

    # Seed probe scratch graph
    try:
        # F2 test node & index
        graph.query("CREATE (:X {id: 'x1'})")

        # F5 constraint test nodes and edges:
        # Direct short route A -> D has isolated=true (1 hop)
        # Longer route A -> B -> C -> D has isolated=false (3 hops)
        graph.query("""
            CREATE (a:Node {id: 'A'}),
                   (b:Node {id: 'B'}),
                   (c:Node {id: 'C'}),
                   (d:Node {id: 'D'})
            CREATE (a)-[:T1 {isolated: true}]->(d)
            CREATE (a)-[:T1 {isolated: false}]->(b)
            CREATE (b)-[:T2 {isolated: false}]->(c)
            CREATE (c)-[:T1 {isolated: false}]->(d)
        """)

        # F7/F8 graph data for algorithms test
        graph.query("""
            CREATE (s1:Service {id: 's1'}),
                   (s2:Service {id: 's2'}),
                   (s3:Service {id: 's3'})
            CREATE (s1)-[:DEPENDS_ON {isolated: false}]->(s2)
            CREATE (s2)-[:DEPENDS_ON {isolated: false}]->(s3)
        """)
    except Exception as e:
        print(f"Error setting up scratch graph: {e}")
        sys.exit(1)

    # F1: ro_query works
    try:
        res = graph.ro_query("RETURN 1 AS n")
        passed = (len(res.result_set) == 1 and res.result_set[0][0] == 1)
        results["F1"] = {
            "name": "ro_query works",
            "passed": passed,
            "details": f"Result: {res.result_set}"
        }
    except Exception as e:
        results["F1"] = {"name": "ro_query works", "passed": False, "details": str(e)}

    # F2: CREATE INDEX FOR (n:X) ON (n.id)
    try:
        graph.query("CREATE INDEX FOR (n:X) ON (n.id)")
        results["F2"] = {
            "name": "CREATE INDEX FOR (n:X) ON (n.id)",
            "passed": True,
            "details": "Index created"
        }
    except Exception as e:
        results["F2"] = {
            "name": "CREATE INDEX FOR (n:X) ON (n.id)",
            "passed": False,
            "details": str(e)
        }

    # F3: Var-length with relationship-type union
    try:
        res = graph.ro_query("""
            MATCH p = (a:Node {id: 'A'})-[:T1|T2*1..5]->(d:Node {id: 'D'})
            RETURN count(p)
        """)
        count = res.result_set[0][0]
        results["F3"] = {
            "name": "var-length with relationship-type union",
            "passed": count >= 1,
            "details": f"Found {count} path(s)"
        }
    except Exception as e:
        results["F3"] = {
            "name": "var-length with relationship-type union",
            "passed": False,
            "details": str(e)
        }

    # F4: shortestPath directed with type union and bound
    try:
        res = graph.ro_query("""
            MATCH (a:Node {id: 'A'}), (d:Node {id: 'D'})
            WITH shortestPath((a)-[:T1|T2*..5]->(d)) AS p
            RETURN length(p)
        """)
        passed = len(res.result_set) > 0
        results["F4"] = {
            "name": "shortestPath directed with type union and bound",
            "passed": passed,
            "details": f"Shortest path length: {res.result_set[0][0] if passed else 'None'}"
        }
    except Exception as e:
        results["F4"] = {
            "name": "shortestPath directed with type union and bound",
            "passed": False,
            "details": str(e)
        }

    # F5: Constraint semantics (shortestPath with WHERE ALL(r.isolated=false))
    try:
        res = graph.ro_query("""
            MATCH (a:Node {id: 'A'}), (d:Node {id: 'D'})
            WITH shortestPath((a)-[:T1|T2*..5]->(d)) AS p
            WHERE ALL(r IN relationships(p) WHERE r.isolated = false)
            RETURN length(p) AS len
        """)
        # If WHERE acts as a path-search constraint, it ignores the 1-hop path (isolated=true)
        # and finds the 3-hop path (isolated=false).
        if len(res.result_set) > 0 and res.result_set[0][0] == 3:
            results["F5"] = {
                "name": "shortestPath constraint semantics",
                "passed": True,
                "details": f"Constraint passed: returned length {res.result_set[0][0]}"
            }
        else:
            returned = res.result_set[0][0] if len(res.result_set) > 0 else "empty"
            results["F5"] = {
                "name": "shortestPath constraint semantics",
                "passed": False,
                "details": f"Post-filter semantics detected (returned: {returned})"
            }
    except Exception as e:
        results["F5"] = {
            "name": "shortestPath constraint semantics",
            "passed": False,
            "details": str(e)
        }

    # F6: ALL() over relationships in WHERE
    try:
        res = graph.ro_query("""
            MATCH p = (a:Node {id: 'A'})-[:T1|T2*1..5]->(d:Node {id: 'D'})
            WHERE ALL(r IN relationships(p) WHERE r.isolated = false)
            RETURN count(p)
        """)
        count = res.result_set[0][0]
        results["F6"] = {
            "name": "ALL() over relationships in WHERE",
            "passed": count >= 1,
            "details": f"Found {count} valid non-isolated path(s)"
        }
    except Exception as e:
        results["F6"] = {
            "name": "ALL() over relationships in WHERE",
            "passed": count >= 1,
            "details": str(e)
        }

    # F7: CALL algo.pageRank
    try:
        res = graph.query("CALL algo.pageRank('Service', 'DEPENDS_ON')")
        results["F7"] = {
            "name": "CALL algo.pageRank",
            "passed": True,
            "details": f"Returned {len(res.result_set)} row(s)"
        }
    except Exception as e:
        results["F7"] = {
            "name": "CALL algo.pageRank",
            "passed": False,
            "details": str(e)
        }

    # F8: CALL algo.betweenness
    try:
        res = graph.query("CALL algo.betweenness('Service', 'DEPENDS_ON')")
        results["F8"] = {
            "name": "CALL algo.betweenness",
            "passed": True,
            "details": f"Returned {len(res.result_set)} row(s)"
        }
    except Exception as e:
        results["F8"] = {
            "name": "CALL algo.betweenness",
            "passed": False,
            "details": str(e)
        }

    # F9: startNode / endNode (informational)
    try:
        res = graph.ro_query("MATCH ()-[r:T1]->() RETURN startNode(r), endNode(r) LIMIT 1")
        results["F9"] = {
            "name": "startNode / endNode",
            "passed": len(res.result_set) > 0,
            "details": "Supported" if len(res.result_set) > 0 else "Empty"
        }
    except Exception as e:
        results["F9"] = {
            "name": "startNode / endNode",
            "passed": False,
            "details": str(e)
        }

    # F10: min(length(p)) with grouping
    try:
        res = graph.ro_query("""
            MATCH p = (a:Node {id: 'A'})-[:T1|T2*1..5]->(d:Node)
            RETURN d.id AS id, min(length(p)) AS min_len
        """)
        results["F10"] = {
            "name": "min(length(p)) with grouping",
            "passed": len(res.result_set) > 0,
            "details": f"Returned {len(res.result_set)} group(s)"
        }
    except Exception as e:
        results["F10"] = {
            "name": "min(length(p)) with grouping",
            "passed": False,
            "details": str(e)
        }

    # Clean up scratch graph
    try:
        graph.delete()
    except Exception:
        pass

    # Save results to probe_results.json
    output_path = "probe_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    # Print summary table
    print("\n" + "=" * 80)
    print(f"{'Probe ID':<10} | {'Status':<6} | {'Capability Description':<38} | {'Details'}")
    print("=" * 80)
    for probe_id, data in results.items():
        status = "PASS" if data["passed"] else "FAIL"
        print(f"{probe_id:<10} | {status:<6} | {data['name']:<38} | {data['details']}")
    print("=" * 80 + "\n")

    return results


if __name__ == "__main__":
    run_probe()
