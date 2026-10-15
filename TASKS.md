# TASKS.md: ordered task list and Definition of Done

**How to use:** do the first unfinished task. Read `AGENTS.md` and only that task's `Read first:` files. Run its Acceptance commands. Log real output in `BUILD_LOG.md`. Commit and push (`docs/spec/07-git-commits.md`). Then continue.

**Order:** T0, T1, T2, T3, T4, T5, T6, T7, T8a, T8b, T9, T10, T11, T12, T13, T14, T15 (optional), T16. T8c is optional.

**Checkpoint after T2 (agent trial):** if you are a smaller or faster model and T0 to T2 needed repeated corrections, tell the owner. They may switch you to a stronger model for T3 to T6 (the hardest tasks: Cypher and MCP).

---

**T0. Bootstrap.** Repo skeleton (`AGENTS.md` Section 8), `requirements.txt` (`falkordb, mcp, pydantic>=2, pydantic-settings, fastapi, uvicorn[standard], sse-starlette, google-genai, pytest, pytest-asyncio, httpx, pyyaml, ruff`), `docker-compose.yml` with pinned FalkorDB tag and healthcheck, `Makefile`, `.env.example`, `.gitignore`.
*Read first:* `AGENTS.md`, `docs/spec/00-stack.md`, `docs/spec/07-git-commits.md` (Sections 19.1 and 19.2)
*Acceptance:* `make up && python -c "from falkordb import FalkorDB; print(FalkorDB().select_graph('t').query('RETURN 1').result_set)"` prints `[[1]]`. Record the pinned tag in `DECISIONS.md`.

**T1. Capability probe.** `scripts/probe_falkordb.py` builds a tiny scratch graph (`probe`) and tests, printing PASS/FAIL per item and writing `probe_results.json`:
*Read first:* `docs/spec/02-queries-scoring-policy.md` (Sections 7.2 and 7.3 only)
F1 `ro_query` works · F2 `CREATE INDEX FOR (n:X) ON (n.id)` · F3 var-length with relationship-type union · F4 `shortestPath` directed with type union and bound · **F5 constraint semantics**: graph A→B→D (blocked edge `isolated=true` on A→B? no: put blocked edge on the *short* route A→D direct with `isolated=true` and a longer A→B→C→D with false); query with `ALL(r IN relationships(p) WHERE r.isolated=false)`; PASS only if it returns the longer path · F6 `ALL()` over relationships in WHERE · F7 `CALL algo.pageRank` (try `('Service','DEPENDS_ON')` form; print raw error text on failure) · F8 `CALL algo.betweenness` (same) · F9 `startNode`/`endNode` (informational) · F10 `min(length(p))` with grouping.
*Acceptance:* `make probe` exits 0 and prints the table. **Then update Section-7 decisions** (record in `DECISIONS.md`: engine for attack paths = `cypher` or `fallback`; algorithms bonus on/off).

**T2. Seed.** Implement Section 5 (`seed/data/*.json` + `seed_graph.py`).
*Read first:* `docs/spec/01-data.md` (Sections 5 and 6)
*Acceptance:* `make seed` prints counts matching G1; `pytest tests/test_seed.py` (asserts counts, acyclicity, every edge has `isolated=false`, each Service has exactly one OWNS).

**T3. Query layer.** `db.py` (connection, `run_ro`, `run_rw`, timing), `queries.py` (Section 7), thin Python functions returning typed dicts (no MCP yet).
*Read first:* `docs/spec/01-data.md`, `docs/spec/02-queries-scoring-policy.md` (Section 7)
*Acceptance:* `pytest tests/test_queries.py` asserts G2, G3 (apply/revert directly), G4, G5, G6, G7.

**T4. Scoring and policy.** `scoring.py`, `policy.py`.
*Read first:* `docs/spec/02-queries-scoring-policy.md` (Section 8), `docs/spec/01-data.md` (G8, G9)
*Acceptance:* `pytest tests/test_scoring.py tests/test_policy.py`: G8 within tolerance; policy truth table covering every row of 8.2 plus G9 expectations (use computed contexts); score is deterministic across 3 runs.

**T5. MCP read tools.** `models.py`, `server.py` tools 1 to 5 and 11, with envelopes, evidence, and visit edge keys.
*Read first:* `docs/spec/03-mcp-tools.md`, `docs/spec/02-queries-scoring-policy.md`, `docs/spec/01-data.md` (Section 6)
*Acceptance:* `pytest tests/test_mcp_tools.py` spawns the server over stdio via the MCP client, lists tools (names and descriptions non-empty), calls each read tool, and asserts G2/G4/G5/G7 through the envelope; invalid `max_hops=99` returns `INVALID_INPUT`; `run_readonly_cypher("MATCH (n) DELETE n")` is rejected.

**T6. MCP write tools.** Tools 6 to 10, global lock, Action state machine.
*Read first:* `docs/spec/03-mcp-tools.md`, `docs/spec/02-queries-scoring-policy.md` (Sections 7.6, 7.7, 8)
*Acceptance:* tests for: propose REVOKE (AUTO, simulation after = [`db-user-billing`]); execute; graph reflects `isolated=true`; verify G3; rollback restores G2; propose ISOLATE gateway → `APPROVAL_REQUIRED` and `execute_containment` without approval → `APPROVAL_REQUIRED` error; ISOLATE config → `DENIED` and execute → `POLICY_DENIED`; `notify_owners` appends valid JSONL; `record_finding` creates `Finding` linked to `Incident`.

**T7. Mock agent + event bus + CLI.** `events.py` (Pydantic event models, in-memory bus with seq numbers and JSONL dump), `mcp_bridge.py`, `agent_mock.py`, `scenarios.py`, `scripts/run_incident.py --scenario A|B|C --mode mock --auto-approve`.
*Read first:* `docs/spec/04-agent-llm-api.md` (Sections 10.1, 10.3, 10.5, 11), `docs/spec/03-mcp-tools.md`
*Acceptance:* `python scripts/run_incident.py --scenario A --mode mock --auto-approve` ends with a `final_report` whose `verification.targets_after == []`, saves `replays/scenario_a.jsonl`; same for B (report lists 4 owner teams, 8 impacted) and C (action `DENIED`, no graph writes except audit nodes). `pytest tests/test_agent_mock.py` asserts these plus that every `graph_visit` node ID exists in the graph.

**T8a. LLM adapter + Gemini probe.** Create `backend/llm/{base,schema,gemini_client,fake_client}.py` exactly as in `docs/spec/04-agent-llm-api.md` Sections 10.2 to 10.2.2. Create `scripts/probe_gemini.py` that does, in order:
*Read first:* `docs/spec/04-agent-llm-api.md` (Section 10.2 and subsections)
1. **Introspection (no API key needed):** print the field names of `types.AutomaticFunctionCallingConfig`, `types.ThinkingConfig`, `types.GenerateContentConfig` and `types.FunctionDeclaration` from the installed `google-genai` (use `.model_fields.keys()`). Compare with the recipe (`disable`, `thinking_level`, `parameters_json_schema`, `system_instruction`, `automatic_function_calling`, `thinking_config`). If any name differs, **fix the recipe in the code** and log it in `DECISIONS.md`.
2. If `GEMINI_API_KEY` is unset: print `SKIPPED live checks (no key)` and exit 0.
3. **Round trip:** one fake tool `add(a:int,b:int)`; ask "What is 2+3? Use the tool."; assert a tool call was returned, send the result, assert a final text containing `5`.
4. **Sequential calls:** two fake tools where the second needs the first's output; assert the loop completes with **no 400 error** (this proves thought signatures are preserved).
5. **Real schemas:** convert all real MCP tools with `simplify_schema` and send one request containing all of them; assert no schema error.
*Acceptance:* `python scripts/probe_gemini.py` exits 0 (introspection printed; live checks pass or are SKIPPED). `pytest tests/test_schema_simple.py tests/test_llm_gemini.py` pass; `test_llm_gemini.py` uses a **stubbed** `genai.Client` and asserts: (a) the model's `Content` is appended to history **unchanged** (identity check), (b) multiple function calls produce **one** results `Content` in the same order, (c) retry happens on a simulated 429 and does not happen on a simulated 400, (d) `thinking_level="minimal"` is rejected by our own config validation before any API call.

**T8b. Live agent loop.** `backend/agent_live.py`, `backend/prompts.py` per `docs/spec/04-agent-llm-api.md` Sections 10.2.3, 10.2.4, 10.4, 10.5. Same event output as the mock agent.
*Read first:* `docs/spec/04-agent-llm-api.md` (Sections 10.2.3, 10.2.4, 10.4, 10.5, 11)
*Acceptance:* `pytest tests/test_agent_live.py` passes using `FakeSession` (scripted turns that call the real MCP tools): asserts the 12-call cap, the repeated-call abort, tool errors fed back as `is_error`, the approval pause, report parse retry, and that `verification` events come from `execute_containment` results. **Then, if `GEMINI_API_KEY` is set:** `LLM_PROVIDER=gemini AGENT_MODE=live python scripts/run_incident.py --scenario A --auto-approve` completes in at most 12 tool calls with a validated `FinalReport` and `verification.targets_after == []`. If no key is available, write "live Gemini run not verified" in `BUILD_LOG.md` (do not claim it passed).

**T8c (OPTIONAL, skip unless the owner asks). Anthropic provider.** `backend/llm/anthropic_client.py` implementing the same `LLMSession` interface.

**T9. FastAPI + SSE + approval.** Section 11.
*Read first:* `docs/spec/04-agent-llm-api.md` (Section 11)
*Acceptance:* `pytest tests/test_api.py` using `httpx.AsyncClient` + SSE stream: POST scenario A in mock mode with `AUTO_APPROVE=false`; assert stream emits `approval_required`; `POST /actions/{id}/approve`; assert stream then emits `verification` and `final_report`. `GET /graph` returns 41-node set minus Team/Vuln as specified (document the exact counts in the test), and each edge id matches `^[a-z-]+\|[A-Z_]+\|[a-z-]+$`.

**T10. Frontend scaffold.** Vite app, Tailwind, shadcn components, API client, `/graph` render with dagre layout, custom nodes.
*Read first:* `docs/spec/05-frontend.md`, `docs/spec/04-agent-llm-api.md` (Section 11 types)
*Acceptance:* `npm run build`, `npx tsc --noEmit`.

**T11. Streaming UI.** Event reducer (pure, tested), trace feed, risk panel, approval card, highlight logic, final report.
*Read first:* `docs/spec/05-frontend.md`, `docs/spec/04-agent-llm-api.md` (Section 11)
*Acceptance:* Vitest reducer test (Section 12 acceptance) passes.

**T12. Replay mode.** Frontend replay toggle using `/replays/*`; ensure the three replay files exist (from T7).
*Read first:* `docs/spec/05-frontend.md`
*Acceptance:* Vitest test feeds `scenario_b.jsonl`; asserts 8 impacted ids highlighted (`impact` kind).

**T13. Evals.** `evals/scenarios.yaml` and `run_evals.py` (Section 14).
*Read first:* `docs/spec/06-evals-docs-demo.md` (Section 14)
*Acceptance:* `make eval` writes `evals/results.md` with the table; mock mode passes 100%.

**T14. Documentation.** `README.md` (skeleton below), `docs/queries.md` (every query with a plain-English explanation and the golden result it produces), `docs/architecture.md` (Mermaid diagrams: architecture, graph schema, sequence for Scenario A), `AI_DISCLOSURE.md`, copy the disclosure into README.
*Read first:* `docs/spec/06-evals-docs-demo.md` (Section 15)
*Acceptance:* a fresh clone follows the README only: `cp .env.example .env && make up && make seed && make test && make dev` and `make web` work (record in `BUILD_LOG.md`).

**T15. Optional deployment.** Dockerfiles for backend and frontend, `docker-compose.yml` full stack (`docker compose up` brings up all three), deployment notes. If you cannot deploy, ensure the full-stack compose works locally and skip hosting.
*Read first:* `AGENTS.md`
*Acceptance:* `docker compose up --build` then `curl localhost:8000/health` returns ok.

**T16. Owner handoff.** `docs/EXPLAINER.md` (plain-language walkthrough: the graph model, why traversal direction matters, each query in `queries.py`, the policy gate, the event flow, where graph is load-bearing), `docs/OWNER_QUESTIONS.md` (20 questions a judge may ask with short model answers), `docs/demo_script.md` (timed script, Section 16), and a list of manual tasks the human must do (record video, submit, deployment, verify live mode with their API key).
*Read first:* `docs/spec/06-evals-docs-demo.md` (Section 16)
*Acceptance:* files exist; EXPLAINER references real function names that exist (grep check).


---

## Definition of Done


- [ ] `make up seed test` passes from a fresh clone; all golden values (G1 to G9) asserted by tests.
- [ ] Scenarios A, B, C run headless in mock mode with the expected outcomes; live Gemini mode verified with a real key (or explicitly logged as unverified).
- [ ] UI renders the graph, streams events, highlights paths, approval and rollback work, replay works.
- [ ] README contains setup, graph model, all queries, AI disclosure, and track name.
- [ ] `DECISIONS.md` records: pinned image tag, probe outcomes, attack-path engine (cypher/fallback), algorithms on/off, any deviation.
- [ ] `BUILD_LOG.md` has real command outputs for every task.
- [ ] No real/private data anywhere; `.env` not committed.
- [ ] Human-owner docs (T16) written.
- [ ] Only libraries from Section 1.1 are used; lockfiles committed; CI workflow green.
- [ ] Git history follows Section 19: 30+ conventional commits, pushed throughout, tags `v0.1-graph`, `v0.2-agent`, `v0.3-ui`, `v1.0`, no backdating, no force-push, first commit after Oct 15 12:01 AM IST.

---

- [ ] `scripts/probe_gemini.py` exits 0; `tests/test_llm_gemini.py` and `tests/test_schema_simple.py` pass; no file outside `backend/llm/` imports `google.genai` or `anthropic`.
