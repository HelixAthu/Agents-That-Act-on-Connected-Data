# AGENTS.md: Blast-Radius Agent (read this at the start of EVERY session)

## 1. What you are building
A graph-native incident-response agent. FalkorDB stores a synthetic infrastructure graph. An MCP server exposes graph tools. An LLM agent (Gemini by default) calls those tools to find blast radius and attack paths, takes policy-gated containment actions, and produces an evidence-linked report. A React UI shows the graph, animates the investigation live, and has approval/rollback buttons.
Hackathon: Graph Hacks (Oct 15 to 18, 2026 IST). Track: *Agents That Act on Connected Data*. FalkorDB must be central: the product must not work without it.

## 2. How to work (the loop)
1. Open `TASKS.md`. Find the **next unfinished task** (T0, T1, T2, ...).
2. Read this file, then **only** the files named in that task's `Read first:` line.
3. Do **only that task**. Do not start the next one.
4. Run every command in the task's **Acceptance** block. All must pass.
5. Paste the real command output into `BUILD_LOG.md` under the task heading.
6. Commit and push following `docs/spec/07-git-commits.md` (summary in Section 6 below).
7. Mark the task done in `BUILD_LOG.md`. Stop, or continue with the next task.

## 3. Hard rules (DO / DO NOT)
DO:
- Copy numbers and IDs from `docs/spec/01-data.md`. If you need a number, open the file. Do not recall it from memory.
- Put **all Cypher** in `mcp_server/queries.py` (exceptions: `scripts/probe_falkordb.py`, `seed/seed_graph.py`).
- Use type hints and a one-line docstring on every public function. Keep files small.
- Write a test for every function that has logic.
- Log every deviation or decision in `DECISIONS.md` as one line: `date | decision | reason`.
- Use synthetic data only.
- Disclose AI assistance in the README (task T14).
- Keep `.env` out of git. Never print secrets.

DO NOT:
- Add a library that is not in `docs/spec/00-stack.md`.
- Add features outside Section 5 (Scope) below.
- Change a golden value to make a test pass. If a test disagrees with `01-data.md`, first re-check your seed transcription. If the spec arithmetic is really wrong, log it in `DECISIONS.md` and tell the owner.
- Print "tests passed" without running them. Never invent command output.
- Backdate commits, rewrite pushed history, or force-push.
- Skip a failing acceptance check and move on.
- Import `google.genai` or `anthropic` anywhere except `backend/llm/`.

## 4. Stack (summary; full list in `docs/spec/00-stack.md`)
| Layer | Choice |
|---|---|
| Database | FalkorDB (Docker, pinned tag), client `falkordb`, graph name `infra` |
| MCP | `mcp` Python SDK, `FastMCP`, stdio transport |
| Backend | Python 3.11+, FastAPI, uvicorn, sse-starlette, Pydantic v2 |
| LLM | **Gemini `gemini-3.8-flash`** via `google-genai`, behind the `LLMSession` interface (`docs/spec/04-agent-llm-api.md`) |
| Keyless mode | `AGENT_MODE=mock` scripted agent (default for tests and CI) |
| Frontend | Vite + React 18 + TypeScript, Tailwind, shadcn/ui, `@xyflow/react`, `@dagrejs/dagre` |
| Tests | pytest (+ asyncio, httpx), vitest |

## 5. Scope
IN: nodes Service, Database, IAMRole, Vulnerability, Team, Incident, Finding, Action. Three scenarios: A (attack), B (outage), C (false alarm). Replay mode. Evals. README and docs.
OUT: Queue/Repo nodes, real Slack, real cloud calls, login, multi-user, extra databases.

## 6. Git rules (summary; full plan in `docs/spec/07-git-commits.md`)
- Conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `refactor:` + optional scope.
- One logical change per commit. Tests pass before every commit. Read `git diff --staged` before committing.
- Push to `origin main` after every task.
- Tags: `v0.1-graph`, `v0.2-agent`, `v0.3-ui`, `v1.0`.
- If you cannot push, commit locally and tell the owner the exact commands to run.

## 7. Conventions
- ID prefixes: `svc-`, `db-`, `role-`, `vuln-`, `team-`, `inc-`, `finding-`, `act-`.
- Edge key format: `<src_id>|<REL_TYPE>|<dst_id>` (example `svc-payments-gateway|ASSUMES_ROLE|role-storage-manager`). Every edge has boolean property `isolated` (default `false`).
- `A -[:DEPENDS_ON]-> B` means **A depends on B**.
  - **Failure impact** (who breaks if X fails): walk edges **backward**.
  - **Attacker reach** (what can X touch if compromised): walk edges **forward**.
- Timestamps: ISO-8601 UTC.

## 8. Repository layout (create exactly)
```
README.md DECISIONS.md BUILD_LOG.md AI_DISCLOSURE.md Makefile docker-compose.yml .env.example requirements.txt pyproject.toml
AGENTS.md GEMINI.md TASKS.md docs/spec/*.md
scripts/{probe_falkordb.py, probe_gemini.py, run_incident.py}
seed/{seed_graph.py, data/*.json}
mcp_server/{__init__,server,db,queries,models,scoring,policy,pathfinder_fallback}.py
backend/{__init__,main,agent_live,agent_mock,mcp_bridge,events,prompts,scenarios}.py
backend/llm/{__init__,base,schema,gemini_client,anthropic_client,fake_client}.py
tests/{test_seed,test_queries,test_scoring,test_policy,test_schema_simple,test_mcp_tools,test_llm_gemini,test_agent_mock,test_agent_live,test_api}.py
evals/{scenarios.yaml, run_evals.py, results.md}
frontend/          (Vite app)
docs/{queries.md, architecture.md, EXPLAINER.md, OWNER_QUESTIONS.md, demo_script.md}
outbox/.gitkeep    replays/{scenario_a,scenario_b,scenario_c}.jsonl
```
`Makefile` targets that must work: `make up`, `make seed`, `make probe`, `make test`, `make dev` (backend :8000), `make web` (frontend :5173), `make eval`, `make reset`.

## 9. Environment variables (`.env.example`)
`FALKORDB_HOST=localhost` `FALKORDB_PORT=6379` `GRAPH_NAME=infra` `AGENT_MODE=mock` `LLM_PROVIDER=gemini` `GEMINI_API_KEY=` `GEMINI_MODEL=gemini-3.8-flash` `GEMINI_THINKING_LEVEL=medium` `AUTO_APPROVE=false` `APPROVAL_TIMEOUT_S=120` `OUTBOX_PATH=./outbox/notifications.jsonl`

## 10. Index: where each part of the spec lives
| Original section | Topic | File |
|---|---|---|
| 1, 1.1 | Fixed decisions, library manifest | `docs/spec/00-stack.md` |
| 4, 5, 6 | Conventions, seed data, golden values G1 to G9 | `docs/spec/01-data.md` |
| 7, 8 | Cypher queries, scoring, policy, action states | `docs/spec/02-queries-scoring-policy.md` |
| 9 | MCP tool contracts | `docs/spec/03-mcp-tools.md` |
| 10, 11 | Agent, LLM adapter (Gemini), mock agent, report, API, SSE events | `docs/spec/04-agent-llm-api.md` |
| 12 | Frontend | `docs/spec/05-frontend.md` |
| 14, 15, 16 | Evals, README content, demo script | `docs/spec/06-evals-docs-demo.md` |
| 19 | Git workflow and commit plan | `docs/spec/07-git-commits.md` |
| 13, 17 | Task list, Definition of Done | `TASKS.md` |

## 11. If you are stuck
1. Re-read the task's `Read first:` files.
2. Run the failing command again and read the full error.
3. Check `DECISIONS.md` for a related decision (for example the probe results).
4. If a FalkorDB feature behaves differently than the spec says, use the fallback described in `docs/spec/02-queries-scoring-policy.md` Section 7.3 and log it.
5. If it is blocked by something outside the repo (no API key, no Docker, no git remote), write the blocker in `BUILD_LOG.md`, finish everything that does not depend on it, and tell the owner.
