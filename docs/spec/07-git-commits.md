# Spec 07: Git workflow and commit plan

- **Purpose:** Defines commit rules, the commit-by-commit plan, push cadence.
- **Read this when:** starting work (skim), and before every commit.

> **File map note:** section numbers (for example "Section 5.6", "G2", "Q-ATTACK") keep the numbering of the original single-file spec. `AGENTS.md` has the index that says which file holds which section.

---

## 19. Git Workflow and Commit Plan

### 19.1 Principles (hard rules)

1. **Honest history.** Never backdate commits (`--date`, `GIT_AUTHOR_DATE`, etc.), never fabricate a history by splitting a finished project into fake commits afterward, and never rewrite history after pushing (no `--amend` on pushed commits, no `push --force`). The first commit must be made after the hackathon starts (Oct 15, 12:01 AM IST).
2. **One logical change per commit.** A commit should be explainable in one line. Do not mix unrelated changes (for example seed data and frontend styling).
3. **Every commit leaves the repo working.** Run the relevant tests (`make test`, or `npm run build` for frontend work) before committing. If a commit would break the build, finish the work first.
4. **Review before committing.** Run `git diff --staged` and read it. Remove debug prints and dead code. This is also how the human owner stays able to explain the code.
5. **Conventional commit messages:** `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `refactor:` with an optional scope, imperative mood, under 72 characters, e.g. `feat(queries): add attacker path to PII databases`.
6. **Push after every task**, and at least every few commits (`git push origin main`). Work directly on `main` (solo) or on short-lived branches merged via PR (team of 2 to 4; then use `feat/<area>` branches, merged with merge commits, not squashes).
7. **Keep fix commits visible.** Bug fixes found during testing stay as their own commits (for example `fix(mcp): reject max_hops above 6`). Do not squash them away.
8. **Never commit:** `.env`, `node_modules/`, `__pycache__/`, `.venv/`, `dist/`, `outbox/*.jsonl`, `probe_results.json` (add to `.gitignore` in the first commit). Do commit: lockfiles, `.env.example`, replay files in `replays/`.
9. **Tag milestones** (annotated tags, pushed): `v0.1-graph`, `v0.2-agent`, `v0.3-ui`, `v1.0`.
10. **Log it.** In `BUILD_LOG.md`, list the commit hashes (`git log --oneline`) under each task heading.

### 19.2 Setup (before T0 content; this is commit 1)

```
git init -b main
# create the GitHub repo (public) and: git remote add origin <url>
```
If you cannot create or push to a remote, commit locally and tell the owner exactly which commands to run to push (do not stop work).

### 19.3 Commit plan (target 30 to 40 commits; adjust sensibly but keep the granularity)

**T0 to T4: Day 1 foundation, tag `v0.1-graph` at the end of T5**

| # | Commit message | Contents |
|---|---|---|
| 1 | `chore: initialize repo with README stub, license and .gitignore` | README stub (title + one-line pitch + track), `LICENSE` (MIT), `.gitignore` |
| 2 | `docs: add problem statement and initial graph schema` | `docs/architecture.md` first draft (node/edge tables, traversal-direction note) |
| 3 | `chore: add docker-compose for pinned FalkorDB` | `docker-compose.yml`, `.env.example` |
| 4 | `chore: scaffold python project, requirements and Makefile` | `requirements.txt`, `Makefile`, package folders with `__init__.py` |
| 5 | `chore: add falkordb capability probe` | `scripts/probe_falkordb.py` |
| 6 | `docs: record probe results and pinned image tag` | `DECISIONS.md` entries |
| 7 | `feat(seed): add entity data for services, databases, roles, teams` | `seed/data/*.json` (entities) |
| 8 | `feat(seed): add dependency, access and vulnerability edges` | `seed/data/edges.json`, `vulns.json` |
| 9 | `feat(seed): idempotent seed script with --reset and acyclicity check` | `seed/seed_graph.py` |
| 10 | `test(seed): assert node/edge counts and acyclicity` | `tests/test_seed.py` |
| 11 | `feat(queries): failure impact traversal` | `db.py`, impact query + function |
| 12 | `feat(queries): attacker paths to PII databases` | attack query (+ fallback if the probe required it) |
| 13 | `feat(queries): criticality ranking and containment writes` | rank query, isolate/revoke/rollback |
| 14 | `test(queries): golden results G2 to G7` | `tests/test_queries.py` |
| 15 | `feat(mcp): server skeleton with component context tool` | `server.py`, `models.py`, envelope helper |
| 16 | `feat(mcp): impact, attack-path, ranking and read-only cypher tools` | tools 2 to 4, 11 + tests; then tag `v0.1-graph` |

**T4 to T9: Day 2 agent and safety (scoring/policy after the tools they depend on exist)**

| # | Commit message |
|---|---|
| 17 | `feat: deterministic risk scoring with tests` |
| 18 | `feat: containment policy gate with tests` |
| 19 | `feat(mcp): compute_risk tool` |
| 20 | `feat(mcp): propose and execute containment with action state machine` |
| 21 | `feat(mcp): rollback, notify-owners and record-finding tools` |
| 22 | `test(mcp): write-tool and policy enforcement tests` |
| 23 | `feat(agent): event models and in-memory event bus` |
| 24 | `feat(agent): mcp bridge client` |
| 25 | `feat(agent): scripted mock agent for scenarios A, B and C` |
| 26 | `feat: incident runner CLI and recorded replays` |
| 27 | `feat(agent): live anthropic tool-calling loop` |
| 28 | `feat(api): fastapi routes, graph endpoint and SSE stream` |
| 29 | `feat(api): approval endpoint with pause and resume` |
| 30 | `test(api): approval flow end to end`; tag `v0.2-agent` |

**T10 to T12: Day 3 frontend, tag `v0.3-ui` at the end**

| # | Commit message |
|---|---|
| 31 | `chore(web): scaffold vite, tailwind and shadcn` |
| 32 | `feat(web): load graph and lay out with dagre` |
| 33 | `feat(web): custom node components with status styling` |
| 34 | `feat(web): event reducer and SSE hook with tests` |
| 35 | `feat(web): live path highlighting from graph_visit events` |
| 36 | `feat(web): trace feed with expandable cypher` |
| 37 | `feat(web): risk panel and approval card` |
| 38 | `feat(web): final report, rollback and export` |
| 39 | `feat(web): replay mode` |

**T13 to T16: Day 4 proof and polish, tag `v1.0` at submission**

| # | Commit message |
|---|---|
| 40 | `feat(evals): scenario harness and results table` |
| 41 | `docs: query reference with golden results` |
| 42 | `docs: readme with graph model, setup and ai disclosure` |
| 43 | `chore: github actions ci for backend and frontend` |
| 44 | `chore: dockerfiles and full-stack compose` |
| 45 | `docs: explainer, owner questions and demo script` |
| 46+ | Real fix commits discovered during testing, then `docs: add demo video link` |

### 19.4 Push cadence
- Push at the end of each task (T0 to T16) and before any long-running step.
- Expect at least 5 pushes on each day. If work has gone more than 90 minutes without a commit, the change is probably too large; split it.
- After the final push, verify from a **fresh clone** in a temporary directory that the README setup works, and log the result.

### 19.5 What not to do
- Do not create a single huge commit ("initial implementation") and do not create dozens of empty or trivial commits to pad history.
- Do not commit generated build output or secrets. If a secret is ever committed, **stop**, rotate it, tell the owner, and do not attempt to hide it by rewriting pushed history.
- Do not edit commit timestamps, and do not make commits from before the hackathon window.
