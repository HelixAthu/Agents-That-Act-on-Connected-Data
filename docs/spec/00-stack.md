# Spec 00: Stack (fixed decisions and library manifest)

- **Purpose:** Lists every technology decision. There are no open choices.
- **Read this when:** starting T0, adding any dependency, or unsure which library to use.

---

## 1. Fixed Decisions

| Area | Decision |
|---|---|
| Python | 3.11+; dependency manager: `pip` + `requirements.txt` (no poetry/uv required) |
| DB | FalkorDB Docker image `falkordb/falkordb` **pinned to a specific tag**; record the exact tag in `DECISIONS.md` after T0 (run `docker pull` and inspect; do not use `latest` in docker-compose) |
| Graph name | `infra` (env `GRAPH_NAME`) |
| DB client | `falkordb` (Python). Read tools use `graph.ro_query`, write tools use `graph.query` |
| MCP server | `mcp` Python SDK, `FastMCP` from `mcp.server.fastmcp`, **stdio transport** |
| MCP client | `mcp` SDK `ClientSession` + `stdio_client`; the backend spawns `python -m mcp_server.server` as a subprocess |
| Validation | Pydantic v2 |
| Backend | FastAPI + `uvicorn`; SSE via `sse-starlette` |
| LLM provider | **Gemini** via the `google-genai` SDK (`from google import genai`). Default model `gemini-3.8-flash` (env `GEMINI_MODEL`). Key from env `GEMINI_API_KEY`. Thinking level from env `GEMINI_THINKING_LEVEL` (`low`, `medium` default, `high`; `minimal` is NOT supported and errors) |
| LLM abstraction | The agent loop talks only to the `LLMSession` interface in `backend/llm/base.py`. `GeminiSession` is the default and is required. `AnthropicSession` is optional (skip unless the owner asks). `FakeSession` (scripted) is used in unit tests. Provider chosen by env `LLM_PROVIDER=gemini\|anthropic` |
| Agent loop | **Custom** tool-calling loop (no LangGraph). Max 12 tool calls per incident |
| Keyless mode | `AGENT_MODE=mock` runs a **scripted agent** (Section 10.3) with identical event output. Default in tests and CI |
| Tests | `pytest`, `pytest-asyncio` |
| Frontend | Vite + React 18 + TypeScript, Tailwind CSS, shadcn/ui (only Button, Card, Badge, ScrollArea, Tabs), `@xyflow/react`, `dagre` (`@dagrejs/dagre`) for layout |
| Time | All timestamps ISO-8601 UTC |

**Env vars** (`.env.example`): `FALKORDB_HOST=localhost`, `FALKORDB_PORT=6379`, `GRAPH_NAME=infra`, `AGENT_MODE=mock|live`, `LLM_PROVIDER=gemini`, `GEMINI_API_KEY=`, `GEMINI_MODEL=gemini-3.8-flash`, `GEMINI_THINKING_LEVEL=medium`, `AUTO_APPROVE=false`, `APPROVAL_TIMEOUT_S=120`, `OUTBOX_PATH=./outbox/notifications.jsonl`.

### 1.1 Library Manifest (install exactly these; add nothing else without logging it in `DECISIONS.md`)

**Database**

| Piece | Choice |
|---|---|
| Graph DB | FalkorDB via Docker, image tag pinned (never `latest`); Redis protocol on 6379; browser UI on 3000 for debugging Cypher |
| Client | `falkordb` (Python): `ro_query` for reads, `query` for writes |
| Query language | OpenCypher; all queries in `mcp_server/queries.py` |

**Backend (Python 3.11+), `requirements.txt`**

| Purpose | Package |
|---|---|
| API server | `fastapi`, `uvicorn[standard]` |
| SSE streaming | `sse-starlette` |
| Validation and settings | `pydantic>=2`, `pydantic-settings` (reads `.env`) |
| MCP server and client | `mcp` (official SDK: `FastMCP` server, `ClientSession` + `stdio_client` client) |
| LLM | `google-genai` (default, required). `anthropic` is optional and not installed unless the owner asks |
| Graph access | `falkordb` |
| Tests | `pytest`, `pytest-asyncio`, `httpx` |
| Eval config | `pyyaml` |
| Lint/format | `ruff` |

After installing, pin exact versions with `pip freeze` filtered to these packages and their dependencies (commit the result).

**Frontend (`frontend/package.json`)**

| Purpose | Package |
|---|---|
| Build | `vite`, `react@18`, `react-dom@18`, `typescript` |
| Styling | `tailwindcss` (+ `postcss`, `autoprefixer`) |
| UI components | shadcn/ui, **only** `button`, `card`, `badge`, `scroll-area`, `tabs` (plus `class-variance-authority`, `clsx`, `tailwind-merge`, `@radix-ui/*` as the shadcn CLI installs them) |
| Icons | `lucide-react` |
| Graph canvas | `@xyflow/react` |
| Auto layout | `@dagrejs/dagre` |
| State | none; use `useReducer` with one pure reducer that consumes SSE events |
| Streaming | native `EventSource` |
| HTTP | native `fetch` |
| Tests | `vitest` (and `@testing-library/react` only if needed) |

**Explicitly NOT used:** LangChain, LangGraph, SQLAlchemy, Celery, Redux, Zustand, React Query, axios. Commit the lockfile (`package-lock.json`) so versions are exact.

**Tooling:** Docker Compose (FalkorDB first, full stack later), `Makefile`, and a GitHub Actions workflow `.github/workflows/ci.yml` that runs `pytest` (mock mode; FalkorDB as a service container) and `npm run build` + `npx tsc --noEmit` + `npx vitest run`.

---

