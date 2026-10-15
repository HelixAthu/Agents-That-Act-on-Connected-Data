# START_HERE.md (for the human owner)

## What is in this folder
| File | Who reads it | Purpose |
|---|---|---|
| `AGENTS.md` (copied to `GEMINI.md`) | The coding agent, every session | Rules, stack, layout, index |
| `TASKS.md` | The coding agent | Ordered tasks T0 to T16 with acceptance commands |
| `docs/spec/00` to `07` | The coding agent, per task | Detailed specs, loaded only when a task needs them |
| `START_HERE.md` | You | How to run the build |

Copy `AGENTS.md` to whatever context filename your agent tool loads automatically (for example `GEMINI.md` for Gemini CLI; it is already provided). If you change `AGENTS.md`, copy it again so the two stay identical.

## Setup (you do this)
1. Install Docker, Python 3.11+, Node 20+, git. Create an empty public GitHub repo.
2. Get a Gemini API key. Put it in `.env` as `GEMINI_API_KEY=...` (never commit it). The build works without a key (mock mode); you need the key only for T8a/T8b live checks and for the live demo take.
3. Create the project folder, copy this whole folder's contents into it, and run `git init -b main` **after** the hackathon has started (Oct 15, 12:01 AM IST). Make your first commit yourself.

## First prompt (paste once)
> Read `AGENTS.md` fully. Then open `TASKS.md` and do task T0 only. Follow the loop in AGENTS.md Section 2. When T0's acceptance commands pass, log the output in `BUILD_LOG.md`, commit and push as described in `docs/spec/07-git-commits.md`, then stop and tell me what you did.

## Every later prompt (one task per session works best)
> Read `AGENTS.md`. Open `TASKS.md` and do the next unfinished task (check `BUILD_LOG.md`). Read only its `Read first:` files. Run its acceptance commands, log real output, commit and push, then stop.

## Tips for a fast, lower-tier model such as Gemini Flash
- Run **one task per session**. Long sessions make small models forget rules. State lives in git and `BUILD_LOG.md`, not in the model's memory.
- Use thinking level `medium` or `high` for the coding agent where your tool allows it.
- After T2, check the trial: did T0 to T2 pass without many corrections? If not, use a stronger model for T3 to T6 (Cypher and MCP are the hardest), then switch back.
- If the agent claims something passed, run the command yourself.
- If it keeps failing a golden value, open `docs/spec/01-data.md` and check the seed transcription against Section 5 together with it.

## What only you can do
- Create the repo, make the first commit after Oct 15 12:01 AM IST, push.
- Provide the Gemini key and run the live checks (T8a, T8b).
- **Read the code and `docs/EXPLAINER.md` (T16)** and be able to explain the graph model, every query, the policy gate and the MCP boundary. Projects that are mostly AI-generated without real understanding can be rejected.
- Record the demo video, deploy (or confirm local setup works from a fresh clone), submit before Oct 18 11:59 PM IST, and name the track: *Agents That Act on Connected Data*.
- Disclose AI use in the README (the agent writes the section; you check it is accurate).
