# FreeLLMAPI Skill — Integration for AdShieldPro

> Skill source: [`skills/freellmapi/SKILL.md`](../skills/freellmapi/SKILL.md) · installed to `.agents/skills/freellmapi` (symlinked to `.claude/skills/freellmapi`) via `skills` CLI 1.7.6 · upstream repo: https://github.com/tashfeenahmed/freellmapi (MIT, 47k stars, 34 providers, 635 endpoints, ~7.4B tokens/mo).

This document is the **AdShieldPro-specific companion** to the skill. The skill itself is the generic FreeLLMAPI reference (setup, agents, keys, API). This doc explains how it fits this repo.

## Why this repo has this skill

AdShieldPro has two surfaces:

- **Android app (`app/`)** — Kotlin + VpnService DNS filtering, Room, Compose. No cloud LLM at runtime.
- **OmniShield X web platform** — `index.html` + `app.js` + `engine.js` + `aether/` + `security/` + `dns/`. Static, local-first, no backend, no telemetry endpoint. Aether AI and Firewall AI are on-device heuristics (see `docs/AETHER.md`, `docs/ARCHITECTURE.md`).

The skill **does not** change that. It gives *developers and coding agents* a zero-cost way to:

1. Point any OpenAI-compatible client at one local `/v1` endpoint instead of 34 SDKs.
2. Configure editors/agents in one command (`setup-claude`, `setup-codex`, etc.) without hand-editing JSON/YAML.
3. Prototype optional LLM features (threat explanations, rule drafting) locally, gated behind an explicit opt-in — never enforced blocking.

## Install

The skill is already installed in this checkout:

```
skills/freellmapi/SKILL.md          ← canonical source (committed)
.agents/skills/freellmapi/SKILL.md  ← universal (shared by all agents)
.claude/skills/freellmapi           → symlink → ../../.agents/skills/freellmapi
skills-lock.json                    ← { "freellmapi": { "source": "./skills/freellmapi" } }
```

Verify:

```bash
npx skills list --json | python3 -m json.tool
cat skills/freellmapi/SKILL.md | head -20
cat skills-lock.json
```

To reinstall after a clean checkout:

```bash
npx skills add ./skills/freellmapi --agent '*' -y
npx skills list
```

## FreeLLMAPI CLI (developer tooling)

Installed as a **devDependency** (not shipped to browsers — `npm run verify` asserts `dependencies` is empty):

```bash
npm install          # installs jsdom + freellmapi CLI
npx freellmapi --help
npx freellmapi list              # supported agents & base URLs
npx freellmapi setup-claude --help
```

Scripts added to `package.json`:

| Script | What it does |
|--------|--------------|
| `npm run freellmapi:setup -- --url http://localhost:3001 --api-key <key> --agent claude` | Wrapper around `npx freellmapi setup-*` with AdShieldPro defaults |
| `npm run freellmapi:doctor` | Checks gateway health + key status (wraps `npx freellmapi keys list`) |
| `node scripts/freellmapi-setup.mjs --help` | Standalone helper (no npx needed) |

## Gateway setup (pick one)

**Desktop app** (no Docker): download `.dmg`/`.exe` from freellmapi Releases → tray → Open Dashboard.

**Docker** (one-liner, this machine):

```bash
curl -fsSL https://freellmapi.co/install.sh | bash
# → http://localhost:3001 — add a free provider key (Google AI Studio is fastest) → copy unified key
```

**Local dev** (from source):

```bash
git clone https://github.com/tashfeenahmed/freellmapi.git /tmp/freellmapi
cd /tmp/freellmapi && npm install && npm run dev
# API :3001, Vite UI :5173
```

Then point an SDK at it (dev only — never commit keys):

```js
// .env (gitignored)
FREELLMAPI_URL=http://localhost:3001
FREELLMAPI_API_KEY=freellmapi-...
```

## Wiring coding agents (examples)

```bash
# Preview first, then apply (backs up original config with timestamp)
npx freellmapi setup-claude --url http://localhost:3001 --dry-run
npx freellmapi setup-claude --url http://localhost:3001 --api-key $FREELLMAPI_API_KEY

# Codex CLI
npx freellmapi setup-codex --url http://localhost:3001/v1 --api-key $FREELLMAPI_API_KEY

# Cursor (prints guide, then follow it)
npx freellmapi setup-cursor --url http://localhost:3001/v1

# Helper script (same, with project defaults)
node scripts/freellmapi-setup.mjs --agent claude --url http://localhost:3001 --dry-run
node scripts/freellmapi-setup.mjs --agent codex --url http://localhost:3001/v1
```

See `cli/tools.json` upstream for the full 20-agent matrix.

## Optional LLM integration in OmniShield X ( advisory only)

An example advisor is shipped as `security/llm-advisor.js` — **not wired into `app.js` by default**. It matches the existing enforcement model:

- Only `engine.js` blocks, on real rule matches.
- `aether/reputation.js` scores advisory (`advisoryIsEnforced: false`).
- `security/firewall-ai.js` recommends (`monitor` default, needs 2 signals to suggest block).

`llm-advisor.js` follows the same rule: it **explains**, never blocks. See its header for usage:

```js
import { explainThreat } from './security/llm-advisor.js';
const text = await explainThreat(domain, aetherVerdict, { baseURL, apiKey });
if (text) renderAdvisory(text, { source: 'LLM', routedVia });
```

Rules:

- Fail open: `null` if gateway not configured or request fails.
- Show `X-Routed-Via` header in UI.
- Never use LLM output to set `blocked: true`.
- Validate any LLM-suggested rules with `engine.js` before preview.

## Keys & secrets

- `.env` is gitignored. Commit only `.env.example`.
- Provider keys are AES-256-GCM in FreeLLMAPI's SQLite (`server/data/freeapi.db` or `FREEAPI_DB_PATH`).
- Dashboard session token (`freellmapi_dashboard_token` in localStorage) is needed for `npx freellmapi keys *` — unified key alone is not enough.

## Verification

```bash
npm run verify   # 86 gates including "no runtime dependencies" — freellmapi is devDependency, so it passes
npm run lint     # house rules for shipped runtime code
npm test         # 166 unit + 19 integration
npx skills list --json | grep freellmapi
```

## Updating

- Skill content: edit `skills/freellmapi/SKILL.md`, then `npx skills add ./skills/freellmapi --agent '*' -y` to refresh links (hash in `skills-lock.json` updates).
- FreeLLMAPI catalog: gateway pulls signed feed 2×/day. Free = monthly snapshot; Premium ($19/yr) = live same-day. See https://freellmapi.co/models
- CLI: `npm update freellmapi` (respects `package.json` semver).

## Uninstall

```bash
npx skills remove freellmapi -y
npm uninstall freellmapi
# optionally
rm -rf skills/freellmapi docs/FREELLMAPI_SKILL.md security/llm-advisor.js scripts/freellmapi-setup.mjs
```

## Links

- Skill source in this repo: `skills/freellmapi/SKILL.md`
- Upstream repo: https://github.com/tashfeenahmed/freellmapi
- Install & deploy: https://github.com/tashfeenahmed/freellmapi/blob/main/docs/en/install/01-install.md
- API reference: https://github.com/tashfeenahmed/freellmapi/blob/main/docs/en/api/01-rest-api.md
- Clients & agents: https://github.com/tashfeenahmed/freellmapi/blob/main/docs/en/clients/01-agent-clients.md
