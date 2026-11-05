---
name: freellmapi
description: Route all LLM traffic through FreeLLMAPI's unified gateway — 34 free providers, 635 model endpoints, ~7.4B tokens/month behind one OpenAI-compatible /v1 endpoint. Use when setting up free inference, configuring coding agents (Claude Code, Codex, Cursor, Cline, Aider, etc.), managing provider keys, or building LLM-powered features in AdShieldPro/OmniShield X without paid APIs.
metadata:
  author: tashfeenahmed
  version: 1.0.0
  source: https://github.com/tashfeenahmed/freellmapi
  license: MIT
---

# FreeLLMAPI — Free Unified LLM Gateway

Self-hosted router that aggregates **34 free LLM providers** (Google, Groq, Cerebras, Mistral, OpenRouter, Cloudflare, Cohere, HuggingFace, Z.ai, NVIDIA + 22 more) behind a single **OpenAI-compatible `/v1` endpoint**. Smart routing, automatic failover on 429/5xx, encrypted key storage (AES-256-GCM), and a dashboard to manage the fallback chain.

> **AdShieldPro context:** OmniShield X (this repo's web platform) runs 100% local-first today — Aether AI is heuristic, not cloud LLM. FreeLLMAPI lets you add optional LLM-powered features (threat explanations, rule generation, feed curation) during development *without* shipping secrets or paying for tokens. Nothing in this skill sends AdShieldPro user data upstream unless you explicitly wire it.

## When to Use

- User asks to "install freellmapi", "use free models", "set up LLM gateway", "configure Claude Code for free"
- Need free inference for development, testing, or AI-feature prototyping in AdShieldPro
- Want to avoid per-provider SDKs — one `base_url + api_key` for everything
- Building a feature that needs LLM (e.g., explain a threat, generate filter rules, summarise feeds)
- Coding-agent setup: `setup-claude`, `setup-codex`, `setup-cursor`, etc.
- Key management: add/list/test/remove provider keys

## Quick Start (Pick One)

### Option A — Desktop App (easiest, no Docker)

Download from **Releases** → `.dmg` (macOS) or `.exe` (Windows). Runs from tray, no password. Tray → **Open Dashboard** at `http://127.0.0.1:31415`.

### Option B — Docker (one-liner)

```bash
curl -fsSL https://freellmapi.co/install.sh | bash
# → generates ENCRYPTION_KEY, pulls ghcr.io/tashfeenahmed/freellmapi:latest, starts on :3001
# Re-run is safe — .env and volume are preserved.
# Read first if you prefer: https://freellmapi.co/install.sh
```

### Option C — Local Dev (this repo)

```bash
git clone https://github.com/tashfeenahmed/freellmapi.git /tmp/freellmapi
cd /tmp/freellmapi
npm install
# .env is auto-created on npm run dev if ENCRYPTION_KEY is unset (dev only)
npm run dev   # API on :3001, dashboard Vite on :5173 (use npm run dev:lan for LAN)
```

> After any install, open `http://localhost:3001` (or the desktop port), add at least **one free provider key** (Google AI Studio is fastest: https://aistudio.google.com/app/apikey) on **Keys**, and copy the **unified API key** from the Keys page header. That's what all SDKs use.

## Verify the Gateway Is Running

```bash
curl -s http://localhost:3001/api/health 2>/dev/null | head -c 200
curl -s http://localhost:3001/v1/models -H "Authorization: Bearer <unified-key>" | head -c 500
# Every response carries X-Routed-Via: <provider>/<model>
```

## Use With Any OpenAI Client

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:3001/v1", api_key="freellmapi-...")
resp = client.chat.completions.create(
    model="auto",  # or auto:fast, auto:smart, or a concrete id like google/gemini-2.0-flash
    messages=[{"role": "user", "content": "Explain this threat: fake-login.example.com"}],
)
print(resp.choices[0].message.content)
print(resp.headers.get("x-routed-via"))
```

```bash
# curl
curl http://localhost:3001/v1/chat/completions \
  -H "Authorization: Bearer $FREELLMAPI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"auto","messages":[{"role":"user","content":"hello"}]}'

# Node / JS
import OpenAI from "openai";
const client = new OpenAI({ baseURL: "http://localhost:3001/v1", apiKey: process.env.FREELLMAPI_API_KEY });
```

Streaming, tool-calling, vision, embeddings, and Anthropic Messages (`/v1/messages`) all work. See `docs/en/api/01-rest-api.md` in the freellmapi repo.

## Configure Coding Agents (One Command Each)

The CLI merges into existing config, backs up the original with a timestamp, and uses the **live catalog** models. Always preview first:

```bash
export FREELLMAPI_API_KEY=<unified-key>
npx freellmapi setup-claude --url http://localhost:3001 --dry-run   # preview diff
npx freellmapi setup-claude --url http://localhost:3001            # apply
```

| Agent | Command | Base URL Note |
|-------|---------|---------------|
| **Claude Code** | `npx freellmapi setup-claude --url http://localhost:3001` | expects **root** (`http://localhost:3001`) |
| **Codex CLI** | `npx freellmapi setup-codex --url http://localhost:3001/v1` | `/v1` |
| **Cursor** | `npx freellmapi setup-cursor --url http://localhost:3001/v1` | prints guide (manual step) |
| **Cline** | `setup-cline` | `/v1` |
| **Aider** | `setup-aider` | `/v1` |
| **Continue** | `setup-continue` | `/v1` |
| **OpenCode** | `setup-opencode` | `/v1` |
| **Goose** | `setup-goose` | `/v1` |
| **Qwen Code** | `setup-qwen` | `/v1` |
| **Roo Code** | `setup-roo` | `/v1` |
| **Kilo Code** | `setup-kilo` | `/v1` |
| **Crush** | `setup-crush` | `/v1` |
| **DeepSeek Harness** | `setup-dsh` | `/v1` |
| **Any other** | `setup-generic` | prints ready block |

- `FREELLMAPI_URL` and `FREELLMAPI_API_KEY` env vars replace `--url` / `--api-key`.
- `--profile <name>` creates a named profile/provider instead of overwriting default.
- `--model <id>` pins a specific model.
- `launch` / `launch-codex` run Claude/Codex with credentials injected only in the child env (never written to disk).

Full agent matrix: `npx freellmapi list` and `cli/tools.json`.

## Provider Keys CLI

Uses a **dashboard session token**, not the unified key. Get it from browser localStorage `freellmapi_dashboard_token` after signing in.

```bash
export FREELLMAPI_URL=http://localhost:3001
export FREELLMAPI_DASHBOARD_TOKEN='<dashboard-token>'

npx freellmapi keys list
npx freellmapi keys add groq --key '<provider-key>'   # or omit --key for hidden prompt
npx freellmapi keys test groq
npx freellmapi keys test groq --id 7
npx freellmapi keys remove groq --id 7
```

`--timeout <ms>` per request (default 30s). Every `add` validates immediately; failed validation still saves the key for later `test`/`remove`.

## AdShieldPro Integration Patterns

### A. Threat Explanation (web platform)

`app.js` already has `Aether` (heuristic reputation) and `FirewallAI`. Add an *optional* LLM explanation path that never blocks — advisory only, matching the existing `advisoryIsEnforced: false` contract:

```js
// security/llm-advisor.js (optional, not shipped by default)
export async function explainThreat(domain, aetherVerdict, opts = {}) {
  const baseURL = opts.baseURL ?? "http://localhost:3001/v1";
  const apiKey = opts.apiKey; // unified key, from dashboard or env
  if (!apiKey) return null; // graceful no-op if gateway not configured
  const res = await fetch(`${baseURL}/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({
      model: "auto:smart",
      messages: [
        { role: "system", content: "You are a security analyst. Explain DNS threat signals concisely, never claim certainty you lack, cite evidence." },
        { role: "user", content: `Domain: ${domain}\nAether score: ${aetherVerdict.score}\nSignals: ${JSON.stringify(aetherVerdict.evidence)}\nExplain risk in 2-3 sentences for a non-expert.` }
      ],
      max_tokens: 300
    })
  });
  if (!res.ok) return null;
  const data = await res.json();
  return data.choices[0]?.message?.content ?? null;
}
```

- Never use LLM output to set `blocked: true`. Only `engine.js` blocks, on real rule matches.
- Show `X-Routed-Via` in UI for transparency.

### B. Rule Generation Assistant

Prompt the gateway to suggest Adblock-style rules from a threat report, then validate with `engine.js` before showing:

```
Suggest 3 Adblock DNS rules (||domain^) for this threat report. Return valid rules only, one per line, no commentary: <report>
```

Validate each suggestion with `engine.js` parser and preview impact (`engine.testMatch`) before adding to custom rules.

### C. CI Helper

In CI or local dev, keep secrets out of Git. Use env vars:

```bash
# .env.example — committed
FREELLMAPI_URL=http://localhost:3001
# .env — gitignored, real value
FREELLMAPI_API_KEY=freellmapi-...
ENCRYPTION_KEY=...
```

## Custom OpenAI-Compatible Endpoints

On the **Keys** page add a Custom provider pointing at any OpenAI-compatible URL (Ollama, llama.cpp, LM Studio, vLLM, remote gateway) for chat/embedding/image/audio. The router treats it like any other provider with failover.

## Health, Analytics & Ops

- **Dashboard**: Models (fallback chain, token budget), Keys, Playground (test with `x-routed-via`), Analytics (24h/7d/30d/90d).
- **Logs**: Docker → `docker compose logs -f freellmapi`; dev → terminal; desktop → `<data-dir>/logs/freeapi.log` (tray → Open Logs Folder).
- **Catalog**: Signed feed pulled 2×/day. Free = monthly snapshot (~303 models behind live); Premium ($19/yr) = same-day live feed. Verification uses pinned Ed25519. State at `freellmapi.co/models`.
- **Data**: SQLite at `server/data/freeapi.db` or `FREEAPI_DB_PATH`. Backup via `FREEAPI_DB_BACKUP_*` envs. Keys encrypted at rest.

## Troubleshooting

- `npx freellmapi setup-claude` → connection error: you passed `:3000` (old default). Use `--url http://localhost:3001`.
- Container can't reach providers but host can: container loopback ≠ host. Set `PROXY_URL=socks5h://host.docker.internal:7890` and `allow-lan: true` in proxy. On IPv6-only hosts, enable `"ipv6": true` in `/etc/docker/daemon.json`.
- Dashboard from another device hangs: default `HOST_BIND=127.0.0.1`. Use `HOST_BIND=0.0.0.0` on trusted LAN.
- Forgot password (server install): Login → Forgot password? → code printed to server log (valid 15 min, `docker compose logs -f freellmapi`).
- Desktop has no password — tray → Open Dashboard auto-signs in.

## Limits & Honesty

Free tiers are best-effort: no frontier models, variable latency, no SLA, quality dips late in day as top models hit daily caps (resets UTC midnight). See `docs/en/architecture/00-high-level-index.md#limitations`. Never promise paid-grade reliability for free-tier routing.

## References

- Repo: https://github.com/tashfeenahmed/freellmapi
- Install & deploy: `docs/en/install/01-install.md`
- API reference: `docs/en/api/01-rest-api.md`
- Clients & agents: `docs/en/clients/01-agent-clients.md`
- Architecture: `docs/en/architecture/00-high-level-index.md`
- Install script: https://freellmapi.co/install.sh
- Model catalog: https://freellmapi.co/models
