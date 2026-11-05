/**
 * OmniShield X — Optional LLM Advisor (FreeLLMAPI).
 *
 * Advisory-only helper that asks a FreeLLMAPI gateway to explain a domain's
 * threat signals in plain language. It NEVER blocks — blocking is exclusively
 * engine.js on real rule matches (see docs/ARCHITECTURE.md §3).
 *
 * This module is NOT imported by app.js by default. Wire it behind an explicit
 * user opt-in and a configured gateway. It fails open (returns null) if the
 * gateway is unreachable, not configured, or returns an error.
 *
 * Gateway: https://github.com/tashfeenahmed/freellmapi
 *   - Default local URL: http://localhost:3001
 *   - Auth: unified API key from dashboard (freellmapi-...)
 *   - Endpoint: POST /v1/chat/completions (OpenAI-compatible)
 *   - Every response carries X-Routed-Via: <provider>/<model>
 *
 * @example
 * import { explainThreat, suggestRules } from './security/llm-advisor.js';
 * const apiKey = localStorage.getItem('freellmapi_unified_key'); // or env
 * if (apiKey) {
 *   const text = await explainThreat('fake-login.example.com', aetherVerdict, {
 *     baseURL: 'http://localhost:3001/v1',
 *     apiKey,
 *   });
 *   if (text) showAdvisory(text, { source: 'LLM' });
 * }
 */

const DEFAULT_BASE_URL = 'http://localhost:3001/v1';
const DEFAULT_MODEL = 'auto:smart';
const TIMEOUT_MS = 12000;
const MAX_TOKENS = 400;

/**
 * Ask the gateway to explain a domain's threat verdict.
 *
 * @param {string} domain
 * @param {{ score?: number, verdict?: string, evidence?: unknown, signals?: unknown } | null} aetherVerdict
 * @param {{ baseURL?: string, apiKey?: string, model?: string, signal?: AbortSignal }} opts
 * @returns {Promise<{ text: string, routedVia: string | null } | null>}
 */
export async function explainThreat(domain, aetherVerdict, opts = {}) {
  const baseURL = (opts.baseURL || DEFAULT_BASE_URL).replace(/\/+$/, '');
  const apiKey = opts.apiKey;
  if (!apiKey || !domain) return null;

  const model = opts.model || DEFAULT_MODEL;
  const evidence = aetherVerdict ? JSON.stringify(aetherVerdict, null, 2).slice(0, 2500) : 'none';
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  const signal = opts.signal ? AbortSignal.any([opts.signal, controller.signal]) : controller.signal;

  try {
    const res = await fetch(`${baseURL}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      signal,
      body: JSON.stringify({
        model,
        messages: [
          {
            role: 'system',
            content:
              'You are a security analyst for OmniShield X, a DNS-filtering tool. ' +
              'Explain why a domain looks risky based ONLY on the evidence given. ' +
              'Be concise (2-4 sentences), plain language, no jargon. ' +
              'Never claim certainty beyond the evidence. ' +
              'Never say you blocked anything — this is advisory only. ' +
              'If evidence is weak, say so.',
          },
          {
            role: 'user',
            content: `Domain: ${domain}\nAether verdict: ${evidence}\nExplain the risk briefly.`,
          },
        ],
        max_tokens: MAX_TOKENS,
        temperature: 0.3,
      }),
    });

    if (!res.ok) return null;
    const data = await res.json();
    const text = data?.choices?.[0]?.message?.content?.trim() || null;
    if (!text) return null;
    const routedVia = res.headers.get('x-routed-via') || data?.headers?.['x-routed-via'] || null;
    return { text, routedVia };
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Ask the gateway to suggest Adblock-style DNS rules for a threat report.
 * ALWAYS validate with engine.js before use — LLM output is untrusted.
 *
 * @param {string} report  — free-form threat description
 * @param {{ baseURL?: string, apiKey?: string, model?: string, signal?: AbortSignal }} opts
 * @returns {Promise<{ rules: string[], routedVia: string | null } | null>}
 */
export async function suggestRules(report, opts = {}) {
  const baseURL = (opts.baseURL || DEFAULT_BASE_URL).replace(/\/+$/, '');
  const apiKey = opts.apiKey;
  if (!apiKey || !report) return null;

  const model = opts.model || 'auto:fast';
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  const signal = opts.signal ? AbortSignal.any([opts.signal, controller.signal]) : controller.signal;

  try {
    const res = await fetch(`${baseURL}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      signal,
      body: JSON.stringify({
        model,
        messages: [
          {
            role: 'system',
            content:
              'You generate DNS filter rules. Return ONLY valid Adblock DNS rules, one per line, like "||example.com^". ' +
              'No numbering, no commentary, no markdown, no explanation. 1-5 rules max. ' +
              'If unsure, return fewer.',
          },
          {
            role: 'user',
            content: `Threat report:\n${report.slice(0, 3000)}\n\nRules:`,
          },
        ],
        max_tokens: 200,
        temperature: 0.2,
      }),
    });

    if (!res.ok) return null;
    const data = await res.json();
    const raw = data?.choices?.[0]?.message?.content || '';
    const rules = raw
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => /^\|\|[a-z0-9.-]+\^$/.test(l))
      .slice(0, 5);
    if (!rules.length) return null;
    const routedVia = res.headers.get('x-routed-via') || null;
    return { rules, routedVia };
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Health check for the gateway (no auth needed for /api/health, auth for /v1/models).
 *
 * @param {string} baseURL
 * @param {string | null} apiKey
 * @returns {Promise<{ ok: boolean, detail: string, models?: number }>}
 */
export async function checkGateway(baseURL = DEFAULT_BASE_URL, apiKey = null) {
  const root = baseURL.replace(/\/v1\/?$/, '').replace(/\/+$/, '');
  try {
    const health = await fetch(`${root}/api/health`, { signal: AbortSignal.timeout(5000) });
    if (!health.ok) return { ok: false, detail: `health ${health.status}` };
  } catch (e) {
    return { ok: false, detail: String(e.message || e).slice(0, 200) };
  }

  if (!apiKey) return { ok: true, detail: 'reachable (no key — models not checked)' };

  try {
    const res = await fetch(`${root}/v1/models`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return { ok: false, detail: `models ${res.status}` };
    const data = await res.json();
    const count = Array.isArray(data?.data) ? data.data.length : 0;
    return { ok: true, detail: `models: ${count}`, models: count };
  } catch (e) {
    return { ok: false, detail: String(e.message || e).slice(0, 200) };
  }
}
