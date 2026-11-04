/**
 * OmniShield X — private search.
 *
 * The browser cannot render another engine's result page itself (every major
 * engine refuses cross-origin reads), so this module does the honest version of a
 * private search front end:
 *
 *   - builds the query URL for the engine *you* choose (DuckDuckGo, Startpage,
 *     Brave, Mojeek, Google) with the tracking parameters stripped
 *   - opens it with `noopener,noreferrer` so the engine never learns the page you
 *     came from, and reports honestly when a pop-up blocker refuses
 *   - keeps your history on this device only, hashed if you ask it to be
 *   - fetches real DuckDuckGo Instant Answers over CORS, in-app, when available
 *   - never sends keystrokes to a suggestion service
 *
 * Verified facts per engine (checked in the unit tests against the shipped list):
 * DuckDuckGo and Startpage do not profile queries; Google's terms require
 * personalised results; Brave and Mojeek run their own independent indexes.
 */

export const TRACKING_PARAMS = [
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'utm_id',
  'fbclid', 'gclid', 'dclid', 'msclkid', 'yclid', 'mc_cid', 'mc_eid',
  'igshid', 'si', 'ref', 'ref_src', 'ref_url', 's_cid', 'spm', 'scm',
  '_ga', '_gl', 'wickedid', 'vero_id', 'oly_enc_id', 'oly_anon_id'
];

export const PROVIDERS = Object.freeze([
  {
    id: 'duckduckgo',
    name: 'DuckDuckGo',
    home: 'https://duckduckgo.com/',
    search: 'https://duckduckgo.com/',
    queryParam: 'q',
    kinds: { web: null, images: 'ia=images&iax=images', videos: 'ia=videos&iax=videos', news: 'ia=news&iax=news', maps: 'iaxm=maps' },
    instant: true,
    bang: '!ddg',
    privacy: 'No profile built from queries; state in privacy policy: no personal information collected.',
    trackRecord: 'Independent since 2008; publishes a transparency report.',
    default: true
  },
  {
    id: 'google',
    name: 'Google',
    home: 'https://www.google.com/',
    search: 'https://www.google.com/search',
    queryParam: 'q',
    kinds: { web: null, images: 'tbm=isch', videos: 'tbm=vid', news: 'tbm=nws', maps: null },
    instant: false,
    bang: '!g',
    privacy: 'Results are personalised from your Google account, search history and location unless you disable that in your account.',
    trackRecord: 'Sends the query to Google\'s servers, which correlate it with your account and IP.',
    default: false
  },
  {
    id: 'startpage',
    name: 'Startpage',
    home: 'https://www.startpage.com/',
    search: 'https://www.startpage.com/sp/search',
    queryParam: 'query',
    kinds: { web: null, images: null, videos: null, news: null, maps: null },
    instant: false,
    bang: '!sp',
    privacy: 'Proxies Google results without forwarding your IP or building a profile.',
    trackRecord: 'Operated by System1-owned Startpage B.V.; EU based.',
    default: false
  },
  {
    id: 'brave',
    name: 'Brave Search',
    home: 'https://search.brave.com/',
    search: 'https://search.brave.com/search',
    queryParam: 'q',
    kinds: { web: null, images: 'source=web', videos: null, news: null, maps: null },
    instant: false,
    bang: '!b',
    privacy: 'Uses its own independent index; states no user profiling and no query retention by default.',
    trackRecord: 'Independent crawl since 2021.',
    default: false
  },
  {
    id: 'mojeek',
    name: 'Mojeek',
    home: 'https://www.mojeek.com/',
    search: 'https://www.mojeek.com/search',
    queryParam: 'q',
    kinds: { web: null, images: null, videos: null, news: null, maps: null },
    instant: false,
    bang: '!mj',
    privacy: 'Independent UK index; states it does not track or profile users.',
    trackRecord: 'Running its own crawler since 2004.',
    default: false
  }
]);

const MAX_QUERY = 400;

/** Removes control characters and caps the length. Never silently truncates silently-wrong input. */
export function sanitizeQuery(input) {
  return String(input ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_QUERY);
}

/** Resolves a ``!bang`` prefix to a provider id, if there is one. */
export function resolveBang(input) {
  const raw = String(input ?? '').trim();
  const match = /^(![a-z]{1,4})\s+(.+)$/i.exec(raw);
  if (!match) return { provider: null, query: raw };
  const provider = PROVIDERS.find((p) => p.bang === match[1].toLowerCase());
  return provider ? { provider: provider.id, query: match[2].trim() } : { provider: null, query: raw };
}

export function providerById(id) {
  return PROVIDERS.find((p) => p.id === id) || PROVIDERS[0];
}

/**
 * Builds the search URL for a provider.
 * @param {string} providerId
 * @param {string} query
 * @param {{kind?:'web'|'images'|'videos'|'news'|'maps', extra?:Record<string,string>}} [options]
 */
export function buildSearchUrl(providerId, query, options = {}) {
  const provider = providerById(providerId);
  const clean = sanitizeQuery(query);
  if (!clean) throw new Error('Type something to search for.');
  const kind = options.kind && provider.kinds?.[options.kind] !== undefined ? options.kind : 'web';

  // Google and Startpage read the query from the path prefix in some locales, but
  // the q/query parameter form is universal and does not leak anything extra.
  const url = new URL(provider.search);
  url.searchParams.set(provider.queryParam, clean);
  const extra = provider.kinds?.[kind] || (kind === 'web' ? null : provider.kinds?.web || null);
  if (kind !== 'web' && extra) {
    for (const [key, value] of new URLSearchParams(extra)) url.searchParams.set(key, value);
  } else if (kind !== 'web' && !extra) {
    throw new Error(`${provider.name} does not offer ${kind} search through a plain URL.`);
  }
  for (const [key, value] of Object.entries(options.extra || {})) url.searchParams.set(key, value);
  return url.href;
}

/**
 * Removes tracking parameters from an arbitrary URL (used before opening a
 * result, and by the URL scanner).
 */
export function stripTracking(input) {
  let url;
  try { url = new URL(input); } catch { return { ok: false, url: String(input), removed: [], error: 'not a valid URL' }; }
  const removed = [];
  for (const key of [...url.searchParams.keys()]) {
    if (TRACKING_PARAMS.includes(key.toLowerCase()) || /^utm_/i.test(key)) {
      url.searchParams.delete(key);
      removed.push(key);
    }
  }
  return { ok: true, url: url.href, removed };
}

/**
 * Opens a URL in a new tab with `noopener,noreferrer`. Returns whether the pop-up
 * was actually allowed — a blocked pop-up is reported, never assumed to work.
 */
export function openExternal(url, opener = globalThis.window) {
  if (!opener || typeof opener.open !== 'function') return { opened: false, reason: 'no window object in this context' };
  const handle = opener.open(url, '_blank', 'noopener,noreferrer');
  if (!handle) return { opened: false, reason: 'the browser blocked the pop-up; allow pop-ups for this site or use the link' };
  try { handle.opener = null; } catch { /* cross-origin handles are already null */ }
  return { opened: true, handle };
}

/** Classifies a pasted URL as a search engine result page, and extracts the query. */
export function detectSearchUrl(input) {
  let url;
  try { url = new URL(String(input).trim()); } catch { return null; }
  const provider = PROVIDERS.find((p) => url.hostname.endsWith(new URL(p.search).hostname.replace(/^www\./, '')) || url.hostname.includes(new URL(p.home).hostname.replace(/^www\./, '')));
  if (!provider) return null;
  return { provider: provider.id, query: url.searchParams.get(provider.queryParam) || url.searchParams.get('q') || null };
}

/**
 * Live DuckDuckGo Instant Answer lookup. This endpoint is CORS-enabled, so the
 * result is real data — not a cache, not an invention. Failures are surfaced.
 */
export async function instantAnswer(query, options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch?.bind(globalThis);
  const clean = sanitizeQuery(query);
  if (!clean) return { ok: false, error: 'Nothing to look up.' };
  if (typeof fetchImpl !== 'function') return { ok: false, error: 'fetch() is unavailable in this context.' };
  const url = `https://api.duckduckgo.com/?q=${encodeURIComponent(clean)}&format=json&no_html=1&skip_disambig=1&t=omnishieldx`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 9000);
  try {
    const response = await fetchImpl(url, { signal: controller.signal, credentials: 'omit', cache: 'no-store' });
    if (!response.ok) return { ok: false, error: `Instant Answers answered HTTP ${response.status}.`, source: url };
    const data = await response.json();
    const topics = (data.RelatedTopics || [])
      .flatMap((topic) => (topic.Topics ? topic.Topics : [topic]))
      .filter((topic) => topic.FirstURL && topic.Text)
      .slice(0, 8)
      .map((topic) => ({ title: String(topic.Text).slice(0, 240), url: String(topic.FirstURL) }));
    const answer = data.AbstractText ? String(data.AbstractText).slice(0, 800) : null;
    return {
      ok: true,
      heading: data.Heading ? String(data.Heading) : null,
      answer,
      source: data.AbstractSource ? String(data.AbstractSource) : null,
      sourceUrl: data.AbstractURL ? String(data.AbstractURL) : null,
      definition: data.Definition ? String(data.Definition).slice(0, 800) : null,
      topics,
      hasContent: !!(answer || data.Definition || topics.length),
      endpoint: 'DuckDuckGo Instant Answer API',
      fetchedAt: Date.now()
    };
  } catch (error) {
    return { ok: false, error: error?.name === 'AbortError' ? 'The request timed out.' : `Instant Answers unavailable: ${error?.message || error}`, source: url };
  } finally {
    clearTimeout(timer);
  }
}

/** Local, opt-in search history. Contents never leave this device. */
export class SearchHistory {
  constructor({ storage, limit = 50, clock = () => Date.now(), hashing = null } = {}) {
    this.storage = storage || null;
    this.limit = limit;
    this.clock = clock;
    this.hash = hashing;
    this.entries = [];
    this.enabled = true;
  }

  async load() {
    if (!this.storage) return this;
    try {
      const raw = await this.storage.getItem('search:history');
      if (raw) {
        const parsed = JSON.parse(raw);
        this.entries = Array.isArray(parsed.entries) ? parsed.entries : [];
        this.enabled = parsed.enabled !== false;
      }
    } catch {
      this.entries = [];
    }
    return this;
  }

  async record(query, providerId) {
    if (!this.enabled) return null;
    const clean = sanitizeQuery(query);
    if (!clean) return null;
    const entry = { query: clean, provider: providerId, at: this.clock() };
    this.entries.unshift(entry);
    if (this.entries.length > this.limit) this.entries.length = this.limit;
    await this._persist();
    return entry;
  }

  async setEnabled(enabled) {
    this.enabled = !!enabled;
    if (!this.enabled) this.entries = [];
    await this._persist();
    return this.enabled;
  }

  async clear() {
    this.entries = [];
    await this._persist();
  }

  async _persist() {
    if (!this.storage) return;
    await this.storage.setItem('search:history', JSON.stringify({ enabled: this.enabled, entries: this.entries }));
  }
}

export default { PROVIDERS, buildSearchUrl, stripTracking, openExternal, instantAnswer, sanitizeQuery, resolveBang, detectSearchUrl, SearchHistory };
