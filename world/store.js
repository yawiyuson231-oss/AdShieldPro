/** Local-first monitor: bounded caches, single-flight sync, backoff, saved watches and alert inbox. */
import { SOURCES, SOURCE_BY_ID, LIMITS, CATEGORIES, REGIONS, SEVERITIES } from './catalog.js';
import { normalizeEvent, normalizeWatch, matchesWatch, filterEvents, cleanText } from './model.js';
import { parseSource } from './parsers.js';
import { fetchJson } from './network.js';
import { normalizeCustomSource, MAX_CUSTOM_SOURCES } from './custom.js';
import { COUNTRIES } from './countries-data.js';

const KEY = 'world:workspace:v1';
export const DEFAULT_FILTERS = Object.freeze({ query: '', range: '7d', region: 'world', severity: 'info', source: 'all', sort: 'newest', categories: CATEGORIES.map((c) => c.id) });
const freshHealth = () => ({ status: 'idle', lastAttempt: null, lastSuccess: null, error: null, retryAt: null, failures: 0, count: 0 });

export function sanitizeFilters(raw = {}) {
  return {
    query: cleanText(raw.query, 160), range: ['24h', '7d', '30d', 'all'].includes(raw.range) ? raw.range : '7d',
    region: REGIONS.some((r) => r.id === raw.region) ? raw.region : 'world',
    severity: SEVERITIES.includes(raw.severity) ? raw.severity : 'info',
    source: SOURCE_BY_ID.has(raw.source) ? raw.source : 'all', sort: raw.sort === 'severity' ? 'severity' : 'newest',
    categories: Array.isArray(raw.categories) ? [...new Set(raw.categories.filter((id) => CATEGORIES.some((c) => c.id === id)))] : [...DEFAULT_FILTERS.categories]
  };
}

export class WorldStore {
  constructor({ storage, fetchImpl = globalThis.fetch?.bind(globalThis), clock = () => Date.now(), timeoutMs = LIMITS.timeoutMs } = {}) {
    this.storage = storage; this.fetchImpl = fetchImpl; this.clock = clock; this.timeoutMs = timeoutMs;
    this.sources = Object.fromEntries(SOURCES.map((s) => [s.id, { enabled: s.enabled, events: [], health: freshHealth() }]));
    this.customSources = []; this.country = 'PH'; this.savedCountries = []; this.dailyRefresh = false; this.lastDaily = 0;
    this.filters = sanitizeFilters(); this.watches = []; this.bookmarks = []; this.alerts = [];
    this.autoRefresh = false; this.listeners = new Set(); this.inflight = new Map(); this.batch = null;
    this.revision = 0; this.sequence = 0; this.storageError = storage?.constructor?.name === 'MemoryStorage' ? 'Storage is session-only; export your watches before closing this window.' : null; this.writeChain = Promise.resolve();
    this.fresh = new Set();
  }

  subscribe(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }
  emit() { for (const fn of this.listeners) { try { fn(); } catch (e) { console.warn('World Monitor observer failed', e); } } }
  get catalog() { return [...SOURCES, ...this.customSources]; }
  get busy() { return this.inflight.size > 0 || this.batch !== null; }
  get events() { return Object.values(this.sources).filter((s) => s.enabled).flatMap((s) => s.events); }
  filtered() { return filterEvents(this.events, this.filters, this.clock()); }

  health() {
    const now = this.clock();
    return Object.fromEntries(this.catalog.map((s) => {
      const row = this.sources[s.id]; const h = { ...row.health, enabled: row.enabled, count: row.events.length };
      if (!row.enabled) h.status = 'disabled';
      else if (['live', 'cached', 'stale'].includes(h.status)) {
        h.status = now - (h.lastSuccess || 0) > s.ttlMs ? 'stale' : this.fresh.has(s.id) ? 'live' : 'cached';
      }
      return [s.id, h];
    }));
  }

  async load() {
    if (!this.storage) { this.storageError = 'Persistent storage is unavailable. This session is kept in memory only.'; return; }
    try {
      const raw = await this.storage.getItem(KEY);
      if (!raw) return;
      if (raw.length > 12_000_000) throw new Error('cache is too large');
      const saved = JSON.parse(raw);
      if (saved?.version !== 1) throw new Error('unsupported workspace version');
      for (const raw of (Array.isArray(saved.customSources) ? saved.customSources : []).slice(0, MAX_CUSTOM_SOURCES)) {
        try {
          const spec = normalizeCustomSource(raw);
          if (this.catalog.some((s) => s.url === spec.url)) continue;
          this.customSources.push(spec); SOURCE_BY_ID.set(spec.id, spec);
          this.sources[spec.id] = { enabled: true, events: [], health: freshHealth() };
        } catch { /* invalid custom sources are never contacted */ }
      }
      this.country = COUNTRIES.some((c) => c.code === saved.country) ? saved.country : 'PH';
      this.savedCountries = Array.isArray(saved.savedCountries) ? [...new Set(saved.savedCountries.filter((id) => COUNTRIES.some((c) => c.code === id)))].slice(0, COUNTRIES.length) : [];
      this.dailyRefresh = saved.dailyRefresh === true;
      this.lastDaily = Number.isFinite(saved.lastDaily) && saved.lastDaily <= this.clock() ? saved.lastDaily : 0;
      this.filters = sanitizeFilters(saved.filters);
      // Auto-refresh is a session choice: never start network activity merely by restoring a cache.
      for (const spec of this.catalog) {
        const record = saved.sources?.[spec.id];
        if (!record || typeof record !== 'object') continue;
        const lastSuccess = Number.isFinite(record.lastSuccess) && record.lastSuccess > 0 && record.lastSuccess <= this.clock() ? record.lastSuccess : null;
        const events = Array.isArray(record.events) ? record.events.slice(0, LIMITS.eventsPerSource).map((e) => normalizeEvent(e, spec.id, this.clock())).filter(Boolean) : [];
        this.sources[spec.id] = {
          enabled: typeof record.enabled === 'boolean' ? record.enabled : spec.enabled,
          events: [...new Map(events.map((e) => [e.id, e])).values()],
          health: { ...freshHealth(), lastSuccess, status: ['error', 'offline', 'rate-limited'].includes(record.status) ? record.status : lastSuccess ? 'cached' : 'idle',
            error: cleanText(record.error, 300) || null, lastAttempt: Number.isFinite(record.lastAttempt) && record.lastAttempt <= this.clock() ? record.lastAttempt : null,
            failures: Number.isInteger(record.failures) ? Math.max(0, Math.min(12, record.failures)) : 0,
            retryAt: Number.isFinite(record.retryAt) && record.retryAt > this.clock() ? Math.min(record.retryAt, this.clock() + 86_400_000) : null }
        };
      }
      this.watches = [];
      for (const [i, rawWatch] of (Array.isArray(saved.watches) ? saved.watches.slice(0, LIMITS.watches) : []).entries()) {
        try { this.watches.push(normalizeWatch(rawWatch, `watch-restored-${i}`)); } catch { /* one corrupt rule cannot erase other rules */ }
      }
      this.bookmarks = (Array.isArray(saved.bookmarks) ? saved.bookmarks : []).slice(0, LIMITS.bookmarks)
        .map((e) => {
          if (e?.sourceMeta) {
            try { const spec = normalizeCustomSource(e.sourceMeta); if (spec.id === e.source) SOURCE_BY_ID.set(spec.id, spec); } catch { /* invalid metadata never registers a source */ }
          }
          return normalizeEvent(e, e?.source, this.clock());
        }).filter(Boolean);
      // Rebuild matches from received records, preserving acknowledgements by event + rule contents.
      const acknowledged = new Set((Array.isArray(saved.acknowledged) ? saved.acknowledged : []).slice(0, LIMITS.alerts).filter((x) => typeof x === 'string'));
      this.collectAlerts();
      for (const a of this.alerts) if (acknowledged.has(a.key)) a.read = true;
      if (this.storage.available === undefined && this.storage.constructor?.name === 'MemoryStorage') this.storageError = 'Storage is session-only; export watches before closing this window.';
    } catch {
      this.storageError = 'The saved World Monitor workspace could not be read. Using safe defaults; no network request was made.';
    }
    this.emit();
  }

  persist() {
    const value = JSON.stringify({ version: 1, filters: this.filters, customSources: this.customSources, country: this.country, savedCountries: this.savedCountries, dailyRefresh: this.dailyRefresh, lastDaily: this.lastDaily,
      sources: Object.fromEntries(this.catalog.map((s) => [s.id, { enabled: this.sources[s.id].enabled, lastSuccess: this.sources[s.id].health.lastSuccess, status: this.sources[s.id].health.status, error: this.sources[s.id].health.error, lastAttempt: this.sources[s.id].health.lastAttempt, failures: this.sources[s.id].health.failures, retryAt: this.sources[s.id].health.retryAt, events: this.sources[s.id].events }])),
      watches: this.watches, bookmarks: this.bookmarks.map((e) => ({ ...e, sourceMeta: SOURCE_BY_ID.get(e.source)?.custom ? SOURCE_BY_ID.get(e.source) : undefined })), acknowledged: this.alerts.filter((a) => a.read).map((a) => a.key)
    });
    this.writeChain = this.writeChain.then(async () => {
      try {
        if (!this.storage) throw new Error('no storage');
        await this.storage.setItem(KEY, value);
        if (this.storage.constructor?.name !== 'MemoryStorage') this.storageError = null;
      } catch { this.storageError = 'Changes are available in this session, but could not be saved (storage unavailable or full). Export your watchlist to keep it.'; this.emit(); }
    });
    return this.writeChain;
  }

  setFilters(patch) { this.filters = sanitizeFilters({ ...this.filters, ...patch }); this.emit(); return this.persist(); }
  resetFilters() { this.filters = sanitizeFilters(); this.emit(); return this.persist(); }

  async setEnabled(id, enabled) {
    if (!this.sources[id]) throw new Error('Unknown source.');
    this.sources[id].enabled = !!enabled;
    if (!enabled) this.inflight.get(id)?.controller.abort();
    this.collectAlerts(); this.emit(); await this.persist();
  }

  sync(id, { force = false } = {}) {
    if (!this.sources[id]) return Promise.reject(new Error('Unknown source.'));
    if (this.inflight.has(id)) return this.inflight.get(id).promise;
    const row = this.sources[id]; const spec = SOURCE_BY_ID.get(id); const now = this.clock();
    if (!row.enabled) return Promise.resolve({ ok: false, reason: 'disabled' });
    if (row.health.retryAt && now < row.health.retryAt) return Promise.resolve({ ok: false, reason: 'cooldown' });
    if (!force && this.fresh.has(id) && row.health.lastSuccess && now - row.health.lastSuccess < spec.ttlMs) return Promise.resolve({ ok: true, reason: 'fresh-cache' });
    const controller = new AbortController();
    const revision = this.revision;
    // Register before starting work; concurrent calls reuse exactly this promise.
    const entry = { controller, promise: null };
    entry.promise = Promise.resolve().then(() => this.runSource(spec, row, controller, revision)).finally(() => {
      if (this.inflight.get(id) === entry) this.inflight.delete(id);
      this.emit();
    });
    this.inflight.set(id, entry); this.emit();
    return entry.promise;
  }

  async runSource(spec, row, controller, revision) {
    const previous = { ...row.health };
    row.health = { ...row.health, status: 'loading', lastAttempt: this.clock(), error: null };
    this.emit();
    try {
      const payload = await fetchJson(spec.url, { fetchImpl: this.fetchImpl, signal: controller.signal, timeoutMs: this.timeoutMs, accept: spec.accept, now: this.clock() });
      const parsed = parseSource(spec.id, payload, this.clock());
      if (revision !== this.revision || controller.signal.aborted || !row.enabled) return { ok: false, reason: 'cancelled' };
      row.events = parsed.events;
      row.health = { ...freshHealth(), status: 'live', lastAttempt: previous.lastAttempt, lastSuccess: this.clock(), count: row.events.length, rejected: parsed.rejected, truncated: parsed.truncated, received: parsed.received };
      row.health.lastAttempt = this.clock();
      this.fresh.add(spec.id); this.collectAlerts();
      await this.persist(); this.emit();
      return { ok: true, count: parsed.events.length };
    } catch (error) {
      if (revision !== this.revision) return { ok: false, reason: 'cancelled' };
      const cancelled = controller.signal.aborted || error.code === 'cancelled';
      const failures = cancelled ? previous.failures : previous.failures + 1;
      row.health = cancelled ? { ...previous, error: 'Refresh cancelled; previous data retained.' }
        : { ...previous, status: error.code === 'rate-limited' ? 'rate-limited' : error.code === 'offline' ? 'offline' : 'error',
          lastAttempt: this.clock(), error: cleanText(error.message, 300), failures,
          retryAt: error.retryAt || this.clock() + Math.min(6 * 3_600_000, 60_000 * 2 ** Math.min(8, failures - 1)) };
      await this.persist(); this.emit();
      return { ok: false, reason: cancelled ? 'cancelled' : row.health.status };
    } finally {
      if (revision === this.revision && row.health.status === 'loading') { row.health = previous; this.emit(); }
    }
  }

  refresh() {
    if (this.batch) return this.batch;
    const revision = this.revision;
    const ids = this.catalog.filter((s) => this.sources[s.id].enabled).map((s) => s.id);
    const result = {};
    this.batch = Promise.resolve().then(async () => {
      const worker = async () => {
        while (ids.length && revision === this.revision) { const id = ids.shift(); result[id] = await this.sync(id); }
      };
      await Promise.all([worker(), worker(), worker()]);
      return result;
    }).finally(() => { this.batch = null; this.emit(); });
    this.emit(); return this.batch;
  }

  cancel() {
    this.revision++;
    for (const [id, entry] of this.inflight) {
      entry.controller.abort();
      const h = this.sources[id].health;
      if (h.status === 'loading') this.sources[id].health = { ...h, status: h.lastSuccess ? 'cached' : 'idle', error: 'Refresh cancelled; previous data retained.' };
    }
    this.emit();
  }

  async clearCache() {
    this.cancel();
    await Promise.allSettled([...this.inflight.values()].map((e) => e.promise));
    for (const row of Object.values(this.sources)) { row.events = []; row.health = freshHealth(); }
    this.fresh.clear(); this.alerts = [];
    this.emit(); await this.persist();
  }

  collectAlerts() {
    const old = new Map(this.alerts.map((a) => [a.key, a]));
    const next = [];
    // Alerts describe matches in the received data, not emergency push notifications.
    for (const event of this.events) {
      if (event.occurredAt < this.clock() - 7 * 86_400_000) continue;
      for (const watch of this.watches) {
        if (!matchesWatch(event, watch)) continue;
        const key = JSON.stringify([watch.label, watch.query, watch.region, watch.category, watch.severity, event.id]);
        next.push({ key, watchId: watch.id, watchName: watch.label, event, read: old.get(key)?.read || false });
      }
    }
    this.alerts = next.sort((a, b) => b.event.occurredAt - a.event.occurredAt).slice(0, LIMITS.alerts);
  }

  async addSource(raw) {
    if (this.customSources.length >= MAX_CUSTOM_SOURCES) throw new Error(`Up to ${MAX_CUSTOM_SOURCES} custom sources are supported, in addition to the built-in sources.`);
    const spec = normalizeCustomSource(raw);
    if (this.catalog.some((s) => s.url === spec.url)) throw new Error('This exact endpoint is already in your source list.');
    this.customSources.push(spec); SOURCE_BY_ID.set(spec.id, spec);
    this.sources[spec.id] = { enabled: true, events: [], health: freshHealth() };
    this.emit(); await this.persist(); return spec;
  }
  async removeSource(id) {
    if (!this.customSources.some((s) => s.id === id)) throw new Error('Built-in sources can be disabled, not removed.');
    this.sources[id].enabled = false;
    const pending = this.inflight.get(id);
    if (pending) { pending.controller.abort(); await pending.promise; }
    this.customSources = this.customSources.filter((s) => s.id !== id);
    delete this.sources[id]; this.fresh.delete(id);
    if (this.filters.source === id) this.filters.source = 'all';
    this.collectAlerts(); this.emit(); await this.persist();
  }
  async setCountry(code) {
    if (!COUNTRIES.some((c) => c.code === code)) throw new Error('Unknown country code.');
    this.country = code; this.emit(); await this.persist();
  }
  async toggleCountry(code) {
    if (!COUNTRIES.some((c) => c.code === code)) throw new Error('Unknown country code.');
    this.savedCountries = this.savedCountries.includes(code) ? this.savedCountries.filter((c) => c !== code) : [...this.savedCountries, code];
    this.emit(); await this.persist();
  }
  async importBackground(data) {
    if (data?.version !== 1 || !Array.isArray(data.sources)) throw new Error('Unsupported background snapshot.');
    let imported = 0;
    for (const entry of data.sources.slice(0, SOURCES.length)) {
      const spec = SOURCES.find((s) => s.id === entry?.id);
      if (!spec || !this.sources[spec.id].enabled || this.inflight.has(spec.id)) continue;
      const row = this.sources[spec.id];
      const attemptedAt = entry.attemptedAt || entry.fetchedAt;
      if (!Number.isFinite(attemptedAt) || attemptedAt > this.clock() || attemptedAt <= (row.health.lastAttempt || 0)) continue;
      try {
        if (Number.isFinite(entry.fetchedAt) && entry.fetchedAt <= this.clock() && entry.fetchedAt > (row.health.lastSuccess || 0) && entry.data) {
          const parsed = parseSource(spec.id, entry.data, this.clock());
          row.events = parsed.events;
          row.health = { ...freshHealth(), status: 'cached', lastSuccess: entry.fetchedAt, lastAttempt: attemptedAt, received: parsed.received, rejected: parsed.rejected, truncated: parsed.truncated, background: true };
          this.fresh.delete(spec.id); imported++;
        }
        if (entry.error) throw new Error(cleanText(entry.error, 300));
      } catch (error) {
        row.health = { ...row.health, status: 'error', lastAttempt: attemptedAt, error: `Daily update: ${cleanText(error.message, 260)}`,
          retryAt: Number.isFinite(entry.nextAllowedAt) ? Math.min(entry.nextAllowedAt, this.clock() + 86_400_000) : row.health.retryAt };
      }
    }
    this.collectAlerts(); this.emit(); await this.persist(); return { imported };
  }
  async setDaily(enabled) { this.dailyRefresh = !!enabled; this.emit(); await this.persist(); }
  async addWatch(raw) {
    if (this.watches.length >= LIMITS.watches) throw new Error(`At most ${LIMITS.watches} watches can be saved.`);
    const watch = normalizeWatch(raw, `watch-${this.clock()}-${++this.sequence}`);
    this.watches.push(watch); this.collectAlerts(); this.emit(); await this.persist(); return watch;
  }
  async replaceWatches(watches) {
    if (!Array.isArray(watches) || watches.length > LIMITS.watches) throw new Error('Too many watches.');
    const valid = watches.map((raw, i) => normalizeWatch(raw, `watch-${this.clock()}-${i}`));
    this.watches = valid; this.collectAlerts(); this.emit(); await this.persist();
  }
  async removeWatch(id) { this.watches = this.watches.filter((w) => w.id !== id); this.collectAlerts(); this.emit(); await this.persist(); }
  async toggleWatch(id) { const w = this.watches.find((r) => r.id === id); if (w) w.enabled = !w.enabled; this.collectAlerts(); this.emit(); await this.persist(); }
  async acknowledge(key = null) { for (const a of this.alerts) if (!key || a.key === key) a.read = true; this.emit(); await this.persist(); }

  async toggleBookmark(event) {
    const found = this.bookmarks.findIndex((b) => b.id === event.id);
    if (found >= 0) this.bookmarks.splice(found, 1);
    else {
      if (this.bookmarks.length >= LIMITS.bookmarks) throw new Error(`At most ${LIMITS.bookmarks} saved events are supported.`);
      const valid = normalizeEvent(event, event.source, this.clock());
      if (!valid) throw new Error('This event is not valid.');
      this.bookmarks.unshift(valid);
    }
    this.emit(); await this.persist();
  }
}
