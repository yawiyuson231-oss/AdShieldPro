/**
 * OmniShield X — DNS cache.
 *
 * TTL-aware LRU with:
 *  - positive caching bounded by the record TTL (and a configurable ceiling),
 *  - RFC 2308 negative caching bounded by the SOA minimum,
 *  - single-flight de-duplication (100 identical lookups => 1 network request),
 *  - stale-while-revalidate support so a slow network never blocks the UI,
 *  - explicit, bounded memory (max entries).
 *
 * All time comes from an injectable clock so tests are deterministic.
 */

const DEFAULT_MAX_ENTRIES = 2048;
const MAX_TTL_SECONDS = 86400;
const MIN_TTL_SECONDS = 1;

export class DnsCache {
  /**
   * @param {{maxEntries?:number, clock?:()=>number}} [options]
   */
  constructor(options = {}) {
    this.maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.clock = options.clock ?? (() => Date.now());
    /** @type {Map<string, object>} insertion order doubles as LRU order */
    this.entries = new Map();
    /** @type {Map<string, Promise<any>>} */
    this.inflight = new Map();
    this.stats = {
      hits: 0, misses: 0, staleHits: 0, negativeHits: 0,
      evictions: 0, expirations: 0, stores: 0, singleFlightJoins: 0
    };
  }

  static key(name, type = 'A') {
    return `${String(type).toUpperCase()}|${String(name).toLowerCase().replace(/\.$/, '')}`;
  }

  _now() { return this.clock(); }

  /** Returns a live entry or null (expired entries are removed). */
  get(name, type = 'A') {
    const key = DnsCache.key(name, type);
    const entry = this.entries.get(key);
    if (!entry) { this.stats.misses++; return null; }
    const now = this._now();
    if (now >= entry.expiresAt && now >= entry.staleUntil) {
      this.entries.delete(key);
      this.stats.expirations++;
      this.stats.misses++;
      return null;
    }
    // Refresh LRU position.
    this.entries.delete(key);
    this.entries.set(key, entry);
    if (now >= entry.expiresAt) { this.stats.staleHits++; entry.stale = true; }
    else { this.stats.hits++; entry.stale = false; if (entry.negative) this.stats.negativeHits++; }
    return entry;
  }

  /**
   * Stores a result.
   * @param {{ttl?:number, negative?:boolean, negativeTtl?:number, staleGrace?:number}} meta
   */
  set(name, type, data, meta = {}) {
    const key = DnsCache.key(name, type);
    const negative = !!meta.negative;
    const rawTtl = negative ? (meta.negativeTtl ?? 60) : (meta.ttl ?? 60);
    const ttl = Math.min(Math.max(Math.round(rawTtl), MIN_TTL_SECONDS), MAX_TTL_SECONDS);
    const now = this._now();
    const staleGrace = (meta.staleGrace ?? 60) * 1000;
    const entry = {
      key, name, type: String(type).toUpperCase(), data, negative,
      storedAt: now,
      ttl,
      expiresAt: now + ttl * 1000,
      staleUntil: now + ttl * 1000 + staleGrace
    };
    if (this.entries.has(key)) this.entries.delete(key);
    this.entries.set(key, entry);
    this.stats.stores++;
    this._evict();
    return entry;
  }

  _evict() {
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      this.entries.delete(oldest);
      this.stats.evictions++;
    }
  }

  /** Drops expired entries; returns the number removed. */
  prune() {
    const now = this._now();
    let removed = 0;
    for (const [key, entry] of this.entries) {
      if (now >= entry.staleUntil) { this.entries.delete(key); removed++; this.stats.expirations++; }
    }
    return removed;
  }

  clear() {
    this.entries.clear();
    this.inflight.clear();
  }

  /**
   * Single-flight wrapper: concurrent callers for the same key share one
   * factory invocation. Errors are propagated to all waiters and never cached.
   *
   * @template T
   * @param {string} key
   * @param {() => Promise<T>} factory
   * @param {(value:T) => {ttl?:number, negative?:boolean, negativeTtl?:number}} [store]
   */
  async singleFlight(key, factory, store) {
    const existing = this.inflight.get(key);
    if (existing) { this.stats.singleFlightJoins++; return existing; }
    const promise = (async () => {
      try {
        const value = await factory();
        if (store) {
          const meta = store(value);
          if (meta) {
            // Key format is `${TYPE}|${name}` — see DnsCache.key().
            const [type, name] = key.split('|');
            this.set(name, type, value, meta);
          }
        }
        return value;
      } finally {
        this.inflight.delete(key);
      }
    })();
    this.inflight.set(key, promise);
    return promise;
  }

  snapshot() {
    const now = this._now();
    return {
      entries: this.entries.size,
      maxEntries: this.maxEntries,
      live: [...this.entries.values()].filter((e) => now < e.expiresAt).length,
      inflight: this.inflight.size,
      stats: { ...this.stats }
    };
  }
}

export default DnsCache;
