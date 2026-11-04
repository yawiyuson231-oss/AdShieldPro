/**
 * OmniShield X — threat-feed manager (automatic updates, integrity, rollback).
 *
 * Real behaviour, no theatre:
 *  - conditional GET (ETag / If-Modified-Since) so unchanged feeds cost nothing,
 *  - structural validation before a feed is allowed to replace the active one,
 *  - SHA-256 content hashes for integrity and for matching an expected hash when
 *    one is published,
 *  - rollback protection: a feed that shrinks drastically or parses badly is
 *    rejected and the last known-good copy is kept,
 *  - every failure is reported with the reason and the retained version.
 *
 * The updater never "downloads and blocks everything": an unvalidated feed is
 * never applied.
 */
import { sha256Hex } from './sha256.js';

/** Real upstream feeds (raw.githubusercontent.com, GPLv3, HaGeZi DNS blocklists). */
export const FEED_REGISTRY = Object.freeze([
  {
    id: 'core_lite_ads',
    name: 'HaGeZi Multi LIGHT — ads & trackers',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt',
    category: 'ADS',
    license: 'GPLv3',
    homepage: 'https://github.com/hagezi/dns-blocklists',
    bundled: 'assets/core_lite_ads.txt',
    minRules: 50000
  },
  {
    id: 'core_max_ads',
    name: 'HaGeZi Multi PRO — ads & trackers',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt',
    category: 'ADS',
    license: 'GPLv3',
    homepage: 'https://github.com/hagezi/dns-blocklists',
    minRules: 100000
  },
  {
    id: 'core_threats',
    name: 'HaGeZi TIF mini — malware & phishing',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt',
    category: 'MALWARE',
    license: 'GPLv3',
    homepage: 'https://github.com/hagezi/dns-blocklists',
    minRules: 100000
  }
]);

const MAX_FEED_BYTES = 32 * 1024 * 1024;
const MIN_FEED_BYTES = 1024;
/** A feed losing more than this fraction of its rules is treated as suspicious. */
const SHRINK_TOLERANCE = 0.4;

export class FeedValidationError extends Error {
  constructor(reason, detail) {
    super(detail ? `${reason}: ${detail}` : reason);
    this.name = 'FeedValidationError';
    this.reason = reason;
    this.detail = detail;
  }
}

/**
 * Validates feed text before it may become active.
 * @returns {{ok:boolean, reason?:string, stats:{rules:number, invalid:number, bytes:number, hash:string}}}
 */
export function validateFeedText(text, descriptor = {}) {
  const bytes = new TextEncoder().encode(String(text ?? '')).length;
  const stats = { rules: 0, invalid: 0, bytes, hash: sha256Hex(String(text ?? '')) };

  if (bytes < MIN_FEED_BYTES) throw new FeedValidationError('feed-too-small', `${bytes} bytes`);
  if (bytes > MAX_FEED_BYTES) throw new FeedValidationError('feed-too-large', `${bytes} bytes`);

  const head = String(text).slice(0, 2048).toLowerCase();
  if (head.includes('<html') || head.includes('<!doctype html')) {
    throw new FeedValidationError('html-instead-of-list', 'upstream returned a web page (captive portal or error page?)');
  }

  let dataLines = 0;
  for (const rawLine of String(text).split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('!') || line.startsWith('#') || line.startsWith('[')) continue;
    dataLines++;
    if (/^\|\|[^\s^]*\^?(\$[^\s]*)?$/.test(line) || /^(@@)?\|\|[^\s]+$/.test(line)
      || /^(0\.0\.0\.0|127\.0\.0\.1)\s+\S+$/.test(line) || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(line)) {
      stats.rules++;
    } else {
      stats.invalid++;
    }
  }

  if (dataLines === 0) throw new FeedValidationError('empty-feed', 'no data lines');
  const validRatio = stats.rules / dataLines;
  if (validRatio < 0.9) {
    throw new FeedValidationError('malformed-feed', `only ${(validRatio * 100).toFixed(1)}% of ${dataLines} lines parsed as rules`);
  }
  if (descriptor.minRules && stats.rules < descriptor.minRules) {
    throw new FeedValidationError('below-expected-size', `${stats.rules} rules < expected ${descriptor.minRules}`);
  }
  return { ok: true, stats };
}

export class FeedManager {
  /**
   * @param {{fetchImpl?:Function, storage:object, clock?:()=>number, onEvent?:Function,
   *          registry?:Array, storagePrefix?:string}} options
   */
  constructor(options = {}) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
    this.storage = options.storage;
    if (!this.storage) throw new Error('FeedManager requires a storage adapter');
    this.clock = options.clock ?? (() => Date.now());
    this.onEvent = options.onEvent ?? null;
    this.registry = options.registry ?? FEED_REGISTRY;
    this.prefix = options.storagePrefix ?? 'feed:';
  }

  _metaKey(id) { return `${this.prefix}${id}:meta`; }
  _contentKey(id) { return `${this.prefix}${id}:content`; }

  _emit(event) { if (this.onEvent) { try { this.onEvent(event); } catch { /* ignore */ } } }

  descriptor(id) {
    const feed = this.registry.find((f) => f.id === id);
    if (!feed) throw new Error(`unknown feed "${id}"`);
    return feed;
  }

  /** Current stored metadata for a feed (or null). */
  async status(id) {
    this.descriptor(id);
    const raw = await this.storage.getItem(this._metaKey(id));
    if (!raw) return { id, installed: false };
    try {
      const meta = JSON.parse(raw);
      return {
        id, installed: true, ...meta,
        ageMs: Math.max(0, this.clock() - Date.parse(meta.fetchedAt)),
        stale: this.clock() - Date.parse(meta.fetchedAt) > 24 * 3600_000
      };
    } catch {
      return { id, installed: false, error: 'corrupt-metadata' };
    }
  }

  async list() {
    return Promise.all(this.registry.map((f) => this.status(f.id)));
  }

  /** The active rule text for a feed, if any. */
  async content(id) {
    this.descriptor(id);
    return this.storage.getItem(this._contentKey(id));
  }

  /**
   * Fetches and applies a feed update.
   *
   * @param {string} id
   * @param {{force?:boolean, expectedHash?:string, text?:string}} [options]
   * @returns {Promise<{ok:boolean, changed:boolean, reason?:string, meta?:object, retained?:object}>}
   */
  async update(id, options = {}) {
    const feed = this.descriptor(id);
    const previous = await this.status(id);
    let text = options.text;
    let etag = null;
    let lastModified = null;

    if (text === undefined) {
      if (!this.fetchImpl) return this._fail(id, previous, 'no-fetch', 'fetch is unavailable in this environment');
      const headers = { accept: 'text/plain' };
      if (!options.force && previous.installed && previous.etag) headers['if-none-match'] = previous.etag;
      if (!options.force && previous.installed && previous.lastModified) headers['if-modified-since'] = previous.lastModified;

      let response;
      try {
        response = await this.fetchImpl(feed.url, { headers, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
      } catch (err) {
        return this._fail(id, previous, 'network-error', err?.message || String(err));
      }

      if (response.status === 304) {
        const meta = { ...(previous.installed ? previous : {}), checkedAt: new Date(this.clock()).toISOString() };
        await this._storeMeta(id, meta);
        this._emit({ kind: 'feed-update', feed: id, changed: false, reason: 'not-modified', at: this.clock() });
        return { ok: true, changed: false, reason: 'not-modified', meta };
      }
      if (!response.ok) {
        return this._fail(id, previous, 'http-error', `HTTP ${response.status}`);
      }
      text = await response.text();
      etag = response.headers?.get?.('etag') || null;
      lastModified = response.headers?.get?.('last-modified') || null;
    }

    // ---- Validate before anything is applied ----
    let stats;
    try {
      ({ stats } = validateFeedText(text, feed));
    } catch (err) {
      return this._fail(id, previous, err.reason || 'validation-failed', err.detail || err.message);
    }

    if (options.expectedHash && stats.hash !== options.expectedHash.toLowerCase()) {
      return this._fail(id, previous, 'hash-mismatch', `expected ${options.expectedHash.slice(0, 16)}…, got ${stats.hash.slice(0, 16)}…`);
    }

    // ---- Rollback protection: refuse suspicious shrinkage ----
    if (previous.installed && Number.isFinite(previous.rules)) {
      const shrink = (previous.rules - stats.rules) / previous.rules;
      if (shrink > SHRINK_TOLERANCE) {
        return this._fail(id, previous, 'suspicious-shrink',
          `${stats.rules} rules vs ${previous.rules} previously (${(shrink * 100).toFixed(0)}% drop) — retained previous version`);
      }
    }

    const meta = {
      id,
      name: feed.name,
      category: feed.category,
      license: feed.license,
      url: feed.url,
      fetchedAt: new Date(this.clock()).toISOString(),
      checkedAt: new Date(this.clock()).toISOString(),
      hash: stats.hash,
      hashAlgorithm: 'sha256',
      rules: stats.rules,
      bytes: stats.bytes,
      etag,
      lastModified
    };

    try {
      await this.storage.setItem(this._contentKey(id), text);
      await this._storeMeta(id, meta);
    } catch (err) {
      return this._fail(id, previous, 'storage-error', err?.message || String(err));
    }

    this._emit({ kind: 'feed-update', feed: id, changed: true, rules: stats.rules, hash: stats.hash, at: this.clock() });
    return { ok: true, changed: true, meta };
  }

  async _storeMeta(id, meta) {
    await this.storage.setItem(this._metaKey(id), JSON.stringify(meta));
  }

  async _fail(id, previous, reason, detail) {
    const result = {
      ok: false, changed: false, reason, detail,
      retained: previous?.installed
        ? { fetchedAt: previous.fetchedAt, rules: previous.rules, hash: previous.hash }
        : null
    };
    this._emit({ kind: 'feed-update', feed: id, ok: false, reason, detail, at: this.clock() });
    return result;
  }

  /**
   * Verifies the installed copy against its stored hash.
   * Detects silent corruption of locally cached feeds.
   */
  async verify(id) {
    const meta = await this.status(id);
    if (!meta.installed) return { ok: false, reason: 'not-installed' };
    const content = await this.content(id);
    if (content == null) return { ok: false, reason: 'missing-content' };
    const hash = sha256Hex(content);
    return {
      ok: hash === meta.hash,
      reason: hash === meta.hash ? 'ok' : 'hash-mismatch',
      expected: meta.hash,
      actual: hash
    };
  }

  /** Removes a feed (the bundled copy in assets/ is never touched). */
  async uninstall(id) {
    this.descriptor(id);
    await this.storage.removeItem(this._contentKey(id));
    await this.storage.removeItem(this._metaKey(id));
    return true;
  }
}

export default FeedManager;
