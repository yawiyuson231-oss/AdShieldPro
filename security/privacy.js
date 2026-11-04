/**
 * OmniShield X — privacy-preserving local analytics.
 *
 * PRINCIPLES
 *  - Nothing leaves the device. There is no analytics endpoint and no network
 *    code in this module; the only output is a report the user can read/export.
 *  - Raw hostnames are never persisted. Where a per-domain distinction is
 *    needed (counting distinct domains), only a salted SHA-256 prefix is stored.
 *  - Small buckets are suppressed (k-anonymity, default k=10), so an exported
 *    report cannot single out one request.
 *  - Retention is enforced by date buckets; expired buckets are deleted.
 */
import { sha256Hex, shortHash } from './sha256.js';

const DAY_MS = 86_400_000;

export class PrivateAnalytics {
  /**
   * @param {{clock?:()=>number, salt?:string, k?:number, retentionDays?:number,
   *          storage?:object, prefix?:string, maxBuckets?:number}} [options]
   */
  constructor(options = {}) {
    this.clock = options.clock ?? (() => Date.now());
    this.salt = options.salt ?? 'omnishield-local-v1';
    this.k = options.k ?? 10;
    this.retentionDays = options.retentionDays ?? 30;
    this.storage = options.storage ?? null;
    this.prefix = options.prefix ?? 'analytics:';
    this.maxBuckets = options.maxBuckets ?? 5000;
    /** day -> {categories:Map, kinds:Map, buckets:Set} */
    this.days = new Map();
    this.saltHash = sha256Hex(this.salt).slice(0, 16);
    this.stats = { recorded: 0, dropped: 0 };
  }

  _dayKey(at = this.clock()) {
    return new Date(at).toISOString().slice(0, 10);
  }

  _day(at) {
    const key = this._dayKey(at);
    let day = this.days.get(key);
    if (!day) {
      day = { categories: new Map(), kinds: new Map(), buckets: new Set() };
      this.days.set(key, day);
      this._purge();
    }
    return day;
  }

  _purge() {
    const cutoff = this._dayKey(this.clock() - this.retentionDays * DAY_MS);
    for (const key of [...this.days.keys()]) if (key < cutoff) this.days.delete(key);
  }

  /**
   * Records an event. `domain` is hashed immediately and never stored in the clear.
   * @param {{kind:'blocked'|'allowed'|'analysis'|'firewall', category?:string,
   *          domain?:string, at?:number}} event
   */
  record(event) {
    const at = event.at ?? this.clock();
    const day = this._day(at);
    const category = String(event.category || 'UNCATEGORISED').toUpperCase();
    day.categories.set(category, (day.categories.get(category) || 0) + 1);
    const kind = String(event.kind || 'unknown');
    day.kinds.set(kind, (day.kinds.get(kind) || 0) + 1);

    if (event.domain) {
      if (day.buckets.size >= this.maxBuckets) { this.stats.dropped++; }
      else day.buckets.add(shortHash(`${this.saltHash}|${String(event.domain).toLowerCase()}`));
    }
    this.stats.recorded++;
    return true;
  }

  /** True if a given domain is already in today's distinct set (no raw compare stored). */
  hasSeen(domain, at = this.clock()) {
    const day = this._day(at);
    return day.buckets.has(shortHash(`${this.saltHash}|${String(domain).toLowerCase()}`));
  }

  /**
   * Human-readable report with k-anonymity suppression.
   */
  report() {
    const days = [...this.days.entries()].sort((a, b) => b[0].localeCompare(a[0])).map(([day, data]) => {
      const categories = {};
      const suppressed = [];
      let kept = 0;
      for (const [cat, count] of data.categories) {
        if (count < this.k) suppressed.push({ category: cat, count });
        else { categories[cat] = count; kept += count; }
      }
      return {
        day,
        categories,
        suppressedBuckets: suppressed.length,
        suppressedEvents: suppressed.reduce((a, b) => a + b.count, 0),
        reportedEvents: kept,
        distinctDomains: data.buckets.size,
        kinds: Object.fromEntries(data.kinds)
      };
    });

    const totals = { reported: 0, suppressed: 0, distinctDomains: 0 };
    for (const d of days) {
      totals.reported += d.reportedEvents;
      totals.suppressed += d.suppressedEvents;
      totals.distinctDomains = Math.max(totals.distinctDomains, d.distinctDomains);
    }

    return {
      generatedAt: new Date(this.clock()).toISOString(),
      days,
      totals,
      k: this.k,
      retentionDays: this.retentionDays,
      note:
        `Aggregated locally on this device. Hostnames are stored only as salted hashes and categories with fewer than ` +
        `${this.k} events are suppressed, so this report cannot single out an individual request.`,
      leavesDevice: false
    };
  }

  /** JSON export (the only supported way to move analytics off-device: by hand). */
  exportJSON() { return JSON.stringify(this.report(), null, 2); }

  /** Persists aggregate state (no hostnames are ever written). */
  async flush() {
    if (!this.storage) return false;
    const serialized = JSON.stringify({
      version: 1,
      saltHash: this.saltHash,
      days: [...this.days.entries()].map(([day, d]) => ({
        day,
        categories: [...d.categories.entries()],
        kinds: [...d.kinds.entries()],
        buckets: [...d.buckets]
      }))
    });
    await this.storage.setItem(`${this.prefix}state`, serialized);
    return true;
  }

  async load() {
    if (!this.storage) return false;
    const raw = await this.storage.getItem(`${this.prefix}state`);
    if (!raw) return false;
    try {
      const parsed = JSON.parse(raw);
      if (parsed.version !== 1) return false;
      this.saltHash = parsed.saltHash || this.saltHash;
      this.days.clear();
      for (const day of parsed.days || []) {
        this.days.set(day.day, {
          categories: new Map(day.categories || []),
          kinds: new Map(day.kinds || []),
          buckets: new Set(day.buckets || [])
        });
      }
      this._purge();
      return true;
    } catch {
      return false;
    }
  }

  async clear() {
    this.days.clear();
    this.stats = { recorded: 0, dropped: 0 };
    if (this.storage) await this.storage.removeItem(`${this.prefix}state`);
    return true;
  }
}

export default PrivateAnalytics;
