/**
 * OmniShield X — real-time security monitor.
 *
 * Aggregates *actual* events produced by the DNS pipeline and the firewall into
 * bounded, time-bucketed metrics. No synthetic traffic is ever injected: if the
 * platform has seen nothing, the monitor shows nothing.
 *
 * Memory is bounded three ways: a ring buffer of recent events, minute buckets
 * covering a fixed window, and capped per-domain counters.
 */

const MAX_EVENTS = 800;
const MAX_DOMAINS = 400;

export class SecurityMonitor {
  /**
   * @param {{clock?:()=>number, bucketMs?:number, buckets?:number}} [options]
   */
  constructor(options = {}) {
    this.clock = options.clock ?? (() => Date.now());
    this.bucketMs = options.bucketMs ?? 60_000;
    this.bucketCount = options.buckets ?? 60;
    /** @type {Array<object>} newest last */
    this.events = [];
    /** @type {Map<number, object>} bucket start -> counters */
    this.buckets = new Map();
    this.domains = new Map();
    this.subscribers = new Set();
    this.totals = {
      events: 0, lookups: 0, blocked: 0, allowed: 0, errors: 0,
      firewallMonitors: 0, firewallBlocks: 0, latencySum: 0, latencyCount: 0
    };
    this.latencies = [];
  }

  /** Records one real event. */
  record(event) {
    const at = event.at ?? this.clock();
    const entry = { ...event, at };
    this.events.push(entry);
    if (this.events.length > MAX_EVENTS) this.events.shift();

    const bucketStart = Math.floor(at / this.bucketMs) * this.bucketMs;
    let bucket = this.buckets.get(bucketStart);
    if (!bucket) {
      bucket = { start: bucketStart, lookups: 0, blocked: 0, allowed: 0, errors: 0, latencySum: 0, latencyCount: 0, categories: {} };
      this.buckets.set(bucketStart, bucket);
      this._pruneBuckets(bucketStart);
    }

    this.totals.events++;
    switch (event.kind) {
      case 'blocked':
        this.totals.blocked++; bucket.blocked++;
        this.totals.lookups++; bucket.lookups++;
        break;
      case 'lookup':
        this.totals.lookups++; bucket.lookups++;
        if (event.status === 'error') { this.totals.errors++; bucket.errors++; }
        else { this.totals.allowed++; bucket.allowed++; }
        break;
      case 'validation':
        if (!event.ok) { this.totals.errors++; bucket.errors++; }
        break;
      case 'firewall':
        if (event.decision === 'block') { this.totals.firewallBlocks++; bucket.blocked++; }
        else if (event.decision === 'monitor') this.totals.firewallMonitors++;
        break;
      default:
        break;
    }

    if (event.category) {
      bucket.categories[event.category] = (bucket.categories[event.category] || 0) + 1;
    }
    if (Number.isFinite(event.latencyMs)) {
      this.totals.latencySum += event.latencyMs;
      this.totals.latencyCount++;
      bucket.latencySum += event.latencyMs;
      bucket.latencyCount++;
      this.latencies.push(event.latencyMs);
      if (this.latencies.length > 1000) this.latencies.shift();
    }
    if (event.domain) {
      const d = this.domains.get(event.domain) || { domain: event.domain, count: 0, blocked: 0, lastSeen: 0, category: null };
      d.count++;
      if (event.kind === 'blocked' || event.decision === 'block') d.blocked++;
      d.lastSeen = at;
      if (event.category) d.category = event.category;
      this.domains.set(event.domain, d);
      if (this.domains.size > MAX_DOMAINS) {
        let oldestKey = null; let oldest = Infinity;
        for (const [k, v] of this.domains) if (v.lastSeen < oldest) { oldest = v.lastSeen; oldestKey = k; }
        if (oldestKey) this.domains.delete(oldestKey);
      }
    }

    for (const fn of this.subscribers) {
      try { fn(entry); } catch { /* a broken observer must not break monitoring */ }
    }
    return entry;
  }

  _pruneBuckets(nowStart) {
    const cutoff = nowStart - (this.bucketCount - 1) * this.bucketMs;
    for (const key of this.buckets.keys()) if (key < cutoff) this.buckets.delete(key);
  }

  subscribe(fn) {
    this.subscribers.add(fn);
    return () => this.subscribers.delete(fn);
  }

  /** Rolling series for the dashboard chart (oldest first). */
  series(field = 'lookups', points = 30) {
    const now = Math.floor(this.clock() / this.bucketMs) * this.bucketMs;
    const out = [];
    for (let i = points - 1; i >= 0; i--) {
      const start = now - i * this.bucketMs;
      const bucket = this.buckets.get(start);
      out.push({ t: start, value: bucket ? (bucket[field] || 0) : 0 });
    }
    return out;
  }

  latencyPercentiles() {
    if (!this.latencies.length) return { count: 0, p50: null, p95: null, max: null };
    const sorted = [...this.latencies].sort((a, b) => a - b);
    const at = (p) => sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))];
    return {
      count: sorted.length,
      p50: Math.round(at(0.5) * 10) / 10,
      p95: Math.round(at(0.95) * 10) / 10,
      max: Math.round(sorted[sorted.length - 1] * 10) / 10
    };
  }

  topDomains(limit = 8) {
    return [...this.domains.values()]
      .sort((a, b) => b.count - a.count || b.lastSeen - a.lastSeen)
      .slice(0, limit);
  }

  categoryTotals() {
    const totals = {};
    for (const bucket of this.buckets.values()) {
      for (const [cat, n] of Object.entries(bucket.categories)) totals[cat] = (totals[cat] || 0) + n;
    }
    return totals;
  }

  metrics() {
    const averageLatency = this.totals.latencyCount
      ? Math.round((this.totals.latencySum / this.totals.latencyCount) * 10) / 10
      : null;
    const blockedRatio = this.totals.lookups ? Math.round((this.totals.blocked / this.totals.lookups) * 1000) / 10 : null;
    return {
      ...this.totals,
      averageLatency,
      blockedRatio,
      latency: this.latencyPercentiles(),
      categories: this.categoryTotals(),
      series: { lookups: this.series('lookups'), blocked: this.series('blocked') },
      topDomains: this.topDomains(),
      recent: this.events.slice(-40),
      bucketMs: this.bucketMs
    };
  }

  reset() {
    this.events.length = 0;
    this.buckets.clear();
    this.domains.clear();
    this.latencies.length = 0;
    for (const key of Object.keys(this.totals)) this.totals[key] = 0;
  }
}

export default SecurityMonitor;
