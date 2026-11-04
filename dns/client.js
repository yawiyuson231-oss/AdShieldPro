/**
 * OmniShield X — DNS resolution pipeline.
 *
 * One lookup passes through, in this exact order:
 *
 *   1. normalize + IP-literal shortcut   (no DNS, no filtering)
 *   2. filter engine                     (blocked names never leave the device)
 *   3. cache                             (positive, negative, stale-while-revalidate)
 *   4. single-flight                     (N identical lookups => 1 network request)
 *   5. encrypted resolver pool           (DoH, health-based fallback)
 *   6. DNSSEC assessment                 (AD bit / RRSIG inspection)
 *   7. observation emit                  (monitor + AETHER reputation)
 *
 * Every step is visible in the returned report, so the UI can always explain
 * what happened. Nothing is simulated: if the network is down, the result says
 * so instead of inventing an answer.
 */
import { OmniShieldFilterEngine } from '../engine.js';
import { DnsCache } from './cache.js';
import { DohTransport, ResolverPool, RESOLVERS, UnsupportedTransportError } from './resolvers.js';
import { DNSSEC_STATUS } from './dnssec.js';

export class DnsClient {
  /**
   * @param {{engine?:OmniShieldFilterEngine, pool?:ResolverPool, cache?:DnsCache,
   *          clock?:()=>number, fetchImpl?:typeof fetch, onObservation?:Function,
   *          timeoutMs?:number, staleWhileRevalidate?:boolean}} [options]
   */
  constructor(options = {}) {
    this.clock = options.clock ?? (() => Date.now());
    this.engine = options.engine ?? null;
    this.cache = options.cache ?? new DnsCache({ clock: this.clock });
    this.fetchImpl = options.fetchImpl;
    this.pool = options.pool ?? new ResolverPool({
      transport: new DohTransport({ fetchImpl: options.fetchImpl, timeoutMs: options.timeoutMs ?? 5000 }),
      clock: this.clock
    });
    this.onObservation = options.onObservation ?? null;
    this.staleWhileRevalidate = options.staleWhileRevalidate ?? true;
    this.stats = {
      lookups: 0, blocked: 0, cached: 0, network: 0, errors: 0,
      nxdomain: 0, totalLatencyMs: 0, latencySamples: [], byCategory: {}
    };
    this._latencies = [];
  }

  setEngine(engine) { this.engine = engine; }

  _record(event) {
    if (this.onObservation) {
      try { this.onObservation(event); } catch { /* observers must never break a lookup */ }
    }
  }

  _noteLatency(ms) {
    this.stats.totalLatencyMs += ms;
    this._latencies.push(ms);
    if (this._latencies.length > 500) this._latencies.shift();
  }

  /**
   * Resolves a hostname through the full pipeline.
   *
   * @param {string} input URL, host or domain
   * @param {{type?:string, skipFilter?:boolean, forceRefresh?:boolean,
   *          allowStale?:boolean, context?:object}} [options]
   */
  async lookup(input, options = {}) {
    const started = this.clock();
    const type = String(options.type ?? 'A').toUpperCase();
    this.stats.lookups++;

    const raw = String(input ?? '');

    // 1a. IP literals need no DNS and cannot be filtered by name.
    if (OmniShieldFilterEngine.isIpLiteral(raw)) {
      const result = {
        name: raw, type, status: 'ip-literal', ok: true, addresses: [raw],
        blocked: false, cached: false, reasons: ['Input is already an IP address; no DNS lookup was performed.'],
        latencyMs: this.clock() - started, dnssec: null, resolver: null, transport: null,
        ttl: null, pipeline: ['ip-literal']
      };
      this._record({ kind: 'lookup', at: this.clock(), ...result });
      return result;
    }

    const name = OmniShieldFilterEngine.normalizeDomain(raw);
    if (!name) {
      const result = {
        name: raw, type, status: 'invalid', ok: false, addresses: [], blocked: false,
        cached: false, reasons: ['Input is not a valid hostname.'],
        latencyMs: this.clock() - started, dnssec: null, resolver: null, transport: null,
        ttl: null, pipeline: ['invalid']
      };
      this.stats.errors++;
      this._record({ kind: 'lookup', at: this.clock(), ...result });
      return result;
    }

    // 2. Filter before any packet leaves the device.
    const verdict = options.skipFilter ? null : this.engine?.evaluate(name) ?? null;
    if (verdict?.blocked) {
      this.stats.blocked++;
      const cat = verdict.category || 'UNCATEGORISED';
      this.stats.byCategory[cat] = (this.stats.byCategory[cat] || 0) + 1;
      const result = {
        name, type, status: 'blocked', ok: false, addresses: [], blocked: true,
        blockedBy: { source: verdict.source, matched: verdict.matched, category: verdict.category },
        reasons: verdict.reasons, latencyMs: this.clock() - started,
        dnssec: null, resolver: null, transport: null, ttl: null,
        pipeline: ['normalize', 'filter:blocked']
      };
      this._record({ kind: 'blocked', at: this.clock(), ...result, context: options.context });
      return result;
    }

    // 3. Cache (fresh, or stale-while-revalidate).
    if (!options.forceRefresh) {
      const hit = this.cache.get(name, type);
      if (hit && !hit.stale) {
        this.stats.cached++;
        const result = this._fromCache(hit, { name, type, started, verdict, stale: false });
        this._record({ kind: 'lookup', at: this.clock(), ...result, context: options.context });
        return result;
      }
      if (hit && hit.stale && this.staleWhileRevalidate && options.allowStale !== false) {
        const result = this._fromCache(hit, { name, type, started, verdict, stale: true });
        this._record({ kind: 'lookup', at: this.clock(), ...result, context: options.context });
        // Refresh in the background; errors are swallowed (stale data is still served).
        this._network(name, type, options).catch(() => {});
        return result;
      }
    }

    // 4-6. Single-flight network resolution.
    const result = await this._network(name, type, options);
    this._record({ kind: 'lookup', at: this.clock(), ...result, context: options.context });
    return result;
  }

  _fromCache(hit, { name, type, started, verdict, stale }) {
    const data = hit.data;
    return {
      name, type,
      status: data.status, ok: data.ok, addresses: data.addresses, cname: data.cname,
      blocked: false, cached: true, stale,
      ttl: data.ttl, resolver: data.resolver, transport: data.transport,
      dnssec: data.dnssec,
      latencyMs: this.clock() - started,
      reasons: [
        stale
          ? `Served from cache after TTL expiry (stale, ${Math.round((this.clock() - hit.expiresAt) / 1000)}s old) while refreshing.`
          : `Served from the local cache; ${Math.max(0, Math.round((hit.expiresAt - this.clock()) / 1000))}s of TTL left.`,
        verdict ? `Filter verdict: ${verdict.source}.` : null
      ].filter(Boolean),
      pipeline: ['normalize', 'filter:allowed', stale ? 'cache:stale' : 'cache:hit']
    };
  }

  async _network(name, type, options) {
    const started = this.clock();
    this.stats.network++;
    const key = DnsCache.key(name, type);

    const result = await this.cache.singleFlight(
      key,
      () => this.pool.query(name, type, { preferredIds: options.preferredIds }),
      (value) => ({
        ttl: value.ttl, negative: value.negative, negativeTtl: value.negativeTtl
      })
    ).catch((err) => ({
      name, type, status: 'error', ok: false, addresses: [], cname: [], ttl: 0,
      negative: false, resolver: null, transport: null, latencyMs: this.clock() - started,
      error: err?.message || String(err),
      dnssec: { status: DNSSEC_STATUS.UNKNOWN, label: 'Unknown', detail: 'Lookup failed.' },
      attempts: []
    }));

    if (result.status === 'error') this.stats.errors++;
    if (result.status === 'nxdomain') this.stats.nxdomain++;
    this._noteLatency(this.clock() - started);

    return {
      ...result,
      blocked: false,
      cached: false,
      reasons: result.status === 'error'
        ? [`No encrypted resolver could answer: ${result.error}`, 'OmniShield X does not fall back to unencrypted DNS.']
        : [
          result.status === 'nxdomain'
            ? 'The resolver returned NXDOMAIN (the name does not exist).'
            : `${result.addresses.length} address record(s) received over ${result.transport} from ${result.resolver?.name}.`,
          result.dnssec?.detail
        ].filter(Boolean),
      pipeline: ['normalize', 'filter:allowed', 'cache:miss', `transport:${result.transport || 'none'}`, `dnssec:${result.dnssec?.status || 'n/a'}`]
    };
  }

  /** Resolves A and AAAA in parallel — real dual-stack behaviour. */
  async lookupDualStack(input, options = {}) {
    const [a, aaaa] = await Promise.all([
      this.lookup(input, { ...options, type: 'A' }),
      this.lookup(input, { ...options, type: 'AAAA' })
    ]);
    return {
      name: a.name || aaaa.name,
      blocked: a.blocked || aaaa.blocked,
      blockedBy: a.blockedBy || aaaa.blockedBy,
      ipv4: a.addresses, ipv6: aaaa.addresses,
      ttl: Math.min(a.ttl ?? Infinity, aaaa.ttl ?? Infinity),
      dnssec: [a.dnssec, aaaa.dnssec].filter(Boolean),
      results: { a, aaaa },
      latencyMs: Math.max(a.latencyMs, aaaa.latencyMs)
    };
  }

  latencyStats() {
    const samples = [...this._latencies].sort((x, y) => x - y);
    if (!samples.length) return { count: 0, p50: null, p95: null, max: null };
    const at = (p) => samples[Math.min(samples.length - 1, Math.floor(p * samples.length))];
    return { count: samples.length, p50: at(0.5), p95: at(0.95), max: samples[samples.length - 1] };
  }

  snapshot() {
    return {
      stats: {
        ...this.stats,
        latencySamples: undefined,
        byCategory: { ...this.stats.byCategory }
      },
      latency: this.latencyStats(),
      cache: this.cache.snapshot(),
      health: this.pool.health.snapshot(),
      order: this.pool.order().map((r) => r.id)
    };
  }
}

export { RESOLVERS, UnsupportedTransportError };
