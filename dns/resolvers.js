/**
 * OmniShield X — encrypted resolver pool (DoH / DoT).
 *
 * REAL CAPABILITIES
 *  - DoH over HTTPS is fully implemented and used by the web platform:
 *      * JSON transport (application/dns-json) where the operator offers it
 *      * wire transport (application/dns-message, RFC 8484 GET) everywhere else
 *  - DoT (RFC 7858) framing is implemented and unit-tested, but a browser
 *    cannot open a TCP socket to port 853. DoT therefore only runs in the
 *    native core; the web platform says so instead of pretending.
 *  - Health-based fallback: EWMA latency, consecutive-failure circuit breaker,
 *    per-resolver timeouts. A failing resolver stops receiving traffic until
 *    its cooldown expires.
 *
 * NOT IMPLEMENTED (never claimed): DoQ, DNSCrypt, local recursive resolution.
 */
import { decodeMessage, encodeQuery, addressesOf, chainOf, minTtl, typeFromString, TYPE, toBase64Url } from './codec.js';
import { assessDnssec } from './dnssec.js';

/**
 * Registry of public encrypted resolvers. `privacy`/`filtering` describe the
 * operator's own published policy — we quote it, we do not verify it.
 */
export const RESOLVERS = Object.freeze([
  {
    id: 'cloudflare',
    name: 'Cloudflare 1.1.1.1',
    operator: 'Cloudflare',
    dohJson: 'https://cloudflare-dns.com/dns-query',
    dohWire: 'https://cloudflare-dns.com/dns-query',
    dot: 'one.one.one.one',
    ipv4: '1.1.1.1',
    ipv6: '2606:4700:4700::1111',
    dnssec: true,
    privacy: 'Operator states queries are not sold and logs are purged within 25h',
    filtering: 'none (1.1.1.2/1.1.1.3 variants block malware only)'
  },
  {
    id: 'google',
    name: 'Google Public DNS',
    operator: 'Google',
    dohJson: 'https://dns.google/resolve',
    dohWire: 'https://dns.google/dns-query',
    dot: 'dns.google',
    ipv4: '8.8.8.8',
    ipv6: '2001:4860:4860::8888',
    dnssec: true,
    privacy: 'Operator states temporary logs are anonymised and deleted after 24-48h',
    filtering: 'none'
  },
  {
    id: 'quad9',
    name: 'Quad9',
    operator: 'Quad9 Foundation',
    dohWire: 'https://dns.quad9.net/dns-query',
    dot: 'dns.quad9.net',
    ipv4: '9.9.9.9',
    ipv6: '2620:fe::fe',
    dnssec: true,
    privacy: 'Swiss non-profit; operator states no IP logging',
    filtering: 'blocks malware/phishing domains (9.9.9.9); 9.9.9.10 is unfiltered'
  },
  {
    id: 'adguard',
    name: 'AdGuard DNS',
    operator: 'AdGuard',
    dohWire: 'https://dns.adguard-dns.com/dns-query',
    dot: 'dns.adguard-dns.com',
    ipv4: '94.140.14.14',
    ipv6: '2a10:50c0::ad1:ff',
    dnssec: true,
    privacy: 'Operator states no permanent logs of personal data',
    filtering: 'blocks ads and trackers at resolver level (own list)'
  },
  {
    id: 'mullvad',
    name: 'Mullvad DNS',
    operator: 'Mullvad VPN',
    dohWire: 'https://dns.mullvad.net/dns-query',
    dot: 'dns.mullvad.net',
    ipv4: '194.242.2.2',
    ipv6: '2a07:e340::2',
    dnssec: true,
    privacy: 'Operator states no logging of DNS queries',
    filtering: 'blocks ads and trackers (own list)'
  }
]);

export const RESOLVER_BY_ID = Object.freeze(
  Object.fromEntries(RESOLVERS.map((r) => [r.id, r]))
);

export class UnsupportedTransportError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UnsupportedTransportError';
    this.code = 'TRANSPORT_UNSUPPORTED';
  }
}

export class ResolverTimeoutError extends Error {
  constructor(resolverId, ms) {
    super(`resolver ${resolverId} timed out after ${ms}ms`);
    this.name = 'ResolverTimeoutError';
    this.code = 'TIMEOUT';
  }
}

/* ------------------------------------------------------------------ */
/* Health tracking                                                     */
/* ------------------------------------------------------------------ */

export class ResolverHealth {
  constructor(options = {}) {
    this.ewmaAlpha = options.ewmaAlpha ?? 0.3;
    this.failureThreshold = options.failureThreshold ?? 3;
    this.cooldownMs = options.cooldownMs ?? 60000;
    this.clock = options.clock ?? (() => Date.now());
    /** @type {Map<string, object>} */
    this.state = new Map();
  }

  _stateFor(id) {
    if (!this.state.has(id)) {
      this.state.set(id, {
        id, successes: 0, failures: 0, consecutiveFailures: 0,
        ewmaMs: null, lastLatencyMs: null, openUntil: 0, lastError: null, lastSuccessAt: 0
      });
    }
    return this.state.get(id);
  }

  recordSuccess(id, latencyMs) {
    const s = this._stateFor(id);
    s.successes++;
    s.consecutiveFailures = 0;
    s.lastLatencyMs = latencyMs;
    s.ewmaMs = s.ewmaMs == null ? latencyMs : s.ewmaMs + this.ewmaAlpha * (latencyMs - s.ewmaMs);
    s.openUntil = 0;
    s.lastError = null;
    s.lastSuccessAt = this.clock();
    return s;
  }

  recordFailure(id, error) {
    const s = this._stateFor(id);
    s.failures++;
    s.consecutiveFailures++;
    s.lastError = error?.message || String(error);
    if (s.consecutiveFailures >= this.failureThreshold) {
      s.openUntil = this.clock() + this.cooldownMs;
    }
    return s;
  }

  isAvailable(id) {
    const s = this._stateFor(id);
    return this.clock() >= s.openUntil;
  }

  /** Lower is better. Unavailable resolvers sort last. */
  score(id) {
    const s = this._stateFor(id);
    if (this.clock() < s.openUntil) return Number.POSITIVE_INFINITY;
    const latency = s.ewmaMs ?? 250;
    const total = s.successes + s.failures;
    const reliability = total === 0 ? 0.85 : s.successes / total;
    return latency + (1 - reliability) * 5000 + s.consecutiveFailures * 250;
  }

  snapshot() {
    return [...this.state.values()].map((s) => ({ ...s, available: this.clock() >= s.openUntil }));
  }
}

/* ------------------------------------------------------------------ */
/* DoH transports                                                      */
/* ------------------------------------------------------------------ */

function jsonToMessage(json) {
  /** Converts a DoH JSON reply into the generic message shape used platform-wide. */
  const toRr = (rr) => {
    const type = Number(rr.type);
    const base = { name: String(rr.name || '').replace(/\.$/, ''), type, typeName: typeNameSafe(type), ttl: Number(rr.TTL ?? rr.ttl ?? 0) };
    if (type === TYPE.A) return { ...base, data: { address: rr.data } };
    if (type === TYPE.AAAA) return { ...base, data: { address: rr.data } };
    if (type === TYPE.CNAME || type === TYPE.NS || type === TYPE.PTR) return { ...base, data: { target: String(rr.data || '').replace(/\.$/, '') } };
    if (type === TYPE.TXT) return { ...base, data: { text: String(rr.data || '').replace(/^"|"$/g, '') } };
    if (type === TYPE.SOA) return { ...base, data: { text: rr.data } };
    return { ...base, data: { raw: rr.data } };
  };
  const answers = (json.Answer || []).map(toRr);
  const authorities = (json.Authority || []).map(toRr);
  return {
    id: 0,
    flags: {
      qr: true,
      authenticatedData: !!json.AD,
      checkingDisabled: !!json.CD,
      truncated: !!json.TC,
      recursionDesired: !!json.RD,
      recursionAvailable: !!json.RA,
      rcode: Number(json.Status ?? 0)
    },
    rcode: Number(json.Status ?? 0),
    rcodeName: ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED'][Number(json.Status ?? 0)] || `RCODE${json.Status}`,
    questions: (json.Question || []).map((q) => ({
      name: String(q.name || '').replace(/\.$/, ''), type: Number(q.type), typeName: typeNameSafe(Number(q.type))
    })),
    answers,
    authorities,
    additionals: [],
    edns: null,
    source: 'doh-json',
    comment: json.Comment || null
  };
}

function typeNameSafe(type) {
  const entry = Object.entries(TYPE).find(([, v]) => v === type);
  return entry ? entry[0] : `TYPE${type}`;
}

/**
 * RFC 2308 negative TTL from the SOA minimum, when available.
 * Handles both the binary SOA record (`data.minimum`) and the DoH JSON text
 * form (`"ns. hostmaster. serial refresh retry expire minimum"`).
 */
function negativeTtlFrom(message) {
  const clamp = (v) => Math.min(Math.max(Math.round(v), 1), 3600);
  const soa = message.authorities.find((r) => r.type === TYPE.SOA);
  if (Number.isFinite(soa?.data?.minimum)) return clamp(soa.data.minimum);
  const text = soa?.data?.text;
  if (typeof text === 'string') {
    const fields = text.trim().split(/\s+/);
    const last = Number(fields[fields.length - 1]);
    if (Number.isFinite(last)) return clamp(last);
  }
  return 60;
}

export class DohTransport {
  /**
   * @param {{fetchImpl?:typeof fetch, timeoutMs?:number, preferJson?:boolean}} [options]
   */
  constructor(options = {}) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.preferJson = options.preferJson ?? true;
  }

  _fetch() {
    if (!this.fetchImpl) {
      throw new UnsupportedTransportError('fetch is unavailable in this environment');
    }
    return this.fetchImpl;
  }

  async _withTimeout(url, init, resolverId) {
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = setTimeout(() => controller?.abort(), this.timeoutMs);
    try {
      return await this._fetch()(url, { ...init, signal: controller?.signal ?? undefined });
    } catch (err) {
      if (err?.name === 'AbortError') throw new ResolverTimeoutError(resolverId, this.timeoutMs);
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Resolves a name against one resolver.
   * @returns {Promise<{message:object, transport:string}>}
   */
  async query(resolver, name, type) {
    const wantJson = this.preferJson && !!resolver.dohJson;
    if (wantJson) {
      const url = new URL(resolver.dohJson);
      url.searchParams.set('name', name);
      // The JSON API accepts names, but numeric types are unambiguous.
      url.searchParams.set('type', String(typeFromString(String(type))));
      url.searchParams.set('do', '1');
      const res = await this._withTimeout(url.toString(), {
        headers: { accept: 'application/dns-json' },
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer'
      }, resolver.id);
      if (!res.ok) throw new Error(`HTTP ${res.status} from ${resolver.name}`);
      const json = await res.json();
      return { message: jsonToMessage(json), transport: 'DoH-JSON' };
    }

    if (!resolver.dohWire) throw new UnsupportedTransportError(`${resolver.name} offers no DoH endpoint usable from a browser`);
    const query = encodeQuery({ name, type, dnssec: true });
    const url = `${resolver.dohWire}${resolver.dohWire.includes('?') ? '&' : '?'}dns=${toBase64Url(query.bytes)}`;
    const res = await this._withTimeout(url, {
      headers: { accept: 'application/dns-message' },
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer'
    }, resolver.id);
    if (!res.ok) throw new Error(`HTTP ${res.status} from ${resolver.name}`);
    const buf = new Uint8Array(await res.arrayBuffer());
    return { message: decodeMessage(buf), transport: 'DoH-WIRE' };
  }
}

/**
 * DoT transport. The framing codec is real and tested; the socket is not
 * available in a browser, so this transport reports that truthfully instead of
 * silently downgrading to plaintext DNS.
 */
export class DotTransport {
  static capability() {
    return {
      implemented: true,
      usableInBrowser: false,
      reason: 'Browsers cannot open arbitrary TCP sockets (port 853). DoT runs in the native core only.',
      spec: 'RFC 7858 — 2-byte length-prefixed TCP stream'
    };
  }
  async query(resolver) {
    throw new UnsupportedTransportError(
      `DoT to ${resolver?.dot || 'resolver'}:853 is not reachable from a browser sandbox. ` +
      'OmniShield X will not silently fall back to unencrypted DNS.'
    );
  }
}

/* ------------------------------------------------------------------ */
/* Pool                                                                */
/* ------------------------------------------------------------------ */

export class ResolverPool {
  /**
   * @param {{resolvers?:Array, transport?:DohTransport, health?:ResolverHealth,
   *          clock?:()=>number, hedgeDelayMs?:number}} [options]
   */
  constructor(options = {}) {
    this.resolvers = options.resolvers ?? RESOLVERS;
    this.transport = options.transport ?? new DohTransport();
    this.health = options.health ?? new ResolverHealth({ clock: options.clock });
    this.clock = options.clock ?? (() => Date.now());
    this.hedgeDelayMs = options.hedgeDelayMs ?? 0;
    this.attemptsLog = [];
  }

  /** Preferred order: healthiest first, round-robin among equals. */
  order() {
    return [...this.resolvers]
      .map((r) => ({ resolver: r, score: this.health.score(r.id) }))
      .sort((a, b) => a.score - b.score)
      .map((x) => x.resolver);
  }

  /**
   * Queries with intelligent fallback.
   * @param {string} name
   * @param {string} type
   * @param {{preferredIds?:string[]}} [options]
   */
  async query(name, type = 'A', options = {}) {
    const ordered = this.order();
    const preferred = options.preferredIds?.length
      ? ordered.slice().sort((a, b) => {
        const ai = options.preferredIds.indexOf(a.id);
        const bi = options.preferredIds.indexOf(b.id);
        return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
      })
      : ordered;

    const attempts = [];
    let lastError = null;

    for (const resolver of preferred) {
      const started = this.clock();
      try {
        const { message, transport } = await this.transport.query(resolver, name, type);
        const latencyMs = Math.max(0, this.clock() - started);
        this.health.recordSuccess(resolver.id, latencyMs);
        const attempt = { resolverId: resolver.id, resolverName: resolver.name, transport, ok: true, latencyMs, rcode: message.rcode };
        attempts.push(attempt);
        this.attemptsLog.push({ ...attempt, name, type, at: this.clock() });
        if (this.attemptsLog.length > 500) this.attemptsLog.shift();
        return this._buildResult({ name, type, resolver, message, transport, latencyMs, attempts, cached: false });
      } catch (err) {
        const latencyMs = Math.max(0, this.clock() - started);
        this.health.recordFailure(resolver.id, err);
        lastError = err;
        const attempt = {
          resolverId: resolver.id, resolverName: resolver.name, ok: false,
          latencyMs, error: err?.message || String(err), code: err?.code || 'ERROR'
        };
        attempts.push(attempt);
        this.attemptsLog.push({ ...attempt, name, type, at: this.clock() });
        if (this.attemptsLog.length > 500) this.attemptsLog.shift();
        if (err instanceof UnsupportedTransportError) continue;
      }
    }

    return {
      name, type, status: 'error', ok: false, addresses: [], cname: [],
      ttl: 0, negative: false, attempts, transport: null, resolver: null,
      latencyMs: attempts.reduce((a, b) => a + b.latencyMs, 0),
      error: lastError?.message || 'all resolvers failed',
      dnssec: assessDnssec({ message: null, requested: true, transportFailed: true })
    };
  }

  _buildResult({ name, type, resolver, message, transport, latencyMs, attempts, cached }) {
    const nx = message.rcode === 3;
    const servfail = message.rcode === 2;
    const addrs = addressesOf(message, type);
    const dnssect = assessDnssec({ message, requested: true, resolverName: resolver.name });
    return {
      name,
      type: String(type).toUpperCase(),
      status: nx ? 'nxdomain' : servfail ? 'servfail' : 'ok',
      ok: !nx && !servfail,
      addresses: addrs.map((a) => a.address),
      cname: chainOf(message),
      ttl: nx ? negativeTtlFrom(message) : Math.max(0, minTtl(message, 60)),
      negative: nx,
      negativeTtl: nx ? negativeTtlFrom(message) : undefined,
      resolver: { id: resolver.id, name: resolver.name, operator: resolver.operator },
      transport,
      latencyMs,
      attempts,
      dnssec: dnssect,
      message,
      cached
    };
  }
}

export { jsonToMessage, negativeTtlFrom, typeFromString };
