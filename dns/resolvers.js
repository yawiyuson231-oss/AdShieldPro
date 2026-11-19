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

import { encodeQuery, decodeMessage, addressesOf, chainOf, minTtl, typeFromString, rcodeToString, CLASS, TYPE, toBase64Url } from './codec.js';
import { assessDnssec } from './dnssec.js';
import { classify as classifyMediaHost } from '../guard/video-safety.js';

/**
 * EDNS Client Subnet (ECS) policy per resolver.
 *
 * Why this is the setting that matters for video: an authoritative server picks a
 * CDN edge from the *resolver's* address, not yours. Cloudflare's 1.1.1.1 sends no
 * client subnet, so a video CDN can hand you an edge in another region and
 * playback buffers; Google Public DNS and Quad9's `.11` service do forward a
 * truncated subnet, which puts you on a nearby edge.
 *
 * This is a trade-off, not a free win: ECS reveals a /24 of your address to the
 * authoritative server. Each value below is quoted from the operator's published
 * policy; it is never inferred or measured here.
 */
export const ECS_POLICY = Object.freeze({
  NONE: 'none',
  SUPPORTED: 'supported'
});

/**
 * Registry of public encrypted resolvers. `privacy`, `filtering` and `ecs`
 * describe the operator's own published policy — we quote it, we do not verify it.
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
    ecs: ECS_POLICY.NONE,
    ecsNote: 'No client subnet is forwarded, so CDN edge selection follows the resolver location. Best privacy; occasionally a distant video edge.',
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
    ecs: ECS_POLICY.SUPPORTED,
    ecsNote: 'Forwards a truncated client subnet to authoritative servers that support ECS, so video CDNs pick an edge near you.',
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
    ecs: ECS_POLICY.NONE,
    ecsNote: 'No client subnet. Quad9 publishes a separate ECS-enabled service (dns11.quad9.net / 9.9.9.11).',
    // Quad9 removed DoH over HTTP/1.1 on 2025-12-15. Browsers negotiate HTTP/2
    // themselves, so only the wire transport is used for this resolver.
    privacy: 'Swiss non-profit; operator states no IP logging',
    filtering: 'blocks malware/phishing domains (9.9.9.9); 9.9.9.10 is unfiltered'
  },
  {
    id: 'quad9-ecs',
    name: 'Quad9 Secure + ECS',
    operator: 'Quad9 Foundation',
    dohWire: 'https://dns11.quad9.net/dns-query',
    dot: 'dns11.quad9.net',
    ipv4: '9.9.9.11',
    ipv6: '2620:fe::11',
    dnssec: true,
    ecs: ECS_POLICY.SUPPORTED,
    ecsNote: 'Same malware blocking as 9.9.9.9 plus a truncated client subnet, for CDN-accurate video edge selection.',
    privacy: 'Operated by Quad9 Foundation under Swiss law; forwarding ECS is the documented trade-off of this endpoint',
    filtering: 'blocks malware/phishing domains and forwards ECS'
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
    ecs: ECS_POLICY.NONE,
    ecsNote: 'No client subnet is forwarded to authoritative servers.',
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
    ecs: ECS_POLICY.NONE,
    ecsNote: 'No client subnet is forwarded to authoritative servers.',
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

function parseRrsigTimestamp(token) {
  if (/^\d{14}$/.test(token)) {
    const iso = `${token.slice(0, 4)}-${token.slice(4, 6)}-${token.slice(6, 8)}T${token.slice(8, 10)}:${token.slice(10, 12)}:${token.slice(12, 14)}Z`;
    const ms = Date.parse(iso);
    if (Number.isFinite(ms)) return new Date(ms).toISOString();
  }
  if (/^\d+$/.test(token)) {
    const sec = Number(token);
    if (Number.isFinite(sec)) return new Date(sec * 1000).toISOString();
  }
  return undefined;
}

function parseRrsigText(raw) {
  const parts = String(raw ?? '').trim().split(/\s+/);
  if (parts.length < 9) return { raw };
  const [coveredRaw, algRaw, labelsRaw, origTtlRaw, expRaw, incRaw, keyTagRaw, signerRaw, ...sigParts] = parts;
  return {
    typeCovered: typeFromString(coveredRaw),
    algorithm: Number(algRaw),
    labels: Number(labelsRaw),
    originalTtl: Number(origTtlRaw),
    expiration: parseRrsigTimestamp(expRaw),
    inception: parseRrsigTimestamp(incRaw),
    keyTag: Number(keyTagRaw),
    signerName: signerRaw.replace(/\.$/, ''),
    signature: sigParts.join('')
  };
}

function jsonToMessage(json) {
  /** Converts a DoH JSON reply into the generic message shape used platform-wide. */
  const toRr = (rr) => {
    const type = Number(rr.type);
    const reportedTtl = Number(rr.TTL ?? rr.ttl ?? 0);
    const ttl = Number.isInteger(reportedTtl) && reportedTtl >= 0 && reportedTtl <= 0x7fffffff ? reportedTtl : 0;
    const base = { name: String(rr.name || '').replace(/\.$/, ''), type, typeName: typeNameSafe(type), ttl };
    if (type === TYPE.A) return { ...base, data: { address: rr.data } };
    if (type === TYPE.AAAA) return { ...base, data: { address: rr.data } };
    if (type === TYPE.CNAME || type === TYPE.NS || type === TYPE.PTR) return { ...base, data: { target: String(rr.data || '').replace(/\.$/, '') } };
    if (type === TYPE.TXT) return { ...base, data: { text: String(rr.data || '').replace(/^"|"$/g, '') } };
    if (type === TYPE.SOA) return { ...base, data: { text: rr.data } };
    if (type === TYPE.RRSIG) return { ...base, data: parseRrsigText(rr.data) };
    return { ...base, data: { raw: rr.data } };
  };
  const answers = (json.Answer || []).map(toRr);
  const authorities = (json.Authority || []).map(toRr);
  return {
    id: 0,
    flags: {
      qr: true,
      authenticatedData: json.AD === true,
      checkingDisabled: !!json.CD,
      truncated: !!json.TC,
      recursionDesired: !!json.RD,
      recursionAvailable: !!json.RA,
      rcode: Number(json.Status ?? 0)
    },
    rcode: Number(json.Status ?? 0),
    rcodeName: rcodeToString(Number(json.Status ?? 0)),
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
  const soa = message.authorities.find((r) => r.type === TYPE.SOA);
  if (!soa) return 0;
  let minimum = soa.data?.minimum;
  if (typeof soa.data?.text === 'string') {
    const fields = soa.data.text.trim().split(/\s+/);
    if (fields.length === 7 && /^\d+$/.test(fields[6])) minimum = Number(fields[6]);
  }
  if (![soa.ttl, minimum].every((n) => Number.isInteger(n) && n >= 0 && n <= 0x7fffffff)) return 0;
  return Math.min(soa.ttl, minimum, minTtl(message, 3600), 3600);
}

class DnsReplyError extends Error {
  constructor(message) {
    super(`Upstream DNS failure: ${rcodeToString(message.rcode)}`);
    this.code = 'UPSTREAM_RCODE';
    this.rcode = message.rcode;
    this.extendedErrors = message.edns?.extendedErrors ?? [];
  }
}

function nameKey(name) {
  return typeof name === 'string' ? name.trim().toLowerCase().replace(/\.$/, '') : null;
}

function matchWireQuestion(message, name, qtype) {
  const question = message.questions[0];
  if (message.questions.length !== 1 || nameKey(question?.name) !== nameKey(name)
      || question.type !== qtype || question.class !== CLASS.IN) {
    throw new Error('DNS reply question did not match the request');
  }
}

async function boundedBody(response, limit, signal) {
  if (Number(response.headers.get('content-length')) > limit) throw new Error('DoH response is too large');
  const reader = response.body?.getReader();
  if (!reader) throw new Error('DoH response had no body');
  const abort = () => { reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', abort, { once: true });
  try {
    const chunks = [];
    let size = 0;
    while (true) {
      signal.throwIfAborted();
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new Error('DoH response is too large');
      chunks.push(value);
    }
    signal.throwIfAborted();
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  } finally {
    signal.removeEventListener('abort', abort);
    reader.releaseLock();
  }
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

  async query(resolver, name, type, { signal } = {}) {
    const wantJson = this.preferJson && !!resolver.dohJson;
    const endpoint = wantJson ? resolver.dohJson : resolver.dohWire;
    if (!this.fetchImpl || !endpoint) throw new UnsupportedTransportError('DoH endpoint or browser fetch unavailable');
    const url = new URL(endpoint);
    if (url.protocol !== 'https:') throw new UnsupportedTransportError('DoH requires HTTPS');
    const qtype = typeFromString(String(type));
    if (wantJson) {
      url.searchParams.set('name', name);
      url.searchParams.set('type', String(qtype));
      url.searchParams.set('do', '1');
    } else {
      // RFC 8484 §4.1: use ID 0 for HTTP cache compatibility and privacy.
      url.searchParams.set('dns', toBase64Url(encodeQuery({ id: 0, name, type: qtype, dnssec: true }).bytes));
    }
    const accept = wantJson ? 'application/dns-json' : 'application/dns-message';
    const controller = new AbortController();
    const cancel = () => controller.abort(signal.reason);
    signal?.throwIfAborted();
    signal?.addEventListener('abort', cancel, { once: true });
    const timer = setTimeout(() => controller.abort(new ResolverTimeoutError(resolver.id, this.timeoutMs)), this.timeoutMs);
    let response;
    try {
      response = await this.fetchImpl(url.toString(), {
        headers: { accept },
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        redirect: 'error',
        signal: controller.signal
      });
      if (!response.ok) throw new Error(`HTTP ${response.status} from ${resolver.name}`);
      const media = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase();
      if (media !== accept && !(wantJson && media === 'application/json')) throw new Error('Unexpected DoH content type');
      const bytes = await boundedBody(response, wantJson ? 256 * 1024 : 65535, controller.signal);
      if (wantJson) {
        let json;
        try { json = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
        catch { throw new Error('Malformed DoH JSON response'); }
        if (!Number.isInteger(json?.Status) || json.Status < 0 || json.Status > 4095
            || !Array.isArray(json.Question) || json.Question.length !== 1
            || (json.Answer != null && (!Array.isArray(json.Answer) || json.Answer.length > 512))
            || (json.Authority != null && (!Array.isArray(json.Authority) || json.Authority.length > 256))) {
          throw new Error('Malformed DoH JSON response');
        }
        const question = json.Question[0];
        if (typeof question?.name !== 'string' || nameKey(question.name) !== nameKey(name) || question.type !== qtype) {
          throw new Error('DNS reply question did not match the request');
        }
        const message = jsonToMessage(json);
        if (message.flags.truncated) throw new Error('Truncated DoH JSON response');
        return { message, transport: 'DoH-JSON' };
      }

      const message = decodeMessage(bytes);
      if (!message.flags.qr) throw new Error('Invalid DoH reply: QR flag not set');
      if (message.id !== 0 || message.flags.opcode !== 0 || message.flags.reservedBit || message.flags.truncated) {
        throw new Error('Invalid DoH reply ID or flags');
      }
      if (message.edns?.version && message.rcode === 0) throw new Error('Unsupported EDNS version');
      matchWireQuestion(message, name, qtype);
      return { message, transport: 'DoH-WIRE' };
    } catch (error) {
      if (controller.signal.aborted) throw controller.signal.reason;
      throw error;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', cancel);
      // Close even when rejected based on headers or the first oversized chunk.
      response?.body?.cancel().catch(() => {});
    }
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
    /**
     * Parallel-race fallback. Sequential failover is correct but slow: a resolver
     * that silently blackholes UDP/443 makes the user wait for the full timeout
     * before the next one is tried — that is the "everything feels laggy" report.
     * Racing the runner-up after a short head start keeps the common case at one
     * request while cutting worst-case lookup time to roughly [raceDelayMs].
     * Set to 0 to disable.
     */
    this.raceDelayMs = options.raceDelayMs ?? 350;
    this.attemptsLog = [];
  }

  /**
   * Resolver ids allowed to answer for media domains, in preference order.
   *
   * Media/CDN hostnames are the ones where EDNS Client Subnet changes the answer,
   * because the authoritative server picks the video edge from it. Resolvers that
   * forward ECS are tried first for those names only, so ordinary browsing keeps
   * using the fastest resolver while video gets a nearby edge.
   */
  _mediaPreference(name) {
    let verdict;
    try { verdict = classifyMediaHost(name); } catch { return null; }
    if (!verdict?.protected) return null;
    const ecs = this.resolvers.filter((r) => r.ecs === 'supported').map((r) => r.id);
    return ecs.length ? ecs : null;
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
  /**
   * Queries with health-based fallback and a parallel hedge.
   *
   * Two behaviours, both measured rather than assumed:
   *  1. Media names prefer ECS-capable resolvers, because the answer itself (which
   *     CDN edge serves the video) depends on the client subnet.
   *  2. If the first resolver is slow, the runner-up is started after
   *     [raceDelayMs] instead of waiting out the full timeout. The first valid
   *     answer wins; the straggler is abandoned. Worst-case lookup time becomes
   *     roughly raceDelay + one timeout instead of the sum of every timeout,
   *     which is what turns a dead resolver into an "everything is laggy" report.
   *
   * A resolver that loses the race is abandoned, not marked unhealthy: losing a
   * race says nothing about it.
   *
   * @param {string} name
   * @param {string} type
   * @param {{preferredIds?:string[], mediaIds?:string[], race?:boolean}} [options]
   */
  async query(name, type = 'A', options = {}) {
    const lookupStarted = this.clock();
    const elapsed = () => Math.max(0, this.clock() - lookupStarted);
    const finish = (outcome) => ({ ...outcome.result, latencyMs: elapsed() });
    const ordered = this.order().filter((r) => this.health.isAvailable(r.id));
    const preference = options.mediaIds ?? options.preferredIds ?? this._mediaPreference(name);
    const preferred = preference?.length
      ? ordered.slice().sort((a, b) => {
        const ai = preference.indexOf(a.id);
        const bi = preference.indexOf(b.id);
        return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
      })
      : ordered;

    const attempts = [];
    const raceEnabled = (options.race ?? this.raceDelayMs > 0) && !(this.transport instanceof DotTransport);

    const record = (attempt) => {
      attempts.push(attempt);
      this.attemptsLog.push({ ...attempt, name, type, at: this.clock() });
      if (this.attemptsLog.length > 500) this.attemptsLog.shift();
    };

    /**
     * One resolver attempt, wrapped so it can never reject. A settled outcome is
     * `{resolver, ok, result|error, latencyMs}`.
     */
    const attempt = async (resolver, signal) => {
      const started = this.clock();
      try {
        const { message, transport } = await this.transport.query(resolver, name, type, { signal });
        signal.throwIfAborted();
        if (message.rcode !== 0 && message.rcode !== 3) throw new DnsReplyError(message);
        const latencyMs = Math.max(0, this.clock() - started);
        const result = this._buildResult({ name, type, resolver, message, transport, latencyMs, attempts, cached: false });
        this.health.recordSuccess(resolver.id, latencyMs);
        record({ resolverId: resolver.id, resolverName: resolver.name, transport, ok: true, latencyMs, rcode: message.rcode });
        return { resolver, ok: true, result };
      } catch (error) {
        if (signal.aborted) return { resolver, ok: false, error }; // Abandoned hedge, not an outage.
        const latencyMs = Math.max(0, this.clock() - started);
        this.health.recordFailure(resolver.id, error);
        record({
          resolverId: resolver.id,
          resolverName: resolver.name,
          ok: false,
          latencyMs,
          error: error?.message || String(error),
          code: error?.code || 'ERROR',
          rcode: error?.rcode,
          extendedErrors: error?.extendedErrors
        });
        return { resolver, ok: false, error };
      }
    };

    const TIMEOUT = 'TIMEOUT';

    let lastError = null;
    let index = 0;

    while (index < preferred.length) {
      const resolver = preferred[index];
      const runnerUp = preferred[index + 1];
      const firstController = new AbortController();
      const pending = attempt(resolver, firstController.signal);

      if (!raceEnabled || !runnerUp) {
        const settled = await pending;
        if (settled.ok) return finish(settled);
        lastError = settled.error;
        index += 1;
        continue;
      }

      // Give the first resolver a head start, then race the fallback.
      let timer;
      const headStart = new Promise((resolve) => {
        timer = setTimeout(() => resolve(TIMEOUT), this.raceDelayMs);
      });
      const early = await Promise.race([pending, headStart]);
      clearTimeout(timer);

      if (early !== TIMEOUT) {
        if (early.ok) return finish(early);
        lastError = early.error;
        index += 1;
        continue;
      }

      const secondController = new AbortController();
      const second = attempt(runnerUp, secondController.signal);
      const settled = await Promise.race([pending, second]);
      if (settled.ok) {
        const loser = settled.resolver.id === resolver.id ? secondController : firstController;
        loser.abort();
        this.racedCount = (this.racedCount || 0) + 1;
        settled.result.attempts = attempts;
        settled.result.raced = true;
        settled.result.abandoned = settled.resolver.id === resolver.id ? runnerUp.id : resolver.id;
        return finish(settled);
      }

      // First finisher failed — still await the surviving competitor before moving on.
      const other = settled.resolver.id === resolver.id ? second : pending;
      const otherSettled = await other;
      if (otherSettled.ok) {
        this.racedCount = (this.racedCount || 0) + 1;
        otherSettled.result.attempts = attempts;
        otherSettled.result.raced = true;
        return finish(otherSettled);
      }

      lastError = otherSettled.error || settled.error;
      // Both candidates of this pair have now failed.
      index += 2;
    }

    return {
      name, type, status: 'error', ok: false, addresses: [], cname: [],
      ttl: 0, negative: false, attempts, transport: null, resolver: null,
      latencyMs: elapsed(),
      error: lastError?.message || (this.resolvers.length ? 'all resolvers are cooling down' : 'no resolvers configured'),
      dnssec: assessDnssec({ message: null, requested: true, transportFailed: true })
    };
  }

  _buildResult({ name, type, resolver, message, transport, latencyMs, attempts, cached }) {
    const rcode = message.rcode;
    const qtype = typeFromString(type);
    const nx = rcode === 3;
    const noData = !nx && !message.answers.some((rr) => rr.type === qtype || qtype === TYPE.ANY);
    const negative = nx || noData;
    const negativeTtl = negative ? negativeTtlFrom(message) : undefined;
    const status = nx ? 'nxdomain' : noData ? 'nodata' : 'ok';
    const addrs = addressesOf(message, type);
    const dnssect = assessDnssec({ message, requested: true, resolverName: resolver.name });
    return {
      name,
      type: String(type).toUpperCase(),
      status,
      ok: rcode === 0,
      addresses: addrs.map((a) => a.address),
      cname: chainOf(message),
      ttl: negative ? negativeTtl : Math.max(0, minTtl(message, 0)),
      negative,
      negativeTtl,
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
