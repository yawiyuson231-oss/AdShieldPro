/**
 * OmniShield X — Unified Filter Engine (v5)
 *
 * Ports the SAME evaluation ladder as the Android FilterRuleEngine, and extends
 * it with wildcard support, hosts-file parsing, per-rule accounting and
 * explainable verdicts. Public API of v4 (`normalizeDomain`, `loadFilterList`,
 * `addUserRule`, `evaluate`, `totalRules`, `stats`) is preserved, so existing
 * callers and the Android backup format keep working unchanged.
 *
 * Evaluation ladder (highest priority first) — identical to v4:
 *   1. User custom allow    (exact + suffix)
 *   2. User custom block    (exact + suffix)
 *   3. System safety allowlist (captive portals, connectivity checks)
 *   4. List exception       (@@ rules)
 *   5. Filter-list block    (exact + suffix + wildcard, category-tagged)
 *
 * Design notes
 *  - Lookup is O(labels) per domain via a suffix walk; no list is ever scanned.
 *  - Wildcards are compiled to anchored RegExp and only consulted when the
 *    literal suffix walk misses, so they never slow down the common path.
 *  - Every verdict carries `reasons[]` so the UI can always explain a block.
 */

/** Characters that may appear inside a hostname label. */
import {
  PROTECTED_REGISTRABLE_DOMAINS,
  PROTECTED_HOSTS as VIDEO_PROTECTED_HOSTS,
  explainDanger as explainVideoDanger,
  classify as classifyVideoHost,
  protectedZone as videoZoneOf
} from './guard/video-safety.js';

const LABEL_RE = /^[a-z0-9_-]+$/;

/** Entries that must never be blocked: they are required for OS/network health. */
export const SYSTEM_SAFETY_ALLOWLIST = Object.freeze([
  'connectivitycheck.gstatic.com',
  'connectivitycheck.android.com',
  'clients3.google.com',
  'clients4.google.com',
  'captive.apple.com',
  'captive.g.aaplimg.com',
  'play.googleapis.com',
  'android.clients.google.com',
  'time.android.com',
  'time.google.com',
  'msftconnecttest.com',
  'msftncsi.com',
  'dns.msftncsi.com',
  'www.msftconnecttest.com',
  'detectportal.firefox.com',
  'nmcheck.gnome.org',
  'connectivity-check.ubuntu.com',
  'network-test.debian.org',
  'cloudflare-dns.com',
  'one.one.one.one',
  'dns.google',
  'dns.quad9.net',
  'doh.opendns.com',
  'dns.nextdns.io',
  'dns.adguard-dns.com',
  'ipv4only.arpa',
  'localhost'
]);

/** Labels that by themselves indicate a tracking/analytics/telco-metrics host. */
export const TRACKER_HINTS = Object.freeze([
  'analytics', 'telemetry', 'metrics', 'tracking', 'tracker', 'beacon',
  'pixel', 'adserver', 'adservice', 'doubleclick', 'scorecard'
]);

export class OmniShieldFilterEngine {
  constructor(options = {}) {
    /** @type {Map<string,{category:string,source:string}>} */
    this.filterSubdomains = new Map();
    /** @type {Set<string>} */
    this.allowSubdomains = new Set();
    this.customBlockExact = new Set();
    this.customBlockSuffix = new Set();
    this.customAllowExact = new Set();
    this.customAllowSuffix = new Set();

    this.safetyAllow = new Set(SYSTEM_SAFETY_ALLOWLIST);

    /**
     * Video Safety: hosts that must never resolve to a block, because losing them
     * means "the player loads but the video never starts". Advert slots are NOT in
     * this set — see guard/video-safety.js for the policy and the reasoning.
     */
    this.videoSafe = true;
    this.videoGuardDropped = [];

    /** Rules refused because they would break media playback, with the reason. */
    this.rejectedRules = [];

    /** Suffix set consulted by the evaluator for the video-safe exception. */
    this.videoAllowSuffix = new Set([...PROTECTED_REGISTRABLE_DOMAINS, ...VIDEO_PROTECTED_HOSTS]);

    /** Compiled wildcard rules: {re, category, source, pattern, mode} */
    this.wildcardBlock = [];
    this.wildcardAllow = [];

    this.stats = {
      parsed: 0,
      duplicates: 0,
      invalid: 0,
      wildcards: 0,
      hostsFormat: 0,
      exceptions: 0,
      filtered: 0,
      sources: 0,
      videoRejected: 0
    };

    /** Verdict memo — pure function of the rule tables, invalidated on mutation. */
    this._verdictCache = new Map();
    this._verdictCacheLimit = options.verdictCacheSize ?? 4096;
    this._generation = 0;
    this._cacheGeneration = -1;

    /** Per-category rule counts, used by the dashboard for real numbers. */
    this.categoryCounts = new Map();
    /** Per-source (feed file) rule counts. */
    this.sourceCounts = new Map();
  }

  /* ------------------------------------------------------------------ */
  /* Normalization                                                       */
  /* ------------------------------------------------------------------ */

  /**
   * Normalizes any user/feed input to a bare lowercase hostname.
   * Returns '' when the input cannot contain a valid hostname.
   * Mirrors the Kotlin engine (strip scheme/creds/path/port/www?, lowercase,
   * trailing dot) and additionally rejects malformed labels.
   */
  static normalizeDomain(input) {
    let s = (input || '').trim().toLowerCase();
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');   // scheme
    s = s.replace(/^\/\//, '');
    s = s.replace(/^[^/@]*@/, '');                  // credentials
    s = s.split('/')[0].split('?')[0].split('#')[0];
    s = s.split(':')[0];                            // port
    s = s.replace(/^\./, '');                       // leading dot (hosts lists)
    s = s.replace(/^www\./, '');
    s = s.replace(/\.+$/, '');                      // trailing dots
    if (!s) return '';
    if (!/^[a-z0-9_.-]+$/.test(s)) return '';
    if (s.length > 253) return '';
    const labels = s.split('.');
    if (labels.some((l) => l.length === 0 || l.length > 63 || !LABEL_RE.test(l))) return '';
    if (!s.includes('.') && s !== 'localhost') return '';
    return s;
  }

  /** True when a string is an IPv4/IPv6 literal (no DNS filtering applies). */
  static isIpLiteral(input) {
    const s = String(input || '').trim().replace(/^\[|\]$/g, '');
    if (!s) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
      return s.split('.').every((octet) => Number(octet) <= 255);
    }
    if (!s.includes(':') || !/^[0-9a-f:.]+$/i.test(s)) return false;
    // Reject single-colon host:port (`foo:80` already blocked, also `a:b` or `127:1`),
    // triple-colons, and leading/trailing single colons.
    const dbl = s.split('::');
    if (dbl.length > 2) return false;
    if (/^:[^:]|[^:]:$/.test(s)) return false;
    const isValidGroup = (g) => {
      if (/^[0-9a-f]{1,4}$/i.test(g)) return true;
      return /^\d{1,3}(\.\d{1,3}){3}$/.test(g) && g.split('.').every((o) => Number(o) <= 255);
    };
    if (dbl.length === 2) {
      const left = dbl[0] ? dbl[0].split(':') : [];
      const right = dbl[1] ? dbl[1].split(':') : [];
      const hasV4 = right.length > 0 && right[right.length - 1].includes('.');
      const maxGroups = hasV4 ? 6 : 7;
      return left.length + right.length <= maxGroups
        && left.every((g) => /^[0-9a-f]{1,4}$/i.test(g))
        && right.every((g, i) => (i === right.length - 1 ? isValidGroup(g) : /^[0-9a-f]{1,4}$/i.test(g)));
    }
    const groups = s.split(':');
    const hasV4 = groups[groups.length - 1].includes('.');
    if (groups.length !== (hasV4 ? 7 : 8)) return false;
    return groups.every((g, i) => (i === groups.length - 1 ? isValidGroup(g) : /^[0-9a-f]{1,4}$/i.test(g)));
  }

  _invalidate() {
    this._generation++;
    if (this._verdictCache.size) this._verdictCache.clear();
  }

  /* ------------------------------------------------------------------ */
  /* Loading                                                             */
  /* ------------------------------------------------------------------ */

  /**
   * Parses a filter list. Accepts Adblock-DNS (`||domain^`), hosts-file
   * (`0.0.0.0 domain`) and plain-domain formats; `!`/`#` comments are skipped.
   *
   * @param {string} text
   * @param {string} category e.g. ADS, TRACKING, MALWARE, PHISHING
   * @param {string} source feed filename for attribution
   * @returns {{added:number, exceptions:number, wildcards:number, invalid:number, hosts:number, duplicates:number}}
   */
  /**
   * Loads a rule list without freezing the page.
   *
   * Parsing 80k lines takes ~700 ms of blocking work in one go, which is exactly
   * the "the website lags / stops responding while it boots" symptom. This variant
   * parses the same list in bounded chunks and yields to the event loop between
   * them, so the UI keeps painting and input stays responsive.
   *
   * @param {string} text
   * @param {{category?:string, source?:string, chunkChars?:number,
   *          onProgress?:(p:{fraction:number, added:number})=>void}} [options]
   */
  async loadFilterListAsync(text, options = {}) {
    const category = options.category ?? 'ADS';
    const source = options.source ?? 'unknown';
    // 256 KB per chunk keeps the longest single blocking pass to a few tens of
    // milliseconds on a phone. Callers may lower it further (tests do).
    const chunkChars = Math.max(256, options.chunkChars ?? 262_144);
    const total = text.length;
    let offset = 0;
    let added = 0;
    let duplicates = 0;
    let firstChunk = true;

    while (offset < total) {
      let end = Math.min(total, offset + chunkChars);
      if (end < total) {
        // Never split a line: a cut inside `@@||example.com^` would turn an
        // exception into a block rule (or vice versa) and break the domain.
        const newline = text.indexOf('\n', end);
        end = newline === -1 ? total : newline + 1;
      }
      const chunk = text.slice(offset, end);
      const result = this.loadFilterList(chunk, category, source, { firstChunk });
      added += result.added;
      duplicates += result.duplicates;
      firstChunk = false;
      offset = end;
      if (options.onProgress) {
        try { options.onProgress({ fraction: offset / total, added }); } catch { /* observers */ }
      }
      if (offset < total) await new Promise((resolve) => setTimeout(resolve, 0));
    }
    this._invalidate();
    return { added, duplicates, source, bytes: total, chunks: Math.ceil(total / chunkChars) };
  }

  loadFilterList(text, category = 'ADS', source = 'unknown', options = {}) {
    const before = {
      added: this.filterSubdomains.size,
      exceptions: this.allowSubdomains.size,
      wildcards: this.stats.wildcards,
      invalid: this.stats.invalid,
      hosts: this.stats.hostsFormat,
      duplicates: this.stats.duplicates,
      videoRejected: this.stats.videoRejected
    };
    if (options.firstChunk !== false) this.stats.sources++;
    let added = 0;

    for (const rawLine of text.split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith('!') || line.startsWith('#') || line.startsWith('[')) continue;
      this.stats.parsed++;

      const isException = line.startsWith('@@');

      // Video Safety applies to feed content too. Upstream lists are conservative,
      // but one entity-level or substring line is enough to take playback down for
      // every video service, so those lines are counted and skipped, never loaded.
      if (!isException && this.videoSafe && explainVideoDanger(line)) {
        this.stats.videoRejected++;
        continue;
      }

      let body = isException ? line.slice(2).trim() : line;

      // hosts-file syntax: "0.0.0.0 domain" / "127.0.0.1 domain [alias...] [# comment]"
      if (/^(0\.0\.0\.0|127\.0\.0\.1|::1?|::ffff:0\.0\.0\.0)\s+\S+/i.test(body)) {
        this.stats.hostsFormat++;
        const commentStripped = body.replace(/\s+#.*$/, '');
        const fields = commentStripped.split(/\s+/).slice(1);
        for (const field of fields) {
          if (!field || field.startsWith('#')) break;
          if (field === 'localhost' || field === 'localhost.localdomain' || field === 'ip6-localhost' || field === 'ip6-loopback' || field === 'broadcasthost') continue;
          if (!isException && this.videoSafe && explainVideoDanger(field)) {
            this.stats.videoRejected++;
            continue;
          }
          if (this._addDomain(field, isException, category, source)) added++;
        }
        continue;
      }

      // Adblock syntax with an explicit type option block that is not DNS-relevant
      if (!body.startsWith('||') && (body.includes('##') || body.includes('#@#') || body.includes('#?#'))) {
        this.stats.invalid++; // cosmetic rule: not applicable to DNS filtering
        continue;
      }

      if (body.startsWith('||')) body = body.slice(2);
      else if (body.startsWith('|')) body = body.slice(1);
      const caret = body.indexOf('^');
      if (caret >= 0) body = body.slice(0, caret);
      body = body.split('$')[0].trim();

      if (/[*?]/.test(body)) {
        if (this._addWildcard(body, isException, category, source)) added++;
        continue;
      }
      if (this._addDomain(body, isException, category, source)) added++;
    }

    this._invalidate();
    const result = {
      added: added,
      exceptions: this.allowSubdomains.size - before.exceptions,
      wildcards: this.stats.wildcards - before.wildcards,
      invalid: this.stats.invalid - before.invalid,
      hosts: this.stats.hostsFormat - before.hosts,
      duplicates: this.stats.duplicates - before.duplicates,
      videoRejected: this.stats.videoRejected - before.videoRejected
    };
    this.sourceCounts.set(source, (this.sourceCounts.get(source) || 0) + added);
    return result;
  }

  _addDomain(rawDomain, isException, category, source) {
    const domain = OmniShieldFilterEngine.normalizeDomain(rawDomain);
    if (!domain) { this.stats.invalid++; return false; }

    if (isException) {
      if (this.allowSubdomains.has(domain)) { this.stats.duplicates++; return false; }
      this.allowSubdomains.add(domain);
      this.stats.exceptions++;
      return true;
    }
    if (this.filterSubdomains.has(domain)) { this.stats.duplicates++; return false; }
    this.filterSubdomains.set(domain, { category, source });
    this.categoryCounts.set(category, (this.categoryCounts.get(category) || 0) + 1);
    return true;
  }

  _addWildcard(pattern, isException, category, source) {
    const normalized = pattern.trim().toLowerCase().replace(/^\|\|?/, '').replace(/\^$/, '');
    if (!/[*?]/.test(normalized) || normalized.length < 3) { this.stats.invalid++; return false; }
    // Guard: a wildcard that matches "everything" is never accepted.
    if (/^[*?.]+$/.test(normalized)) { this.stats.invalid++; return false; }
    const escaped = normalized
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '[^/]*')
      .replace(/\?/g, '[^/.]');
    const re = new RegExp(`^${escaped}$`);
    const entry = { re, category, source, pattern: normalized };
    const bucket = isException ? this.wildcardAllow : this.wildcardBlock;
    const isUser = source === 'user';
    if (bucket.some((w) => w.pattern === normalized && (w.source === 'user') === isUser)) {
      this.stats.duplicates++;
      return false;
    }
    bucket.push(entry);
    this.stats.wildcards++;
    if (!isException && !isUser) this.categoryCounts.set(category, (this.categoryCounts.get(category) || 0) + 1);
    this._invalidate();
    return true;
  }

  /**
   * Adds a user custom rule. Accepts `||domain^`, `@@||domain^`, plain domain.
   * @returns {boolean} false when the pattern could not be parsed
   */
  addUserRule(pattern, isAllow, matchType = 'SUFFIX') {
    // Video Safety: an entity-level, substring or shared-CDN block rule takes
    // playback down. Refuse it and keep the reason, instead of silently breaking
    // every video the user watches.
    if (!isAllow && this.videoSafe) {
      const danger = explainVideoDanger(pattern);
      if (danger) {
        this.rejectedRules.push({ rule: String(pattern), code: danger.code, detail: danger.detail });
        if (this.rejectedRules.length > 100) this.rejectedRules.shift();
        return false;
      }
    }
    const cleaned = String(pattern || '')
      .trim()
      .replace(/^@@/, '')
      .replace(/^\|\|?/, '')
      .replace(/\^.*$/, '')
      .split('$')[0]
      .trim();
    const normalizedMatch = String(matchType || 'SUFFIX').toUpperCase();
    if (/[*?]/.test(cleaned) || normalizedMatch === 'WILDCARD') {
      return this._addWildcard(cleaned, !!isAllow, isAllow ? 'USER_ALLOW' : 'USER_BLOCK', 'user');
    }
    const domain = OmniShieldFilterEngine.normalizeDomain(cleaned);
    if (!domain) return false;
    const exactOnly = normalizedMatch === 'EXACT';
    if (isAllow) {
      this.customAllowExact.add(domain);
      if (!exactOnly) this.customAllowSuffix.add(domain);
    } else {
      this.customBlockExact.add(domain);
      if (!exactOnly) this.customBlockSuffix.add(domain);
    }
    this._invalidate();
    return true;
  }

  removeUserRule(pattern, isAllow) {
    const cleaned = String(pattern || '')
      .trim()
      .replace(/^@@/, '')
      .replace(/^\|\|?/, '')
      .replace(/\^.*$/, '')
      .split('$')[0]
      .trim();
    if (/[*?]/.test(cleaned)) {
      const normalized = cleaned.toLowerCase();
      const bucket = isAllow ? this.wildcardAllow : this.wildcardBlock;
      const beforeLen = bucket.length;
      const next = bucket.filter((w) => !(w.source === 'user' && w.pattern === normalized));
      if (next.length === beforeLen) return false;
      if (isAllow) this.wildcardAllow = next;
      else this.wildcardBlock = next;
      this.stats.wildcards = Math.max(0, this.stats.wildcards - (beforeLen - next.length));
      this._invalidate();
      return true;
    }
    const domain = OmniShieldFilterEngine.normalizeDomain(cleaned);
    if (!domain) return false;
    // Both sets must be cleared: `||` would short-circuit after the first delete
    // and leave the suffix rule behind (which silently kept the domain allowed).
    const exact = isAllow ? this.customAllowExact : this.customBlockExact;
    const suffix = isAllow ? this.customAllowSuffix : this.customBlockSuffix;
    const removedExact = exact.delete(domain);
    const removedSuffix = suffix.delete(domain);
    const changed = removedExact || removedSuffix;
    if (changed) this._invalidate();
    return changed;
  }

  /** Replaces user rules wholesale (used by config import / recovery). */
  setUserRules(rules = []) {
    this.customBlockExact.clear(); this.customBlockSuffix.clear();
    this.customAllowExact.clear(); this.customAllowSuffix.clear();
    const prevWildcards = this.wildcardBlock.length + this.wildcardAllow.length;
    this.wildcardBlock = this.wildcardBlock.filter((w) => w.source !== 'user');
    this.wildcardAllow = this.wildcardAllow.filter((w) => w.source !== 'user');
    const removedWildcards = prevWildcards - (this.wildcardBlock.length + this.wildcardAllow.length);
    this.stats.wildcards = Math.max(0, this.stats.wildcards - removedWildcards);
    let ok = 0;
    for (const rule of rules) {
      if (!rule) continue;
      if (this.addUserRule(rule.pattern ?? rule.rawPattern, rule.isAllow ?? rule.ruleType === 'ALLOW')) ok++;
    }
    this._invalidate();
    return ok;
  }

  /* ------------------------------------------------------------------ */
  /* Evaluation                                                          */
  /* ------------------------------------------------------------------ */

  /** All suffixes of a domain, most specific first (includes the domain itself). */
  suffixesOf(domain) {
    const clean = String(domain || '').trim();
    if (!clean) return [];
    const parts = clean.split('.');
    if (parts.length <= 1) return [clean];
    const out = new Array(parts.length - 1);
    for (let i = 0; i < parts.length - 1; i++) out[i] = parts.slice(i).join('.');
    return out;
  }

  /** Cheap, allocation-free suffix walk helper: yields 'a.b.c', 'b.c', 'c'. */
  *_walk(domain) {
    let idx = 0;
    while (true) {
      yield domain.slice(idx);
      const next = domain.indexOf('.', idx);
      if (next < 0) break;
      idx = next + 1;
      if (idx >= domain.length) break;
    }
  }

  /**
   * Evaluates a domain and returns the verdict, including the matched rule,
   * its category and a human-readable explanation.
   *
   * @param {string} input raw user input (URL, host or domain)
   * @returns {{domain:string, blocked:boolean, source:string, category?:string,
   *            matched?:string, action:string, reasons:string[], cached?:boolean}}
   */
  evaluate(input) {
    if (this._cacheGeneration !== this._generation) {
      this._verdictCache.clear();
      this._cacheGeneration = this._generation;
    }
    const key = String(input ?? '');
    const cached = this._verdictCache.get(key);
    if (cached) return { ...cached, cached: true };

    const verdict = this._evaluateUncached(key);
    if (this._verdictCache.size >= this._verdictCacheLimit) {
      // Simple FIFO eviction — bounded memory, no unbounded growth.
      const oldest = this._verdictCache.keys().next().value;
      this._verdictCache.delete(oldest);
    }
    this._verdictCache.set(key, verdict);
    return verdict;
  }

  _evaluateUncached(input) {
    const base = { domain: input, blocked: false, source: 'Invalid/Empty', action: 'ALLOW', reasons: [] };

    if (OmniShieldFilterEngine.isIpLiteral(input)) {
      return {
        ...base,
        source: 'IP literal',
        reasons: ['Input is an IP address literal — domain filtering does not apply.']
      };
    }

    const domain = OmniShieldFilterEngine.normalizeDomain(input);
    if (!domain) return base;

    // 1. User allowlist outranks everything.
    if (this.customAllowExact.has(domain)) {
      return {
        domain, blocked: false, source: 'User Allowlist', action: 'ALLOW',
        matched: domain, reasons: [`You explicitly allowed ${domain}.`]
      };
    }
    for (const suffix of this._walk(domain)) {
      if (this.customAllowSuffix.has(suffix)) {
        return {
          domain, blocked: false, source: 'User Allowlist', action: 'ALLOW', matched: suffix,
          reasons: [`You explicitly allowed ${suffix}, which covers this host.`]
        };
      }
    }
    for (const w of this.wildcardAllow) {
      if (w.source === 'user' && w.re.test(domain)) {
        return {
          domain, blocked: false, source: 'User Allowlist', action: 'ALLOW', matched: w.pattern,
          reasons: [`Wildcard allow rule "${w.pattern}" matches this host.`]
        };
      }
    }

    // 2. User blocklist.
    if (this.customBlockExact.has(domain)) {
      return {
        domain, blocked: true, source: 'User Blocklist', action: 'BLOCK', category: 'USER_BLOCK', matched: domain,
        reasons: [`You explicitly blocked ${domain}.`]
      };
    }
    for (const suffix of this._walk(domain)) {
      if (this.customBlockSuffix.has(suffix)) {
        return {
          domain, blocked: true, source: 'User Blocklist', action: 'BLOCK', category: 'USER_BLOCK', matched: suffix,
          reasons: [`You explicitly blocked ${suffix}.`]
        };
      }
    }
    for (const w of this.wildcardBlock) {
      if (w.source === 'user' && w.re.test(domain)) {
        return {
          domain, blocked: true, source: 'User Blocklist', action: 'BLOCK', category: 'USER_BLOCK', matched: w.pattern,
          reasons: [`Wildcard block rule "${w.pattern}" matches this host.`]
        };
      }
    }

    // 3. System safety allowlist — protects captive portals and connectivity checks.
    for (const suffix of this._walk(domain)) {
      if (this.safetyAllow.has(suffix)) {
        return {
          domain, blocked: false, source: 'System Safety Allowlist', action: 'ALLOW', matched: suffix,
          reasons: [`${suffix} is required for network connectivity checks and is never blocked.`]
        };
      }
    }

    // 4. List exceptions.
    for (const suffix of this._walk(domain)) {
      if (this.allowSubdomains.has(suffix)) {
        return {
          domain, blocked: false, source: 'List Exception', action: 'ALLOW', matched: suffix,
          reasons: [`The upstream feed carries an exception (@@) for ${suffix}.`]
        };
      }
    }
    for (const w of this.wildcardAllow) {
      if (w.source !== 'user' && w.re.test(domain)) {
        return {
          domain, blocked: false, source: 'List Exception', action: 'ALLOW', matched: w.pattern,
          reasons: [`Feed exception wildcard "${w.pattern}" matches this host.`]
        };
      }
    }

    /**
     * Video Safety, applied where it belongs: at the moment a feed rule matches.
     *
     * A rule that blocks the media *domain itself* (`||googlevideo.com^`) would
     * take playback down, so it is ignored for playback hosts. A rule for a
     * specific host (`||log.byteoversea.com^`, `||views.hulu.com^`) is a
     * deliberate block of an ad or telemetry endpoint and is always enforced —
     * exempting whole media domains instead silently unblocked 195 such hosts.
     */
    const videoZone = this.videoSafe ? videoZoneOf(domain) : null;
    const playbackExemption = (matchedSuffix) => {
      if (!videoZone || matchedSuffix !== videoZone) return null;
      const verdict = classifyVideoHost(domain);
      if (!verdict.protected) return null;
      return {
        domain, blocked: false, source: 'Video Safety', action: 'ALLOW', matched: matchedSuffix,
        reasons: [
          verdict.reason,
          `The rule blocking ${matchedSuffix} would stop playback; specific ad and telemetry hosts under it stay blocked.`
        ]
      };
    };

    // 5. Feed block rules.
    for (const suffix of this._walk(domain)) {
      const hit = this.filterSubdomains.get(suffix);
      if (hit) {
        const exempt = playbackExemption(suffix);
        if (exempt) return exempt;
        return {
          domain, blocked: true, source: hit.source, action: 'BLOCK', category: hit.category, matched: suffix,
          reasons: [
            `Rule "${suffix}" appears in the ${hit.category} feed ${hit.source}.`,
            suffix === domain
              ? 'The hostname itself is listed.'
              : `The listed parent domain ${suffix} covers this host.`
          ],
          confidence: 'high'
        };
      }
    }
    for (const w of this.wildcardBlock) {
      if (w.source !== 'user' && w.re.test(domain)) {
        if (this.videoSafe) {
          const verdict = classifyVideoHost(domain);
          if (verdict.protected) {
            return {
              domain, blocked: false, source: 'Video Safety', action: 'ALLOW', matched: w.pattern,
              reasons: [
                verdict.reason,
                `Wildcard feed rule "${w.pattern}" would stop playback and was ignored for this media host.`
              ]
            };
          }
        }
        return {
          domain, blocked: true, source: w.source, action: 'BLOCK', category: w.category, matched: w.pattern,
          reasons: [`Wildcard rule "${w.pattern}" from ${w.source} matches this host.`]
        };
      }
    }

    return {
      domain, blocked: false, source: 'Allowed (no rule matched)', action: 'ALLOW',
      reasons: ['No user rule, exception, safety entry or feed rule matched this hostname.']
    };
  }

  /* ------------------------------------------------------------------ */
  /* Introspection                                                       */
  /* ------------------------------------------------------------------ */

  totalRules() {
    return this.filterSubdomains.size + this.allowSubdomains.size + this.wildcardBlock.length + this.wildcardAllow.length;
  }

  ruleCountByCategory() { return Object.fromEntries(this.categoryCounts); }

  breakdown() {
    const userWildcards = this.wildcardBlock.filter((w) => w.source === 'user').length
      + this.wildcardAllow.filter((w) => w.source === 'user').length;
    const feedWildcards = (this.wildcardBlock.length + this.wildcardAllow.length) - userWildcards;
    return {
      blockDomains: this.filterSubdomains.size,
      exceptions: this.allowSubdomains.size,
      wildcards: feedWildcards,
      userRules: this.customBlockExact.size + this.customAllowExact.size + userWildcards,
      safetyEntries: this.safetyAllow.size,
      videoSafeEntries: this.videoAllowSuffix.size,
      videoRulesRejected: this.stats.videoRejected,
      total: this.totalRules(),
      categories: this.ruleCountByCategory(),
      sources: Object.fromEntries(this.sourceCounts)
    };
  }
}

export default OmniShieldFilterEngine;
