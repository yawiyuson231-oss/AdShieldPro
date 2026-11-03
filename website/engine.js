/**
 * OmniShield X — Unified Filter Engine (JavaScript port for the web platform).
 *
 * Ports the SAME evaluation ladder as the Android FilterRuleEngine for the
 * rule types shared by both platforms:
 *   1. User custom allow (exact + suffix)
 *   2. User custom block (exact + suffix)
 *   3. Built-in safety allowlist (suffix)
 *   4. Filter list block (exact + suffix, category-gated)
 * Domain normalization matches the Kotlin engine (strip scheme/creds/path/
 * port/www?, lowercase, trailing dot). Wildcards are out of scope here and
 * reported in stats — the web tester states that honestly.
 *
 * The same bundled rule files (core_lite_ads.txt / core_max_ads.txt /
 * core_max_threats.txt) power both the Android app and this website —
 * ONE intelligence core, TWO platforms.
 */

export class OmniShieldFilterEngine {
  constructor() {
    this.filterSubdomains = new Map(); // domain -> {category, source}
    this.allowSubdomains = new Set();
    this.customBlockExact = new Set();
    this.customBlockSuffix = new Set();
    this.customAllowExact = new Set();
    this.customAllowSuffix = new Set();
    this.safetyAllow = new Set([
      'connectivitycheck.gstatic.com', 'clients3.google.com',
      'captive.apple.com', 'play.googleapis.com', 'android.clients.google.com'
    ]);
    this.stats = { parsed: 0, duplicates: 0, invalid: 0, wildcards: 0 };
  }

  static normalizeDomain(input) {
    let s = (input || '').trim().toLowerCase();
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');   // scheme
    s = s.replace(/^\/\/+/, '');
    s = s.replace(/^([^/@]+@)/, '');                 // credentials
    s = s.split('/')[0].split('?')[0].split('#')[0];
    s = s.split(':')[0];                             // port
    s = s.replace(/^www\./, '');
    s = s.replace(/\.+$/, '');
    if (!/^[a-z0-9.-]+$/.test(s)) return '';
    if (!s.includes('.') && s !== 'localhost') return '';
    return s;
  }

  /** Parses Adblock-DNS style lines: ||domain^, @@||domain^, comments ignored. */
  loadFilterList(text, category, source) {
    for (const rawLine of text.split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith('!') || line.startsWith('#')) continue;
      this.stats.parsed++;
      const isException = line.startsWith('@@');
      let body = isException ? line.slice(2) : line;
      if (!body.startsWith('||')) { this.stats.invalid++; continue; }
      body = body.slice(2);
      const caret = body.indexOf('^');
      if (caret >= 0) body = body.slice(0, caret);
      body = body.split('$')[0];
      if (body.includes('*')) { this.stats.wildcards++; continue; }
      const domain = OmniShieldFilterEngine.normalizeDomain(body);
      if (!domain || !domain.includes('.')) { this.stats.invalid++; continue; }
      if (isException) {
        if (!this.allowSubdomains.has(domain)) this.allowSubdomains.add(domain);
        else this.stats.duplicates++;
      } else {
        if (!this.filterSubdomains.has(domain)) {
          this.filterSubdomains.set(domain, { category, source });
        } else this.stats.duplicates++;
      }
    }
  }

  addUserRule(pattern, isAllow) {
    const domain = OmniShieldFilterEngine.normalizeDomain(pattern.replace(/^@@/, '').replace(/^\|\|/, '').replace(/\^$/, ''));
    if (!domain) return false;
    if (isAllow) {
      this.customAllowExact.add(domain);
      this.customAllowSuffix.add(domain);
    } else {
      this.customBlockExact.add(domain);
      this.customBlockSuffix.add(domain);
    }
    return true;
  }

  suffixesOf(domain) {
    const parts = domain.split('.');
    const out = [];
    for (let i = 0; i < parts.length - 1; i++) out.push(parts.slice(i).join('.'));
    return out;
  }

  /** Returns the verdict object for a domain — mirrors the Android ladder. */
  evaluate(input) {
    const domain = OmniShieldFilterEngine.normalizeDomain(input);
    if (!domain) return { domain: input, blocked: false, source: 'Invalid/Empty' };

    if (this.customAllowExact.has(domain)) return { domain, blocked: false, source: 'User Allowlist' };

    for (const suffix of this.suffixesOf(domain)) {
      if (this.customAllowSuffix.has(suffix)) return { domain, blocked: false, source: 'User Allowlist', matched: suffix };
    }

    for (const suffix of this.suffixesOf(domain)) {
      if (this.customBlockExact.has(suffix)) return { domain, blocked: true, source: 'User Blocklist', matched: suffix };
    }

    // Merged allowlist FIRST (as in the Kotlin engine): built-in safety + list exceptions
    for (const suffix of this.suffixesOf(domain)) {
      if (this.safetyAllow.has(suffix)) return { domain, blocked: false, source: 'System Safety Allowlist', matched: suffix };
    }
    for (const suffix of this.suffixesOf(domain)) {
      if (this.allowSubdomains.has(suffix)) return { domain, blocked: false, source: 'List Exception', matched: suffix };
    }

    for (const suffix of this.suffixesOf(domain)) {
      const hit = this.filterSubdomains.get(suffix);
      if (hit) return { domain, blocked: true, source: hit.source, category: hit.category, matched: suffix };
    }
    return { domain, blocked: false, source: 'Allowed (no rule matched)' };
  }

  totalRules() { return this.filterSubdomains.size + this.allowSubdomains.size; }
}
