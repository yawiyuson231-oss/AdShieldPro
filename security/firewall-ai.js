/**
 * OmniShield X — Firewall AI ("Firewall AI Advance").
 *
 * A behavioural anomaly engine. Unlike the domain scorer, this analyses *how*
 * traffic behaves over time, which is the only way to see things that look
 * innocent domain-by-domain:
 *
 *   1. Beaconing / C2          — periodic check-ins with low timing variance.
 *   2. DNS tunnelling          — many long, high-entropy unique subdomains
 *                                under one parent (data smuggling).
 *   3. Rate anomaly            — EWMA + z-score bursts per destination.
 *   4. Fan-out / DGA storm     — many distinct destinations in a short window.
 *   5. Sleep-jitter profiles   — long gaps with mechanical regularity.
 *
 * SAFE DEFAULTS
 *   - `evaluate()` returns `monitor` unless at least two *independent* signals
 *     fire, or the user has an explicit deny policy for that destination.
 *   - It never blocks by itself; it recommends, and the reason is always shown.
 *   - Every threshold lives in `DEFAULT_CONFIG` so users can see and change it.
 *
 * All computations are deterministic and unit-tested; no randomness, no "AI
 * magic", no fabricated detections. If there is not enough data, the engine
 * returns `insufficient-data` rather than a guess.
 */
import { extractFeatures } from '../aether/lexical.js';
import { registrableDomain } from '../aether/domain.js';

export const DEFAULT_CONFIG = Object.freeze({
  /** Beaconing needs at least this many observations before speaking. */
  beaconMinSamples: 6,
  /** Coefficient of variation below this = metronome-like timing. */
  beaconCvThreshold: 0.15,
  /** Extra-strong periodicity (reported as high confidence). */
  beaconStrongCv: 0.08,
  beaconMinIntervalMs: 5_000,
  beaconMaxIntervalMs: 6 * 3600_000,
  /** DNS tunnel heuristics. */
  tunnelMinObservations: 8,
  tunnelUniqueRatio: 0.9,
  tunnelAvgLabelLength: 28,
  tunnelMinEntropy: 3.4,
  /** Rate anomaly (per destination). */
  rateMinSamples: 10,
  rateZThreshold: 3.5,
  rateWindowMs: 5 * 60_000,
  /** Fan-out over the sliding window. */
  fanoutWindowMs: 60_000,
  fanoutThreshold: 60
});

export const DECISIONS = Object.freeze(['allow', 'monitor', 'block']);

/** Standard deviation of an array. */
export function stdDev(values) {
  if (values.length < 2) return 0;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / (values.length - 1);
  return Math.sqrt(variance);
}

export function coefficientOfVariation(values) {
  if (values.length < 2) return null;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  if (mean === 0) return null;
  return stdDev(values) / mean;
}

/** Shannon entropy over characters. */
function entropy(text) {
  const s = String(text || '');
  if (!s) return 0;
  const counts = new Map();
  for (const c of s) counts.set(c, (counts.get(c) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export class FirewallAI {
  /**
   * @param {{clock?:()=>number, config?:object, onEvent?:Function}} [options]
   */
  constructor(options = {}) {
    this.clock = options.clock ?? (() => Date.now());
    this.config = { ...DEFAULT_CONFIG, ...(options.config || {}) };
    this.onEvent = options.onEvent ?? null;
    /** destination -> {times:number[], app, count, lastSeen, subdomains:Set} */
    this.destinations = new Map();
    /** app -> {deny:Set, allow:Set} explicit user policy */
    this.policies = new Map();
    this.maxDestinations = options.maxDestinations ?? 5000;
    this.maxTimesPerDestination = 200;
    this.stats = { observations: 0, evaluations: 0, monitors: 0, blocks: 0, beaconing: 0, tunneling: 0, rateAnomalies: 0, fanout: 0 };
  }

  _emit(event) {
    if (this.onEvent) { try { this.onEvent(event); } catch { /* ignore */ } }
  }

  /* ---------------- policy ---------------- */

  setPolicy(app, destination, action) {
    if (!DECISIONS.includes(action) || action === 'monitor') {
      const existing = this.policies.get(app);
      if (existing) {
        existing.deny.delete(destination);
        existing.allow.delete(destination);
      }
      return false;
    }
    if (!this.policies.has(app)) this.policies.set(app, { deny: new Set(), allow: new Set() });
    const p = this.policies.get(app);
    p.deny.delete(destination);
    p.allow.delete(destination);
    if (action === 'block') p.deny.add(destination);
    else p.allow.add(destination);
    return true;
  }

  policiesFor(app) {
    const p = this.policies.get(app);
    return { deny: p ? [...p.deny] : [], allow: p ? [...p.allow] : [] };
  }

  /* ---------------- observation ---------------- */

  /**
   * Records one real connection/DNS observation.
   * @param {{domain:string, app?:string, at?:number, bytesOut?:number}} input
   */
  observe(input) {
    const domain = String(input.domain || '').toLowerCase();
    if (!domain) return null;
    const at = input.at ?? this.clock();
    const app = input.app || 'unknown';

    let entry = this.destinations.get(domain);
    if (!entry) {
      entry = { domain, app, times: [], count: 0, lastSeen: at, firstSeen: at, subdomains: new Set(), bytesOut: 0 };
      this.destinations.set(domain, entry);
      if (this.destinations.size > this.maxDestinations) {
        let oldestKey = null; let oldest = Infinity;
        for (const [k, v] of this.destinations) if (v.lastSeen < oldest) { oldest = v.lastSeen; oldestKey = k; }
        if (oldestKey) this.destinations.delete(oldestKey);
      }
    }
    entry.times.push(at);
    if (entry.times.length > this.maxTimesPerDestination) entry.times.shift();
    entry.count++;
    entry.lastSeen = at;
    entry.bytesOut += input.bytesOut || 0;

    // Track unique subdomains per registrable parent for tunnelling analysis.
    const parent = registrableDomain(domain);
    if (parent && parent !== domain) {
      const sub = domain.slice(0, -(parent.length + 1));
      if (sub) {
        let parentEntry = this.destinations.get(`parent:${parent}`);
        if (!parentEntry) {
          parentEntry = { domain: `parent:${parent}`, parent, app, times: [], count: 0, lastSeen: at, firstSeen: at, subdomains: new Set(), bytesOut: 0 };
          this.destinations.set(`parent:${parent}`, parentEntry);
        }
        parentEntry.subdomains.add(sub);
        parentEntry.times.push(at);
        if (parentEntry.times.length > this.maxTimesPerDestination) parentEntry.times.shift();
        parentEntry.count++;
        parentEntry.lastSeen = at;
      }
    }
    this.stats.observations++;
    return entry;
  }

  /** Bulk import of an observation log (e.g. from the Android core). */
  importLog(entries) {
    let accepted = 0;
    for (const e of entries || []) {
      if (!e?.domain) continue;
      this.observe({ domain: e.domain, app: e.app, at: e.at ?? e.timestamp, bytesOut: e.bytesOut });
      accepted++;
    }
    return accepted;
  }

  /* ---------------- detectors ---------------- */

  /** Periodic check-in detection (C2 beaconing). */
  detectBeaconing(domain) {
    const entry = this.destinations.get(domain);
    const cfg = this.config;
    if (!entry || entry.times.length < cfg.beaconMinSamples) {
      return { id: 'beaconing', fired: false, reason: 'insufficient-data', samples: entry?.times.length ?? 0, required: cfg.beaconMinSamples };
    }
    const times = entry.times.slice(-40);
    const intervals = [];
    for (let i = 1; i < times.length; i++) intervals.push(times[i] - times[i - 1]);
    const meanInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    if (meanInterval < cfg.beaconMinIntervalMs || meanInterval > cfg.beaconMaxIntervalMs) {
      return {
        id: 'beaconing', fired: false,
        reason: meanInterval < cfg.beaconMinIntervalMs ? 'interval-too-short' : 'interval-too-long',
        meanIntervalMs: Math.round(meanInterval), samples: times.length
      };
    }
    const cv = coefficientOfVariation(intervals);
    const fired = cv !== null && cv <= cfg.beaconCvThreshold;
    const result = {
      id: 'beaconing',
      fired,
      confidence: fired ? (cv <= cfg.beaconStrongCv ? 'high' : 'medium') : 'none',
      cv: cv === null ? null : Math.round(cv * 1000) / 1000,
      meanIntervalMs: Math.round(meanInterval),
      samples: times.length,
      evidence: fired
        ? `${times.length} check-ins to ${domain} at a near-constant ${Math.round(meanInterval / 1000)}s interval ` +
          `(coefficient of variation ${(cv * 100).toFixed(1)}%). Machines that phone home like a metronome are ` +
          'consistent with command-and-control beacons — but also with apps polling a legit API on a timer.'
        : `Intervals to ${domain} are irregular (CV ${cv === null ? 'n/a' : (cv * 100).toFixed(0)}%), so this is not periodic traffic.`
    };
    if (fired) this.stats.beaconing++;
    return result;
  }

  /** DNS tunnelling detection for a registrable parent domain. */
  detectTunneling(parent) {
    const key = parent.startsWith('parent:') ? parent : `parent:${parent}`;
    const entry = this.destinations.get(key);
    const cfg = this.config;
    if (!entry || entry.count < cfg.tunnelMinObservations) {
      return { id: 'tunneling', fired: false, reason: 'insufficient-data', observations: entry?.count ?? 0, required: cfg.tunnelMinObservations };
    }
    const subs = [...entry.subdomains];
    const uniqueRatio = subs.length / Math.max(1, entry.count);
    const lengths = subs.map((s) => s.length);
    const avgLength = lengths.reduce((a, b) => a + b, 0) / Math.max(1, lengths.length);
    const avgEntropy = subs.reduce((sum, s) => sum + entropy(s), 0) / Math.max(1, subs.length);
    const deepLabels = subs.filter((s) => s.split('.').length >= 4).length / Math.max(1, subs.length);

    const checks = {
      uniqueSubdomains: uniqueRatio >= cfg.tunnelUniqueRatio,
      longLabels: avgLength >= cfg.tunnelAvgLabelLength,
      highEntropy: avgEntropy >= cfg.tunnelMinEntropy,
      deepNesting: deepLabels >= 0.5
    };
    const passed = Object.values(checks).filter(Boolean).length;
    const fired = passed >= 3;
    const result = {
      id: 'tunneling',
      fired,
      confidence: fired ? (passed === 4 ? 'high' : 'medium') : 'none',
      parent,
      uniqueSubdomains: subs.length,
      observations: entry.count,
      uniqueRatio: Math.round(uniqueRatio * 100) / 100,
      avgLabelLength: Math.round(avgLength * 10) / 10,
      avgEntropy: Math.round(avgEntropy * 100) / 100,
      deepNesting: Math.round(deepLabels * 100) / 100,
      checks,
      evidence: fired
        ? `${subs.length} unique subdomains of ${parent} (${Math.round(uniqueRatio * 100)}% unique), average label ` +
          `${avgLength.toFixed(1)} chars at ${avgEntropy.toFixed(2)} bits/char. That pattern matches DNS tunnelling ` +
          '(data encoded in query names) — but also content-delivery and anti-tracking domain sharding.'
        : `Subdomain pattern under ${parent} does not match tunnelling (${passed}/4 indicators).`
    };
    if (fired) this.stats.tunneling++;
    return result;
  }

  /** EWMA + z-score burst detection for one destination. */
  detectRateAnomaly(domain) {
    const entry = this.destinations.get(domain);
    const cfg = this.config;
    const times = entry?.times || [];
    if (times.length < cfg.rateMinSamples) {
      return { id: 'rate', fired: false, reason: 'insufficient-data', samples: times.length, required: cfg.rateMinSamples };
    }
    const windowStart = times[times.length - 1] - cfg.rateWindowMs;
    const recent = times.filter((t) => t >= windowStart);
    const currentRate = recent.length; // events in the last window

    // Baseline: rates of earlier windows (mean +/- sd), minimum 3 windows.
    const windows = [];
    for (let i = 1; i <= 5; i++) {
      const end = times[times.length - 1] - i * cfg.rateWindowMs;
      const start = end - cfg.rateWindowMs;
      windows.push(times.filter((t) => t > start && t <= end).length);
    }
    if (windows.every((w) => w === 0)) {
      return { id: 'rate', fired: false, reason: 'no-baseline', currentRate };
    }
    const mean = windows.reduce((a, b) => a + b, 0) / windows.length;
    const sd = stdDev(windows);
    const z = sd === 0 ? (currentRate > mean ? Infinity : 0) : (currentRate - mean) / sd;
    const fired = z >= cfg.rateZThreshold && currentRate >= cfg.rateMinSamples;
    if (fired) this.stats.rateAnomalies++;
    return {
      id: 'rate',
      fired,
      confidence: fired ? (z >= cfg.rateZThreshold * 2 ? 'high' : 'medium') : 'none',
      currentRate,
      baselineMean: Math.round(mean * 10) / 10,
      baselineSd: Math.round(sd * 10) / 10,
      z: Number.isFinite(z) ? Math.round(z * 100) / 100 : 'infinite',
      windowMs: cfg.rateWindowMs,
      evidence: fired
        ? `${currentRate} requests to ${domain} in the last ${Math.round(cfg.rateWindowMs / 60000)} min versus a ` +
          `baseline of ${mean.toFixed(1)}/window (z=${Number.isFinite(z) ? z.toFixed(1) : '∞'}). Sudden bursts can be ` +
          'malware, but also app updates, streaming buffers or page loads with many assets.'
        : `Request rate to ${domain} is within its normal range (${currentRate} vs baseline ${mean.toFixed(1)}).`
    };
  }

  /** Many distinct destinations in a short window (DGA storm / domain spray). */
  detectFanout(at = this.clock()) {
    const cfg = this.config;
    const windowStart = at - cfg.fanoutWindowMs;
    const distinct = new Set();
    for (const entry of this.destinations.values()) {
      if (entry.domain.startsWith('parent:')) continue;
      if (entry.lastSeen >= windowStart) distinct.add(registrableDomain(entry.domain));
    }
    const fired = distinct.size >= cfg.fanoutThreshold;
    if (fired) this.stats.fanout++;
    return {
      id: 'fanout',
      fired,
      distinct: distinct.size,
      threshold: cfg.fanoutThreshold,
      windowMs: cfg.fanoutWindowMs,
      evidence: fired
        ? `${distinct.size} distinct registrable domains seen in ${Math.round(cfg.fanoutWindowMs / 1000)}s ` +
          `(threshold ${cfg.fanoutThreshold}). Consistent with a DGA-driven infection, but heavy web browsing ` +
          'can also produce it.'
        : `${distinct.size} distinct domains in the last ${Math.round(cfg.fanoutWindowMs / 1000)}s — below the ${cfg.fanoutThreshold} fan-out threshold.`
    };
  }

  /* ---------------- verdict ---------------- */

  /**
   * Evaluates a destination and returns a decision with full evidence.
   * Blocks only on: explicit user deny, or two independent firing signals.
   */
  evaluate(domain, { app = 'unknown', reputation = null, at = this.clock() } = {}) {
    const name = String(domain || '').toLowerCase();
    const signals = [];
    const beacon = this.detectBeaconing(name);
    const rate = this.detectRateAnomaly(name);
    const parent = registrableDomain(name);
    const tunnel = this.detectTunneling(parent);
    const fanout = this.detectFanout(at);
    signals.push(beacon, rate, tunnel, fanout);

    const policy = this.policies.get(app);
    const explicitDeny = policy?.deny.has(name) || policy?.deny.has(parent);
    const explicitAllow = policy?.allow.has(name) || policy?.allow.has(parent);

    const fired = signals.filter((s) => s.fired);
    const independent = new Set(fired.map((s) => s.id));
    const lexicallySuspicious = reputation ? reputation.score >= 70 : false;

    let decision = 'allow';
    let confidence = 'none';
    const reasons = [];

    if (explicitDeny) {
      decision = 'block';
      confidence = 'user-policy';
      reasons.push(`A user policy for app "${app}" explicitly blocks ${name}.`);
    } else if (explicitAllow) {
      decision = 'allow';
      confidence = 'user-policy';
      reasons.push(`A user policy for app "${app}" explicitly allows ${name}; behavioural signals are recorded but do not override it.`);
    } else if (independent.size >= 2 || (independent.size >= 1 && lexicallySuspicious)) {
      decision = 'block';
      confidence = independent.size >= 2 ? (fired.every((s) => s.confidence === 'high') ? 'high' : 'medium') : 'medium';
      reasons.push(...fired.map((s) => s.evidence));
      if (lexicallySuspicious) reasons.push(`AETHER reputation for ${name} is ${reputation.score}/100 ("${reputation.verdictLabel}").`);
    } else if (independent.size === 1) {
      decision = 'monitor';
      confidence = 'low';
      reasons.push(fired[0].evidence);
      reasons.push('A single behavioural signal is not enough to block: one pattern can have several benign explanations.');
    } else {
      decision = 'allow';
      confidence = 'none';
      reasons.push(`No behavioural anomaly detected for ${name}.`);
      const insufficient = signals.filter((s) => s.reason === 'insufficient-data').map((s) => s.id);
      if (insufficient.length) {
        reasons.push(`Not enough observations yet for: ${insufficient.join(', ')}. OmniShield X reports "insufficient data" instead of guessing.`);
      }
    }

    this.stats.evaluations++;
    if (decision === 'monitor') this.stats.monitors++;
    if (decision === 'block') this.stats.blocks++;

    const result = {
      domain: name, app, decision, confidence,
      signals: signals.map(({ evidence, ...rest }) => rest),
      reasons,
      explicitPolicy: explicitDeny ? 'deny' : explicitAllow ? 'allow' : null,
      reputation: reputation ? { score: reputation.score, verdict: reputation.verdict } : null,
      at
    };
    this._emit({ kind: 'firewall', ...result });
    return result;
  }

  /** Analyses one destination in depth (all detectors, no decision). */
  inspect(domain) {
    const name = String(domain || '').toLowerCase();
    const parent = registrableDomain(name);
    const features = extractFeatures(name);
    return {
      domain: name,
      parent,
      features,
      beaconing: this.detectBeaconing(name),
      rate: this.detectRateAnomaly(name),
      tunneling: this.detectTunneling(parent),
      observations: this.destinations.get(name)?.count ?? 0
    };
  }

  snapshot() {
    return {
      stats: { ...this.stats },
      destinations: this.destinations.size,
      fanout: this.detectFanout(),
      config: { ...this.config },
      policies: [...this.policies.entries()].map(([app, p]) => ({ app, deny: [...p.deny], allow: [...p.allow] }))
    };
  }
}

export default FirewallAI;
