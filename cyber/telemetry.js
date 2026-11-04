/**
 * CyberShield AI — threat telemetry model.
 *
 * HONESTY CONTRACT (this is the important part of this file):
 *   The browser cannot observe a global attack surface. It sees one device.
 *   So this module keeps two strictly separated lanes:
 *
 *     MEASURED   numbers read straight out of the running app — rule count,
 *                domains this browser actually blocked, model AUC, scanner
 *                passes. Never invented, never scaled up.
 *
 *     SIMULATED  a labelled, deterministic background of worldwide attack
 *                telemetry so the map and the feed have something to show.
 *                It is seeded, it is reproducible, and every panel built on it
 *                says "simulated" in its own body text.
 *
 * Nothing simulated ever reaches the filter engine, the reputation scorer or
 * the firewall: `enforced` is always false and the UI states that.
 */

export const REGIONS = [
  { id: 'n_america', name: 'North America', lat: 39, lon: -98 },
  { id: 's_america', name: 'South America', lat: -16, lon: -60 },
  { id: 'eu_west', name: 'Western Europe', lat: 47, lon: 6 },
  { id: 'eu_east', name: 'Eastern Europe', lat: 50, lon: 26 },
  { id: 'africa', name: 'Africa', lat: 2, lon: 20 },
  { id: 'middle_east', name: 'Middle East', lat: 28, lon: 45 },
  { id: 's_asia', name: 'South Asia', lat: 20, lon: 78 },
  { id: 'e_asia', name: 'East Asia', lat: 33, lon: 115 },
  { id: 'se_asia', name: 'South-East Asia', lat: 10, lon: 108 },
  { id: 'oceania', name: 'Oceania', lat: -27, lon: 140 },
  { id: 'central_asia', name: 'Central Asia', lat: 45, lon: 68 },
  { id: 'nordics', name: 'Nordics', lat: 60, lon: 16 },
  { id: 'canada', name: 'Canada', lat: 56, lon: -106 },
  { id: 'southern_africa', name: 'Southern Africa', lat: -28, lon: 26 }
];

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];

/** Attack vectors, in the order the reference art ranks them. */
export const VECTORS = [
  { id: 'malware', name: 'Malware' },
  { id: 'phishing', name: 'Phishing' },
  { id: 'exploit', name: 'Exploits' },
  { id: 'access', name: 'Unauthorized Access' },
  { id: 'ddos', name: 'DDoS' },
  { id: 'other', name: 'Other' }
];

/** Detection signals behind the engine meter. */
export const SIGNALS = [
  { id: 'behaviour', name: 'Behaviour Analysis' },
  { id: 'anomaly', name: 'Anomaly Detection' },
  { id: 'ml', name: 'ML Classification' },
  { id: 'correlation', name: 'Threat Correlation' }
];

/** Asset classes shown as the three health tiles. */
export const ASSET_CLASSES = [
  { id: 'endpoints', name: 'Endpoints', icon: 'laptop' },
  { id: 'cloud', name: 'Cloud Systems', icon: 'cloud' },
  { id: 'network', name: 'Network', icon: 'network' }
];

export const FRAMEWORKS = [
  { id: 'iso27001', name: 'ISO 27001' },
  { id: 'soc2', name: 'SOC 2' },
  { id: 'gdpr', name: 'GDPR' },
  { id: 'hipaa', name: 'HIPAA' }
];

/**
 * A small deterministic PRNG (mulberry32). Same seed → same stream, so the
 * simulation is reproducible in tests and never drifts between reloads.
 */
export function rng(seed = 0x51ed270b) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SEVERITY_BASE = { critical: 430, high: 1930, medium: 4380, low: 17600 };
const VECTOR_BASE = [38.7, 24.1, 17.3, 12.6, 4.6, 2.7];

/** Threat titles per family, used by the feed and the drill-down tables. */
const CATALOGUE = {
  malware: ['Ransomware Detected', 'Trojan Payload Blocked', 'Worm Propagation Attempt', 'Malicious Dropper Quarantined'],
  phishing: ['Phishing Email Quarantined', 'Credential Harvest Page Blocked', 'Look-alike Login Domain Blocked', 'Spoofed Mail Gateway Rejected'],
  exploit: ['Exploit Attempt Blocked', 'Remote Code Execution Attempt', 'Privilege Escalation Attempt', 'Memory Corruption Probe'],
  access: ['Unauthorized Access Attempt', 'Brute-force Sign-in Blocked', 'Impossible-travel Sign-in', 'Token Replay Rejected'],
  ddos: ['Volumetric Burst Absorbed', 'SYN Flood Mitigated', 'Amplification Attempt Dropped', 'Traffic Spike Contained'],
  other: ['Suspicious Behaviour Observed', 'Malicious IP Connection Blocked', 'Policy Violation Logged', 'Unusual DNS Pattern Flagged']
};

const SOURCES = [
  'src 185.224.216.98', 'src 45.148.10.77', 'src 103.79.76.41', 'src 91.240.118.5',
  'src 194.26.29.113', 'src 80.94.95.22', 'src 141.98.11.61', 'src 212.83.168.4'
];

const ASSETS = [
  'FIN-LAPTOP-52', 'DEV-WS-113', 'HR-DESK-08', 'OPS-SRV-21', 'EXEC-MBP-03', 'BKP-NAS-01'
];

/**
 * Builds a fresh simulation state. Call once per console instance.
 * @param {{seed?: number}} [options]
 */
export function createScenario({ seed = 0x51ed270b } = {}) {
  const next = rng(seed);
  const jitter = (base, spread = 0.04) => Math.round(base * (1 + (next() - 0.5) * spread * 2));

  const counts = {
    critical: jitter(SEVERITY_BASE.critical, 0.06),
    high: jitter(SEVERITY_BASE.high, 0.06),
    medium: jitter(SEVERITY_BASE.medium, 0.06),
    low: jitter(SEVERITY_BASE.low, 0.06)
  };
  const total = counts.critical + counts.high + counts.medium + counts.low;

  const vectors = VECTORS.map((v, i) => {
    const pct = i < VECTOR_BASE.length ? VECTOR_BASE[i] * (1 + (next() - 0.5) * 0.12) : 1;
    return { id: v.id, name: v.name, pct };
  });
  const vectorSum = vectors.reduce((sum, v) => sum + v.pct, 0);
  for (const v of vectors) v.pct = Math.round((v.pct / vectorSum) * 1000) / 10;

  return {
    seed,
    startedAt: Date.now(),
    counts,
    total,
    delta: { total: 12.4, critical: 3.2, high: 15.3, medium: 3.2, low: -1.1 },
    vectors,
    // Asset inventory: shape only — the browser can never enumerate real ones.
    assets: {
      endpoints: { total: jitter(7892, 0.02), atRisk: jitter(23, 0.25), trend: makeTrend(next, 26) },
      cloud: { total: jitter(1256, 0.02), atRisk: jitter(8, 0.3), trend: makeTrend(next, 26) },
      network: { total: jitter(4325, 0.02), atRisk: jitter(17, 0.25), trend: makeTrend(next, 26) }
    },
    compliance: FRAMEWORKS.map((f) => ({ ...f, state: 'Compliant' })),
    engine: { progress: 87, signals: SIGNALS.map((s) => ({ ...s, state: 'Active', weight: null })) },
    // 40 points of background history for the overview sparkline.
    history: makeTrend(next, 40, 0.55),
    events: [],
    arcs: [],
    counters: { endpoints: 7892, cloud: 1256, network: 4325 }
  };
}

function makeTrend(next, n, spread = 0.35) {
  const out = [];
  let value = 0.45;
  for (let i = 0; i < n; i++) {
    value = Math.max(0.05, Math.min(1, value + (next() - 0.45) * spread * 0.6));
    out.push(Math.round(value * 1000) / 1000);
  }
  return out;
}

/** Picks a weighted severity — critical is rare, exactly like real telemetry. */
function pickSeverity(next, scenario) {
  const r = next() * scenario.total;
  let acc = 0;
  for (const sev of SEVERITIES) {
    acc += scenario.counts[sev];
    if (r <= acc) return sev;
  }
  return 'low';
}

function pickVector(next, scenario) {
  const r = next() * 100;
  let acc = 0;
  for (const v of scenario.vectors) {
    acc += v.pct;
    if (r <= acc) return v.id;
  }
  return 'other';
}

/** One synthetic event, shaped like a real detection record. */
export function makeEvent(next, scenario, now = Date.now()) {
  const vector = pickVector(next, scenario);
  const severity = pickSeverity(next, scenario);
  const titles = CATALOGUE[vector] || CATALOGUE.other;
  const title = titles[Math.floor(next() * titles.length)];
  const asset = ASSETS[Math.floor(next() * ASSETS.length)];
  return {
    id: `evt-${now.toString(36)}-${Math.floor(next() * 1e6).toString(36)}`,
    at: now,
    vector,
    severity,
    title,
    detail: vector === 'other' ? SOURCES[Math.floor(next() * SOURCES.length)] : `asset ${asset}`,
    source: SOURCES[Math.floor(next() * SOURCES.length)]
  };
}

/** Seed the feed so it is never empty on first paint. */
export function seedEvents(scenario, count = 9, now = Date.now()) {
  const next = rng(scenario.seed ^ 0x9e3779b9);
  const events = [];
  for (let i = 0; i < count; i++) {
    events.push(makeEvent(next, scenario, now - i * (9000 + Math.floor(next() * 21000))));
  }
  return events.sort((a, b) => b.at - a.at);
}

/** A map arc: source region → target region, with a random weight. */
export function makeArc(next, scenario, severity = null) {
  let from = Math.floor(next() * REGIONS.length);
  let to = Math.floor(next() * REGIONS.length);
  if (to === from) to = (to + 3) % REGIONS.length;
  const sev = severity || pickSeverity(next, scenario);
  return {
    id: `arc-${Math.floor(next() * 1e9).toString(36)}`,
    from: REGIONS[from].id,
    to: REGIONS[to].id,
    weight: 0.45 + next() * 0.55,
    severity: sev,
    vector: pickVector(next, scenario),
    t: 0
  };
}

/**
 * MEASURED lane — reads the running app. Every field is optional; missing
 * inputs come back as null so the UI prints "—" instead of a guess.
 * @param {object} appState the controller's live state object
 */
export function measuredFrom(appState) {
  if (!appState) return { rules: null, blocked: null, lookups: null, auc: null, scanned: null, resolver: null };
  const engine = appState.engine;
  const breakdown = engine && typeof engine.breakdown === 'function' ? engine.breakdown() : null;
  const metrics = appState.monitor && typeof appState.monitor.metrics === 'function'
    ? appState.monitor.metrics()
    : null;
  const clf = appState.aether && appState.aether.classifier;
  return {
    rules: breakdown ? breakdown.total : null,
    blocked: metrics ? metrics.blocked : null,
    lookups: metrics ? metrics.lookups : null,
    auc: clf && clf.isTrained ? clf.metrics.auc : null,
    scanned: appState.lastBenchmark && appState.lastBenchmark.ok ? appState.lastBenchmark.evaluated : null,
    resolver: metrics ? metrics.latency.p50 : null
  };
}

/** Percentage of `total` for the donut, to one decimal. */
export function share(count, total) {
  if (!total) return 0;
  return Math.round((count / total) * 1000) / 10;
}
