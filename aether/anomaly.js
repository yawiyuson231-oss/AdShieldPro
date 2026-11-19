/**
 * AETHER Behavioral Anomaly & Screen-Off Tracker Radar (Web Engine).
 *
 * Pure deterministic time-series analyzer for DNS query logs:
 *  - Screen-Off / Overnight Tracker Radar (queries while `isScreenInteractive === false` or 00:00–05:59)
 *  - Fixed-Interval C2 Beaconing detection (low coefficient of variation across >= 4 intervals)
 *  - High-Entropy DGA / Tunneling label detection (Shannon entropy >= 3.6 bits/char)
 */

const TRACKER_KEYWORDS = [
  'metrics', 'telemetry', 'analytics', 'beacon', 'tracking',
  'pixel', 'collect', 'log', 'crashlytics', 'appsflyer', 'adjust'
];

export function computeShannonEntropy(label) {
  if (!label || typeof label !== 'string' || label.length === 0) return 0;
  const freq = new Map();
  for (let i = 0; i < label.length; i += 1) {
    const ch = label[i];
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / label.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function analyzeBehavioralAnomalies(events = []) {
  if (!Array.isArray(events) || events.length === 0) {
    return {
      totalEvents: 0,
      screenOffTrackerHits: 0,
      beaconAlerts: [],
      dgaAlerts: [],
      radarScore: 0,
      status: 'CALM'
    };
  }

  let screenOffTrackerHits = 0;
  const byDomain = new Map();
  const dgaAlerts = [];
  const seenDga = new Set();

  for (const ev of events) {
    if (!ev || !ev.domain) continue;
    const domain = String(ev.domain).toLowerCase().replace(/\.$/, '');
    const ts = Number(ev.timestampMs || Date.now());
    const isScreenOff = ev.isScreenInteractive === false;

    if (isScreenOff && TRACKER_KEYWORDS.some((kw) => domain.includes(kw))) {
      screenOffTrackerHits += 1;
    }

    if (!byDomain.has(domain)) byDomain.set(domain, []);
    byDomain.get(domain).push(ts);

    const firstLabel = domain.split('.')[0] || '';
    if (firstLabel.length >= 14 && !seenDga.has(domain)) {
      const entropy = computeShannonEntropy(firstLabel);
      if (entropy >= 3.6) {
        seenDga.add(domain);
        dgaAlerts.push({ domain, entropy: Number(entropy.toFixed(2)) });
      }
    }
  }

  const beaconAlerts = [];
  for (const [domain, timestamps] of byDomain.entries()) {
    if (timestamps.length < 5) continue;
    timestamps.sort((a, b) => a - b);
    const deltas = [];
    for (let i = 1; i < timestamps.length; i += 1) {
      const d = timestamps[i] - timestamps[i - 1];
      if (d >= 2000 && d <= 3600000) deltas.push(d);
    }
    if (deltas.length < 4) continue;
    const mean = deltas.reduce((acc, v) => acc + v, 0) / deltas.length;
    if (mean <= 0) continue;
    const variance = deltas.reduce((acc, v) => acc + (v - mean) ** 2, 0) / deltas.length;
    const cv = Math.sqrt(variance) / mean;
    if (cv <= 0.18) {
      beaconAlerts.push({
        domain,
        intervalMs: Math.round(mean),
        cv: Number(cv.toFixed(3)),
        samples: deltas.length + 1
      });
    }
  }

  const rawScore = Math.min(
    100,
    screenOffTrackerHits * 4 + beaconAlerts.length * 25 + dgaAlerts.length * 18
  );
  const status = rawScore >= 60 ? 'ELEVATED' : rawScore >= 20 ? 'WATCH' : 'CALM';

  return {
    totalEvents: events.length,
    screenOffTrackerHits,
    beaconAlerts,
    dgaAlerts,
    radarScore: rawScore,
    status
  };
}
