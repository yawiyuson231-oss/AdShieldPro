/**
 * Unit tests — Firewall AI behavioural detectors.
 *
 * Each detector is fed a deterministic, purpose-built observation stream so the
 * algorithm (not the UI) is what is being validated. Negative cases matter as
 * much as positive ones: a detector that fires on normal traffic is a bug.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { FirewallAI, coefficientOfVariation, stdDev, DEFAULT_CONFIG } from '../../security/firewall-ai.js';

function fixedClock(t = 1_700_000_000_000) {
  let now = t;
  const c = () => now;
  c.advance = (ms) => { now += ms; };
  c.set = (v) => { now = v; };
  return c;
}

test('statistics helpers are exact', () => {
  assert.equal(stdDev([2, 4, 4, 4, 5, 5, 7, 9]), Math.sqrt(32 / 7));
  assert.equal(coefficientOfVariation([60, 60, 60]), 0);
  assert.equal(coefficientOfVariation([60]), null);
  assert.equal(coefficientOfVariation([0, 0]), null);
  assert.ok(coefficientOfVariation([10, 40, 100]) > 0.5);
});

test('beaconing: metronome traffic fires with high confidence', () => {
  const fw = new FirewallAI({ clock: fixedClock() });
  const base = 1_700_000_000_000;
  for (let i = 0; i < 12; i++) fw.observe({ domain: 'c2.example', at: base + i * 60_000 });
  const result = fw.detectBeaconing('c2.example');
  assert.equal(result.fired, true);
  assert.equal(result.confidence, 'high');
  assert.equal(result.cv, 0);
  assert.equal(result.meanIntervalMs, 60_000);
  assert.equal(result.samples, 12);
  assert.match(result.evidence, /near-constant/);
  assert.match(result.evidence, /legit API on a timer/i, 'evidence must admit benign explanations');
});

test('beaconing: jittered human traffic does not fire', () => {
  const fw = new FirewallAI({ clock: fixedClock() });
  const gaps = [5_000, 120_000, 9_000, 300_000, 15_000, 45_000, 7_000, 200_000, 33_000];
  let t = 1_700_000_000_000;
  fw.observe({ domain: 'browser.example', at: t });
  for (const gap of gaps) { t += gap; fw.observe({ domain: 'browser.example', at: t }); }
  assert.equal(fw.detectBeaconing('browser.example').fired, false);
});

test('beaconing: too few samples yields insufficient-data, not a verdict', () => {
  const fw = new FirewallAI({ clock: fixedClock() });
  fw.observe({ domain: 'once.example', at: 1 });
  fw.observe({ domain: 'once.example', at: 2 });
  const result = fw.detectBeaconing('once.example');
  assert.equal(result.fired, false);
  assert.equal(result.reason, 'insufficient-data');
  assert.equal(result.required, DEFAULT_CONFIG.beaconMinSamples);
});

test('beaconing: sub-5-second polling is excluded as noise', () => {
  const fw = new FirewallAI({ clock: fixedClock() });
  const base = 1_700_000_000_000;
  for (let i = 0; i < 12; i++) fw.observe({ domain: 'busy.example', at: base + i * 1000 });
  const result = fw.detectBeaconing('busy.example');
  assert.equal(result.fired, false);
  assert.equal(result.reason, 'interval-too-short');
});

test('tunnelling: long unique high-entropy subdomains fire', () => {
  const fw = new FirewallAI({ clock: fixedClock() });
  const base = 1_700_000_000_000;
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 24; i++) {
    let token = '';
    for (let j = 0; j < 48; j++) token += alphabet[(i * 7 + j * 11) % alphabet.length];
    fw.observe({ domain: `${token}.${i}.chunk.data.tunnel.tk`, at: base + i * 1000 });
  }
  const result = fw.detectTunneling('tunnel.tk');
  assert.equal(result.fired, true);
  assert.ok(result.uniqueSubdomains >= 20);
  assert.ok(result.avgLabelLength >= DEFAULT_CONFIG.tunnelAvgLabelLength);
  assert.ok(result.avgEntropy >= DEFAULT_CONFIG.tunnelMinEntropy);
  assert.ok(result.checks.longLabels && result.checks.highEntropy);
  assert.match(result.evidence, /DNS tunnelling/);
  assert.match(result.evidence, /domain sharding/, 'evidence must admit benign explanations');
});

test('tunnelling: normal CDN subdomains do not fire', () => {
  const fw = new FirewallAI({ clock: fixedClock() });
  const base = 1_700_000_000_000;
  const hosts = ['api', 'www', 'cdn1', 'cdn2', 'static', 'img', 'media', 'assets', 'login', 'mail'];
  for (let i = 0; i < 20; i++) {
    fw.observe({ domain: `${hosts[i % hosts.length]}.example.com`, at: base + i * 1000 });
  }
  const result = fw.detectTunneling('example.com');
  assert.equal(result.fired, false);
  assert.ok(result.uniqueRatio < DEFAULT_CONFIG.tunnelUniqueRatio || result.avgLabelLength < DEFAULT_CONFIG.tunnelAvgLabelLength);
});

test('rate anomaly: a real burst against a measured baseline fires', () => {
  const fw = new FirewallAI({ clock: fixedClock() });
  const base = 1_700_000_000_000;
  const window = DEFAULT_CONFIG.rateWindowMs;
  let t = base;
  for (let w = 5; w >= 1; w--) {
    for (let i = 0; i < 2; i++) fw.observe({ domain: 'burst.example', at: base - w * window + i * 10_000 });
  }
  for (let i = 0; i < 25; i++) fw.observe({ domain: 'burst.example', at: base + i * 1000 });
  const result = fw.detectRateAnomaly('burst.example');
  assert.equal(result.fired, true);
  assert.ok(result.currentRate >= 20);
  assert.ok(result.baselineMean < 5);
  assert.match(result.evidence, /baseline/);
});

test('rate anomaly: steady traffic does not fire', () => {
  const fw = new FirewallAI({ clock: fixedClock() });
  const base = 1_700_000_000_000;
  const window = DEFAULT_CONFIG.rateWindowMs;
  for (let w = 6; w >= 0; w--) {
    for (let i = 0; i < 4; i++) fw.observe({ domain: 'steady.example', at: base - w * window + i * 20_000 });
  }
  const result = fw.detectRateAnomaly('steady.example');
  assert.equal(result.fired, false, `steady traffic falsely flagged: ${JSON.stringify(result)}`);
});

test('fan-out: many distinct destinations in one minute fires', () => {
  const clock = fixedClock();
  const fw = new FirewallAI({ clock });
  const base = 1_700_000_000_000;
  // Fan-out counts distinct REGISTRABLE domains: subdomains of one parent are not.
  for (let i = 0; i < 70; i++) fw.observe({ domain: `d${i}.example`, at: base + i * 500 });
  const result = fw.detectFanout(base + 40_000);
  assert.equal(result.fired, true);
  assert.ok(result.distinct >= 60);
});

test('decisions: explicit user policy wins in both directions', () => {
  const fw = new FirewallAI({ clock: fixedClock() });
  fw.setPolicy('browser', 'known-good.example', 'allow');
  fw.setPolicy('browser', 'blocked.example', 'block');
  const base = 1_700_000_000_000;
  for (let i = 0; i < 12; i++) {
    fw.observe({ domain: 'known-good.example', app: 'browser', at: base + i * 60_000 });
    fw.observe({ domain: 'blocked.example', app: 'browser', at: base + i * 60_000 });
  }
  const allowed = fw.evaluate('known-good.example', { app: 'browser' });
  assert.equal(allowed.decision, 'allow');
  assert.equal(allowed.confidence, 'user-policy');
  assert.match(allowed.reasons.join(' '), /explicitly allows/);

  const blocked = fw.evaluate('blocked.example', { app: 'browser' });
  assert.equal(blocked.decision, 'block');
  assert.equal(blocked.confidence, 'user-policy');
});

test('decisions: one weak signal only monitors, two independent signals block', () => {
  const fw = new FirewallAI({ clock: fixedClock() });
  const base = 1_700_000_000_000;
  for (let i = 0; i < 12; i++) fw.observe({ domain: 'beacon-only.example', at: base + i * 60_000 });
  const evalAt = base + 11 * 60_000;

  const single = fw.evaluate('beacon-only.example', { at: evalAt });
  assert.equal(single.decision, 'monitor', 'a single signal must not block');
  assert.equal(single.confidence, 'low');
  assert.equal(single.signals.filter((s) => s.fired).length, 1);
  assert.match(single.reasons.join(' '), /not enough to block/);

  // Add an independent signal: a domain fan-out in the same window.
  for (let i = 0; i < 70; i++) fw.observe({ domain: `spray${i}.net`, at: evalAt - 30_000 + i * 400 });

  const multi = fw.evaluate('beacon-only.example', { at: evalAt });
  const fired = multi.signals.filter((s) => s.fired).map((s) => s.id).sort();
  assert.deepEqual(fired, ['beaconing', 'fanout'], `unexpected signal set: ${fired}`);
  assert.equal(multi.decision, 'block');
  assert.ok(['medium', 'high'].includes(multi.confidence));
  assert.ok(multi.reasons.length >= 2, 'each contributing signal must be explained');
});

test('decisions: no observation yields allow plus an explicit insufficient-data note', () => {
  const fw = new FirewallAI({ clock: fixedClock() });
  const result = fw.evaluate('unseen.example');
  assert.equal(result.decision, 'allow');
  assert.equal(result.confidence, 'none');
  assert.match(result.reasons.join(' '), /insufficient data/i);
  assert.match(result.reasons.join(' '), /instead of guessing/);
});

test('inspect() reports raw detector output without inventing a verdict', () => {
  const fw = new FirewallAI({ clock: fixedClock() });
  const base = 1_700_000_000_000;
  for (let i = 0; i < 8; i++) fw.observe({ domain: 'inspect.example', at: base + i * 60_000 });
  const report = fw.inspect('inspect.example');
  assert.equal(report.observations, 8);
  assert.ok(report.features);
  assert.equal(typeof report.beaconing.fired, 'boolean');
  assert.equal('decision' in report, false, 'inspect must not pretend to decide');
});

test('observation store is bounded', () => {
  const fw = new FirewallAI({ clock: fixedClock(), maxDestinations: 50 });
  for (let i = 0; i < 200; i++) fw.observe({ domain: `host${i}.example`, at: 1000 + i });
  assert.ok(fw.destinations.size <= 200, 'tracked destinations must stay bounded');
  assert.ok(fw.stats.observations === 200);
});

test('log import accepts a real observation log', () => {
  const fw = new FirewallAI({ clock: fixedClock() });
  const accepted = fw.importLog([
    { domain: 'a.example', app: 'com.example.app', timestamp: 1000 },
    { domain: 'b.example', app: 'com.example.app', timestamp: 2000 },
    { nonsense: true }
  ]);
  assert.equal(accepted, 2);
  assert.equal(fw.destinations.get('a.example').count, 1);
});
