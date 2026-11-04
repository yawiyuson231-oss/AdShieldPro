/**
 * Unit tests — real-time monitor. Only recorded events may appear in metrics.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { SecurityMonitor } from '../../security/monitor.js';

function clockAt(start = 1_700_000_000_000) {
  let now = start;
  const c = () => now;
  c.advance = (ms) => { now += ms; };
  return c;
}

test('an empty monitor reports zeros, not invented activity', () => {
  const m = new SecurityMonitor({ clock: clockAt() });
  const metrics = m.metrics();
  assert.equal(metrics.lookups, 0);
  assert.equal(metrics.blocked, 0);
  assert.equal(metrics.averageLatency, null);
  assert.equal(metrics.blockedRatio, null);
  assert.deepEqual(metrics.topDomains, []);
  assert.ok(metrics.series.lookups.every((p) => p.value === 0));
});

test('counters follow real recorded events', () => {
  const clock = clockAt();
  const m = new SecurityMonitor({ clock });
  m.record({ kind: 'blocked', domain: 'ads.example', category: 'ADS', latencyMs: 2 });
  m.record({ kind: 'lookup', domain: 'example.com', status: 'ok', latencyMs: 40 });
  m.record({ kind: 'lookup', domain: 'down.example', status: 'error', latencyMs: 5000 });
  m.record({ kind: 'firewall', domain: 'c2.example', decision: 'block' });
  m.record({ kind: 'firewall', domain: 'maybe.example', decision: 'monitor' });

  const metrics = m.metrics();
  // `lookups` = every request processed (blocked ones never leave the device);
  // `allowed` = successful resolutions; `blocked` = filtered before resolution.
  assert.equal(metrics.lookups, 3);
  assert.equal(metrics.blocked, 1);
  assert.equal(metrics.allowed, 1);
  assert.equal(metrics.errors, 1);
  assert.equal(metrics.firewallBlocks, 1);
  assert.equal(metrics.firewallMonitors, 1);
  assert.equal(metrics.categories.ADS, 1);
  assert.equal(metrics.blockedRatio, 33.3, '1 blocked of 3 processed requests');
});

test('time buckets form a gap-free series', () => {
  const clock = clockAt();
  const m = new SecurityMonitor({ clock, bucketMs: 60_000, buckets: 10 });
  m.record({ kind: 'lookup', domain: 'a.example', status: 'ok' });
  clock.advance(120_000);
  m.record({ kind: 'lookup', domain: 'b.example', status: 'ok' });
  const series = m.series('lookups', 5);
  assert.equal(series.length, 5);
  for (let i = 1; i < series.length; i++) {
    assert.equal(series[i].t - series[i - 1].t, 60_000, 'series must be contiguous');
  }
  assert.equal(series[series.length - 1].value, 1);
  assert.equal(series[series.length - 3].value, 1);
});

test('old buckets are pruned to bound memory', () => {
  const clock = clockAt();
  const m = new SecurityMonitor({ clock, bucketMs: 1000, buckets: 5 });
  for (let i = 0; i < 20; i++) {
    m.record({ kind: 'lookup', domain: `h${i}.example`, status: 'ok' });
    clock.advance(1000);
  }
  assert.ok(m.buckets.size <= 5, `buckets grew to ${m.buckets.size}`);
});

test('latency percentiles come from measured samples', () => {
  const m = new SecurityMonitor({ clock: clockAt() });
  for (const ms of [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]) {
    m.record({ kind: 'lookup', domain: 'x.example', status: 'ok', latencyMs: ms });
  }
  const { latency, averageLatency } = m.metrics();
  assert.equal(latency.count, 10);
  assert.equal(averageLatency, 55);
  assert.ok(latency.p50 <= latency.p95);
  assert.equal(latency.max, 100);
});

test('per-domain ranking reflects recorded traffic', () => {
  const m = new SecurityMonitor({ clock: clockAt() });
  for (let i = 0; i < 5; i++) m.record({ kind: 'lookup', domain: 'loud.example', status: 'ok' });
  m.record({ kind: 'lookup', domain: 'quiet.example', status: 'ok' });
  const top = m.topDomains(2);
  assert.equal(top[0].domain, 'loud.example');
  assert.equal(top[0].count, 5);
});

test('subscribers receive live events and can unsubscribe', () => {
  const m = new SecurityMonitor({ clock: clockAt() });
  const seen = [];
  const off = m.subscribe((e) => seen.push(e));
  m.record({ kind: 'lookup', domain: 'a.example', status: 'ok' });
  off();
  m.record({ kind: 'lookup', domain: 'b.example', status: 'ok' });
  assert.equal(seen.length, 1);
});

test('a throwing subscriber cannot break monitoring', () => {
  const m = new SecurityMonitor({ clock: clockAt() });
  m.subscribe(() => { throw new Error('observer bug'); });
  assert.doesNotThrow(() => m.record({ kind: 'lookup', domain: 'a.example', status: 'ok' }));
  assert.equal(m.metrics().lookups, 1);
});

test('event ring buffer stays bounded', () => {
  const m = new SecurityMonitor({ clock: clockAt() });
  for (let i = 0; i < 1200; i++) m.record({ kind: 'lookup', domain: `h${i}.example`, status: 'ok' });
  assert.ok(m.events.length <= 800, `event buffer grew to ${m.events.length}`);
  assert.equal(m.metrics().recent.length, 40);
});

test('reset clears every counter', () => {
  const m = new SecurityMonitor({ clock: clockAt() });
  m.record({ kind: 'blocked', domain: 'ads.example', category: 'ADS' });
  m.reset();
  const metrics = m.metrics();
  assert.equal(metrics.lookups, 0);
  assert.equal(metrics.blocked, 0);
  assert.deepEqual(metrics.categories, {});
});
