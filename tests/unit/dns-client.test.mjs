/**
 * Unit tests — full DNS pipeline (filter → cache → transport → DNSSEC).
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { DnsClient } from '../../dns/client.js';
import { DnsCache } from '../../dns/cache.js';
import { DohTransport, ResolverPool, RESOLVER_BY_ID, ResolverHealth } from '../../dns/resolvers.js';
import { OmniShieldFilterEngine } from '../../engine.js';
import { createMockDoh } from '../helpers/mock-dns.mjs';

const [CF, GOOGLE] = [RESOLVER_BY_ID.cloudflare, RESOLVER_BY_ID.google];

function clockAt() {
  let now = 1_000_000;
  const c = () => now;
  c.advance = (ms) => { now += ms; };
  return c;
}

function makeClient(options = {}) {
  const clock = options.clock ?? clockAt();
  const net = options.net ?? createMockDoh();
  const engine = options.engine ?? (() => {
    const e = new OmniShieldFilterEngine();
    e.loadFilterList('||ads.doubleclick.net^\n||tracker.example^\n', 'ADS', 'test_feed');
    return e;
  })();
  const cache = new DnsCache({ clock });
  const pool = new ResolverPool({
    resolvers: options.resolvers ?? [CF, GOOGLE],
    transport: new DohTransport({ fetchImpl: net.fetchImpl, timeoutMs: 2000 }),
    health: new ResolverHealth({ clock }),
    clock
  });
  const observations = [];
  const client = new DnsClient({
    engine, pool, cache, clock,
    onObservation: (e) => observations.push(e)
  });
  return { client, net, cache, engine, clock, observations };
}

test('blocked names never leave the device', async () => {
  const { client, net, observations } = makeClient();
  const result = await client.lookup('https://ads.doubleclick.net/banner.js');
  assert.equal(result.status, 'blocked');
  assert.equal(result.blocked, true);
  assert.equal(result.addresses.length, 0);
  assert.equal(net.calls.length, 0, 'a filtered domain must not trigger a DNS request');
  assert.equal(result.blockedBy.category, 'ADS');
  assert.equal(result.blockedBy.source, 'test_feed');
  assert.match(result.reasons.join(' '), /doubleclick/);
  assert.equal(client.stats.blocked, 1);
  assert.equal(client.stats.byCategory.ADS, 1);
  assert.ok(observations.some((o) => o.kind === 'blocked'));
});

test('allowed names resolve once and are then served from cache', async () => {
  const { client, net, cache } = makeClient();
  const first = await client.lookup('example.com');
  assert.equal(first.status, 'ok');
  assert.deepEqual(first.addresses, ['93.184.216.34']);
  assert.equal(first.cached, false);
  assert.equal(first.pipeline.includes('cache:miss'), true);
  assert.equal(net.calls.length, 1);

  const second = await client.lookup('example.com');
  assert.equal(second.cached, true);
  assert.deepEqual(second.addresses, ['93.184.216.34']);
  assert.equal(net.calls.length, 1, 'cache hit must not hit the network');
  assert.equal(client.stats.cached, 1);
  assert.ok(cache.get('example.com', 'A'));
});

test('forceRefresh bypasses a warm cache', async () => {
  const { client, net } = makeClient();
  await client.lookup('example.com');
  await client.lookup('example.com', { forceRefresh: true });
  assert.equal(net.calls.length, 2);
});

test('single-flight collapses concurrent lookups', async () => {
  const { client, net } = makeClient({ net: createMockDoh({ latencyMs: 20 }) });
  const results = await Promise.all(Array.from({ length: 10 }, () => client.lookup('cdn.example.net')));
  assert.equal(net.calls.length, 1, `expected 1 request, saw ${net.calls.length}`);
  assert.ok(results.every((r) => r.status === 'ok'));
});

test('stale-while-revalidate serves immediately and refreshes in the background', async () => {
  const clock = clockAt();
  const net = createMockDoh();
  const { client, cache } = makeClient({ clock, net });
  await client.lookup('example.com');           // TTL 120s from the mock
  const cached = cache.get('example.com', 'A');
  clock.advance(121_000);                       // past TTL, inside stale grace (60s)

  const stale = await client.lookup('example.com');
  assert.equal(stale.cached, true);
  assert.equal(stale.stale, true);
  assert.match(stale.reasons.join(' '), /stale/i);

  await new Promise((r) => setTimeout(r, 30)); // let the background refresh land
  assert.equal(net.calls.length, 2, 'stale hit must trigger exactly one background refresh');
  const refreshed = cache.get('example.com', 'A');
  assert.equal(refreshed.stale, false, 'cache must be fresh again after revalidation');
});

test('NXDOMAIN is negatively cached using the SOA-derived TTL', async () => {
  const { client, net, cache } = makeClient({ net: createMockDoh({ nxdomain: new Set(['gone.example']) }) });
  const first = await client.lookup('gone.example');
  assert.equal(first.status, 'nxdomain');
  assert.equal(first.ok, false);
  assert.match(first.reasons.join(' '), /NXDOMAIN/);
  const entry = cache.get('gone.example', 'A');
  assert.equal(entry.negative, true);
  assert.equal(entry.ttl, 300, 'negative TTL comes from the SOA minimum');

  await client.lookup('gone.example');
  assert.equal(net.calls.length, 1);
  assert.equal(client.stats.nxdomain, 1);
});

test('network failure is surfaced honestly (no plaintext fallback, no fake answer)', async () => {
  const net = createMockDoh({ failHosts: new Set(['cloudflare-dns.com', 'dns.google']) });
  const { client } = makeClient({ net });
  const result = await client.lookup('example.com');
  assert.equal(result.status, 'error');
  assert.equal(result.ok, false);
  assert.deepEqual(result.addresses, []);
  assert.match(result.reasons.join(' '), /does not fall back to unencrypted DNS/);
  assert.equal(client.stats.errors, 1);
});

test('IP literals and invalid input short-circuit without network traffic', async () => {
  const { client, net } = makeClient();
  const ip = await client.lookup('192.0.2.55');
  assert.equal(ip.status, 'ip-literal');
  assert.deepEqual(ip.addresses, ['192.0.2.55']);
  assert.equal(net.calls.length, 0);

  const bad = await client.lookup('not a hostname');
  assert.equal(bad.status, 'invalid');
  assert.equal(bad.ok, false);
  assert.equal(net.calls.length, 0);
});

test('dual-stack resolution queries A and AAAA in parallel', async () => {
  const { client, net } = makeClient();
  const res = await client.lookupDualStack('cdn.example.net');
  assert.deepEqual(res.ipv4, ['203.0.113.10']);
  assert.deepEqual(res.ipv6, ['2001:db8::10']);
  assert.equal(net.calls.length, 2);
  assert.equal(res.blocked, false);
  const types = net.calls.map((c) => new URL(c.url).searchParams.get('type')).sort();
  assert.deepEqual(types, ['1', '28']);
});

test('DNSSEC verdict travels with the result', async () => {
  const { client } = makeClient({ net: createMockDoh({ ad: true }) });
  const result = await client.lookup('example.com');
  assert.equal(result.dnssec.status, 'VALIDATED_UPSTREAM');
  assert.equal(result.dnssec.validatedBy, 'Cloudflare 1.1.1.1');
  assert.match(result.pipeline.join(' '), /dnssec:VALIDATED_UPSTREAM/);
});

test('latency statistics are real percentiles', async () => {
  const clock = clockAt();
  const net = createMockDoh({ latencyMs: 2 });
  const { client } = makeClient({ clock, net });
  for (let i = 0; i < 5; i++) await client.lookup(`host${i}.example`); // NXDOMAIN but measured
  const snapshot = client.snapshot();
  assert.ok(snapshot.latency.count > 0);
  assert.ok(snapshot.latency.p50 <= snapshot.latency.p95);
  assert.ok(snapshot.cache.entries > 0);
  assert.ok(Array.isArray(snapshot.health));
  assert.equal(snapshot.stats.latencySamples, undefined, 'raw samples must not leak into snapshots');
});
