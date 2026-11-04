/**
 * Unit tests — DNS cache: TTL, negative caching, LRU bound, single-flight.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { DnsCache } from '../../dns/cache.js';

function clockAt() {
  let now = 1_000_000;
  const clock = () => now;
  clock.advance = (ms) => { now += ms; };
  return clock;
}

test('honours TTL and expires entries', () => {
  const clock = clockAt();
  const cache = new DnsCache({ clock });
  cache.set('example.com', 'A', { addresses: ['1.2.3.4'] }, { ttl: 60 });

  assert.equal(cache.get('example.com', 'A').data.addresses[0], '1.2.3.4');
  clock.advance(59_000);
  assert.ok(cache.get('example.com', 'A'), 'still valid at 59s');
  clock.advance(61_000); // past stale grace (60s default) as well
  assert.equal(cache.get('example.com', 'A'), null);
  assert.ok(cache.stats.expirations >= 1);
});

test('serves stale data inside the grace window', () => {
  const clock = clockAt();
  const cache = new DnsCache({ clock });
  cache.set('stale.example', 'A', { addresses: ['1.1.1.1'] }, { ttl: 10, staleGrace: 120 });
  clock.advance(11_000);
  const hit = cache.get('stale.example', 'A');
  assert.ok(hit, 'entry must still be served while stale');
  assert.equal(hit.stale, true);
  assert.ok(cache.stats.staleHits >= 1);
});

test('negative caching uses the SOA-derived TTL, clamped', () => {
  const clock = clockAt();
  const cache = new DnsCache({ clock });
  cache.set('nope.example', 'A', { status: 'nxdomain' }, { negative: true, negativeTtl: 300 });
  const hit = cache.get('nope.example', 'A');
  assert.equal(hit.negative, true);
  assert.equal(hit.expiresAt - hit.storedAt, 300_000);
  assert.ok(cache.stats.negativeHits >= 1);

  cache.set('tiny.example', 'A', {}, { ttl: 0 });
  const tiny = cache.entries.get(DnsCache.key('tiny.example', 'A'));
  assert.equal(tiny.ttl, 1, 'TTL is clamped to a 1s floor');
  cache.set('huge.example', 'A', {}, { ttl: 10_000_000 });
  assert.equal(cache.entries.get(DnsCache.key('huge.example', 'A')).ttl, 86400, 'TTL is capped at 24h');
});

test('memory is bounded (LRU eviction)', () => {
  const cache = new DnsCache({ maxEntries: 3 });
  for (const n of ['a.example', 'b.example', 'c.example', 'd.example']) {
    cache.set(n, 'A', { addresses: ['1.1.1.1'] }, { ttl: 60 });
  }
  assert.equal(cache.entries.size, 3);
  assert.ok(cache.stats.evictions >= 1);
  assert.equal(cache.get('a.example', 'A'), null, 'oldest entry evicted');
  // Accessing an entry refreshes its LRU position.
  cache.set('e.example', 'A', {}, { ttl: 60 });
  cache.get('d.example', 'A');
  cache.set('f.example', 'A', {}, { ttl: 60 });
  assert.ok(cache.get('d.example', 'A'), 'recently used entry must survive');
});

test('single-flight collapses concurrent lookups into one factory call', async () => {
  const cache = new DnsCache();
  let calls = 0;
  const factory = async () => {
    calls++;
    await new Promise((r) => setTimeout(r, 10));
    return { addresses: ['9.9.9.9'] };
  };
  const key = DnsCache.key('same.example', 'A');
  const results = await Promise.all(
    Array.from({ length: 20 }, () => cache.singleFlight(key, factory, (v) => ({ ttl: 30, value: v })))
  );
  assert.equal(calls, 1, `factory ran ${calls} times, expected 1`);
  assert.equal(cache.stats.singleFlightJoins, 19);
  assert.equal(results.length, 20);
  assert.deepEqual(cache.get('same.example', 'A').data.addresses, ['9.9.9.9']);
});

test('single-flight does not cache failures', async () => {
  const cache = new DnsCache();
  let calls = 0;
  const failing = async () => { calls++; throw new Error('boom'); };
  await assert.rejects(() => cache.singleFlight(DnsCache.key('x.example', 'A'), failing));
  await assert.rejects(() => cache.singleFlight(DnsCache.key('x.example', 'A'), failing));
  assert.equal(calls, 2, 'a failed lookup must be retried, never cached');
  assert.equal(cache.entries.size, 0);
});

test('prune removes only fully dead entries', () => {
  const clock = clockAt();
  const cache = new DnsCache({ clock });
  cache.set('live.example', 'A', {}, { ttl: 600, staleGrace: 0 });
  cache.set('dead.example', 'A', {}, { ttl: 1, staleGrace: 0 });
  clock.advance(5_000);
  const removed = cache.prune();
  assert.equal(removed, 1);
  assert.ok(cache.get('live.example', 'A'));
  assert.equal(cache.snapshot().entries, 1);
});
