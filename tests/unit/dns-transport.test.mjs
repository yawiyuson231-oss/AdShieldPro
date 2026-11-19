/**
 * Unit tests — encrypted transport, health/fallback, DNSSEC assessment.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import {
  DohTransport, ResolverPool, ResolverHealth, DotTransport, RESOLVERS,
  UnsupportedTransportError, ResolverTimeoutError, RESOLVER_BY_ID
} from '../../dns/resolvers.js';
import { assessDnssec, inspectSignatures, DNSSEC_STATUS } from '../../dns/dnssec.js';
import { decodeMessage, fromHex } from '../../dns/codec.js';
import { createMockDoh, makeJson, wireResponse } from '../helpers/mock-dns.mjs';

const CF = RESOLVER_BY_ID.cloudflare;
const GOOGLE = RESOLVER_BY_ID.google;
const QUAD9 = RESOLVER_BY_ID.quad9;

function clockAt() {
  let now = 1_000_000;
  const c = () => now;
  c.advance = (ms) => { now += ms; };
  return c;
}

test('resolver registry is real and complete', () => {
  for (const r of RESOLVERS) {
    assert.ok(r.id && r.name && r.operator, `resolver ${r.id} missing metadata`);
    assert.ok(r.dohJson || r.dohWire, `resolver ${r.id} has no DoH endpoint`);
    assert.ok(r.dot, `resolver ${r.id} should document its DoT name`);
    assert.match(r.dohWire || r.dohJson, /^https:\/\//, 'DoH endpoints must be HTTPS');
    assert.ok(r.privacy, 'privacy policy must be quoted, not assumed');
  }
  assert.ok(RESOLVERS.length >= 4);
});

test('DoH JSON transport parses answers, AD bit and NXDOMAIN', async () => {
  const net = createMockDoh({ ad: true });
  const transport = new DohTransport({ fetchImpl: net.fetchImpl, timeoutMs: 1000 });

  const ok = await transport.query(CF, 'example.com', 'A');
  assert.equal(ok.transport, 'DoH-JSON');
  assert.equal(ok.message.rcode, 0);
  assert.equal(ok.message.flags.authenticatedData, true);
  assert.equal(ok.message.answers[0].data.address, '93.184.216.34');
  assert.match(net.calls[0].url, /do=1/, 'DNSSEC records must be requested');
  assert.match(net.calls[0].url, /name=example\.com/);

  const nx = await transport.query(CF, 'doesnotexist.example', 'A');
  assert.equal(nx.message.rcode, 3);
  assert.equal(nx.message.authorities[0].data.minimum, undefined, 'SOA from JSON is opaque text');
});

test('DoH wire transport (RFC 8484) decodes binary responses', async () => {
  const packet =
    '0000' + '8180' + '0001' + '0001' + '0000' + '0000' +
    '07' + '6578616d706c65' + '03' + '636f6d' + '00' + '0001' + '0001' +
    'c00c' + '0001' + '0001' + '0000012c' + '0004' + '5db8d822';
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push(String(url));
    assert.equal(init.redirect, 'error');
    return wireResponse(packet);
  };
  const transport = new DohTransport({ fetchImpl, preferJson: false });
  const { message, transport: kind } = await transport.query(QUAD9, 'example.com', 'A');
  assert.equal(kind, 'DoH-WIRE');
  assert.equal(message.answers[0].data.address, '93.184.216.34');
  assert.match(seen[0], /^https:\/\/dns\.quad9\.net\/dns-query\?dns=[A-Za-z0-9_-]+$/);
});

test('DoT is implemented but honestly reports browser limitations', async () => {
  const cap = DotTransport.capability();
  assert.equal(cap.implemented, true);
  assert.equal(cap.usableInBrowser, false);
  assert.match(cap.reason, /TCP/);
  await assert.rejects(
    () => new DotTransport().query(CF),
    (err) => err instanceof UnsupportedTransportError && /DoT/.test(err.message)
  );
});

test('timeouts abort cleanly and are classified', async () => {
  const net = createMockDoh({ latencyMs: 200 });
  const transport = new DohTransport({ fetchImpl: net.fetchImpl, timeoutMs: 20 });
  await assert.rejects(
    () => transport.query(CF, 'example.com', 'A'),
    (err) => err instanceof ResolverTimeoutError && err.code === 'TIMEOUT'
  );
});

test('health scoring and intelligent fallback', async () => {
  const clock = clockAt();
  const health = new ResolverHealth({ clock, failureThreshold: 2, cooldownMs: 30_000 });
  health.recordSuccess('mulvad', 20);
  health.recordSuccess('cloudflare', 400);
  assert.ok(health.score('mulvad') < health.score('cloudflare'), 'fast+reliable must rank first');

  const net = createMockDoh({ failHosts: new Set(['cloudflare-dns.com']) });
  const pool = new ResolverPool({
    resolvers: [CF, GOOGLE],
    transport: new DohTransport({ fetchImpl: net.fetchImpl }),
    health, clock
  });
  const result = await pool.query('example.com', 'A');
  assert.equal(result.status, 'ok');
  assert.equal(result.resolver.id, 'google', 'must failver over to the healthy resolver');
  assert.equal(result.attempts.length, 2);
  assert.equal(result.attempts[0].ok, false);
  assert.match(result.attempts[0].error, /simulated network failure/);
  assert.equal(health.state.get('cloudflare').consecutiveFailures, 1);
});

test('circuit breaker stops routing to a dead resolver, then recovers', async () => {
  const clock = clockAt();
  const health = new ResolverHealth({ clock, failureThreshold: 2, cooldownMs: 10_000 });
  const net = createMockDoh();

  // Health first: the breaker opens only after the failure threshold.
  health.recordFailure('cloudflare', new Error('down'));
  assert.equal(health.isAvailable('cloudflare'), true, 'one failure must not trip the breaker');
  health.recordFailure('cloudflare', new Error('down'));
  assert.equal(health.isAvailable('cloudflare'), false, 'two consecutive failures must trip it');

  const pool = new ResolverPool({
    resolvers: [CF, GOOGLE],
    transport: new DohTransport({ fetchImpl: net.fetchImpl }),
    health, clock
  });
  assert.equal(pool.order()[0].id, 'google', 'open resolver must be routed last');

  const result = await pool.query('example.com', 'A');
  assert.equal(result.resolver.id, 'google');
  assert.equal(net.calls.length, 1, 'an open breaker must not receive traffic');
  assert.equal(result.attempts.length, 1);

  // A successful call closes the circuit again.
  health.recordSuccess('cloudflare', 12);
  assert.equal(health.isAvailable('cloudflare'), true);
  assert.equal(health.state.get('cloudflare').consecutiveFailures, 0);

  // Cooldown expiry also restores availability.
  health.recordFailure('cloudflare', new Error('down'));
  health.recordFailure('cloudflare', new Error('down'));
  assert.equal(health.isAvailable('cloudflare'), false);
  clock.advance(10_001);
  assert.equal(health.isAvailable('cloudflare'), true, 'cooldown must restore availability');
});

test('total failure is reported honestly, never faked', async () => {
  const net = createMockDoh({ failHosts: new Set(['cloudflare-dns.com', 'dns.google']) });
  const pool = new ResolverPool({
    resolvers: [CF, GOOGLE],
    transport: new DohTransport({ fetchImpl: net.fetchImpl }),
    health: new ResolverHealth({ failureThreshold: 5 })
  });
  const result = await pool.query('example.com', 'A');
  assert.equal(result.ok, false);
  assert.equal(result.status, 'error');
  assert.equal(result.addresses.length, 0);
  assert.equal(result.attempts.length, 2);
  assert.match(result.error, /simulated network failure/);
});

test('DNSSEC: AD bit means validated BY THE RESOLVER, and says so', () => {
  const msg = decodeMessage(fromHex(
    '1234' + '8020' + '0001' + '0000' + '0000' + '0000' +   // AD set
    '07' + '6578616d706c65' + '03' + '636f6d' + '00' + '0001' + '0001'
  ));
  const a = assessDnssec({ message: msg, requested: true, resolverName: 'Cloudflare 1.1.1.1' });
  assert.equal(a.status, DNSSEC_STATUS.VALIDATED_UPSTREAM);
  assert.equal(a.validatedBy, 'Cloudflare 1.1.1.1');
  assert.match(a.detail, /did not perform local cryptographic validation/);
});

test('DNSSEC: SERVFAIL is not claimed as "bogus"', () => {
  const msg = decodeMessage(fromHex(
    '1234' + '8182' + '0001' + '0000' + '0000' + '0000' +
    '07' + '6578616d706c65' + '00' + '0001' + '0001'
  ));
  const a = assessDnssec({ message: msg, requested: true, resolverName: 'Cloudflare' });
  assert.equal(a.status, DNSSEC_STATUS.BOGUS_SUSPECTED);
  assert.match(a.detail, /does not claim a signature was proven invalid/);
});

test('DNSSEC: unsigned zones and missing responses', () => {
  const msg = decodeMessage(fromHex(
    '1234' + '8180' + '0001' + '0000' + '0000' + '0000' +
    '07' + '6578616d706c65' + '03' + '636f6d' + '00' + '0001' + '0001'
  ));
  assert.equal(assessDnssec({ message: msg, requested: true }).status, DNSSEC_STATUS.UNSIGNED);
  assert.equal(
    assessDnssec({ message: null, requested: true, transportFailed: true }).status,
    DNSSEC_STATUS.UNKNOWN
  );
  const sig = inspectSignatures(msg);
  assert.equal(sig.signed, false);
});

test('DoH wire rejects mismatched IDs, questions, truncated replies and trailing bytes', async () => {
  const packet = '000081800001000000000000076578616d706c6503636f6d0000010001';
  for (const hex of [
    `0100${packet.slice(4)}`,
    `${packet.slice(0, 4)}8380${packet.slice(8)}`,
    `${packet.slice(0, -8)}001c0001`,
    `${packet.slice(0, -4)}0003`,
    `${packet}00`
  ]) {
    const transport = new DohTransport({ fetchImpl: async () => wireResponse(hex), preferJson: false });
    await assert.rejects(() => transport.query(QUAD9, 'example.com', 'A'), /ID or flags|question|trailing/);
  }
});

test('DoH JSON rejects replies for a different question and never calls plain HTTP', async () => {
  let calls = 0;
  const transport = new DohTransport({ fetchImpl: async () => {
    calls++;
    return makeJson({ Status: 0, Question: [{ name: 'different.example.', type: 1 }] });
  } });
  await assert.rejects(() => transport.query({ ...CF, dohJson: 'http://resolver.example/dns' }, 'example.com', 'A'), /requires HTTPS/);
  assert.equal(calls, 0);
  await assert.rejects(() => transport.query(CF, 'example.com', 'A'), /question did not match/);
});

test('DoH checks content type, bounds streamed bodies and enforces its timeout after headers', async () => {
  const wrongType = new DohTransport({ fetchImpl: async () => new Response('<html>Not DNS</html>'), preferJson: false });
  await assert.rejects(() => wrongType.query(QUAD9, 'example.com', 'A'), /content type/);
  const response = (body) => new Response(body, { headers: { 'content-type': 'application/dns-message' } });
  const oversized = new DohTransport({ fetchImpl: async () => response(new Uint8Array(65536)), preferJson: false });
  await assert.rejects(() => oversized.query(QUAD9, 'example.com', 'A'), /too large/);
  let canceled = false;
  const slow = new DohTransport({ fetchImpl: async () => response(new ReadableStream({
    pull: () => new Promise(() => {}),
    cancel: () => { canceled = true; }
  })), preferJson: false, timeoutMs: 30 });
  await assert.rejects(() => slow.query(QUAD9, 'example.com', 'A'), ResolverTimeoutError);
  assert.equal(canceled, true);
});

test('extended RCODE and EDE cause encrypted failover rather than a false success', async () => {
  const fixture = '000081800001000000000001076578616d706c6503636f6d0000010001'
    + '00002904d0010080000006000f00020006'; // Extended RCODE 16 (BADVERS), EDE 6.
  const healthy = createMockDoh();
  const pool = new ResolverPool({
    resolvers: [QUAD9, GOOGLE], raceDelayMs: 0,
    transport: new DohTransport({ fetchImpl: (url, init) => url.includes('quad9') ? wireResponse(fixture) : healthy.fetchImpl(url, init) })
  });
  const result = await pool.query('example.com', 'A');
  assert.equal(result.resolver.id, 'google');
  assert.equal(result.attempts[0].rcode, 16);
  assert.deepEqual(result.attempts[0].extendedErrors, [6]);
  assert.equal(pool.health.isAvailable('quad9'), true);
  assert.equal(pool.health.snapshot().find((provider) => provider.id === 'quad9').successes, 0);
});

test('a losing browser hedge is canceled without counting it as a failure', async () => {
  let canceled = false;
  const healthy = createMockDoh();
  const pool = new ResolverPool({
    resolvers: [CF, GOOGLE], raceDelayMs: 15,
    transport: new DohTransport({ fetchImpl: async (url, init) => {
      if (!url.includes('cloudflare-dns.com')) return healthy.fetchImpl(url, init);
      return new Promise((resolve, reject) => {
        init.signal.addEventListener('abort', () => {
          canceled = true;
          reject(init.signal.reason);
        }, { once: true });
      });
    } })
  });
  const result = await pool.query('example.com', 'A');
  assert.equal(result.resolver.id, 'google');
  assert.equal(canceled, true);
  assert.equal(pool.health.snapshot().find((provider) => provider.id === 'cloudflare').failures, 0);
});

test('an all-open web resolver plan reports cooldown without sending additional queries', async () => {
  const clock = clockAt();
  const health = new ResolverHealth({ clock, failureThreshold: 1, cooldownMs: 1000 });
  const net = createMockDoh();
  health.recordFailure(CF.id, new Error('unavailable'));
  const pool = new ResolverPool({ resolvers: [CF], health, clock, transport: new DohTransport({ fetchImpl: net.fetchImpl }) });
  const blocked = await pool.query('example.com', 'A');
  assert.match(blocked.error, /cooling down/);
  assert.deepEqual(blocked.attempts, []);
  assert.equal(net.calls.length, 0);
  clock.advance(1000);
  assert.equal((await pool.query('example.com', 'A')).ok, true);
  assert.equal(net.calls.length, 1);
});

test('valid per-name RCODE failures do not open the browser resolver circuit', async () => {
  let calls = 0;
  const healthy = createMockDoh();
  const pool = new ResolverPool({
    resolvers: [CF],
    health: new ResolverHealth({ failureThreshold: 2 }),
    transport: new DohTransport({ fetchImpl: (url, init) => {
      calls++;
      const name = new URL(url).searchParams.get('name');
      if (name === 'broken.example') {
        return makeJson({ Status: 2, Question: [{ name, type: 1 }] });
      }
      return healthy.fetchImpl(url, init);
    } })
  });
  for (let i = 0; i < 4; i++) {
    const failed = await pool.query('broken.example', 'A');
    assert.equal(failed.ok, false);
    assert.equal(failed.attempts[0].rcode, 2);
    assert.equal(pool.health.isAvailable(CF.id), true);
  }
  const result = await pool.query('example.com', 'A');
  assert.equal(result.status, 'ok');
  assert.equal(result.resolver.id, CF.id);
  assert.equal(calls, 5);
  assert.equal(pool.health.snapshot().find((provider) => provider.id === CF.id).failures, 0);
});
