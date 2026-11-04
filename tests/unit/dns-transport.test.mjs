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
import { createMockDoh, wireResponse } from '../helpers/mock-dns.mjs';

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
    '1234' + '8180' + '0001' + '0001' + '0000' + '0000' +
    '07' + '6578616d706c65' + '03' + '636f6d' + '00' + '0001' + '0001' +
    'c00c' + '0001' + '0001' + '0000012c' + '0004' + '5db8d822';
  const seen = [];
  const fetchImpl = async (url) => { seen.push(String(url)); return wireResponse(packet); };
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
