/**
 * Unit tests — CNAME chain audit (DNS-level redirect analysis).
 *
 * A DNS filter cannot see HTTP redirects. It can see CNAME chains, and CNAME
 * cloaking (a first-party hostname pointing at a third-party tracker) is exactly
 * the case where blocking the third party by name silently fails. These tests
 * pin the detection, the evidence strings and the "not flagged" path.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { auditChain, registrableDomain } from '../../dns/chain.js';
import { OmniShieldFilterEngine } from '../../engine.js';

const engine = new OmniShieldFilterEngine();
engine.loadFilterList(['||tracker.example.net^', '||metrics.vendor.example^'].join('\n'), 'ADS', 'test-feed');

const reputation = (domain) => (domain === 'evil.example' ? { score: 80, verdict: 'likely-malicious' } : { score: 0, verdict: 'clean' });

test('registrableDomain keeps simple names and common two-label suffixes', () => {
  assert.equal(registrableDomain('example.com'), 'example.com');
  assert.equal(registrableDomain('metrics.shop.example.com'), 'example.com');
  assert.equal(registrableDomain('news.bbc.co.uk'), 'bbc.co.uk');
  assert.equal(registrableDomain('localhost'), 'localhost');
  assert.equal(registrableDomain(''), null);
});

test('no CNAME chain is reported as direct, not as clean', () => {
  const audit = auditChain({ name: 'shop.example', cname: [], engine, reputation });
  assert.equal(audit.cloaking, false);
  assert.equal(audit.links.length, 0);
  assert.match(audit.summary, /direct/i);
  assert.match(audit.scope, /HTTP redirects .* invisible/i, 'the DNS-only scope must be stated');
});

test('CNAME cloaking is detected when a chain link is blocked by a feed', () => {
  const audit = auditChain({
    name: 'metrics.shop.example',
    cname: [{ from: 'metrics.shop.example', to: 'tracker.example.net' }],
    engine,
    reputation
  });
  assert.equal(audit.cloaking, true);
  assert.deepEqual(audit.cloakedTargets, ['tracker.example.net']);
  assert.equal(audit.links[0].blocked, true);
  assert.equal(audit.links[0].blockedBy.source, 'test-feed');
  assert.match(audit.summary, /CNAME cloaking/);
  assert.ok(audit.evidence.some((e) => /blocked by test-feed/.test(e)), JSON.stringify(audit.evidence));
  assert.ok(audit.evidence.some((e) => /leave the queried site/.test(e)));
});

test('a risky reputation score also counts as cloaking, with the score shown', () => {
  const audit = auditChain({ name: 'www.shop.example', cname: ['evil.example'], engine, reputation });
  assert.equal(audit.cloaking, true);
  assert.equal(audit.links[0].score, 80);
  assert.ok(audit.evidence.some((e) => /scores 80\/100 \(likely-malicious\)/.test(e)));
});

test('an off-site chain to clean hosts is recorded but not flagged', () => {
  const audit = auditChain({
    name: 'www.example.com',
    cname: ['edge.cdn.example.org'],
    engine,
    reputation
  });
  assert.equal(audit.cloaking, false);
  assert.equal(audit.offSiteLinks, 1);
  assert.match(audit.summary, /no link is blocked or risky/);
  assert.equal(audit.links[0].blocked, false);
});

test('same-site indirection is not treated as cloaking', () => {
  const audit = auditChain({ name: 'shop.example.com', cname: ['edge.shop.example.com'], engine, reputation });
  assert.equal(audit.cloaking, false);
  assert.equal(audit.offSiteLinks, 0);
  assert.match(audit.summary, /stays inside/);
});

test('chains are capped and malformed links are ignored', () => {
  const many = Array.from({ length: 30 }, (_, i) => `hop${i}.example.com`);
  const audit = auditChain({ name: 'start.example.com', cname: [...many, null, ''], engine, reputation });
  assert.ok(audit.links.length <= 12, `depth must be bounded, got ${audit.links.length}`);
  assert.ok(audit.links.every((l) => typeof l.target === 'string' && l.target.length > 0));
});

test('the audit never blocks anything itself', () => {
  const audit = auditChain({ name: 'metrics.shop.example', cname: ['tracker.example.net'], engine, reputation });
  assert.equal(Object.prototype.hasOwnProperty.call(audit, 'blocked'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(audit, 'action'), false);
  // The engine is untouched: querying the parent still resolves normally.
  assert.equal(engine.evaluate('shop.example').blocked, false);
});
