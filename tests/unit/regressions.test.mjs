/**
 * Regression suite covering audit findings across security, DNS, AETHER,
 * video-safety, filter engine, and static lint.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { sha256Hex } from '../../security/sha256.js';
import { BackupManager, migrate, SCHEMA_VERSION } from '../../security/backup.js';
import { FeedManager, validateFeedText } from '../../security/feedmanager.js';
import { FirewallAI } from '../../security/firewall-ai.js';
import { PrivateAnalytics } from '../../security/privacy.js';
import { SecurityMonitor } from '../../security/monitor.js';
import { MemoryStorage } from '../../security/storage.js';
import { decodeMessage, fromHex, typeFromString, DnsFormatError } from '../../dns/codec.js';
import { DnsCache } from '../../dns/cache.js';
import { DnsClient } from '../../dns/client.js';
import { DohTransport, ResolverPool, ResolverHealth, jsonToMessage } from '../../dns/resolvers.js';
import { inspectSignatures } from '../../dns/dnssec.js';
import { decodePunycodeLabel, extractFeatures } from '../../aether/lexical.js';
import { skeleton, findImpersonation } from '../../aether/typosquat.js';
import { DomainClassifier, tokenizeDomain } from '../../aether/classifier.js';
import { ReputationEngine } from '../../aether/reputation.js';
import { Aether } from '../../aether/index.js';
import { classify as classifyMedia, explainDanger } from '../../guard/video-safety.js';
import { OmniShieldFilterEngine } from '../../engine.js';
import { lint, reachableModules } from '../../scripts/lint.mjs';

test('sha256Hex matches node:crypto across every 64-byte block boundary (0..200 bytes)', () => {
  for (let len = 0; len <= 200; len++) {
    const msg = 'a'.repeat(len);
    const expected = createHash('sha256').update(msg, 'utf8').digest('hex');
    assert.equal(sha256Hex(msg), expected, `mismatch at length ${len}`);
  }
  const utf8 = 'OmniShield — 🛡️ '.repeat(5);
  assert.equal(sha256Hex(utf8), createHash('sha256').update(utf8, 'utf8').digest('hex'));
});

test('BackupManager rejects missing hashes, validates schemaVersion, and measures UTF-8 bytes', async () => {
  const storage = new MemoryStorage();
  const backups = new BackupManager({ storage, clock: () => 1_700_000_000_000 });

  assert.throws(() => migrate({ schemaVersion: 'not-a-number' }), /invalid schema version/);
  assert.throws(() => migrate({ schemaVersion: SCHEMA_VERSION + 5 }), /future schema version/);

  const saved = await backups.save({ schemaVersion: SCHEMA_VERSION, note: '🛡️🛡️🛡️' }, { reason: 'utf8' });
  const rawRecord = JSON.parse(await storage.getItem(`backup:${saved.id}`));
  assert.equal(saved.bytes, new TextEncoder().encode(rawRecord.payload).length);
  assert.ok(saved.bytes > rawRecord.payload.length, 'multi-byte UTF-8 snapshot bytes must exceed UTF-16 length');

  // Tamper by stripping `hash`: restore and list must reject, never silently accept.
  await storage.setItem('backup:tampered', JSON.stringify({ id: 'tampered', payload: rawRecord.payload }));
  const restored = await backups.restore('tampered');
  assert.equal(restored.ok, false);
  assert.equal(restored.reason, 'missing-hash');

  const listing = await backups.list();
  const tamperedEntry = listing.find((e) => e.id === 'tampered');
  assert.equal(tamperedEntry.valid, false);
  assert.equal(listing[0].id, saved.id, 'valid timestamped snapshots sort ahead of null/corrupt ones');
});

test('FeedManager rolls back content on metadata failure, omits transient 304 fields, and detects unchanged payloads', async () => {
  const feedBody = Array.from({ length: 80 }, (_, i) => `||ads-${i}.example.com^`).join('\n') + '\n';
  const descriptor = [{ id: 't', name: 'Test', url: 'https://example.invalid/list.txt', category: 'ADS', minRules: 50 }];
  const inner = new MemoryStorage();
  let failMeta = false;
  const storage = {
    getItem: (k) => inner.getItem(k),
    setItem: async (k, v) => {
      if (failMeta && k.endsWith(':meta')) throw new Error('quota exceeded');
      return inner.setItem(k, v);
    },
    removeItem: (k) => inner.removeItem(k),
    keys: () => inner.keys()
  };

  let mode = 'v1';
  const fetchImpl = async () => {
    if (mode === 'v1') return new Response(feedBody, { status: 200, headers: { etag: '"e1"' } });
    if (mode === 'v2') return new Response(feedBody + '||ads-extra.example.com^\n', { status: 200, headers: { etag: '"e2"' } });
    if (mode === '304') return new Response(null, { status: 304 });
    return new Response(feedBody, { status: 200 });
  };

  const fm = new FeedManager({ storage, fetchImpl, registry: descriptor, clock: () => 1_700_000_000_000 });
  const r1 = await fm.update('t');
  assert.equal(r1.ok, true);
  assert.equal(r1.changed, true);

  // Same content returned with HTTP 200 must report changed: false.
  mode = 'same';
  const rSame = await fm.update('t');
  assert.equal(rSame.ok, true);
  assert.equal(rSame.changed, false);

  // Metadata write fails during v2 install -> content rolls back so v1 still verifies.
  mode = 'v2';
  failMeta = true;
  const rFail = await fm.update('t');
  assert.equal(rFail.ok, false);
  assert.equal((await fm.verify('t')).ok, true, 'retained feed must still pass SHA-256 verification after rollback');

  // 304 must not persist transient derived fields into stored metadata.
  failMeta = false;
  mode = '304';
  const r304 = await fm.update('t');
  assert.equal(r304.ok, true);
  const storedMeta = JSON.parse(await inner.getItem('feed:t:meta'));
  assert.equal(storedMeta.installed, undefined);
  assert.equal(storedMeta.ageMs, undefined);
  assert.equal(storedMeta.stale, undefined);

  // Hosts-file feeds with inline comments and IPv6 loopback validate cleanly.
  const hostsFeed = Array.from({ length: 80 }, (_, i) =>
    (i % 2 === 0 ? `0.0.0.0 tracker-${i}.example.net # inline comment` : `::1 ipv6-${i}.example.net`)
  ).join('\n');
  assert.equal(validateFeedText(hostsFeed, { minRules: 70 }).stats.rules, 80);
});

test('FirewallAI handles out-of-order logs, exact-allow over parent-deny, future fanout, and pure snapshots', () => {
  const base = 1_700_000_000_000;
  const fw = new FirewallAI({ clock: () => base + 600_000 });

  // Out-of-order beacon observations still resolve to exact 60s cadence.
  const times = Array.from({ length: 10 }, (_, i) => base + i * 60_000).reverse();
  fw.importLog([{ domain: 'c2.bad.example', app: 'app1', times }]);
  assert.equal(fw.detectBeaconing('c2.bad.example', { recordStats: false }).fired, true);
  assert.equal(fw.stats.beaconing, 0, 'inspect/snapshot must not inflate detection counters');
  fw.inspect('c2.bad.example');
  fw.snapshot();
  assert.equal(fw.stats.beaconing, 0);

  // Exact host allow beats registrable-domain deny.
  fw.setPolicy('browser', 'example.com', 'block');
  fw.setPolicy('browser', 'safe.example.com', 'allow');
  assert.equal(fw.evaluate('safe.example.com', { app: 'browser' }).decision, 'allow');
  assert.equal(fw.evaluate('ads.example.com', { app: 'browser' }).decision, 'block');

  // Future timestamps do not fire an earlier fan-out window.
  for (let i = 0; i < 80; i++) fw.observe({ domain: `future${i}.org`, at: base + 9_000_000 });
  assert.equal(fw.detectFanout(base + 50_000, { recordStats: false }).fired, false);
});

test('PrivateAnalytics.hasSeen does not create phantom days and handles NaN timestamps', () => {
  const analytics = new PrivateAnalytics({ clock: () => 1_700_000_000_000 });
  assert.equal(analytics.hasSeen('example.com'), false);
  assert.equal(analytics.days.size, 0);
  analytics.record({ kind: 'blocked', category: 'ADS', domain: 'example.com', at: Number.NaN });
  assert.equal(analytics.hasSeen('example.com'), true);
});

test('DNS codec enforces RDATA bounds, rejects header compression pointers, and validates numeric types', () => {
  // Compression pointer to offset 4 (inside 12-byte header) must be rejected.
  const headerPtr = fromHex('000181800001000000000000c00400010001');
  assert.throws(() => decodeMessage(headerPtr), DnsFormatError);

  // A record with rdlength=5 (overlong) must be rejected.
  const badARdlen = fromHex(
    '000181800001000100000000' +
    '017803636f6d0000010001' +
    'c00c000100010000003c00050102030405'
  );
  assert.throws(() => decodeMessage(badARdlen), DnsFormatError);

  assert.equal(typeFromString('   '), 1);
  assert.equal(typeFromString('0'), 1);
  assert.equal(typeFromString('70000'), 1);
  assert.equal(typeFromString(' aaaa '), 28);
  assert.equal(typeFromString('65'), 65);
});

test('DNS cache, client, and resolver pool handle NaN TTL, clear races, hedged failures, and JSON RRSIG', async () => {
  const cache = new DnsCache({ clock: () => 1000 });
  const entry = cache.set('example.com', 'A', { ok: true }, { ttl: Number.NaN });
  assert.equal(Number.isFinite(entry.expiresAt), true);

  // clear() during an in-flight lookup prevents stale population.
  let release;
  const flight = cache.singleFlight(
    DnsCache.key('race.example', 'A'),
    () => new Promise((r) => { release = r; }),
    () => ({ ttl: 60 })
  );
  cache.clear();
  release({ ok: true });
  await flight;
  assert.equal(cache.get('race.example', 'A'), null);

  // Hedged race: runner-up fails immediately, slower primary succeeds and wins.
  const resolvers = [
    { id: 'slow-ok', name: 'Slow OK', operator: 'Test', dohJson: 'https://a.invalid/dns' },
    { id: 'fast-fail', name: 'Fast Fail', operator: 'Test', dohJson: 'https://b.invalid/dns' }
  ];
  const pool = new ResolverPool({
    resolvers,
    raceDelayMs: 15,
    health: new ResolverHealth(),
    transport: {
      query: (resolver) => new Promise((resolve, reject) => {
        if (resolver.id === 'slow-ok') {
          setTimeout(() => resolve({
            transport: 'DoH-JSON',
            message: jsonToMessage({ Status: 0, AD: true, Answer: [{ name: 'ok.example.', type: 1, TTL: 120, data: '93.184.216.34' }] })
          }), 45);
        } else {
          setTimeout(() => reject(new Error('boom')), 5);
        }
      })
    }
  });
  const hedged = await pool.query('ok.example', 'A');
  assert.equal(hedged.ok, true);
  assert.deepEqual(hedged.addresses, ['93.184.216.34']);

  // DoH-WIRE rejects responses with QR=0 (reflected query).
  const queryPacket = '000001000001000000000000076578616d706c6503636f6d0000010001';
  const wireTransport = new DohTransport({
    preferJson: false,
    fetchImpl: async () => new Response(fromHex(queryPacket), { status: 200, headers: { 'content-type': 'application/dns-message' } })
  });
  await assert.rejects(
    () => wireTransport.query({ id: 'w', name: 'Wire', dohWire: 'https://w.invalid/dns-query' }, 'example.com', 'A'),
    /QR flag/
  );

  // JSON RRSIG parsing populates signerName, signature, and timestamps.
  const signedMsg = jsonToMessage({
    Status: 0,
    Answer: [
      { name: 'example.com.', type: 1, TTL: 300, data: '93.184.216.34' },
      { name: 'example.com.', type: 46, TTL: 300, data: 'A 13 2 300 20350101000000 20240101000000 12345 example.com. YWJjZA==' }
    ]
  });
  const sigCheck = inspectSignatures(signedMsg);
  assert.equal(sigCheck.signed, true);
  assert.deepEqual(sigCheck.problems, []);

  // Dual-stack blocked lookup reports null TTL (never Infinity), and bracketed IPv6 short-circuits.
  const engine = new OmniShieldFilterEngine();
  engine.addUserRule('blocked.example', false);
  const client = new DnsClient({ engine, pool });
  const dual = await client.lookupDualStack('blocked.example');
  assert.equal(dual.blocked, true);
  assert.equal(dual.ttl, null);
  const ip6 = await client.lookup(' [2001:db8::1] ');
  assert.equal(ip6.status, 'ip-literal');
  assert.equal(ip6.name, '2001:db8::1');
});

test('AETHER punycode, IDN homograph skeleton, affix matching, classifier serialization, and FP undo', () => {
  // Hostile overflow punycode never throws RangeError.
  assert.doesNotThrow(() => decodePunycodeLabel('xn--999999999999999999999999999'));
  // Cyrillic 'аpple' -> xn--pple-43d collapses to 'apple' in skeleton().
  assert.equal(skeleton('xn--pple-43d'), 'apple');
  const homograph = findImpersonation('xn--pple-43d.com');
  assert.equal(homograph.suspicious, true);
  assert.equal(homograph.matches[0].kind, 'homoglyph');

  // 'confirm' contains 'rn' (-> 'm' in skeleton), so paypal-confirm.com must match brand-affix.
  const affix = findImpersonation('paypal-confirm.com');
  assert.equal(affix.suspicious, true);
  assert.equal(affix.matches[0].kind, 'brand-affix');

  // Threat tokens are deduplicated when present in both subdomain and main label.
  const feats = extractFeatures('login.login-portal.com');
  assert.equal(feats.threatTokens.filter((t) => t === 'login').length, 1);

  // DomainClassifier.fromJSON preserves featureMode, binary, and evidenceExponent, and rejects corrupt JSON.
  assert.deepEqual(tokenizeDomain('...'), []);
  assert.equal(DomainClassifier.fromJSON({ version: 1, vocab: ['a'], logLikPos: [], logLikNeg: [0], logPriorPos: 0, logPriorNeg: 0 }), null);
  const clf = new DomainClassifier({ featureMode: 'trigram', binary: false, evidenceExponent: 0.5 });
  const pos = Array.from({ length: 40 }, (_, i) => `adtrack-banner-${i}.ads.example`);
  const neg = Array.from({ length: 40 }, (_, i) => `library-journal-${i}.edu.org`);
  clf.train({ positives: pos, negatives: neg });
  const restored = DomainClassifier.fromJSON(clf.toJSON());
  assert.deepEqual(restored.predict('adtrack-banner-99.ads.example'), clf.predict('adtrack-banner-99.ads.example'));

  // Cached reputation signals are isolated against caller mutation; FP removes user block rule.
  const rep = new ReputationEngine();
  const r1 = rep.analyze('paypal-confirm.com');
  r1.signals[0].contribution = -999;
  const r2 = rep.analyze('paypal-confirm.com');
  assert.equal(r2.signals[0].contribution > 0, true);

  const engine = new OmniShieldFilterEngine();
  engine.addUserRule('mistake.example', false);
  const aether = new Aether({ engine });
  aether.reportFalsePositive('mistake.example');
  aether.undoFalsePositive('mistake.example');
  assert.equal(engine.evaluate('mistake.example').blocked, false, 'user block must not resurrect after undoing FP');
});

test('Video safety and filter engine handle 3-label zones, CDN wildcards, hosts comments, and wildcard precedence', () => {
  assert.equal(explainDanger('*.cloudfront.net')?.code, 'SHARED_CDN_BLANKET');
  assert.equal(explainDanger('*.youtubei.googleapis.com')?.code, 'WILDCARD_ON_MEDIA_DOMAIN');
  assert.equal(explainDanger('||meet.google.com^')?.code, 'ENTITY_LEVEL_RULE');
  assert.equal(explainDanger('0.0.0.0 google.com # comment')?.code, 'ENTITY_LEVEL_RULE');
  assert.equal(explainDanger('video*')?.code, 'SUBSTRING_WILDCARD');
  assert.equal(classifyMedia('ads_api.twitch.tv').protected, false);

  const e = new OmniShieldFilterEngine();
  assert.equal(OmniShieldFilterEngine.normalizeDomain('_dmarc.example.com'), '_dmarc.example.com');
  assert.equal(OmniShieldFilterEngine.isIpLiteral('999.999.999.999'), false);
  assert.equal(OmniShieldFilterEngine.isIpLiteral('a:b'), false);
  assert.equal(OmniShieldFilterEngine.isIpLiteral('2001:db8::1'), true);
  assert.deepEqual(e.suffixesOf('localhost'), ['localhost']);

  // Feed wildcard exception must NOT outrank an explicit user block rule.
  e.loadFilterList('@@||*.tracker.example^\n0.0.0.0 h1.example # comment.not.a.domain\n', 'ADS', 'feed1');
  assert.equal(e.evaluate('h1.example').blocked, true);
  assert.equal(e.evaluate('comment.not.a.domain').blocked, false);
  e.addUserRule('sub.tracker.example', false);
  assert.equal(e.evaluate('sub.tracker.example').blocked, true);

  // User `?` wildcard compiles, matches single label char, and removes cleanly.
  assert.equal(e.addUserRule('ad?.custom.example', false), true);
  assert.equal(e.evaluate('ad1.custom.example').blocked, true);
  assert.equal(e.evaluate('ad12.custom.example').blocked, false);
  assert.equal(e.removeUserRule('ad?.custom.example', false), true);
  assert.equal(e.evaluate('ad1.custom.example').blocked, false);
});

test('lint resolves nested relative imports and flags insertAdjacentHTML calls', () => {
  const dir = mkdtempSync(join(tmpdir(), 'omnishield-lint-'));
  try {
    for (const sub of ['ui', 'dns', 'aether', 'security', 'guard']) mkdirSync(join(dir, sub));
    writeFileSync(join(dir, 'app.js'), "import { a } from './dns/a.js';\nexport default a;\n");
    writeFileSync(join(dir, 'engine.js'), 'export const e = 1;\n');
    writeFileSync(join(dir, 'sw.js'), "const a = ['./engine.js'];\nvoid a;\n");
    writeFileSync(join(dir, 'dns/a.js'), "import { b } from './b.js';\nexport const a = b;\n");
    writeFileSync(join(dir, 'dns/b.js'), "el.insertAdjacentHTML('beforeend', x);\nexport const b = 1;\n");

    const reach = reachableModules(dir);
    assert.equal(reach.has('dns/b.js'), true, 'sibling import inside dns/ must resolve to dns/b.js');
    const res = lint(dir);
    assert.ok(res.findings.some((f) => f.rule === 'no-html-sink' && f.file.startsWith('dns/b.js')));
    assert.ok(!res.findings.some((f) => f.rule === 'no-orphan-module'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * Regression: analytics persistence must go through a method that exists.
 *
 * app.js used to call `state.analytics.save()`, but PrivateAnalytics only ever
 * implemented `flush()`. The optional-call operator hid the mistake from the type
 * checker and the `.catch()` swallowed the follow-on error, so every DNS event
 * raised a `save is not a function` TypeError on the debounce timer and no
 * analytics were ever written to storage.
 */
test('analytics persistence uses the method the class actually exposes', () => {
  const analytics = new PrivateAnalytics({ storage: new MemoryStorage() });
  assert.equal(typeof analytics.flush, 'function', 'PrivateAnalytics.flush must exist');
  assert.equal(analytics.save, undefined,
    'app.js must not depend on a save() alias that does not exist');
});

test('privacy analytics survive a flush/load round-trip through storage', async () => {
  const storage = new MemoryStorage();
  const clock = () => 1_700_000_000_000;
  const first = new PrivateAnalytics({ storage, clock });
  for (let i = 0; i < 12; i++) first.record({ kind: 'blocked', category: 'ADS', domain: `t${i}.example` });
  assert.equal(await first.flush(), true, 'flush must report success when a storage adapter exists');

  const second = new PrivateAnalytics({ storage, clock });
  assert.equal(await second.load(), true, 'flushed state must load back');
  const report = second.report();
  assert.equal(report.days.length, 1);
  assert.equal(report.days[0].categories.ADS, 12, 'recorded counts must survive the round-trip');
  assert.equal(report.days[0].distinctDomains, 12, 'distinct hashed domains must survive the round-trip');
});

test('every cross-module method app.js calls exists on the class that owns it', async () => {
  const owners = {
    Aether: (await import('../../aether/index.js')).Aether,
    BackupManager: (await import('../../security/backup.js')).BackupManager,
    FeedManager: (await import('../../security/feedmanager.js')).FeedManager,
    FirewallAI: (await import('../../security/firewall-ai.js')).FirewallAI,
    SecurityMonitor: (await import('../../security/monitor.js')).SecurityMonitor,
    PrivateAnalytics: (await import('../../security/privacy.js')).PrivateAnalytics,
    PowerGovernor: (await import('../../security/power.js')).PowerGovernor
  };
  const expected = {
    Aether: ['analyze', 'attachEngine', 'exportState', 'importState', 'observe', 'reportFalsePositive', 'train'],
    BackupManager: ['list', 'recover', 'remove', 'restore', 'save'],
    FeedManager: ['content', 'list', 'update', 'verify'],
    FirewallAI: ['evaluate', 'importLog', 'inspect', 'observe', 'setPolicy', 'snapshot'],
    SecurityMonitor: ['metrics', 'record'],
    PrivateAnalytics: ['clear', 'exportJSON', 'flush', 'load', 'record', 'report'],
    PowerGovernor: ['describe', 'intervalFor', 'start', 'stop']
  };
  for (const [name, methods] of Object.entries(expected)) {
    const cls = owners[name];
    assert.ok(cls, `${name} must be importable`);
    for (const method of methods) {
      assert.equal(typeof cls.prototype[method], 'function', `${name}.${method} is referenced by app.js but missing`);
    }
  }
});

test('app.js never calls a persistence method the analytics class does not have', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../../app.js', import.meta.url), 'utf8');
  assert.equal(/state\.analytics\??\.save\s*\(/.test(source), false,
    'app.js must call analytics.flush(), not the non-existent analytics.save()');
});

/**
 * Regression: a non-finite timestamp or latency must never reach the recent-event
 * view. The monitor table renders `new Date(e.at).toLocaleTimeString()`, so a NaN
 * `at` printed "Invalid Date", and a NaN latency leaked into the report/export.
 */
test('monitor drops non-finite timestamps and latencies instead of displaying them', () => {
  const m = new SecurityMonitor();
  m.record({ kind: 'blocked', domain: 'nan-latency.example', latencyMs: NaN });
  m.record({ kind: 'blocked', domain: 'inf-latency.example', latencyMs: Infinity });
  m.record({ kind: 'blocked', domain: 'nan-at.example', at: NaN, latencyMs: 5 });
  m.record({ kind: 'blocked', domain: 'bad-at.example', at: 'yesterday' });

  const recent = m.metrics().recent;
  assert.equal(recent.length, 4, 'every event is still recorded');
  for (const event of recent) {
    assert.ok(Number.isFinite(event.at), `event.at must be a real timestamp, got ${event.at}`);
    assert.ok(!Number.isNaN(new Date(event.at).getTime()), 'at must render as a real time');
    if ('latencyMs' in event) {
      assert.ok(Number.isFinite(event.latencyMs), `latencyMs must be finite, got ${event.latencyMs}`);
    }
  }
  assert.ok(Number.isFinite(m.metrics().averageLatency), 'the average must stay a real number');
});

/**
 * Regression: `setUserRules` (config import / snapshot recovery) dropped matchType.
 *
 * Every restored rule became a SUFFIX rule, so an EXACT rule that blocked one
 * host started blocking every subdomain of it after a restore — the engine
 * blocked more than the user configured. The match type must survive the
 * round-trip, and a wildcard pattern must stay a wildcard.
 */
test('setUserRules preserves EXACT, SUFFIX and WILDCARD semantics across a restore', () => {
  const exact = new OmniShieldFilterEngine();
  exact.setUserRules([{ pattern: 'exactonly.example', isAllow: false, matchType: 'EXACT' }]);
  assert.equal(exact.evaluate('exactonly.example').blocked, true, 'EXACT still blocks its host');
  assert.equal(exact.evaluate('deep.sub.exactonly.example').blocked, false,
    'EXACT must not widen to subdomains after a restore');

  const suffix = new OmniShieldFilterEngine();
  suffix.setUserRules([{ pattern: 'tree.example', isAllow: false, matchType: 'SUFFIX' }]);
  assert.equal(suffix.evaluate('a.b.tree.example').blocked, true, 'SUFFIX keeps matching subdomains');

  const wildcard = new OmniShieldFilterEngine();
  wildcard.setUserRules([{ pattern: 'ads*.example', isAllow: false }]);
  assert.equal(wildcard.evaluate('ads7.example').blocked, true,
    'a wildcard pattern must be restored as a wildcard, not as a literal suffix');

  const allow = new OmniShieldFilterEngine();
  allow.setUserRules([{ rawPattern: 'allowed.example', ruleType: 'ALLOW' }]);
  assert.equal(allow.evaluate('allowed.example').blocked, false, 'ALLOW survives via ruleType');
});

test('setUserRules([]) clears every user rule', () => {
  const engine = new OmniShieldFilterEngine();
  engine.setUserRules([
    { pattern: 'one.example', isAllow: false, matchType: 'SUFFIX' },
    { pattern: 'two.example', isAllow: true, matchType: 'EXACT' },
    { pattern: 'three*.example', isAllow: false }
  ]);
  assert.ok(engine.totalRules() > 0, 'rules were installed');
  engine.setUserRules([]);
  assert.equal(engine.totalRules(), 0, 'no user rule may survive an empty replacement');
  assert.equal(engine.evaluate('one.example').blocked, false);
});
