/**
 * Regression tests for the audit findings fixed in this pass.
 *
 * Each test names the bug it pins, so a future refactor that reintroduces it fails
 * here instead of shipping. Nothing here duplicates an existing suite: these are the
 * specific behaviours that were wrong (not merely untested).
 */
import test from 'node:test';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

import ui, * as uiModule from '../../ui/dom.js';
import { OmniShieldFilterEngine } from '../../engine.js';
import { SecurityMonitor } from '../../security/monitor.js';
import { DnsClient } from '../../dns/client.js';
import { DnsCache } from '../../dns/cache.js';
import { DohTransport, ResolverPool, RESOLVER_BY_ID } from '../../dns/resolvers.js';
import { createMockDoh } from '../helpers/mock-dns.mjs';
import { BackupManager, SCHEMA_VERSION } from '../../security/backup.js';
import { MemoryStorage } from '../../security/storage.js';

const ROOT = new URL('../../', import.meta.url);
const read = (path) => readFileSync(new URL(path, ROOT), 'utf8');

/* ------------------------------------------------------------------ UI helpers */

test('the default DOM helper export carries every function, including plural()', () => {
  // The object literal used to be evaluated before `plural` was initialised, so a
  // consumer doing `import ui from './ui/dom.js'` got `undefined` for it.
  for (const name of ['h', 'clear', 'mount', 'pill', 'note', 'empty', 'kpi', 'table', 'kv',
    'buttons', 'number', 'plural', 'bytes', 'relativeTime', 'drawSeries', 'toast',
    'download', 'setBusy']) {
    assert.equal(typeof ui[name], 'function', `default export must expose ${name}()`);
    assert.equal(ui[name], uiModule[name], `default and named ${name} must be the same function`);
  }
  assert.equal(ui.plural(1, 'point'), '1 point');
  assert.equal(ui.plural(2, 'point'), '2 points');
});

/* ------------------------------------------------------------------- engine */

test('switching a domain between allow and block never leaves both rules installed', () => {
  // toggleDomainRule used to add the new direction before removing the old one, and
  // the DOM-only bookkeeping could leave an allow rule winning forever.
  const engine = new OmniShieldFilterEngine();
  engine.loadFilterList('||ads.example^', 'ADS', 'test_feed');
  assert.equal(engine.evaluate('ads.example').blocked, true);

  // allow
  engine.removeUserRule('ads.example', false);
  engine.removeUserRule('ads.example', true);
  engine.addUserRule('ads.example', true);
  assert.equal(engine.evaluate('ads.example').blocked, false);

  // block again
  engine.removeUserRule('ads.example', false);
  engine.removeUserRule('ads.example', true);
  engine.addUserRule('ads.example', false);
  assert.equal(engine.evaluate('ads.example').blocked, true,
    're-blocking must not be defeated by the earlier allow rule');
  assert.equal(engine.customAllowExact.size + engine.customAllowSuffix.size, 0);
});

/* ------------------------------------------------------------------ monitor */

test('latency percentiles use nearest-rank (p95 of 100 samples is the 95th value)', () => {
  const monitor = new SecurityMonitor({ clock: () => 1_000_000 });
  for (let i = 1; i <= 100; i++) monitor.record({ kind: 'lookup', domain: `h${i}.example`, latencyMs: i });
  const { p50, p95, max } = monitor.latencyPercentiles();
  assert.equal(p95, 95, `p95 was ${p95}; the old index picked the 96th value`);
  assert.equal(p50, 50);
  assert.equal(max, 100);
});

test('a chart never shows buckets older than its window, even with no traffic', () => {
  let now = 0;
  const monitor = new SecurityMonitor({ clock: () => now, bucketMs: 60_000, buckets: 60 });
  monitor.record({ kind: 'lookup', domain: 'once.example', latencyMs: 5 });
  const filled = [...monitor.buckets.keys()];
  assert.equal(filled.length, 1);

  // Six hours pass with the tab open and nothing resolved.
  now += 6 * 3_600_000;
  monitor.series('lookups');
  assert.equal(monitor.buckets.size, 0, 'stale buckets must be pruned when the chart is read');
  assert.ok(!monitor.buckets.has(filled[0]), 'the empty old bucket must be gone');
});

/* ---------------------------------------------------------------- DNS client */

test('dual-stack results expose the fields the UI renders (ttl, latency, statuses)', async () => {
  const clock = (() => { let n = 1_000; return () => n++; })();
  const cache = new DnsCache({ clock });
  const net = createMockDoh();
  const [CF] = [RESOLVER_BY_ID.cloudflare];
  const client = new DnsClient({
    engine: new OmniShieldFilterEngine(),
    cache,
    clock,
    pool: new ResolverPool({
      resolvers: [CF],
      transport: new DohTransport({ fetchImpl: net.fetchImpl, timeoutMs: 2000 }),
      clock
    })
  });
  const dual = await client.lookupDualStack('cdn.example.net');
  assert.deepEqual(dual.ipv4, ['203.0.113.10']);
  assert.deepEqual(dual.ipv6, ['2001:db8::10']);
  assert.equal(typeof dual.ttl, 'number', 'TTL used to be undefined for dual-stack lookups');
  assert.ok(Number.isFinite(dual.latencyMs), 'latency used to be NaN');
  assert.equal(dual.status, 'ok');
  assert.equal(dual.results.a.status, 'ok', 'per-family rows exist for the detail table');
  assert.equal(dual.results.aaaa.status, 'ok');
});

test('a name blocked after its answer was cached is blocked, not served from the stale cache', async () => {
  const clock = (() => { let n = 1_000; return () => n++; })();
  const cache = new DnsCache({ clock });
  const net = createMockDoh({ latencyMs: 0 });
  const engine = new OmniShieldFilterEngine();
  const client = new DnsClient({
    engine,
    cache,
    clock,
    timeoutMs: 2000,
    pool: new ResolverPool({
      resolvers: [RESOLVER_BY_ID.cloudflare],
      transport: new DohTransport({ fetchImpl: net.fetchImpl, timeoutMs: 2000 }),
      clock
    })
  });
  await client.lookup('example.com');
  const entry = cache.get('example.com', 'A');
  assert.ok(entry, 'the answer must be cached');

  // Age the entry past its TTL but inside the stale-revalidate grace window.
  entry.expiresAt = clock() - 1_000;
  entry.staleUntil = clock() + 60_000;

  engine.addUserRule('example.com', false, 'SUFFIX');
  const callsBefore = net.calls.length;
  const blocked = await client.lookup('example.com', { allowStale: true });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(blocked.blocked, true, 'the new rule must win over the stale answer');
  assert.deepEqual(blocked.addresses, []);
  assert.equal(net.calls.length, callsBefore,
    'a blocked name must never be refreshed from the network');
});

test('a stale entry can be invalidated so a later allowance cannot serve old data', () => {
  const cache = new DnsCache({ clock: () => 1_000 });
  cache.set('invalidate.example', 'A', { addresses: ['192.0.2.1'] }, { ttl: 60 });
  assert.ok(cache.get('invalidate.example', 'A'), 'entry exists');
  assert.equal(cache.remove('invalidate.example', 'A'), true);
  assert.equal(cache.get('invalidate.example', 'A'), null, 'removed entries are gone');
  assert.equal(cache.remove('invalidate.example', 'A'), false, 'removing twice is harmless');
});

/* ------------------------------------------------------------------- backup */

test('new snapshots are labelled with the shipped app version', async () => {
  const backups = new BackupManager({ storage: new MemoryStorage(), clock: () => 1_700_000_000_000 });
  await backups.save({ schemaVersion: SCHEMA_VERSION }, { reason: 'version' });
  const raw = JSON.parse(await backups.storage.getItem(`backup:${(await backups.list())[0].id}`));
  const payload = JSON.parse(raw.payload);
  const pkg = JSON.parse(read('package.json'));
  assert.equal(payload.appVersion, pkg.version,
    'a snapshot must not claim a version older than the release it was written by');
});

/* --------------------------------------------------- application wiring (static) */

test('app.js applies imported browser site exceptions to the engine', () => {
  const source = read('app.js');
  assert.match(source, /function applyImportedExceptions/, 'the helper must exist');
  assert.match(source, /importedBackup\?\.browserSiteExceptions/,
    'the imported exception list is the source of truth');
  // applyUserRules() owns the whole user-rule layer: it clears the engine's user
  // rules and then re-installs custom rules *and* imported exceptions. That is what
  // makes boot, engine rebuild and the single-rule "Remove" path all consistent.
  const body = source.slice(source.indexOf('function applyUserRules'), source.indexOf('function applyImportedExceptions'));
  assert.match(body, /clearUserRules\(\)/, 'the user-rule layer must be replaced, not patched');
  assert.match(body, /applyImportedExceptions\(engine\)/,
    'a clear that forgets imported exceptions silently un-allows every imported site');
  const rebuild = source.slice(source.indexOf('async function rebuildEngine'), source.indexOf('function refreshRuleSummary'));
  assert.match(rebuild, /applyUserRules\(engine\)/,
    'a rebuilt engine must receive the user rules again');
});

test('the aggressive tier toggle and the custom-rule view stay consistent', () => {
  const source = read('app.js');
  const toggle = source.slice(source.indexOf('async function enableAggressiveTier'),
    source.indexOf('async function rebuildEngine'));
  assert.match(toggle, /await rebuildEngine\(\)/,
    'both directions must rebuild, otherwise the off switch cannot remove the rules');
  const button = source.slice(source.indexOf("text: state.settings.aggressiveTier ? 'Disable aggressive tier'"),
    source.indexOf("pill(state.settings.aggressiveTier ? 'enabled'"));
  assert.match(button, /if \(!await enableAggressiveTier\(/,
    'the UI must not claim the tier changed when the load failed');
  assert.match(toggle, /return false/, 'a failed load must be reported to the caller');
  // Wildcards must be persisted with their match type so re-applying keeps them.
  assert.equal(/state\.customRules\.push\(\{ pattern: domain, isAllow: true, enabled: true/.test(source), false,
    'new rules must record matchType, not rely on pattern sniffing');
});

test('page rendering is limited to what the user can see', () => {
  const source = read('app.js');
  const start = source.indexOf('function renderAll()');
  const end = source.indexOf('nav.tabs button', start);
  assert.ok(start > 0 && end > start, 'renderAll must be locatable in app.js');
  const body = source.slice(start, end);
  assert.match(body, /state\.currentPage/, 'renderAll must not redraw every page');
  assert.equal(/Object\.values\(PAGE_RENDERERS\)\.forEach/.test(body), false);
});

test('shutdown-critical Android writes outlive the service scope', () => {
  const app = read('app/src/main/java/com/adshield/pro/AdShieldApplication.kt');
  const service = read('app/src/main/java/com/adshield/pro/service/AdShieldVpnService.kt');
  assert.match(app, /interface ProcessScopeOwner/, 'a process-lifetime scope must be reachable');
  assert.match(app, /override val appScope/, 'the application owns that scope');
  assert.match(service, /private fun persistShutdownState\(\)/,
    'STOP/onRevoke persistence must be one shared, process-scoped path');
  const stop = service.slice(service.indexOf('ACTION_STOP_VPN ->'), service.indexOf('ACTION_PAUSE_VPN ->'));
  const revoke = service.slice(service.indexOf('override fun onRevoke()'), service.indexOf('private fun persistShutdownState'));
  for (const [name, body] of [['STOP', stop], ['onRevoke', revoke]]) {
    assert.match(body, /persistShutdownState\(\)/, `${name} must use the durable writer`);
    assert.equal(/runBlocking \{/.test(body), false,
      `${name} must not write on its own (cancellable) coroutine context`);
  }
});

test('the header rule count is re-derived after a rule-set change', () => {
  const source = read('app.js');
  assert.match(source, /function refreshRuleSummary\(\)/, 'the summary must be recomputed, not incremented');
  for (const site of ["scheduleSnapshot('aggressive-tier')", "saveSnapshot('feed-update')"]) {
    const index = source.indexOf(site);
    assert.ok(index > 0, `${site} must still snapshot`);
    const before = source.slice(Math.max(0, index - 700), index);
    assert.match(before, /refreshRuleSummary\(\)/,
      `the rule count shown after ${site} must come from the engine`);
  }
});

test('the dashboard counts rule entries, not only blocks', () => {
  const source = read('app.js');
  assert.equal(/kpi\(number\(breakdown\.total\), 'block rules active/.test(source), false,
    'breakdown.total includes exceptions and allow rules');
  assert.match(source, /rule entries loaded/);
});
