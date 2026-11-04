/**
 * Unit tests — SHA-256, storage, feed manager, backup/recovery, privacy analytics.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { sha256Hex, sha256Bytes } from '../../security/sha256.js';
import { MemoryStorage, createStorage, LocalStorageAdapter } from '../../security/storage.js';
import { FeedManager, FEED_REGISTRY, validateFeedText, FeedValidationError } from '../../security/feedmanager.js';
import { BackupManager, migrate, SCHEMA_VERSION } from '../../security/backup.js';
import { PrivateAnalytics } from '../../security/privacy.js';

/* ------------------------------- SHA-256 ------------------------------- */

test('SHA-256 matches the NIST test vectors', () => {
  assert.equal(sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256Hex('The quick brown fox jumps over the lazy dog'),
    'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');
  assert.equal(sha256Hex('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  assert.equal(sha256Hex('a'.repeat(1_000_000)),
    'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
  assert.equal(sha256Bytes(new TextEncoder().encode('abc')).length, 32);
  assert.equal(sha256Hex('abc'), sha256Hex(new TextEncoder().encode('abc')), 'bytes and string agree');
});

/* ------------------------------- storage ------------------------------- */

test('memory storage fails loudly when told to', async () => {
  const s = new MemoryStorage();
  await s.setItem('a', '1');
  assert.equal(await s.getItem('a'), '1');
  s.failNext = 'write';
  await assert.rejects(() => s.setItem('b', '2'), /QuotaExceeded/);
  s.failNext = 'read';
  await assert.rejects(() => s.getItem('a'), /read failure/);
});

test('createStorage falls back to memory without localStorage', () => {
  const storage = createStorage('test-ns');
  assert.ok(typeof storage.getItem === 'function');
  assert.ok(storage instanceof MemoryStorage || storage instanceof LocalStorageAdapter);
});

/* ----------------------------- feed manager ---------------------------- */

/** Same real feed descriptors, with test-sized minimums so fixtures stay small. */
const TEST_REGISTRY = FEED_REGISTRY.map((f) => ({ ...f, minRules: 100 }));

const GOOD_FEED = ['# header', '! comment', ...Array.from({ length: 400 }, (_, i) => `||feed${i}.example^`)].join('\n') + '\n' + 'x'.repeat(2048);

function feedFetch({ status = 200, body = '', etag = '"abc"', headers = {} } = {}) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: (k) => ({ etag, 'last-modified': headers['last-modified'] }[k.toLowerCase()] ?? null) },
      async text() { return body; }
    };
  };
  impl.calls = calls;
  return impl;
}

test('feed registry points at real HTTPS sources', () => {
  for (const feed of FEED_REGISTRY) {
    assert.match(feed.url, /^https:\/\/raw\.githubusercontent\.com\//);
    assert.ok(feed.license === 'GPLv3');
    assert.ok(feed.category);
    assert.ok(feed.minRules > 0);
  }
});

test('a valid feed is validated, hashed and installed', async () => {
  const storage = new MemoryStorage();
  const manager = new FeedManager({ registry: TEST_REGISTRY, storage, fetchImpl: feedFetch({ body: GOOD_FEED }), clock: () => 1_700_000_000_000 });
  const result = await manager.update('core_lite_ads');
  assert.equal(result.ok, true);
  assert.equal(result.changed, true);
  assert.equal(result.meta.rules, 400);
  assert.equal(result.meta.hash, sha256Hex(GOOD_FEED));
  assert.equal(result.meta.hashAlgorithm, 'sha256');
  assert.equal((await manager.verify('core_lite_ads')).ok, true);
});

test('conditional GET avoids re-downloading an unchanged feed', async () => {
  const storage = new MemoryStorage();
  const first = new FeedManager({ registry: TEST_REGISTRY, storage, fetchImpl: feedFetch({ body: GOOD_FEED }), clock: () => 1000 });
  await first.update('core_lite_ads');

  const notModified = feedFetch({ status: 304 });
  const second = new FeedManager({ registry: TEST_REGISTRY, storage, fetchImpl: notModified, clock: () => 2000 });
  const result = await second.update('core_lite_ads');
  assert.equal(result.ok, true);
  assert.equal(result.changed, false);
  assert.equal(result.reason, 'not-modified');
  assert.equal(notModified.calls[0].init.headers['if-none-match'], '"abc"', 'ETag must be sent back');
  assert.equal(await second.content('core_lite_ads'), GOOD_FEED, 'content must be untouched');
});

test('HTML instead of a list is rejected and the previous copy is retained', async () => {
  const storage = new MemoryStorage();
  const good = new FeedManager({ registry: TEST_REGISTRY, storage, fetchImpl: feedFetch({ body: GOOD_FEED }), clock: () => 1000 });
  await good.update('core_lite_ads');

  const bad = new FeedManager({ registry: TEST_REGISTRY,
    storage,
    fetchImpl: feedFetch({ body: '<!DOCTYPE html><html><body>Blocked by captive portal</body></html>' + 'x'.repeat(3000) }),
    clock: () => 2000
  });
  const result = await bad.update('core_lite_ads');
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'html-instead-of-list');
  assert.equal(result.retained.rules, 400);
  assert.equal(await bad.content('core_lite_ads'), GOOD_FEED);
  assert.equal((await bad.verify('core_lite_ads')).ok, true);
});

test('rollback protection refuses a suspiciously shrunken feed', async () => {
  const storage = new MemoryStorage();
  await new FeedManager({ registry: TEST_REGISTRY, storage, fetchImpl: feedFetch({ body: GOOD_FEED }), clock: () => 1000 }).update('core_lite_ads');
  // Structurally valid (150 rules) but 62% smaller than the installed 400.
  const shrunk = Array.from({ length: 150 }, (_, i) => `||shrunk${i}.example^`).join('\n');
  const manager = new FeedManager({ registry: TEST_REGISTRY, storage, fetchImpl: feedFetch({ body: shrunk }), clock: () => 2000 });
  const result = await manager.update('core_lite_ads');
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'suspicious-shrink');
  assert.equal(result.retained.rules, 400, 'the retained version must be reported');
  assert.match(result.detail, /retained previous version/);
  assert.equal(await manager.content('core_lite_ads'), GOOD_FEED, 'active rules must be unchanged');
});

test('an expected hash that does not match aborts the update', async () => {
  const storage = new MemoryStorage();
  const manager = new FeedManager({ registry: TEST_REGISTRY, storage, fetchImpl: feedFetch({ body: GOOD_FEED }) });
  const result = await manager.update('core_lite_ads', { expectedHash: 'deadbeef'.repeat(8) });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'hash-mismatch');
  assert.equal(await manager.content('core_lite_ads'), null, 'nothing may be installed');
});

test('network and HTTP failures are reported, not hidden', async () => {
  const storage = new MemoryStorage();
  const netFail = new FeedManager({ registry: TEST_REGISTRY, storage, fetchImpl: async () => { throw new Error('offline'); } });
  const a = await netFail.update('core_lite_ads');
  assert.equal(a.ok, false);
  assert.equal(a.reason, 'network-error');

  const http = new FeedManager({ registry: TEST_REGISTRY, storage, fetchImpl: feedFetch({ status: 503 }) });
  const b = await http.update('core_lite_ads');
  assert.equal(b.ok, false);
  assert.equal(b.reason, 'http-error');
});

test('tampered local content is detected by verify()', async () => {
  const storage = new MemoryStorage();
  const manager = new FeedManager({ registry: TEST_REGISTRY, storage, fetchImpl: feedFetch({ body: GOOD_FEED }) });
  await manager.update('core_lite_ads');
  await storage.setItem('feed:core_lite_ads:content', GOOD_FEED.replace('feed0', 'evil0'));
  const result = await manager.verify('core_lite_ads');
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'hash-mismatch');
});

test('validateFeedText rejects malformed data with a specific reason', () => {
  assert.throws(() => validateFeedText('tiny'), (e) => e.reason === 'feed-too-small');
  assert.throws(() => validateFeedText('#'.repeat(2000)), (e) => e.reason === 'empty-feed', 'comments-only feed');
  assert.throws(() => validateFeedText('x'.repeat(5000)), (e) => e.reason === 'malformed-feed', 'no rule syntax');
  const garbage = ['# c', ...Array.from({ length: 200 }, () => 'not a rule at all !!!')].join('\n') + 'x'.repeat(2000);
  assert.throws(() => validateFeedText(garbage), (e) => e.reason === 'malformed-feed');
  assert.ok(validateFeedText(GOOD_FEED).ok);
});

/* --------------------------- backup / recovery ------------------------- */

test('snapshots are hashed, verified and restorable', async () => {
  const storage = new MemoryStorage();
  const backup = new BackupManager({ storage, clock: () => 1_700_000_000_000 });
  const saved = await backup.save({ settings: { protectionMode: 'BALANCED' }, customRules: [{ rawPattern: '||x.example^' }] });
  assert.equal(saved.schemaVersion, SCHEMA_VERSION);
  assert.match(saved.hash, /^[0-9a-f]{64}$/);

  const restored = await backup.restore(saved.id);
  assert.equal(restored.ok, true);
  assert.equal(restored.state.customRules.length, 1);
  assert.equal(restored.state.settings.protectionMode, 'BALANCED');
});

test('corruption falls back to the previous good snapshot (auto-recovery)', async () => {
  const storage = new MemoryStorage();
  let now = 1_700_000_000_000;
  const clock = () => now;
  const backup = new BackupManager({ storage, clock });

  const first = await backup.save({ settings: { mode: 'first' } });
  now += 60_000;
  const second = await backup.save({ settings: { mode: 'second' } });

  // Corrupt the newest snapshot's payload without updating its hash.
  const newest = JSON.parse(await storage.getItem(`backup:${second.id}`));
  newest.payload = newest.payload.replace('second', 'tampered');
  await storage.setItem(`backup:${second.id}`, JSON.stringify(newest));

  const recovered = await backup.recover();
  assert.equal(recovered.ok, true);
  assert.equal(recovered.id, first.id, 'must fall back to the older valid snapshot');
  assert.equal(recovered.state.settings.mode, 'first');
  assert.equal(recovered.skipped.length, 1);
  assert.equal(recovered.skipped[0].reason, 'hash-mismatch');
});

test('recovery with no snapshots says so instead of inventing defaults', async () => {
  const backup = new BackupManager({ storage: new MemoryStorage() });
  const result = await backup.recover();
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'no-snapshots');
  assert.match(result.detail, /No configuration snapshot/);
});

test('snapshot count is bounded', async () => {
  const storage = new MemoryStorage();
  let now = 1_700_000_000_000;
  const backup = new BackupManager({ storage, clock: () => now, maxSnapshots: 3 });
  for (let i = 0; i < 6; i++) { await backup.save({ settings: { i } }); now += 1000; }
  const list = await backup.list();
  assert.equal(list.length, 3);
  assert.equal(list[0].valid, true);
});

test('schema migrations upgrade older backups', () => {
  const v1 = { schemaVersion: 1, customRules: [], settings: {} };
  const migrated = migrate(v1);
  assert.equal(migrated.version, SCHEMA_VERSION);
  assert.equal(migrated.applied.length, 2);
  assert.ok(migrated.state.aether, 'v3 state must include AETHER');
  assert.ok(migrated.state.firewall, 'v3 state must include firewall config');
  assert.equal(migrated.state.settings.autoUpdateFeeds, true);

  const missingVersion = migrate({ customRules: [] });
  assert.equal(missingVersion.version, SCHEMA_VERSION, 'unversioned legacy backups migrate from v1');
});

test('a failed write never looks like a saved snapshot', async () => {
  const storage = new MemoryStorage();
  const backup = new BackupManager({ storage, clock: () => 1000 });
  storage.failNext = 'write';
  await assert.rejects(() => backup.save({ settings: {} }), /QuotaExceeded/);
  assert.equal((await backup.list()).length, 0);
});

/* ------------------------------- privacy ------------------------------- */

test('analytics never persists raw hostnames', async () => {
  const storage = new MemoryStorage();
  const clock = () => 1_700_000_000_000;
  const analytics = new PrivateAnalytics({ storage, clock });
  analytics.record({ kind: 'blocked', category: 'ADS', domain: 'secret-tracker.example' });
  analytics.record({ kind: 'blocked', category: 'ADS', domain: 'secret-tracker.example' });
  await analytics.flush();

  const stored = await storage.getItem('analytics:state');
  assert.ok(stored, 'state must be written');
  assert.equal(stored.includes('secret-tracker'), false, 'raw hostname leaked into storage!');
  assert.equal(JSON.stringify(analytics.report()).includes('secret-tracker'), false, 'raw hostname leaked into report!');
  assert.equal(analytics.hasSeen('secret-tracker.example'), true, 'hashed bucketing still works');
  assert.equal(analytics.report().leavesDevice, false);
});

test('k-anonymity suppresses small buckets', () => {
  const analytics = new PrivateAnalytics({ clock: () => 1_700_000_000_000, k: 10 });
  for (let i = 0; i < 3; i++) analytics.record({ kind: 'blocked', category: 'RARE' });
  for (let i = 0; i < 25; i++) analytics.record({ kind: 'blocked', category: 'ADS' });
  const report = analytics.report();
  const day = report.days[0];
  assert.equal(day.categories.ADS, 25);
  assert.equal(day.categories.RARE, undefined, 'small bucket must be suppressed');
  assert.equal(day.suppressedBuckets, 1);
  assert.equal(day.suppressedEvents, 3);
  assert.match(report.note, /suppressed/);
});

test('retention removes old day buckets', () => {
  let now = Date.parse('2026-01-01T00:00:00Z');
  const clock = () => now;
  const analytics = new PrivateAnalytics({ clock, retentionDays: 3 });
  analytics.record({ kind: 'blocked', category: 'ADS' });
  now += 5 * 86_400_000;
  analytics.record({ kind: 'blocked', category: 'ADS' });
  const days = analytics.report().days.map((d) => d.day);
  assert.equal(days.includes('2026-01-01'), false, 'expired bucket must be purged');
  assert.equal(days.length, 1);
});

test('analytics state round-trips', async () => {
  const storage = new MemoryStorage();
  const a = new PrivateAnalytics({ storage, clock: () => 1_700_000_000_000 });
  a.record({ kind: 'blocked', category: 'TRACKING', domain: 'a.example' });
  await a.flush();

  const b = new PrivateAnalytics({ storage, clock: () => 1_700_000_000_000 });
  assert.equal(await b.load(), true);
  assert.equal(b.report().days[0].kinds.blocked, 1);
  assert.equal(b.hasSeen('a.example'), true);
});
