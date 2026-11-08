import test from 'node:test';
import assert from 'node:assert/strict';
import { IDBFactory } from 'fake-indexeddb';
import { WorldIndexedStorage, createWorldStorage } from '../../world/storage.js';
import { WorldStore, serializeWorkspace } from '../../world/store.js';
import { normalizeEvent } from '../../world/model.js';
import { MemoryStorage } from '../../security/storage.js';
import { NOW } from '../fixtures/world.mjs';

const factory = () => new IDBFactory();
const event = (id, source = 'usgs', summary = 'Public source record') => normalizeEvent({ id: String(id), title: `${source} test ${id}`, summary, category: 'seismic', occurredAt: NOW - id, lat: 15, lon: 121 }, source, NOW);

test('World IndexedDB adapter implements committed CRUD without using localStorage for large data', async () => {
  const legacy = new MemoryStorage(); const storage = await createWorldStorage(legacy, { factory: factory() });
  assert.ok(storage instanceof WorldIndexedStorage);
  await storage.setItem('world:large', 'x'.repeat(6_000_000));
  assert.equal((await storage.getItem('world:large')).length, 6_000_000); assert.equal(legacy.size, 0);
  assert.deepEqual(await storage.keys(), ['world:large']);
  await storage.removeItem('world:large'); assert.equal(await storage.getItem('world:large'), null); storage.close();
});
test('World records survive reopening the IndexedDB connection', async () => {
  const db = factory(); const first = await createWorldStorage(new MemoryStorage(), { factory: db });
  await first.setItem('world:test', 'retained'); first.close();
  const second = await createWorldStorage(new MemoryStorage(), { factory: db });
  assert.equal(await second.getItem('world:test'), 'retained'); second.close();
});
test('read-through migration moves only world records after the new transaction commits', async () => {
  const legacy = new MemoryStorage({ 'world:workspace:v1': '{"version":1}', 'security:settings': 'untouched' });
  const storage = await createWorldStorage(legacy, { factory: factory() });
  assert.equal(await storage.getItem('world:workspace:v1'), '{"version":1}');
  assert.equal(await legacy.getItem('world:workspace:v1'), null); assert.equal(await legacy.getItem('security:settings'), 'untouched');
  await assert.rejects(storage.getItem('security:settings'), /own keys/); storage.close();
});
test('a failed migration keeps the readable legacy value instead of deleting it', async () => {
  const legacy = new MemoryStorage({ 'world:workspace:v1': 'original' });
  const storage = await createWorldStorage(legacy, { factory: factory() }); storage.setItem = async () => { throw new Error('quota denied'); };
  assert.equal(await storage.getItem('world:workspace:v1'), 'original'); assert.equal(await legacy.getItem('world:workspace:v1'), 'original'); storage.close();
});
test('unavailable and security-denied IndexedDB use the existing honest fallback', async () => {
  const legacy = new MemoryStorage();
  assert.equal(await createWorldStorage(legacy, { factory: null }), legacy);
  assert.equal(await createWorldStorage(legacy, { factory: { open() { throw new Error('SecurityError'); } } }), legacy);
});
test('blocked or nonresponding database opens cannot hang application startup', async () => {
  const legacy = new MemoryStorage();
  const blocked = { open() { const request = {}; queueMicrotask(() => request.onblocked()); return request; } };
  assert.equal(await createWorldStorage(legacy, { factory: blocked, timeoutMs: 20 }), legacy);
  assert.equal(await createWorldStorage(legacy, { factory: { open: () => ({}) }, timeoutMs: 5 }), legacy);
});
test('closed database transactions reject rather than claiming a successful write', async () => {
  const storage = await createWorldStorage(new MemoryStorage(), { factory: factory() }); storage.close();
  await assert.rejects(storage.setItem('world:test', 'not saved'));
});
test('workspace serialization enforces UTF-8 byte budget, distributes space and keeps newest evidence', () => {
  const snapshot = { version: 1, watches: [{ label: 'Keep this rule' }], bookmarks: [event(1)], sources: {
    usgs: { events: Array.from({ length: 20 }, (_, i) => event(i, 'usgs', '界'.repeat(500))) },
    geonet: { events: Array.from({ length: 20 }, (_, i) => event(i, 'geonet', '界'.repeat(500))) }
  } };
  const value = serializeWorkspace(snapshot, 12_000); const saved = JSON.parse(value.json);
  assert.ok(new TextEncoder().encode(value.json).length <= 12_000); assert.equal(value.trimmed, true);
  assert.equal(saved.watches[0].label, 'Keep this rule'); assert.equal(saved.bookmarks.length, 1);
  assert.ok(saved.sources.usgs.events.length > 0 && saved.sources.geonet.events.length > 0);
  assert.equal(saved.sources.usgs.events[0].id, 'usgs:0'); assert.equal(snapshot.sources.usgs.events.length, 20);
  assert.ok(saved.sources.usgs.cacheReduced); assert.ok(saved.sources.geonet.cacheReduced);
});
test('oversized user metadata is rejected instead of silently dropping saved events or watches', () => {
  assert.throws(() => serializeWorkspace({ sources: {}, bookmarks: ['x'.repeat(10000)] }, 1000), /metadata exceeds/);
});
test('a reduced offline cache stays disclosed across reload and filter changes until refreshed or cleared', async () => {
  const storage = new MemoryStorage(); const first = new WorldStore({ storage, clock: () => NOW, cacheMaxBytes: 8_000 });
  first.sources.usgs.events = Array.from({ length: 30 }, (_, i) => event(i, 'usgs', '界'.repeat(400)));
  first.sources.usgs.health.lastSuccess = NOW;
  await first.toggleBookmark(first.sources.usgs.events[0]); await first.addWatch({ label: 'Keep watch', severity: 'info' });
  assert.match(first.cacheNotice, /offline snapshot/); assert.equal(first.sources.usgs.events.length, 30);
  const next = new WorldStore({ storage, clock: () => NOW, cacheMaxBytes: 8_000 }); await next.load();
  assert.ok(next.sources.usgs.events.length > 0 && next.sources.usgs.events.length < 30);
  assert.equal(next.watches.length, 1); assert.equal(next.bookmarks.length, 1); assert.match(next.cacheNotice, /reduced/);
  await next.setFilters({ query: 'test' }); assert.match(next.cacheNotice, /offline snapshot/);
  assert.equal(JSON.parse(await storage.getItem('world:workspace:v1')).cacheTrimmed, true);
  await next.clearCache(); assert.equal(next.cacheNotice, null); assert.equal(next.watches.length, 1); assert.equal(next.bookmarks.length, 1);
});
