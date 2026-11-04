/**
 * Storage adapters.
 *
 * The v5 build kept everything in localStorage, so ~5 MB was a hard ceiling and
 * binary values could not survive at all. These tests pin the new contract:
 * values round-trip unchanged, a broken IndexedDB falls back rather than losing
 * data, and every failure is thrown rather than swallowed.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { MemoryStorage, LocalStorageAdapter, IndexedDbAdapter, FallbackAdapter, createStorage } from '../../security/storage.js';

/** Minimal in-memory stand-in for IDBFactory, faithful enough to exercise the adapter. */
function fakeIndexedDb({ failOpen = false, quota = 0 } = {}) {
  const stores = new Map();
  let writes = 0;
  const factory = {
    open() {
      const request = {};
      setTimeout(() => {
        if (failOpen) {
          request.error = new Error('open failed');
          request.onerror?.();
          return;
        }
        const db = {
          objectStoreNames: { contains: (name) => stores.has(name) },
          createObjectStore: (name) => { stores.set(name, new Map()); },
          transaction(name) {
            if (!stores.has(name)) stores.set(name, new Map());
            const map = stores.get(name);
            const tx = { error: null, complete: null, fail: null };
            const fail = (message) => { tx.error = new Error(message); setTimeout(() => tx.fail?.(tx.error), 0); };
            const store = {
              get(key) { const request = {}; setTimeout(() => { request.result = map.get(key); request.onsuccess?.(); }, 0); return request; },
              put(value, key) {
                writes += 1;
                if (quota && writes > quota) { fail('QuotaExceededError'); return; }
                map.set(key, value);
              },
              delete(key) { map.delete(key); },
              getAllKeys() { const request = {}; setTimeout(() => { request.result = [...map.keys()]; request.onsuccess?.(); }, 0); return request; }
            };
            // Real IndexedDB fires every request's onsuccess before the
            // transaction's complete event; the double must do the same or it
            // would test an ordering the browser never produces.
            setTimeout(() => { if (!tx.error) tx.complete?.(); }, 5);
            return {
              objectStore: () => store,
              set oncomplete(fn) { tx.complete = fn; }, get oncomplete() { return tx.complete; },
              set onerror(fn) { tx.fail = fn; }, get onerror() { return tx.fail; },
              set onabort(fn) { tx.abort = fn; }
            };
          }
        };
        request.result = db;
        request.onupgradeneeded?.();
        request.onsuccess?.();
      }, 0);
      return request;
    }
  };
  return { factory, stores };
}

test('the in-memory adapter keeps binary values intact', async () => {
  const storage = new MemoryStorage();
  const blob = new Blob(['hello']);
  await storage.setItem('bin', blob);
  const read = await storage.getItem('bin');
  assert.ok(read instanceof Blob);
  assert.equal(await read.text(), 'hello');
  assert.deepEqual(await storage.keys(), ['bin']);
});

test('a simulated write failure is thrown, not swallowed', async () => {
  const storage = new MemoryStorage();
  storage.failNext = 'write';
  await assert.rejects(() => storage.setItem('a', 'b'), /QuotaExceeded/);
  storage.failNext = 'read';
  await assert.rejects(() => storage.getItem('a'), /read failure/);
});

test('IndexedDB adapter round-trips strings, objects and binary blobs', async () => {
  const { factory } = fakeIndexedDb();
  const adapter = new IndexedDbAdapter({ namespace: 'test', factory });
  await adapter.setItem('text', 'value');
  await adapter.setItem('obj', { a: 1 });
  await adapter.setItem('bin', new Blob(['bytes']));
  assert.equal(await adapter.getItem('text'), 'value');
  assert.deepEqual(await adapter.getItem('obj'), { a: 1 });
  assert.equal(await (await adapter.getItem('bin')).text(), 'bytes');
  assert.equal(await adapter.getItem('missing'), null);
  assert.deepEqual((await adapter.keys()).sort(), ['bin', 'obj', 'text']);
  await adapter.removeItem('text');
  assert.equal(await adapter.getItem('text'), null);
});

test('IndexedDB open failure surfaces as a rejection', async () => {
  const { factory } = fakeIndexedDb({ failOpen: true });
  const adapter = new IndexedDbAdapter({ namespace: 'test', factory });
  await assert.rejects(() => adapter.open(), /open failed/);
});

test('the fallback adapter degrades to localStorage instead of losing writes', async () => {
  const { factory } = fakeIndexedDb({ failOpen: true });
  const primary = new IndexedDbAdapter({ namespace: 'fbtest', factory });
  globalThis.localStorage = {
    map: new Map(),
    getItem(k) { return this.map.has(k) ? this.map.get(k) : null; },
    setItem(k, v) { this.map.set(k, String(v)); },
    removeItem(k) { this.map.delete(k); },
    key(i) { return [...this.map.keys()][i] ?? null; },
    get length() { return this.map.size; }
  };
  const adapter = new FallbackAdapter(primary, 'fbtest');
  await adapter.setItem('k', 'v');
  assert.equal(await adapter.getItem('k'), 'v');
  assert.equal(adapter.name, 'localStorage');
});

test('createStorage never returns null and reports which backend it chose', () => {
  const adapter = createStorage('probe', { kind: 'local' });
  assert.ok(adapter);
  assert.ok(['localStorage', 'memory'].includes(adapter.name));
  const detect = createStorage('probe2');
  assert.ok(detect);
  assert.ok(typeof detect.getItem === 'function');
  assert.equal(LocalStorageAdapter.detect() !== undefined, true);
});

test('quota estimation reports unsupported rather than inventing numbers', async () => {
  const original = globalThis.navigator;
  try {
    Object.defineProperty(globalThis, 'navigator', { value: {}, configurable: true, writable: true });
    assert.deepEqual(await IndexedDbAdapter.estimate(), { supported: false });
  } finally {
    Object.defineProperty(globalThis, 'navigator', { value: original, configurable: true, writable: true });
  }
});
