/**
 * OmniShield X — storage adapters.
 *
 * A tiny async key/value contract so the same code runs against IndexedDB (large
 * binaries: the private cloud box and media files), localStorage (small config)
 * and an in-memory map in tests. Failures (quota exceeded, privacy mode, denied
 * access) are surfaced, never swallowed silently into a fake success — callers
 * decide how to degrade.
 *
 * The v5 platform could only keep ~5 MB because everything went to localStorage.
 * `IndexedDbAdapter` removes that ceiling (subject to the browser's per-origin
 * quota, which is queried with `navigator.storage.estimate()` and shown to the
 * user) while keeping the exact same async contract.
 */

export class MemoryStorage {
  constructor(initial = {}) { this.map = new Map(Object.entries(initial)); this.failNext = null; this.name = 'memory'; }
  async getItem(key) {
    if (this.failNext === 'read') { this.failNext = null; throw new Error('storage read failure (simulated)'); }
    return this.map.has(key) ? this.map.get(key) : null;
  }
  async setItem(key, value) {
    if (this.failNext === 'write') { this.failNext = null; throw new Error('QuotaExceededError (simulated)'); }
    // Values are kept as given so binary payloads (Blob/ArrayBuffer) survive, the
    // same contract IndexedDbAdapter offers. Callers that want text store text.
    this.map.set(key, value);
  }
  async removeItem(key) { this.map.delete(key); }
  async keys() { return [...this.map.keys()]; }
  get size() { return this.map.size; }
  /** Memory keeps whatever it is given, including Blobs. */
  get binarySafe() { return true; }
}

export class LocalStorageAdapter {
  constructor(namespace = 'omnishield-x') {
    this.namespace = namespace;
    this.available = LocalStorageAdapter.detect();
    this.name = 'localStorage';
  }
  static detect() {
    try {
      const probe = '__omnishield_probe__';
      globalThis.localStorage.setItem(probe, '1');
      globalThis.localStorage.removeItem(probe);
      return true;
    } catch { return false; }
  }
  _key(key) { return `${this.namespace}:${key}`; }
  _assert() {
    if (!this.available) throw new Error('localStorage is unavailable (private mode or blocked)');
  }
  /** localStorage stringifies everything, so callers must encode binaries first. */
  get binarySafe() { return false; }
  async getItem(key) { this._assert(); return globalThis.localStorage.getItem(this._key(key)); }
  async setItem(key, value) { this._assert(); globalThis.localStorage.setItem(this._key(key), String(value)); }
  async removeItem(key) { this._assert(); globalThis.localStorage.removeItem(this._key(key)); }
  async keys() {
    this._assert();
    const prefix = `${this.namespace}:`;
    const out = [];
    for (let i = 0; i < globalThis.localStorage.length; i++) {
      const k = globalThis.localStorage.key(i);
      if (k && k.startsWith(prefix)) out.push(k.slice(prefix.length));
    }
    return out;
  }
}

/**
 * IndexedDB key/value adapter.
 *
 * Values are stored as-is (strings, Blobs, ArrayBuffers, plain objects) so the
 * private cloud box can keep real binary payloads without base64 inflation.
 * `getItem` returns exactly what `setItem` was given.
 */
export class IndexedDbAdapter {
  /**
   * @param {{namespace?:string, store?:string, factory?:IDBFactory}} [options]
   */
  constructor(options = {}) {
    this.namespace = options.namespace || 'omnishield-x';
    this.store = options.store || 'kv';
    this.factory = options.factory || globalThis.indexedDB || null;
    this.name = 'indexedDB';
    this.available = !!this.factory;
    this._db = null;
    this._opening = null;
  }

  /** Structured clone keeps Blobs and ArrayBuffers intact. */
  get binarySafe() { return true; }

  static detect(factory = globalThis.indexedDB) {
    return !!factory;
  }

  /** Opens (and caches) the database. Rejects with a real reason, never fakes success. */
  async open() {
    if (!this.available) throw new Error('IndexedDB is unavailable in this context');
    if (this._db) return this._db;
    if (this._opening) return this._opening;
    this._opening = new Promise((resolve, reject) => {
      let request;
      try {
        request = this.factory.open(`${this.namespace}-db`, 1);
      } catch (error) {
        reject(error);
        return;
      }
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(this.store)) db.createObjectStore(this.store);
      };
      request.onsuccess = () => {
        const db = request.result;
        db.onversionchange = () => { try { db.close(); } catch { /* already closed */ } this._db = null; };
        this._db = db;
        resolve(db);
      };
      request.onerror = () => reject(request.error || new Error('IndexedDB open failed'));
      request.onblocked = () => reject(new Error('IndexedDB open blocked by another tab'));
    }).finally(() => { this._opening = null; });
    return this._opening;
  }

  async _tx(mode, run) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      let transaction;
      try {
        transaction = db.transaction(this.store, mode);
      } catch (error) {
        reject(error);
        return;
      }
      const store = transaction.objectStore(this.store);
      let result;
      try {
        result = run(store);
      } catch (error) {
        reject(error);
        return;
      }
      transaction.oncomplete = () => resolve(result?.__value);
      transaction.onerror = () => reject(transaction.error || new Error('IndexedDB transaction failed'));
      transaction.onabort = () => reject(transaction.error || new Error('IndexedDB transaction aborted'));
    });
  }

  async getItem(key) {
    const holder = { __value: null };
    await this._tx('readonly', (store) => {
      const request = store.get(key);
      request.onsuccess = () => { holder.__value = request.result === undefined ? null : request.result; };
      return holder;
    });
    return holder.__value;
  }

  async setItem(key, value) {
    await this._tx('readwrite', (store) => { store.put(value, key); });
  }

  async removeItem(key) {
    await this._tx('readwrite', (store) => { store.delete(key); });
  }

  async keys() {
    const holder = { __value: [] };
    await this._tx('readonly', (store) => {
      const request = store.getAllKeys();
      request.onsuccess = () => { holder.__value = (request.result || []).map(String); };
      return holder;
    });
    return holder.__value;
  }

  /** Real bytes used by this origin, when the browser reports it. */
  static async estimate() {
    try {
      const api = globalThis.navigator?.storage;
      if (!api || typeof api.estimate !== 'function') return { supported: false };
      const { usage, quota } = await api.estimate();
      if (!Number.isFinite(usage) || !Number.isFinite(quota)) return { supported: false };
      return { supported: true, usage, quota, available: Math.max(0, quota - usage) };
    } catch {
      return { supported: false };
    }
  }
}

/**
 * Chooses the best available adapter, always returning something usable.
 *
 * Order: IndexedDB (large capacity, binary-safe) → localStorage (small config) →
 * memory (last resort; the UI reports that nothing will persist).
 */
export function createStorage(namespace = 'omnishield-x', options = {}) {
  if (options.kind !== 'local' && IndexedDbAdapter.detect()) {
    const idb = new IndexedDbAdapter({ namespace });
    return new FallbackAdapter(idb, namespace);
  }
  const local = new LocalStorageAdapter(namespace);
  if (local.available) return local;
  return new MemoryStorage();
}

/**
 * Uses the primary adapter and transparently falls back to localStorage when the
 * primary cannot be opened (private windows, blocked storage, broken upgrades).
 * `name` always reports which adapter actually served the last operation.
 */
export class FallbackAdapter {
  constructor(primary, namespace) {
    this.primary = primary;
    this.secondary = new LocalStorageAdapter(namespace);
    this.fallback = null;
    this.name = primary.name;
    this.lastError = null;
  }

  async _run(operation) {
    if (!this.fallback) {
      try {
        return await operation(this.primary);
      } catch (error) {
        this.lastError = error;
        if (!this.secondary.available) throw error;
        this.fallback = this.secondary;
        this.name = this.secondary.name;
      }
    }
    return operation(this.fallback);
  }

  /** Follows whichever backend is actually serving reads and writes. */
  get binarySafe() {
    const active = this.fallback || this.primary;
    return active.binarySafe !== false;
  }

  getItem(key) { return this._run((adapter) => adapter.getItem(key)); }
  setItem(key, value) { return this._run((adapter) => adapter.setItem(key, value)); }
  removeItem(key) { return this._run((adapter) => adapter.removeItem(key)); }
  keys() { return this._run((adapter) => adapter.keys()); }
}

export default { MemoryStorage, LocalStorageAdapter, IndexedDbAdapter, FallbackAdapter, createStorage };
