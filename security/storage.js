/**
 * OmniShield X — storage adapters.
 *
 * A tiny async key/value contract so the same code runs against localStorage in
 * the browser and an in-memory map in tests. Failures (quota exceeded, privacy
 * mode, denied access) are surfaced, never swallowed silently into a fake
 * success — callers decide how to degrade.
 */

export class MemoryStorage {
  constructor(initial = {}) { this.map = new Map(Object.entries(initial)); this.failNext = null; }
  async getItem(key) {
    if (this.failNext === 'read') { this.failNext = null; throw new Error('storage read failure (simulated)'); }
    return this.map.has(key) ? this.map.get(key) : null;
  }
  async setItem(key, value) {
    if (this.failNext === 'write') { this.failNext = null; throw new Error('QuotaExceededError (simulated)'); }
    this.map.set(key, String(value));
  }
  async removeItem(key) { this.map.delete(key); }
  async keys() { return [...this.map.keys()]; }
  get size() { return this.map.size; }
}

export class LocalStorageAdapter {
  constructor(namespace = 'omnishield-x') {
    this.namespace = namespace;
    this.available = LocalStorageAdapter.detect();
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

/** Chooses the best available adapter, always returning something usable. */
export function createStorage(namespace = 'omnishield-x') {
  const local = new LocalStorageAdapter(namespace);
  if (local.available) return local;
  return new MemoryStorage();
}

export default { MemoryStorage, LocalStorageAdapter, createStorage };
