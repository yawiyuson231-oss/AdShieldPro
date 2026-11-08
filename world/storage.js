/** Large world caches must not consume the small localStorage quota used by DNS/security settings. */
const DATABASE = 'omnishield-world-v2';
const OBJECT_STORE = 'entries';
const validKey = (key) => { if (typeof key !== 'string' || !key.startsWith('world:')) throw new Error('World storage only accepts its own keys.'); };

export class WorldIndexedStorage {
  constructor(database, legacy) { this.database = database; this.legacy = legacy; this.available = true; }
  transaction(mode, action) {
    return new Promise((resolve, reject) => {
      let transaction; let request; let value;
      try {
        transaction = this.database.transaction(OBJECT_STORE, mode);
        request = action(transaction.objectStore(OBJECT_STORE));
      } catch (error) { reject(error); return; }
      request.onsuccess = () => { value = request.result; };
      transaction.oncomplete = () => resolve(value ?? null);
      transaction.onerror = transaction.onabort = () => reject(transaction.error || request.error || new Error('World database transaction failed.'));
    });
  }
  async getItem(key) {
    validKey(key);
    const value = await this.transaction('readonly', (store) => store.get(key));
    if (value !== null) return value;
    // Read-through migration only for this workspace, never DNS settings/rules. Delete the old
    // value only after the new transaction commits; a failed migration must retain the original.
    const previous = await this.legacy?.getItem(key);
    if (previous === null || previous === undefined) return null;
    try { await this.setItem(key, previous); await this.legacy.removeItem(key); } catch { /* retain a readable legacy copy */ }
    return previous;
  }
  async setItem(key, value) { validKey(key); await this.transaction('readwrite', (store) => store.put(String(value), key)); }
  async removeItem(key) { validKey(key); await this.transaction('readwrite', (store) => store.delete(key)); await this.legacy?.removeItem(key); }
  async keys() { return (await this.transaction('readonly', (store) => store.getAllKeys())).filter((key) => typeof key === 'string' && key.startsWith('world:')); }
  close() { this.database.close(); }
}

export async function createWorldStorage(legacy, { factory = globalThis.indexedDB, timeoutMs = 3_000, name = DATABASE } = {}) {
  if (!factory) return legacy;
  try {
    const database = await new Promise((resolve, reject) => {
      let finished = false; let request;
      const fail = (error) => { if (!finished) { finished = true; clearTimeout(timer); reject(error); } };
      const timer = setTimeout(() => fail(new Error('World database could not be opened.')), timeoutMs);
      try { request = factory.open(name, 1); } catch (error) { fail(error); return; }
      request.onupgradeneeded = () => {
        try { if (!request.result.objectStoreNames.contains(OBJECT_STORE)) request.result.createObjectStore(OBJECT_STORE); }
        catch (error) { request.transaction?.abort(); fail(error); }
      };
      request.onblocked = () => fail(new Error('World database upgrade is blocked by another page.'));
      request.onerror = () => fail(request.error || new Error('World database is unavailable.'));
      request.onsuccess = () => {
        if (finished) { request.result.close(); return; }
        finished = true; clearTimeout(timer);
        request.result.onversionchange = () => request.result.close();
        resolve(request.result);
      };
    });
    return new WorldIndexedStorage(database, legacy);
  } catch { return legacy; } // Existing adapter still reports quota/denied/session-only storage honestly.
}
