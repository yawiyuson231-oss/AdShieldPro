/**
 * OmniShield X — configuration backup, migration and crash recovery.
 *
 * Every save is hashed (SHA-256) and written as an immutable snapshot; the newest
 * N snapshots are kept. On startup the platform calls `recover()`, which walks
 * snapshots newest-first and returns the first one that both passes schema
 * migration and matches its stored hash. Corrupt data therefore degrades to the
 * previous good configuration instead of wiping the user's settings.
 *
 * If nothing is recoverable the result says so explicitly (`ok:false`) — the
 * caller decides whether to start from safe defaults, and the UI tells the user.
 */
import { sha256Hex } from './sha256.js';

export const SCHEMA_VERSION = 3;

/** Migrations are total functions: they never throw on plausible input. */
export const MIGRATIONS = Object.freeze({
  /** v1 (Android backup) -> v2 */
  1: (state) => ({
    ...state,
    schemaVersion: 2,
    settings: { ...(state.settings || {}), autoUpdateFeeds: state.settings?.autoUpdateFeeds ?? true }
  }),
  /** v2 -> v3: adds AETHER state and firewall configuration */
  2: (state) => ({
    ...state,
    schemaVersion: 3,
    aether: state.aether ?? { version: 1, reputation: null, classifier: null, observations: [] },
    firewall: state.firewall ?? { policies: [], config: {} }
  })
});

export function migrate(state) {
  let current = { ...(state && typeof state === 'object' ? state : {}) };
  let version = Number(current.schemaVersion ?? 1);
  if (!Number.isInteger(version) || version < 1) {
    throw new Error(`invalid schema version ${current.schemaVersion}`);
  }
  if (version > SCHEMA_VERSION) {
    throw new Error(`unsupported future schema version ${version} (max ${SCHEMA_VERSION})`);
  }
  const applied = [];
  while (version < SCHEMA_VERSION) {
    const step = MIGRATIONS[version];
    if (!step) throw new Error(`no migration path from schema version ${version}`);
    current = step(current);
    applied.push(version);
    version = Number(current.schemaVersion);
  }
  return { state: current, applied, version };
}

export class BackupManager {
  /**
   * @param {{storage:object, clock?:()=>number, maxSnapshots?:number,
   *          appVersion?:string, prefix?:string}} options
   */
  constructor(options = {}) {
    this.storage = options.storage;
    if (!this.storage) throw new Error('BackupManager requires a storage adapter');
    this.clock = options.clock ?? (() => Date.now());
    this.maxSnapshots = options.maxSnapshots ?? 5;
    // Defaults to the release this module ships with; app.js passes its own.
    this.appVersion = options.appVersion ?? '5.0.3';
    this.prefix = options.prefix ?? 'backup:';
  }

  _key(id) { return `${this.prefix}${id}`; }

  /** Saves a snapshot. Returns its id, hash and size. */
  async save(state, { reason = 'manual' } = {}) {
    const migrated = migrate({ ...state, schemaVersion: state.schemaVersion ?? SCHEMA_VERSION });
    const payload = JSON.stringify({
      schemaVersion: SCHEMA_VERSION,
      appVersion: this.appVersion,
      reason,
      createdAt: new Date(this.clock()).toISOString(),
      state: migrated.state
    });
    const hash = sha256Hex(payload);
    const bytes = new TextEncoder().encode(payload).length;
    const id = `${this.clock().toString(36)}-${hash.slice(0, 8)}`;
    const record = JSON.stringify({ id, hash, bytes, payload });

    // Verify the write immediately: a silently failed write must not look saved.
    await this.storage.setItem(this._key(id), record);
    const readBack = await this.storage.getItem(this._key(id));
    if (readBack !== record) throw new Error('backup write verification failed (storage did not persist the snapshot)');

    await this._prune();
    return { id, hash, bytes, schemaVersion: SCHEMA_VERSION, appliedMigrations: migrated.applied };
  }

  async list() {
    const keys = (await this.storage.keys()).filter((k) => k.startsWith(this.prefix));
    const out = [];
    for (const key of keys) {
      const raw = await this.storage.getItem(key);
      if (!raw) continue;
      try {
        const record = JSON.parse(raw);
        let meta = null;
        try { meta = JSON.parse(record.payload); } catch { meta = null; }
        const hasHash = typeof record.hash === 'string' && record.hash.length > 0;
        out.push({
          id: record.id ?? key.slice(this.prefix.length), hash: record.hash, bytes: record.bytes,
          createdAt: meta?.createdAt ?? null, reason: meta?.reason ?? 'unknown',
          schemaVersion: meta?.schemaVersion ?? null,
          valid: !!meta && hasHash && sha256Hex(record.payload) === record.hash
        });
      } catch {
        out.push({ id: key.slice(this.prefix.length), createdAt: null, corrupt: true, valid: false });
      }
    }
    return out.sort((a, b) => (b.createdAt ?? '').localeCompare(a.createdAt ?? ''));
  }

  async _prune() {
    const snapshots = (await this.list()).filter((s) => !s.corrupt);
    if (snapshots.length <= this.maxSnapshots) return 0;
    const doomed = snapshots.slice(this.maxSnapshots);
    for (const s of doomed) await this.storage.removeItem(this._key(s.id));
    return doomed.length;
  }

  /**
   * Loads and verifies a specific snapshot.
   * @returns {{ok:boolean, state?:object, reason?:string, migrations?:number[]}}
   */
  async restore(id) {
    const raw = await this.storage.getItem(this._key(id));
    if (!raw) return { ok: false, reason: 'not-found' };
    let record;
    try { record = JSON.parse(raw); } catch { return { ok: false, reason: 'corrupt-record' }; }
    if (typeof record.payload !== 'string') return { ok: false, reason: 'corrupt-payload' };

    if (typeof record.hash !== 'string' || !record.hash) {
      return { ok: false, reason: 'missing-hash' };
    }
    const actual = sha256Hex(record.payload);
    if (actual !== record.hash) {
      return { ok: false, reason: 'hash-mismatch', expected: record.hash, actual };
    }
    let parsed;
    try { parsed = JSON.parse(record.payload); } catch { return { ok: false, reason: 'corrupt-json' }; }
    try {
      const migrated = migrate(parsed.state || {});
      return { ok: true, state: migrated.state, migrations: migrated.applied, createdAt: parsed.createdAt };
    } catch (err) {
      return { ok: false, reason: 'migration-failed', detail: err.message };
    }
  }

  /**
   * Automatic recovery: newest valid snapshot wins; corrupt ones are skipped.
   */
  async recover() {
    const snapshots = (await this.list()).filter((s) => !s.corrupt);
    const skipped = [];
    for (const snapshot of snapshots) {
      const result = await this.restore(snapshot.id);
      if (result.ok) {
        return {
          ok: true, id: snapshot.id, state: result.state,
          migrations: result.migrations, createdAt: result.createdAt,
          skipped, attempts: skipped.length + 1
        };
      }
      skipped.push({ id: snapshot.id, reason: result.reason });
    }
    return {
      ok: false,
      reason: snapshots.length ? 'no-valid-snapshot' : 'no-snapshots',
      skipped,
      detail: snapshots.length
        ? 'Every stored snapshot failed verification. Start from safe defaults; nothing was deleted.'
        : 'No configuration snapshot exists yet.'
    };
  }

  async remove(id) { await this.storage.removeItem(this._key(id)); return true; }
}

export default BackupManager;
