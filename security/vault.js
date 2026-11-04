/**
 * OmniShield X — private storage box (on-device vault).
 *
 * Real cloud-style storage with **no server**: files are kept in IndexedDB on this
 * origin, so they survive reloads, work offline and never leave the device. The
 * module provides the operations the UI needs — put/read/rename/move/delete,
 * folders, search, integrity verification, quota reporting and an optional
 * passphrase lock (AES-GCM via WebCrypto) — and it reports every failure instead
 * of pretending a write succeeded.
 */
import { sha256Hex } from './sha256.js';
import { IndexedDbAdapter, MAX_FILE_BYTES, MAX_FILE_LABEL } from './storage.js';

const INDEX_KEY = 'vault:index';
const FILE_PREFIX = 'vault:file:';
const LOCK_KEY = 'vault:lock';
const MAX_FOLDERS = 200;

const KIND_BY_MIME = [
  [/^image\//, 'image'],
  [/^video\//, 'video'],
  [/^audio\//, 'audio'],
  [/^text\/|^application\/(json|xml|pdf|msword|vnd\.|rtf)/, 'document'],
  [/^application\/(zip|x-zip|gzip|x-tar|x-7z)/, 'archive']
];

const EXT_KIND = {
  image: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'svg', 'bmp', 'heic', 'ico'],
  video: ['mp4', 'webm', 'mkv', 'mov', 'm4v', 'ogv', 'avi', 'ts'],
  audio: ['mp3', 'm4a', 'aac', 'ogg', 'opus', 'wav', 'flac', 'weba'],
  document: ['pdf', 'txt', 'md', 'json', 'csv', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'rtf', 'xml', 'html', 'js', 'kt'],
  archive: ['zip', 'gz', 'tar', '7z', 'rar']
};

/** Classifies a file by MIME type first, then by extension. */
export function classify(kindHint, mime = '', name = '') {
  if (kindHint && Object.hasOwn(EXT_KIND, kindHint)) return kindHint;
  const cleanMime = String(mime || '').toLowerCase();
  for (const [re, kind] of KIND_BY_MIME) if (re.test(cleanMime)) return kind;
  const ext = String(name).toLowerCase().split('.').pop();
  for (const [kind, list] of Object.entries(EXT_KIND)) if (list.includes(ext)) return kind;
  return 'other';
}

/** Human label for a kind. */
export function kindLabel(kind) {
  return ({ image: 'Photos', video: 'Videos', audio: 'Audio', document: 'Documents', archive: 'Archives', other: 'Other' })[kind] || 'Other';
}

const normaliseFolder = (folder) => {
  const raw = String(folder || '/').trim();
  if (!raw || raw === '/') return '/';
  return `/${raw.split('/').filter(Boolean).join('/')}`;
};

/** WebCrypto helpers — AES-GCM 256 with a PBKDF2-SHA256 derived key. */
const cryptoApi = () => globalThis.crypto?.subtle || null;

async function deriveKey(passphrase, salt, iterations = 210_000) {
  const subtle = cryptoApi();
  if (!subtle) throw new Error('WebCrypto is unavailable, so the vault cannot be locked in this context.');
  const base = await subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

const toHex = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');

/**
 * String-only backends (localStorage, ~5 MB) cannot hold a Blob: assigning one
 * stores the literal text "[object Blob]" and the bytes are lost. Files are
 * base64-encoded for those backends and decoded on read, so the fallback path
 * degrades in capacity — never in correctness.
 */
async function encodeForStringBackend(blob) {
  const bytes = new Uint8Array(await blob.arrayBuffer());
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  return `b64:${blob.type || 'application/octet-stream'}:${btoa(binary)}`;
}

function decodeFromStringBackend(value) {
  const text = String(value);
  if (!text.startsWith('b64:')) return new Blob([text]);
  const rest = text.slice(4);
  const split = rest.indexOf(':');
  const type = split > 0 ? rest.slice(0, split) : 'application/octet-stream';
  const binary = atob(split > 0 ? rest.slice(split + 1) : rest);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new Blob([bytes], { type });
}
const fromHex = (hex) => new Uint8Array(String(hex).match(/.{2}/g).map((pair) => parseInt(pair, 16)));

export class FileVault {
  /**
   * @param {{storage:object, namespace?:string, maxFileBytes?:number, clock?:()=>number, randomBytes?:Function}} options
   */
  constructor(options = {}) {
    if (!options.storage) throw new Error('FileVault requires a storage adapter');
    this.storage = options.storage;
    this.namespace = options.namespace || 'vault';
    this.maxFileBytes = options.maxFileBytes ?? MAX_FILE_BYTES;
    this.clock = options.clock || (() => Date.now());
    this.randomBytes = options.randomBytes || ((n) => globalThis.crypto.getRandomValues(new Uint8Array(n)));
    this.entries = [];
    this.folders = new Set(['/']);
    this.loaded = false;
    this.key = null;           // CryptoKey when unlocked
    this.lockRecord = null;    // {salt, verifier, iterations}
    this.objectUrls = new Set();
    this._sequence = 0;
  }

  async load() {
    if (this.loaded) return this;
    const rawIndex = await this.storage.getItem(INDEX_KEY);
    if (rawIndex) {
      try {
        const parsed = JSON.parse(rawIndex);
        this.entries = Array.isArray(parsed.entries) ? parsed.entries : [];
        this.folders = new Set(['/', ...(Array.isArray(parsed.folders) ? parsed.folders : [])].map(normaliseFolder));
      } catch {
        // A corrupt index must not silently delete the files: surface it.
        this.indexError = 'The vault index could not be parsed. Files are still on disk; reset the index to recover them.';
        this.entries = [];
      }
    }
    const rawLock = await this.storage.getItem(LOCK_KEY);
    if (rawLock) {
      try { this.lockRecord = JSON.parse(rawLock); } catch { this.lockRecord = null; }
    }
    this.loaded = true;
    return this;
  }

  async _persist() {
    await this.storage.setItem(INDEX_KEY, JSON.stringify({
      version: 1,
      updatedAt: this.clock(),
      folders: [...this.folders],
      entries: this.entries
    }));
  }

  /* ---------------------------------------------------------------- */
  /* Lock                                                              */
  /* ---------------------------------------------------------------- */

  get locked() { return !!this.lockRecord; }
  get unlocked() { return !this.lockRecord || !!this.key; }

  /** Enables the passphrase lock. Files written afterwards are encrypted. */
  async setPassphrase(passphrase) {
    const value = String(passphrase || '');
    if (value.length < 8) throw new Error('Use at least 8 characters for the vault passphrase.');
    if (!cryptoApi()) throw new Error('WebCrypto is unavailable in this context, so encryption cannot be enabled.');
    const salt = this.randomBytes(16);
    const key = await deriveKey(value, salt);
    const iv = this.randomBytes(12);
    const verifier = toHex(await cryptoApi().encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode('omnishield-vault')));
    // The verifier keeps its own IV: without it the passphrase check can never succeed.
    this.lockRecord = { salt: toHex(salt), verifier, verifierIv: toHex(iv), iterations: 210_000, createdAt: this.clock() };
    this.key = key;
    await this.storage.setItem(LOCK_KEY, JSON.stringify(this.lockRecord));
    return true;
  }

  /** Removes the lock. Encrypted files are decrypted in place first. */
  async removePassphrase(passphrase) {
    await this.unlock(passphrase);
    for (const entry of this.entries.filter((e) => e.encrypted)) {
      const blob = await this.read(entry.id);
      entry.encrypted = false;
      await this.storage.setItem(FILE_PREFIX + entry.id, blob.blob);
    }
    this.lockRecord = null;
    this.key = null;
    await this.storage.removeItem(LOCK_KEY);
    await this._persist();
    return true;
  }

  /** Verifies a passphrase against the stored verifier. Throws on a wrong one. */
  async unlock(passphrase) {
    if (!this.lockRecord) return true;
    const key = await deriveKey(String(passphrase || ''), fromHex(this.lockRecord.salt), this.lockRecord.iterations);
    try {
      await cryptoApi().decrypt(
        { name: 'AES-GCM', iv: fromHex(this.lockRecord.verifierIv || '000000000000000000000000') },
        key,
        fromHex(this.lockRecord.verifier)
      );
    } catch {
      // A wrong passphrase fails the AES-GCM tag check. That is the expected path.
      this.key = null;
      throw new Error('That passphrase does not match the vault lock.');
    }
    this.key = key;
    return true;
  }

  lock() { this.key = null; }

  async _encrypt(blob) {
    if (!this.lockRecord || !this.key) return { blob, iv: null };
    const iv = this.randomBytes(12);
    const cipher = await cryptoApi().encrypt({ name: 'AES-GCM', iv }, this.key, new Uint8Array(await blob.arrayBuffer()));
    return { blob: new Blob([cipher], { type: 'application/octet-stream' }), iv: toHex(iv) };
  }

  async _decrypt(blob, ivHex) {
    if (!ivHex) return blob;
    if (!this.key) throw new Error('The vault is locked. Unlock it to read this file.');
    const plain = await cryptoApi().decrypt({ name: 'AES-GCM', iv: fromHex(ivHex) }, this.key, new Uint8Array(await blob.arrayBuffer()));
    return new Blob([plain]);
  }

  /* ---------------------------------------------------------------- */
  /* Files                                                             */
  /* ---------------------------------------------------------------- */

  /**
   * Stores a File/Blob (or a string) in the vault.
   * @returns {Promise<object>} the stored entry
   */
  async put(input, options = {}) {
    await this.load();
    if (!this.unlocked && this.locked && !this.key) {
      throw new Error('The vault is locked. Unlock it before adding files.');
    }
    const isBlob = input instanceof Blob;
    const blob = isBlob ? input : new Blob([input ?? ''], { type: options.mime || 'text/plain' });
    // The localStorage fallback caps out around 5 MB in total and base64 adds
    // 33 %, so a large file there fails with an obscure quota error. Say so first.
    if (this.storage.binarySafe === false && blob.size > 2 * 1024 * 1024) {
      throw new Error(`This browser fell back to ${this.storage.name} (about 5 MB total, base64-encoded), so files above 2 MB cannot be stored. IndexedDB is required for larger files — check that storage is not blocked for this site.`);
    }
    if (blob.size > this.maxFileBytes) {
      throw new Error(`File is ${(blob.size / 1048576).toFixed(1)} MB; the per-file limit is ${this.maxFileBytes === MAX_FILE_BYTES ? MAX_FILE_LABEL : `${(this.maxFileBytes / 1048576).toFixed(0)} MB`}.`);
    }
    const name = String(options.name || (isBlob && input.name) || 'untitled').replace(/[/\\]/g, '_').slice(0, 180) || 'untitled';
    const mime = options.mime || blob.type || 'application/octet-stream';
    const id = `f${this.clock().toString(36)}${(this._sequence++).toString(36)}${Math.floor(Math.random() * 1e4).toString(36)}`;

    const buffer = new Uint8Array(await blob.arrayBuffer());
    const digest = sha256Hex(buffer);
    const { blob: encrypted, iv } = await this._encrypt(blob);
    const binarySafe = this.storage.binarySafe !== false;
    const stored = binarySafe ? encrypted : await encodeForStringBackend(encrypted);
    await this.storage.setItem(FILE_PREFIX + id, stored);
    if (iv) await this.storage.setItem(`${FILE_PREFIX}${id}:iv`, iv);

    // Verify the write: confirm the bytes came back before claiming success.
    const check = await this.storage.getItem(FILE_PREFIX + id);
    const written = binarySafe
      ? (check && typeof check.size === 'number' ? check.size : -1)
      : (typeof check === 'string' ? new TextDecoder().decode(new TextEncoder().encode(check)).length : -1);
    const expectedBytes = binarySafe ? encrypted.size : String(stored).length;
    if (written < 0 || (binarySafe && written !== expectedBytes)) {
      await this.storage.removeItem(FILE_PREFIX + id).catch(() => {});
      throw new Error('The file could not be verified after writing — storage may be full or unavailable.');
    }

    const folder = normaliseFolder(options.folder);
    this.folders.add(folder);
    const entry = {
      id, name, folder, kind: classify(options.kind, mime, name), mime,
      size: blob.size, sha256: digest, encrypted: !!iv,
      tags: Array.isArray(options.tags) ? options.tags.slice(0, 12) : [],
      source: options.source || 'upload',
      createdAt: this.clock(), updatedAt: this.clock()
    };
    this.entries.unshift(entry);
    await this._persist();
    return { ...entry };
  }

  list(filter = {}) {
    const query = String(filter.query || '').trim().toLowerCase();
    const folder = filter.folder && filter.folder !== '/' ? normaliseFolder(filter.folder) : null;
    return this.entries
      .filter((entry) => (folder ? entry.folder === folder : true))
      .filter((entry) => (filter.kind ? entry.kind === filter.kind : true))
      .filter((entry) => {
        if (!query) return true;
        return entry.name.toLowerCase().includes(query)
          || entry.kind.includes(query)
          || (entry.tags || []).some((tag) => String(tag).toLowerCase().includes(query));
      })
      .sort((a, b) => b.createdAt - a.createdAt);
  }

  get(id) { return this.entries.find((entry) => entry.id === id) || null; }

  foldersList() {
    const counts = new Map([...this.folders].map((folder) => [folder, 0]));
    for (const entry of this.entries) counts.set(entry.folder, (counts.get(entry.folder) || 0) + 1);
    return [...counts.entries()]
      .sort((a, b) => (a[0] === '/' ? -1 : b[0] === '/' ? 1 : a[0].localeCompare(b[0])))
      .map(([path, count]) => ({ path, count }));
  }

  async createFolder(path) {
    const folder = normaliseFolder(path);
    if (folder === '/') return '/';
    if (this.folders.size >= MAX_FOLDERS) throw new Error(`The vault supports at most ${MAX_FOLDERS} folders.`);
    this.folders.add(folder);
    await this._persist();
    return folder;
  }

  /** Reads a stored file back. Throws a clear error when locked or missing. */
  async read(id) {
    const entry = this.get(id);
    if (!entry) throw new Error('That file is not in the vault.');
    const raw = await this.storage.getItem(FILE_PREFIX + id);
    if (!raw) throw new Error('The stored bytes are missing — the index and storage disagree.');
    const stored = this.storage.binarySafe !== false ? raw : decodeFromStringBackend(raw);
    const iv = entry.encrypted ? await this.storage.getItem(`${FILE_PREFIX}${id}:iv`) : null;
    const blob = await this._decrypt(stored, iv);
    return { entry: { ...entry }, blob: blob.type ? blob : new Blob([blob], { type: entry.mime }) };
  }

  /**
   * URL for previews; revoke with `releaseUrl`.
   *
   * `URL.createObjectURL` is the browser path. Where it is missing (older
   * engines, some embeds, jsdom) the bytes are inlined as a data URL instead of
   * failing the preview — the image still renders from the stored file.
   */
  async urlFor(id) {
    const { blob, entry } = await this.read(id);
    const typed = blob.type ? blob : new Blob([blob], { type: entry.mime });
    if (typeof URL !== 'undefined' && typeof URL.createObjectURL === 'function') {
      const url = URL.createObjectURL(typed);
      this.objectUrls.add(url);
      return url;
    }
    const encoded = await encodeForStringBackend(typed);
    const [, type, base64] = /^b64:([^:]*):([\s\S]*)$/.exec(encoded) || [];
    return `data:${type || entry.mime};base64,${base64 || ''}`;
  }

  releaseUrl(url) {
    if (!url) return;
    try { URL.revokeObjectURL(url); } catch { /* already gone */ }
    this.objectUrls.delete(url);
  }

  releaseAll() {
    for (const url of [...this.objectUrls]) this.releaseUrl(url);
  }

  async remove(id) {
    const index = this.entries.findIndex((entry) => entry.id === id);
    if (index < 0) return false;
    await this.storage.removeItem(FILE_PREFIX + id);
    await this.storage.removeItem(`${FILE_PREFIX}${id}:iv`).catch(() => {});
    this.entries.splice(index, 1);
    await this._persist();
    return true;
  }

  async rename(id, name) {
    const entry = this.get(id);
    if (!entry) throw new Error('That file is not in the vault.');
    const clean = String(name || '').replace(/[/\\]/g, '_').trim().slice(0, 180);
    if (!clean) throw new Error('A file name is required.');
    entry.name = clean;
    entry.updatedAt = this.clock();
    await this._persist();
    return { ...entry };
  }

  async move(id, folder) {
    const entry = this.get(id);
    if (!entry) throw new Error('That file is not in the vault.');
    const target = normaliseFolder(folder);
    this.folders.add(target);
    entry.folder = target;
    entry.updatedAt = this.clock();
    await this._persist();
    return { ...entry };
  }

  async tag(id, tags) {
    const entry = this.get(id);
    if (!entry) throw new Error('That file is not in the vault.');
    entry.tags = [...new Set((tags || []).map((t) => String(t).trim()).filter(Boolean))].slice(0, 12);
    entry.updatedAt = this.clock();
    await this._persist();
    return { ...entry };
  }

  /** Recomputes SHA-256 of stored bytes and compares with the index. */
  async verify(id) {
    const entry = this.get(id);
    if (!entry) return { ok: false, error: 'not in the vault' };
    try {
      const { blob } = await this.read(id);
      if (entry.encrypted) return { ok: true, id, note: 'encrypted — verified by successful AES-GCM tag check', checkedAt: this.clock() };
      const digest = sha256Hex(new Uint8Array(await blob.arrayBuffer()));
      return digest === entry.sha256
        ? { ok: true, id, note: 'digest matches', checkedAt: this.clock() }
        : { ok: false, id, error: 'digest mismatch — the stored bytes changed', expected: entry.sha256, actual: digest, checkedAt: this.clock() };
    } catch (error) {
      return { ok: false, id, error: String(error?.message || error), checkedAt: this.clock() };
    }
  }

  /** Total bytes and browser quota, when the browser reports it. */
  async usage() {
    await this.load();
    const bytes = this.entries.reduce((sum, entry) => sum + (entry.size || 0), 0);
    const estimate = await IndexedDbAdapter.estimate();
    return {
      files: this.entries.length,
      bytes,
      byKind: this.entries.reduce((acc, entry) => { acc[entry.kind] = (acc[entry.kind] || 0) + entry.size; return acc; }, {}),
      estimate,
      locked: this.locked,
      unlocked: this.unlocked
    };
  }

  /** Manifest for export (metadata only — no bytes leave the device). */
  manifest() {
    return {
      exportedAt: new Date(this.clock()).toISOString(),
      files: this.entries.length,
      bytes: this.entries.reduce((sum, entry) => sum + (entry.size || 0), 0),
      entries: this.entries.map((entry) => ({ ...entry }))
    };
  }

  /** Deletes every file and the index. Reports how many files were removed. */
  async destroy() {
    const ids = this.entries.map((entry) => entry.id);
    for (const id of ids) await this.storage.removeItem(FILE_PREFIX + id).catch(() => {});
    this.entries = [];
    this.folders = new Set(['/']);
    await this.storage.removeItem(INDEX_KEY).catch(() => {});
    this.releaseAll();
    return { removed: ids.length };
  }
}

/**
 * File sink used by the download queue.
 *
 * A registered default vault receives the completed file; without one the bytes
 * stay in memory so the transfer can still be measured (and the caller is told
 * the result was not persisted).
 */
let defaultSinkVault = null;
export function setDefaultSinkVault(vault) { defaultSinkVault = vault; }
export function getDefaultSinkVault() { return defaultSinkVault; }

export function createFileSink({ name = 'download', resumeFrom = 0, folder = '/', kind = null } = {}) {
  const chunks = [];
  if (resumeFrom > 0 && defaultSinkVault) {
    const existing = defaultSinkVault.list().find((entry) => entry.name === name);
    if (existing) {
      // Resuming an interrupted transfer appends to a fresh file; the queue's
      // retry path re-downloads from the saved offset, so start cleanly.
      void existing;
    }
  }
  let closed = false;
  const sink = {
    path: name,
    persisted: !!defaultSinkVault,
    async write(chunk) {
      if (closed) throw new Error('sink already closed');
      chunks.push(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));
    },
    async close() {
      if (closed) return null;
      closed = true;
      const blob = new Blob(chunks, { type: guessMime(name) });
      sink.blob = blob;
      if (defaultSinkVault) {
        sink.entry = await defaultSinkVault.put(blob, { name, folder, kind, source: 'downloader' });
      }
      return sink.entry || null;
    },
    async digest() {
      const blob = sink.blob || new Blob(chunks);
      return sha256Hex(new Uint8Array(await blob.arrayBuffer()));
    },
    async abort() { closed = true; chunks.length = 0; }
  };
  return sink;
}

export function guessMime(name) {
  const ext = String(name).toLowerCase().split('.').pop();
  const map = {
    mp4: 'video/mp4', webm: 'video/webm', mkv: 'video/x-matroska', mov: 'video/quicktime',
    mp3: 'audio/mpeg', m4a: 'audio/mp4', aac: 'audio/aac', ogg: 'audio/ogg', opus: 'audio/opus', wav: 'audio/wav', flac: 'audio/flac',
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', svg: 'image/svg+xml',
    pdf: 'application/pdf', json: 'application/json', txt: 'text/plain', md: 'text/markdown', csv: 'text/csv', html: 'text/html',
    zip: 'application/zip', gz: 'application/gzip'
  };
  return map[ext] || 'application/octet-stream';
}

export default { FileVault, createFileSink, classify, kindLabel, guessMime };
