/**
 * Private storage box — the on-device vault.
 *
 * These tests exercise real bytes: a FileVault over the in-memory adapter writes
 * and reads back Blobs, verifies SHA-256 digests, survives a corrupt index, and
 * proves the AES-GCM lock actually encrypts (the stored ciphertext must not
 * contain the plaintext, and a wrong passphrase must fail).
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { webcrypto } from 'node:crypto';
import { FileVault, classify, kindLabel, guessMime, createFileSink, setDefaultSinkVault } from '../../security/vault.js';
import { MemoryStorage } from '../../security/storage.js';
import { sha256Hex } from '../../security/sha256.js';

if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;

const vaultOf = (options = {}) => new FileVault({ storage: new MemoryStorage(), clock: () => 1_700_000_000_000, ...options });

test('stores a real file and reads back identical bytes with a matching digest', async () => {
  const vault = vaultOf();
  await vault.load();
  const bytes = new TextEncoder().encode('invoice #42 — hello vault');
  const entry = await vault.put(new File([bytes], 'invoice.txt', { type: 'text/plain' }), { folder: '/Finance/2026' });

  assert.equal(entry.name, 'invoice.txt');
  assert.equal(entry.size, bytes.length);
  assert.equal(entry.folder, '/Finance/2026');
  assert.equal(entry.kind, 'document');
  assert.equal(entry.sha256, sha256Hex(bytes));
  assert.equal(entry.encrypted, false);

  const { blob, entry: read } = await vault.read(entry.id);
  const round = new Uint8Array(await blob.arrayBuffer());
  assert.deepEqual([...round], [...bytes]);
  assert.equal(read.name, 'invoice.txt');

  const check = await vault.verify(entry.id);
  assert.equal(check.ok, true);
  assert.equal(check.note, 'digest matches');
});

test('classifies images, video, audio and archives by MIME then extension', async () => {
  assert.equal(classify(null, 'image/png', 'shot.png'), 'image');
  assert.equal(classify(null, '', 'clip.mp4'), 'video');
  assert.equal(classify(null, 'audio/mpeg', 'song'), 'audio');
  assert.equal(classify(null, '', 'backup.zip'), 'archive');
  assert.equal(classify(null, 'application/octet-stream', 'mystery.bin'), 'other');
  assert.equal(kindLabel('image'), 'Photos');
});

test('folders, rename, move and search are real state changes', async () => {
  const vault = vaultOf();
  await vault.load();
  await vault.createFolder('/Photos/2026');
  const a = await vault.put(new Blob(['a']), { name: 'a.png', mime: 'image/png', folder: '/Photos/2026' });
  const b = await vault.put(new Blob(['b']), { name: 'notes.md', mime: 'text/markdown' });

  await vault.rename(a.id, 'holiday.png');
  await vault.move(b.id, '/Photos/2026');
  await vault.tag(a.id, ['family', 'family', 'summer']);

  assert.equal(vault.get(a.id).name, 'holiday.png');
  assert.deepEqual(vault.get(a.id).tags, ['family', 'summer']);
  assert.equal(vault.list({ folder: '/Photos/2026' }).length, 2);
  assert.equal(vault.list({ query: 'holiday' }).length, 1);
  assert.equal(vault.list({ kind: 'image' }).length, 1);
  assert.equal(vault.foldersList().find((f) => f.path === '/Photos/2026').count, 2);

  const removed = await vault.remove(b.id);
  assert.equal(removed, true);
  assert.equal(vault.get(b.id), null);
});

test('refuses a file above the per-file limit instead of writing it', async () => {
  const vault = vaultOf({ maxFileBytes: 16 });
  await vault.load();
  await assert.rejects(
    () => vault.put(new Blob([new Uint8Array(64)]), { name: 'big.bin' }),
    /per-file limit/
  );
  assert.equal(vault.list().length, 0);
});

test('reports a storage write failure instead of claiming success', async () => {
  const storage = new MemoryStorage();
  const vault = new FileVault({ storage, clock: () => 1 });
  await vault.load();
  storage.failNext = 'write';
  await assert.rejects(() => vault.put(new Blob(['x']), { name: 'x.txt' }), /QuotaExceeded|verified/);
  assert.equal(vault.list().length, 0);
});

test('passphrase lock encrypts new files and rejects the wrong passphrase', async () => {
  const storage = new MemoryStorage();
  const vault = new FileVault({ storage, clock: () => 1 });
  await vault.load();
  await vault.setPassphrase('correct horse battery');
  assert.equal(vault.locked, true);
  assert.equal(vault.unlocked, true);

  const secret = 'TOP-SECRET-MARKER-42';
  const entry = await vault.put(new Blob([secret], { type: 'text/plain' }), { name: 'secret.txt' });
  assert.equal(entry.encrypted, true);

  const rawStored = await storage.getItem(`vault:file:${entry.id}`);
  assert.ok(rawStored instanceof Blob);
  const cipherText = new TextDecoder('latin1').decode(new Uint8Array(await rawStored.arrayBuffer()));
  assert.equal(cipherText.includes(secret), false, 'ciphertext must not contain the plaintext');

  vault.lock();
  assert.equal(vault.unlocked, false);
  await assert.rejects(() => vault.read(entry.id), /locked/);
  await assert.rejects(() => vault.unlock('wrong passphrase'), /does not match/);

  await vault.unlock('correct horse battery');
  const { blob } = await vault.read(entry.id);
  assert.equal(await blob.text(), secret);

  const verified = await vault.verify(entry.id);
  assert.equal(verified.ok, true);
  assert.match(verified.note, /AES-GCM/);
});

test('a corrupt index is reported, not silently treated as an empty vault', async () => {
  const storage = new MemoryStorage();
  await storage.setItem('vault:index', '{not json');
  const vault = new FileVault({ storage, clock: () => 1 });
  await vault.load();
  assert.match(vault.indexError, /could not be parsed/);
  assert.equal(vault.list().length, 0);
});

test('download sink stores the finished file and returns its digest', async () => {
  const vault = vaultOf();
  await vault.load();
  setDefaultSinkVault(vault);
  try {
    const sink = createFileSink({ name: 'clip.mp4' });
    await sink.write(new Uint8Array([1, 2, 3]));
    await sink.write(new Uint8Array([4, 5]));
    const entry = await sink.close();
    assert.ok(entry, 'the sink must persist through the default vault');
    assert.equal(entry.size, 5);
    assert.equal(entry.kind, 'video');
    assert.match(await sink.digest(), /^[0-9a-f]{64}$/);
    assert.equal(guessMime('clip.mp4'), 'video/mp4');
  } finally {
    setDefaultSinkVault(null);
  }
});

test('usage report totals bytes per kind and states the lock state', async () => {
  const vault = vaultOf();
  await vault.load();
  await vault.put(new Blob([new Uint8Array(10)]), { name: 'a.png', mime: 'image/png' });
  await vault.put(new Blob([new Uint8Array(30)]), { name: 'b.mp4', mime: 'video/mp4' });
  const usage = await vault.usage();
  assert.equal(usage.files, 2);
  assert.equal(usage.bytes, 40);
  assert.equal(usage.byKind.image, 10);
  assert.equal(usage.byKind.video, 30);
  assert.equal(usage.locked, false);
});

test('destroy removes every file and the index', async () => {
  const storage = new MemoryStorage();
  const vault = new FileVault({ storage, clock: () => 1 });
  await vault.load();
  await vault.put(new Blob(['1']), { name: '1.txt' });
  await vault.put(new Blob(['2']), { name: '2.txt' });
  const result = await vault.destroy();
  assert.equal(result.removed, 2);
  assert.equal((await storage.keys()).length, 0);
  assert.equal(vault.list().length, 0);
});

test('a string-only backend gets base64, so binaries survive the localStorage fallback', async () => {
  // A backend that behaves like localStorage: every value becomes a string.
  class StringStorage extends MemoryStorage {
    get binarySafe() { return false; }
    async setItem(key, value) { this.map.set(key, String(value)); }
  }
  const storage = new StringStorage();
  const vault = new FileVault({ storage, clock: () => 1 });
  await vault.load();
  const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0x10]);
  const entry = await vault.put(new File([bytes], 'icon.png', { type: 'image/png' }), { folder: '/' });
  const raw = await storage.getItem(`vault:file:${entry.id}`);
  assert.equal(typeof raw, 'string');
  assert.match(raw, /^b64:image\/png:/);
  const { blob } = await vault.read(entry.id);
  assert.deepEqual([...new Uint8Array(await blob.arrayBuffer())], [...bytes]);
});
