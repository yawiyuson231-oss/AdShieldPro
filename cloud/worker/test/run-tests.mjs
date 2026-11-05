#!/usr/bin/env node
/**
 * CyberShield Cloud — real end-to-end integration tests.
 *
 * These are NOT mocks. The script:
 *   1. applies the D1 migrations to a local SQLite D1 database
 *   2. boots the actual worker with `wrangler dev --local` (real workerd runtime,
 *      real R2 emulation backed by miniflare, real D1)
 *   3. drives the public HTTP API exactly like the Android client does
 *
 * Run: npm test        (or: node test/run-tests.mjs --keep for logs only)
 */
import { spawn, spawnSync } from 'node:child_process';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.TEST_PORT ?? 8787 + Math.floor(Math.random() * 500));
const BASE = `http://127.0.0.1:${PORT}`;
const JWT_SECRET = 'test-jwt-secret-0123456789abcdef0123456789abcdef';
const SERVER_SECRET = 'test-server-secret-0123456789abcdef0123456789';
const SUPABASE_ANON_KEY = 'test-anon-key';
const LOG_FILE = join(ROOT, 'test', 'worker-dev.log');

const env = {
  ENVIRONMENT: 'test',
  STORAGE_PROVIDER: 'r2',
  DEFAULT_QUOTA_BYTES: String(64 * 1024 * 1024),
  GLOBAL_SAFETY_CAP_BYTES: String(1024 * 1024 * 1024),
  MAX_SINGLE_UPLOAD_BYTES: String(100 * 1024 * 1024),
  PART_SIZE_BYTES: String(5 * 1024 * 1024),
  SIGNED_URL_TTL_SECONDS: '300',
  TRASH_RETENTION_DAYS: '30',
  DAILY_REQUEST_BUDGET: '100000',
  RATE_LIMIT_GENERAL_PER_MINUTE: '5000',
  ALLOWED_ORIGINS: '*',
  SERVER_SECRET,
  SUPABASE_URL: 'https://local-test.supabase.co',
  SUPABASE_ANON_KEY,
  SUPABASE_JWT_SECRET: JWT_SECRET,
};

// ---------------------------------------------------------------------------
// tiny test harness
// ---------------------------------------------------------------------------
const results = [];
let currentSuite = 'general';

function suite(name) {
  currentSuite = name;
  console.log(`\n\x1b[1m▸ ${name}\x1b[0m`);
}

async function test(name, fn) {
  const started = Date.now();
  try {
    await fn();
    results.push({ suite: currentSuite, name, ok: true, ms: Date.now() - started });
    console.log(`  \x1b[32m✓\x1b[0m ${name} \x1b[90m(${Date.now() - started}ms)\x1b[0m`);
  } catch (error) {
    results.push({ suite: currentSuite, name, ok: false, error: error?.message ?? String(error), ms: Date.now() - started });
    console.log(`  \x1b[31m✗ ${name}\x1b[0m\n      ${error?.message ?? error}`);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message ?? 'assertion failed');
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) throw new Error(`${message ?? 'values differ'} (expected ${expected}, got ${actual})`);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
function b64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function mintJwt(sub, email, { secret = JWT_SECRET, ttlSeconds = 3600, alg = 'HS256' } = {}) {
  const header = b64url(JSON.stringify({ alg, typ: 'JWT' }));
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(
    JSON.stringify({
      sub,
      email,
      role: 'authenticated',
      aud: 'authenticated',
      iat: now,
      exp: now + ttlSeconds,
      user_metadata: { display_name: email.split('@')[0] },
    })
  );
  const signature = createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${header}.${payload}.${signature}`;
}

function sha256Hex(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

function randomBuffer(bytes) {
  return randomBytes(bytes);
}

class ApiClient {
  constructor(label) {
    this.label = label;
    this.token = null;
  }

  async request(method, path, { body, headers = {}, token = this.token, raw = false, redirect = 'follow' } = {}) {
    const url = path.startsWith('http') ? path : `${BASE}${path}`;
    const init = { method, headers: { ...headers }, redirect };
    if (token) init.headers.Authorization = `Bearer ${token}`;
    if (body !== undefined && !(body instanceof Buffer) && typeof body !== 'string') {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    } else if (body instanceof Buffer) {
      init.body = body;
    } else if (typeof body === 'string') {
      init.body = body;
    }
    const response = await fetch(url, init);
    if (raw) return response;
    const text = await response.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = { raw: text };
    }
    return { status: response.status, headers: response.headers, json, text };
  }

  get(path, options) { return this.request('GET', path, options); }
  post(path, body, options) { return this.request('POST', path, { body, ...options }); }
  put(path, body, options) { return this.request('PUT', path, { body, ...options }); }
  del(path, options) { return this.request('DELETE', path, options); }
}

/** Full upload flow exactly as the Android upload engine performs it. */
async function uploadFile(client, { name, data, parentId = null, mime = 'application/octet-stream', sha256 = true, dedupeMode } = {}) {
  const hash = sha256 ? sha256Hex(data) : undefined;
  const init = await client.post('/v1/uploads', {
    name,
    size: data.byteLength,
    parentId,
    mime,
    sha256: hash,
    dedupeMode,
  });
  assertEqual(init.status, 201, `upload init failed: ${JSON.stringify(init.json)}`);
  if (init.json.duplicate) return { init: init.json, completed: null };

  const { uploadId, mode, partSize, partsTotal, uploadToken } = init.json;
  if (mode === 'single') {
    const res = await client.put(`/v1/upload/${uploadId}/content?token=${encodeURIComponent(uploadToken)}`, data, {
      headers: { 'Content-Type': mime },
      token: null,
    });
    assertEqual(res.status, 200, `single upload body failed: ${res.text}`);
  } else {
    for (let partNumber = 1; partNumber <= partsTotal; partNumber += 1) {
      const start = (partNumber - 1) * partSize;
      const chunk = data.subarray(start, Math.min(start + partSize, data.byteLength));
      const res = await client.put(`/v1/upload/${uploadId}/parts/${partNumber}?token=${encodeURIComponent(uploadToken)}`, Buffer.from(chunk), {
        headers: { 'Content-Type': 'application/octet-stream' },
        token: null,
      });
      assertEqual(res.status, 200, `part ${partNumber} failed: ${res.text}`);
    }
  }
  const completed = await client.post(`/v1/uploads/${uploadId}/complete`, {});
  assertEqual(completed.status, 200, `complete failed: ${completed.text}`);
  return { init: init.json, completed: completed.json };
}

async function downloadNode(client, nodeId, { range } = {}) {
  const issued = await client.get(`/v1/files/${nodeId}/download`);
  assertEqual(issued.status, 200, `download issue failed: ${issued.text}`);
  const headers = range ? { Range: range } : {};
  const response = await client.get(issued.json.url, { token: null, raw: true, headers });
  const buffer = Buffer.from(await response.arrayBuffer());
  return { response, buffer, issued: issued.json };
}

function d1(sql) {
  const args = ['wrangler', 'd1', 'execute', 'adshield_cloud', '--local', '--command', sql, '--json'];
  const result = spawnSync('npx', args, { cwd: ROOT, encoding: 'utf8', env: { ...process.env } });
  if (result.status !== 0) throw new Error(`d1 execute failed: ${result.stderr || result.stdout}`);
  return result.stdout;
}

function applyMigrations() {
  const result = spawnSync('npx', ['wrangler', 'd1', 'migrations', 'apply', 'adshield_cloud', '--local'], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env },
  });
  if (result.status !== 0) throw new Error(`migrations failed: ${result.stderr || result.stdout}`);
  return result.stdout;
}

async function waitForWorker(timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${BASE}/health`);
      if (response.ok || response.status === 503) return true;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error('worker did not start in time');
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
async function main() {
  console.log('\x1b[1m\x1b[36mCyberShield Cloud — integration test suite\x1b[0m');
  console.log(`runtime: workerd (wrangler dev --local), storage: R2 emulation, db: local D1\n`);

  const stateDir = join(ROOT, '.wrangler');
  if (existsSync(stateDir) && process.env.TEST_RESET !== 'false') {
    rmSync(stateDir, { recursive: true, force: true });
  }

  // .dev.vars holds local-only test secrets; it is gitignored.
  const devVars = Object.entries(env).map(([key, value]) => `${key}=${value}`).join('\n');
  writeFileSync(join(ROOT, '.dev.vars'), `${devVars}\n`);

  console.log('applying D1 migrations…');
  applyMigrations();
  console.log('starting worker…');

  const logChunks = [];
  const child = spawn('npx', ['wrangler', 'dev', '--port', String(PORT), '--local', '--ip', '127.0.0.1'], {
    cwd: ROOT,
    env: { ...process.env, WRANGLER_SEND_METRICS: 'false', CI: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  });
  child.stdout.on('data', (chunk) => logChunks.push(chunk.toString()));
  child.stderr.on('data', (chunk) => logChunks.push(chunk.toString()));

  let exitCode = 0;
  try {
    await waitForWorker();

    const owner = new ApiClient('owner');
    const other = new ApiClient('other');
    owner.token = mintJwt('user-owner-0001', 'owner@adshield.test');
    other.token = mintJwt('user-other-0002', 'other@adshield.test');

    // =====================================================================
    suite('Service health & metadata');
    await test('health reports a working deployment', async () => {
      const res = await owner.get('/health');
      assertEqual(res.status, 200, `health returned ${res.status}: ${res.text}`);
      assertEqual(res.json.status, 'ok');
      assertEqual(res.json.database, 'connected');
      assertEqual(res.json.storage, 'connected');
      assertEqual(res.json.configurationProblems.length, 0);
      assertEqual(res.json.freeTier.paidFeaturesEnabled, false);
    });
    await test('meta exposes real limits (no fake capacity)', async () => {
      const res = await owner.get('/v1/meta');
      assertEqual(res.status, 200);
      assertEqual(res.json.defaultQuotaBytes, 64 * 1024 * 1024);
      assertEqual(res.json.partSizeBytes, 5 * 1024 * 1024);
      assertEqual(res.json.paidFeaturesEnabled, false);
    });
    await test('unauthenticated request is rejected', async () => {
      const res = await owner.get('/v1/account', { token: null });
      assertEqual(res.status, 401);
      assertEqual(res.json.error.code, 'unauthorized');
    });
    await test('forged signature is rejected', async () => {
      const forged = mintJwt('attacker', 'attacker@adshield.test', { secret: 'wrong-secret-wrong-secret-wrong!' });
      const res = await owner.get('/v1/account', { token: forged });
      assertEqual(res.status, 401);
      assertEqual(res.json.error.code, 'invalid_token_signature');
    });
    await test('expired access token is rejected', async () => {
      const expired = mintJwt('user-owner-0001', 'owner@adshield.test', { ttlSeconds: -600 });
      const res = await owner.get('/v1/account', { token: expired });
      assertEqual(res.status, 401);
      assertEqual(res.json.error.code, 'token_expired');
    });

    // =====================================================================
    suite('Account, quota & free-tier guardrails');
    let firstNodeId = null;
    await test('account provisions a real profile with a zeroed quota', async () => {
      const res = await owner.get('/v1/account');
      assertEqual(res.status, 200);
      assertEqual(res.json.user.id, 'user-owner-0001');
      assertEqual(res.json.quota.usedBytes, 0);
      assertEqual(res.json.quota.quotaBytes, 64 * 1024 * 1024);
      assertEqual(res.json.quota.providerFreeBytes, 10 * 1024 * 1024 * 1024);
      assertEqual(res.json.dailyUsage.requestBudget, 100000);
      assertEqual(res.json.dailyUsage.requests >= 0, true);
      await owner.get('/v1/usage');
      const second = await owner.get('/v1/account');
      assert(second.json.dailyUsage.requests >= 1, 'request counter increments between calls');
    });

    // =====================================================================
    suite('Single-shot upload & download');
    const smallBytes = Buffer.from('CyberShield AI integration test payload — DNS blocklist backup '.repeat(40));
    let smallHash = sha256Hex(smallBytes);
    await test('upload a document through init → PUT → complete', async () => {
      const result = await uploadFile(owner, { name: 'notes.txt', data: smallBytes, mime: 'text/plain' });
      assertEqual(result.init.mode, 'single', 'small files must use single-shot mode');
      assertEqual(result.completed.status, 'completed');
      assertEqual(result.completed.size, smallBytes.byteLength);
      assertEqual(result.completed.sha256, smallHash);
      assertEqual(result.completed.sha256Verified, true, 'server must verify the SHA-256 for small files');
      assertEqual(result.completed.scan.verdict, 'clean');
      firstNodeId = result.completed.nodeId;
      assert(firstNodeId, 'node id returned');
    });
    await test('file appears in the folder listing with correct metadata', async () => {
      const res = await owner.get('/v1/files?parentId=root');
      assertEqual(res.status, 200);
      const node = res.json.items.find((item) => item.id === firstNodeId);
      assert(node, 'uploaded node is listed');
      assertEqual(node.name, 'notes.txt');
      assertEqual(node.size, smallBytes.byteLength);
      assertEqual(node.sha256, smallHash);
      assertEqual(node.status, 'active');
      assertEqual(node.encrypted, false);
    });
    await test('quota reflects the uploaded bytes exactly', async () => {
      const res = await owner.get('/v1/account');
      assertEqual(res.json.quota.usedBytes, smallBytes.byteLength);
      assertEqual(res.json.quota.remainingBytes, 64 * 1024 * 1024 - smallBytes.byteLength);
    });
    await test('download returns byte-identical content and a matching hash', async () => {
      const { response, buffer, issued } = await downloadNode(owner, firstNodeId);
      assertEqual(response.status, 200);
      assertEqual(issued.size, smallBytes.byteLength);
      assertEqual(sha256Hex(buffer), smallHash, 'downloaded bytes must hash to the recorded value');
      assert(buffer.equals(smallBytes), 'downloaded bytes identical');
      assertEqual(response.headers.get('cache-control'), 'private, no-store');
      assertEqual(response.headers.get('x-content-type-options'), 'nosniff');
    });
    await test('HTTP Range request returns 206 with the requested slice', async () => {
      const { response, buffer } = await downloadNode(owner, firstNodeId, { range: 'bytes=0-99' });
      assertEqual(response.status, 206);
      assertEqual(buffer.byteLength, 100);
      assertEqual(buffer.toString(), smallBytes.subarray(0, 100).toString());
      assertEqual(response.headers.get('content-range'), `bytes 0-99/${smallBytes.byteLength}`);
    });
    await test('server-side integrity verification re-derives the same SHA-256', async () => {
      const res = await owner.post(`/v1/files/${firstNodeId}/verify`, {});
      assertEqual(res.status, 200);
      assertEqual(res.json.matches, true);
      assertEqual(res.json.computedSha256, smallHash);
    });
    await test('preview URL is issued for previewable types', async () => {
      const res = await owner.get(`/v1/files/${firstNodeId}/preview`);
      assertEqual(res.status, 200);
      const fetched = await owner.get(res.json.url, { token: null, raw: true });
      assertEqual(fetched.status, 200);
      assertEqual(fetched.headers.get('content-disposition'), 'inline');
    });

    // =====================================================================
    suite('Signed URL security');
    await test('tampered signed URL signature is refused', async () => {
      const issued = await owner.get(`/v1/files/${firstNodeId}/download`);
      const url = new URL(issued.json.url);
      const token = url.pathname.replace(/^\/d\//, '');
      const [body, signature] = token.split('.');
      const flipped = signature.slice(0, -2) + (signature.slice(-2) === 'AA' ? 'BB' : 'AA');
      const res = await owner.get(`/d/${body}.${flipped}`, { token: null });
      assertEqual(res.status, 401);
      assertEqual(res.json.error.code, 'invalid_token_signature');
    });
    await test('expired signed URL returns 410 Gone', async () => {
      const payload = {
        p: 'download',
        sub: 'user-owner-0001',
        iat: Math.floor(Date.now() / 1000) - 7200,
        exp: Math.floor(Date.now() / 1000) - 3600,
        jti: 'expired-test',
        nodeId: firstNodeId,
        storageKey: 'u/ignored/key.bin',
      };
      const ordered = JSON.stringify({
        p: payload.p, sub: payload.sub, iat: payload.iat, exp: payload.exp, jti: payload.jti,
        nodeId: payload.nodeId, storageKey: payload.storageKey,
      });
      const body = b64url(ordered);
      const sig = createHmac('sha256', SERVER_SECRET).update(body).digest('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const res = await owner.get(`/d/${body}.${sig}`, { token: null });
      assertEqual(res.status, 410);
      assertEqual(res.json.error.code, 'token_expired');
    });
    await test('another account cannot download someone else’s file', async () => {
      const res = await other.get(`/v1/files/${firstNodeId}/download`);
      assertEqual(res.status, 404);
      const meta = await other.get(`/v1/files/${firstNodeId}`);
      assertEqual(meta.status, 404);
    });
    await test('upload token is bound to its upload session', async () => {
      const init = await owner.post('/v1/uploads', { name: 'bound.txt', size: 8, mime: 'text/plain' });
      const otherInit = await other.post('/v1/uploads', { name: 'bound2.txt', size: 8, mime: 'text/plain' });
      const res = await owner.put(`/v1/upload/${otherInit.json.uploadId}/content?token=${encodeURIComponent(init.json.uploadToken)}`, Buffer.from('12345678'), {
        token: null,
        headers: { 'Content-Type': 'text/plain' },
      });
      assertEqual(res.status, 403);
      assertEqual(res.json.error.code, 'upload_token_mismatch');
      await owner.post(`/v1/uploads/${init.json.uploadId}/abort`, {});
      await other.post(`/v1/uploads/${otherInit.json.uploadId}/abort`, {});
    });
    await test('missing upload token is refused', async () => {
      const init = await owner.post('/v1/uploads', { name: 'notoken.txt', size: 4, mime: 'text/plain' });
      const res = await owner.put(`/v1/upload/${init.json.uploadId}/content`, Buffer.from('abcd'), { token: null });
      assertEqual(res.status, 401);
      assertEqual(res.json.error.code, 'upload_token_missing');
      await owner.post(`/v1/uploads/${init.json.uploadId}/abort`, {});
    });

    // =====================================================================
    suite('Multipart upload, pause/resume, abort');
    let bigNodeId = null;
    const bigBytes = randomBuffer(12 * 1024 * 1024 + 777);
    const bigHash = sha256Hex(bigBytes);
    await test('12 MB upload uses multipart with 5 MB parts', async () => {
      const init = await owner.post('/v1/uploads', {
        name: 'video-clip.mp4',
        size: bigBytes.byteLength,
        mime: 'video/mp4',
        sha256: bigHash,
      });
      assertEqual(init.status, 201);
      assertEqual(init.json.mode, 'multipart');
      assertEqual(init.json.partSize, 5 * 1024 * 1024);
      assertEqual(init.json.partsTotal, 3);

      // pause after the first two parts, then query resume state
      for (let partNumber = 1; partNumber <= 2; partNumber += 1) {
        const start = (partNumber - 1) * init.json.partSize;
        const chunk = bigBytes.subarray(start, start + init.json.partSize);
        const res = await owner.put(
          `/v1/upload/${init.json.uploadId}/parts/${partNumber}?token=${encodeURIComponent(init.json.uploadToken)}`,
          Buffer.from(chunk),
          { token: null, headers: { 'Content-Type': 'application/octet-stream' } }
        );
        assertEqual(res.status, 200, res.text);
        assertEqual(res.json.partsDone, partNumber);
      }
      const resume = await owner.get(`/v1/uploads/${init.json.uploadId}`);
      assertEqual(resume.status, 200);
      assertEqual(resume.json.acceptedParts.length, 2);
      assertEqual(JSON.stringify(resume.json.missingParts), JSON.stringify([3]));
      assert(resume.json.uploadToken, 'resume endpoint re-issues a token');

      // resuming mid-flight must not be completable yet
      const premature = await owner.post(`/v1/uploads/${init.json.uploadId}/complete`, {});
      assertEqual(premature.status, 409);
      assertEqual(premature.json.error.code, 'upload_incomplete');

      const start = 2 * init.json.partSize;
      const last = bigBytes.subarray(start);
      const res = await owner.put(
        `/v1/upload/${init.json.uploadId}/parts/3?token=${encodeURIComponent(resume.json.uploadToken)}`,
        Buffer.from(last),
        { token: null, headers: { 'Content-Type': 'application/octet-stream' } }
      );
      assertEqual(res.status, 200, res.text);

      const completed = await owner.post(`/v1/uploads/${init.json.uploadId}/complete`, {});
      assertEqual(completed.status, 200, completed.text);
      assertEqual(completed.json.size, bigBytes.byteLength);
      assertEqual(completed.json.sha256, bigHash);
      bigNodeId = completed.json.nodeId;
    });
    await test('multipart object downloads byte-identically', async () => {
      const issued = await owner.get(`/v1/files/${bigNodeId}/download`);
      const response = await owner.get(issued.json.url, { token: null, raw: true });
      const buffer = Buffer.from(await response.arrayBuffer());
      assertEqual(buffer.byteLength, bigBytes.byteLength);
      assertEqual(sha256Hex(buffer), bigHash);
    });
    await test('too-small non-final part is rejected', async () => {
      const init = await owner.post('/v1/uploads', { name: 'tiny-part.mp4', size: 11 * 1024 * 1024, mime: 'video/mp4' });
      const res = await owner.put(
        `/v1/upload/${init.json.uploadId}/parts/1?token=${encodeURIComponent(init.json.uploadToken)}`,
        Buffer.alloc(1024),
        { token: null, headers: { 'Content-Type': 'application/octet-stream' } }
      );
      assertEqual(res.status, 400);
      assertEqual(res.json.error.code, 'part_too_small');
      await owner.post(`/v1/uploads/${init.json.uploadId}/abort`, {});
    });
    await test('aborted upload leaves no file and no quota charge', async () => {
      const before = (await owner.get('/v1/account')).json.quota.usedBytes;
      const init = await owner.post('/v1/uploads', { name: 'aborted.bin', size: 7 * 1024 * 1024, mime: 'application/octet-stream' });
      const firstPart = randomBuffer(5 * 1024 * 1024);
      await owner.put(
        `/v1/upload/${init.json.uploadId}/parts/1?token=${encodeURIComponent(init.json.uploadToken)}`,
        firstPart,
        { token: null, headers: { 'Content-Type': 'application/octet-stream' } }
      );
      const abort = await owner.post(`/v1/uploads/${init.json.uploadId}/abort`, {});
      assertEqual(abort.status, 200);
      const after = (await owner.get('/v1/account')).json.quota.usedBytes;
      assertEqual(after, before, 'aborted uploads must not consume quota');
      const list = await owner.get('/v1/files?parentId=root');
      assert(!list.json.items.some((item) => item.name === 'aborted.bin'), 'aborted upload must not appear');
    });

    // =====================================================================
    suite('Folders, rename, move, copy, search');
    let folderId = null;
    let copyId = null;
    await test('create nested folders', async () => {
      const res = await owner.post('/v1/folders', { name: 'Backups', parentId: 'root' });
      assertEqual(res.status, 201);
      folderId = res.json.folder.id;
      const nested = await owner.post('/v1/folders', { name: 'DNS Rules', parentId: folderId });
      assertEqual(nested.status, 201);
    });
    await test('duplicate folder names are rejected in the same parent', async () => {
      const res = await owner.post('/v1/folders', { name: 'Backups', parentId: 'root' });
      assertEqual(res.status, 409);
      assertEqual(res.json.error.code, 'name_taken');
    });
    await test('rename a file', async () => {
      const res = await owner.post(`/v1/files/${firstNodeId}/rename`, { name: 'dns-notes.txt' });
      assertEqual(res.status, 200);
      assertEqual(res.json.node.name, 'dns-notes.txt');
    });
    await test('path traversal in names is neutralised', async () => {
      const res = await owner.post('/v1/folders', { name: '../../../etc/passwd', parentId: 'root' });
      assertEqual(res.status, 201);
      assert(!res.json.folder.name.includes('/'), 'slashes stripped');
      assert(!res.json.folder.name.startsWith('.'), 'leading dots stripped');
    });
    await test('move into a folder and back', async () => {
      const moved = await owner.post(`/v1/files/${firstNodeId}/move`, { parentId: folderId });
      assertEqual(moved.status, 200);
      assertEqual(moved.json.node.parentId, folderId);
      const back = await owner.post(`/v1/files/${firstNodeId}/move`, { parentId: 'root' });
      assertEqual(back.status, 200);
    });
    await test('folder cannot be moved into itself', async () => {
      const res = await owner.post(`/v1/files/${folderId}/move`, { parentId: folderId });
      assertEqual(res.status, 400);
      assertEqual(res.json.error.code, 'invalid_move');
    });
    await test('copy a file (new object, new quota)', async () => {
      const before = (await owner.get('/v1/account')).json.quota.usedBytes;
      const res = await owner.post(`/v1/files/${firstNodeId}/copy`, { parentId: folderId });
      assertEqual(res.status, 201);
      copyId = res.json.node.id;
      assert(copyId !== firstNodeId, 'copy must be a distinct node');
      const after = (await owner.get('/v1/account')).json.quota.usedBytes;
      assertEqual(after, before + smallBytes.byteLength);
      const { buffer } = await downloadNode(owner, copyId);
      assert(buffer.equals(smallBytes), 'copy is byte-identical');
    });
    await test('search by name finds the file', async () => {
      const res = await owner.get('/v1/search?q=dns-notes');
      assertEqual(res.status, 200);
      assert(res.json.items.some((item) => item.id === firstNodeId), 'search hit');
    });
    await test('category filters return only matching types', async () => {
      const videos = await owner.get('/v1/files?parentId=root&category=videos');
      assertEqual(videos.status, 200);
      assert(videos.json.items.every((item) => (item.mime ?? '').startsWith('video/')), 'only videos');
      const photos = await owner.get('/v1/files?parentId=root&category=photos');
      assertEqual(photos.json.items.length, 0);
    });

    // =====================================================================
    suite('Version history');
    await test('upload a second version, both versions remain listed', async () => {
      const v2 = Buffer.from('version two content — updated blocklist strategy '.repeat(20));
      const init = await owner.post(`/v1/files/${firstNodeId}/versions/init`, {
        size: v2.byteLength,
        sha256: sha256Hex(v2),
        mime: 'text/plain',
      });
      assertEqual(init.status, 201);
      await owner.put(
        `/v1/upload/${init.json.uploadId}/content?token=${encodeURIComponent(init.json.uploadToken)}`,
        v2,
        { token: null, headers: { 'Content-Type': 'text/plain' } }
      );
      const completed = await owner.post(`/v1/uploads/${init.json.uploadId}/complete`, {});
      assertEqual(completed.status, 200, completed.text);
      const versions = await owner.get(`/v1/files/${firstNodeId}/versions`);
      assertEqual(versions.status, 200);
      assertEqual(versions.json.currentVersion, 2);
      assertEqual(versions.json.versions.length, 2);
      assertEqual(versions.json.versions[0].version, 2);
    });
    await test('download serves the newest version', async () => {
      const { buffer } = await downloadNode(owner, firstNodeId);
      assert(buffer.toString().startsWith('version two content'), 'current content is v2');
    });
    await test('restore version 1 creates version 3 with the old bytes', async () => {
      const versions = await owner.get(`/v1/files/${firstNodeId}/versions`);
      const v1 = versions.json.versions.find((version) => version.version === 1);
      const res = await owner.post(`/v1/files/${firstNodeId}/versions/${v1.id}/restore`, {});
      assertEqual(res.status, 200, res.text);
      assertEqual(res.json.currentVersion, 3);
      const { buffer } = await downloadNode(owner, firstNodeId);
      assert(buffer.equals(smallBytes), 'restored bytes match version 1');
    });

    // =====================================================================
    suite('Duplicate detection');
    await test('identical content is detected and stored as a reference', async () => {
      const res = await owner.post('/v1/uploads', {
        name: 'notes-copy.txt',
        size: smallBytes.byteLength,
        mime: 'text/plain',
        sha256: smallHash,
      });
      assertEqual(res.status, 201);
      assert(res.json.duplicate, 'duplicate reported');
      assertEqual(res.json.duplicate.referenceCreated, true);
      const list = await owner.get('/v1/files?parentId=root');
      assert(list.json.items.some((item) => item.name === 'notes-copy.txt'), 'reference node visible');
    });

    // =====================================================================
    suite('Trash, restore, permanent delete');
    await test('trashed file is hidden from listings', async () => {
      const res = await owner.post(`/v1/files/${copyId}/trash`, {});
      assertEqual(res.status, 200);
      const list = await owner.get(`/v1/files?parentId=${folderId}`);
      assert(!list.json.items.some((item) => item.id === copyId), 'trashed item hidden');
      const trash = await owner.get('/v1/trash');
      assert(trash.json.items.some((item) => item.id === copyId), 'visible in trash');
      assertEqual(trash.json.retentionDays, 30);
    });
    await test('restore brings the file back with its bytes', async () => {
      const res = await owner.post(`/v1/files/${copyId}/restore`, {});
      assertEqual(res.status, 200);
      const { buffer } = await downloadNode(owner, copyId);
      assert(buffer.equals(smallBytes));
    });
    await test('permanent delete reclaims quota', async () => {
      const before = (await owner.get('/v1/account')).json.quota.usedBytes;
      await owner.post(`/v1/files/${copyId}/trash`, {});
      const res = await owner.del(`/v1/files/${copyId}`);
      assertEqual(res.status, 200, res.text);
      const after = (await owner.get('/v1/account')).json.quota.usedBytes;
      assert(after < before, `quota must drop after purge (before=${before}, after=${after})`);
      const gone = await owner.get(`/v1/files/${copyId}`);
      assertEqual(gone.status, 404);
    });
    await test('deleting a non-trashed file requires trashing first', async () => {
      const res = await owner.del(`/v1/files/${firstNodeId}`);
      assertEqual(res.status, 400);
      assertEqual(res.json.error.code, 'not_trashed');
    });

    // =====================================================================
    suite('Malware scanning & quarantine');
    let eicarId = null;
    await test('EICAR test file is quarantined, not downloadable', async () => {
      const eicar = Buffer.from(
        'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
      );
      const result = await uploadFile(owner, { name: 'eicar-test.txt', data: eicar, mime: 'text/plain' });
      assertEqual(result.completed.scan.verdict, 'infected');
      eicarId = result.completed.nodeId;
      const res = await owner.get(`/v1/files/${eicarId}/download`);
      assertEqual(res.status, 423);
      assertEqual(res.json.error.code, 'file_quarantined');
    });
    await test('executable disguised as an image is quarantined', async () => {
      const fake = Buffer.concat([Buffer.from([0x4d, 0x5a, 0x90, 0x00]), randomBuffer(4096)]);
      const result = await uploadFile(owner, { name: 'totally-a-photo.jpg', data: fake, mime: 'image/jpeg' });
      assertEqual(result.completed.scan.verdict, 'infected');
      const security = await owner.get('/v1/security');
      assert(security.json.scanning.quarantined.some((item) => item.id === result.completed.nodeId));
    });
    await test('owner can release a quarantined file after review', async () => {
      const res = await owner.post(`/v1/files/${eicarId}/release`, {});
      assertEqual(res.status, 200);
      const download = await owner.get(`/v1/files/${eicarId}/download`);
      assertEqual(download.status, 200);
      const security = await owner.get('/v1/security');
      const node = security.json.scanning.quarantined.find((item) => item.id === eicarId);
      assert(!node, 'released file leaves the quarantine list');
    });
    await test('blocked extensions are refused with 415', async () => {
      const res = await owner.post('/v1/uploads', { name: 'payload.exe', size: 1024, mime: 'application/octet-stream' });
      assertEqual(res.status, 415);
      assertEqual(res.json.error.code, 'unsupported_file_type');
    });
    await test('audit log records security-relevant actions', async () => {
      const res = await owner.get('/v1/audit?limit=100');
      assertEqual(res.status, 200);
      const actions = res.json.entries.map((entry) => entry.action);
      for (const expected of ['upload_completed', 'download_url_issued', 'quarantine_released', 'file_trashed']) {
        assert(actions.includes(expected), `audit log contains ${expected}`);
      }
      assert(res.json.entries.every((entry) => entry.ipHash === null || entry.ipHash.length === 32), 'IPs are hashed');
    });

    // =====================================================================
    suite('Secure sharing');
    let shareToken = null;
    let shareId = null;
    await test('create a password-protected share with expiry', async () => {
      const res = await owner.post('/v1/shares', {
        nodeId: firstNodeId,
        expiresInSeconds: 3600,
        maxDownloads: 3,
        password: 'hunter2-share',
        allowPreview: true,
      });
      assertEqual(res.status, 201, res.text);
      shareToken = res.json.token;
      shareId = res.json.share.id;
      assertEqual(res.json.share.passwordProtected, true);
      assert(!res.json.shareUrl.includes('null'), 'share URL built');
    });
    await test('public metadata hides the file until the password is supplied', async () => {
      const res = await owner.get(`/s/${shareToken}`, { token: null });
      assertEqual(res.status, 200);
      assertEqual(res.json.requiresPassword, true);
      assertEqual(res.json.fileName, 'dns-notes.txt');
    });
    await test('wrong share password is rejected', async () => {
      const res = await owner.post(`/s/${shareToken}/download`, { password: 'wrong' }, { token: null });
      assertEqual(res.status, 403);
      assertEqual(res.json.error.code, 'share_password_invalid');
    });
    await test('correct password yields a working download URL', async () => {
      const res = await owner.post(`/s/${shareToken}/download`, { password: 'hunter2-share' }, { token: null });
      assertEqual(res.status, 200, res.text);
      const response = await owner.get(res.json.url, { token: null, raw: true });
      const buffer = Buffer.from(await response.arrayBuffer());
      assertEqual(sha256Hex(buffer), smallHash);
    });
    await test('share download limits are enforced', async () => {
      await owner.post(`/s/${shareToken}/download`, { password: 'hunter2-share' }, { token: null });
      await owner.post(`/s/${shareToken}/download`, { password: 'hunter2-share' }, { token: null });
      const res = await owner.post(`/s/${shareToken}/download`, { password: 'hunter2-share' }, { token: null });
      assertEqual(res.status, 403);
      assertEqual(res.json.error.code, 'share_exhausted');
    });
    await test('revoked share stops resolving immediately', async () => {
      const revoke = await owner.del(`/v1/shares/${shareId}`);
      assertEqual(revoke.status, 200);
      const res = await owner.get(`/s/${shareToken}`, { token: null });
      assertEqual(res.status, 403);
      assertEqual(res.json.error.code, 'share_revoked');
    });
    await test('expired share returns 410', async () => {
      const created = await owner.post('/v1/shares', { nodeId: firstNodeId, expiresInSeconds: 300 });
      d1(`UPDATE shares SET expires_at = ${Date.now() - 1000} WHERE id = '${created.json.share.id}'`);
      const res = await owner.get(`/s/${created.json.token}`, { token: null });
      assertEqual(res.status, 410);
      assertEqual(res.json.error.code, 'share_expired');
    });

    // =====================================================================
    suite('Encrypted DNS/security configuration backups');
    let backupId = null;
    const backupPlaintext = JSON.stringify({
      schema: 1,
      kind: 'full',
      dns: { resolver: 'cloudflare-doh', protocol: 'doh', blocklists: 12 },
      rules: Array.from({ length: 25 }, (_, index) => `ads${index}.example.com`),
      exportedAt: new Date().toISOString(),
    });
    const backupBytes = Buffer.concat([Buffer.from('CSHIELDV1'), randomBuffer(64), Buffer.from(backupPlaintext)]);
    const backupHash = sha256Hex(backupBytes);
    await test('initialise a backup upload session', async () => {
      const res = await owner.post('/v1/backups/init', {
        size: backupBytes.byteLength,
        sha256: backupHash,
        kind: 'dns_config',
        label: 'Nightly DNS snapshot',
        appVersion: '2.2.5',
      });
      assertEqual(res.status, 201, res.text);
      const put = await owner.put(
        `/v1/upload/${res.json.uploadId}/content?token=${encodeURIComponent(res.json.uploadToken)}`,
        backupBytes,
        { token: null, headers: { 'Content-Type': 'application/x-adshield-backup' } }
      );
      assertEqual(put.status, 200, put.text);
      const completed = await owner.post(`/v1/uploads/${res.json.uploadId}/complete`, {});
      assertEqual(completed.status, 200, completed.text);
      backupId = completed.json.backupId;
      assert(backupId, 'backup id returned');
    });
    await test('backup is listed with metadata and counts against quota', async () => {
      const res = await owner.get('/v1/backups');
      assertEqual(res.status, 200);
      const backup = res.json.backups.find((item) => item.id === backupId);
      assert(backup, 'backup listed');
      assertEqual(backup.sha256, backupHash);
      assertEqual(backup.encrypted, true);
      assert(res.json.totalBytes >= backupBytes.byteLength);
      const account = await owner.get('/v1/account');
      assert(account.json.backups.count >= 1);
    });
    await test('integrity verification recomputes the stored hash', async () => {
      const res = await owner.post(`/v1/backups/${backupId}/verify`, {});
      assertEqual(res.status, 200, res.text);
      assertEqual(res.json.matches, true);
      assertEqual(res.json.computedSha256, backupHash);
    });
    await test('restore returns the exact ciphertext and is recorded', async () => {
      const res = await owner.post(`/v1/backups/${backupId}/restore`, {});
      assertEqual(res.status, 200, res.text);
      const response = await owner.get(res.json.url, { token: null, raw: true });
      const buffer = Buffer.from(await response.arrayBuffer());
      assertEqual(sha256Hex(buffer), backupHash, 'restored ciphertext matches');
      assert(buffer.equals(backupBytes));
      const done = await owner.post(`/v1/backups/${backupId}/restored`, {});
      assertEqual(done.status, 200);
      const list = await owner.get('/v1/backups');
      const backup = list.json.backups.find((item) => item.id === backupId);
      assert(backup.restoredAt, 'restored timestamp recorded');
      assertEqual(backup.integrityOk, true);
    });
    await test('another user cannot read the backup', async () => {
      const res = await other.get(`/v1/backups/${backupId}/download`);
      assertEqual(res.status, 404);
    });

    // =====================================================================
    suite('Quota enforcement (per-user configuration)');
    await test('upload beyond the configured quota returns 507', async () => {
      const account = await owner.get('/v1/account');
      const used = account.json.quota.usedBytes;
      d1(`UPDATE users SET quota_bytes = ${used + 1024} WHERE id = 'user-owner-0001'`);
      const res = await owner.post('/v1/uploads', {
        name: 'too-big.bin',
        size: 5 * 1024 * 1024,
        mime: 'application/octet-stream',
      });
      assertEqual(res.status, 507);
      assertEqual(res.json.error.code, 'quota_exceeded');
      assertEqual(res.json.error.details.scope, 'user');
      d1(`UPDATE users SET quota_bytes = ${64 * 1024 * 1024} WHERE id = 'user-owner-0001'`);
    });
    await test('global free-tier pool is protected by the safety cap', async () => {
      const original = d1(`SELECT used_bytes FROM users WHERE id = 'user-owner-0001'`);
      d1(`UPDATE users SET used_bytes = 1024 * 1024 * 1024 - 100 WHERE id = 'user-other-0002'`);
      const res = await owner.post('/v1/uploads', {
        name: 'cap-test.bin',
        size: 1024 * 1024,
        mime: 'application/octet-stream',
      });
      assertEqual(res.status, 507);
      assertEqual(res.json.error.details.scope, 'global');
      d1(`UPDATE users SET used_bytes = 0 WHERE id = 'user-other-0002'`);
      void original;
    });

    // =====================================================================
    suite('Error handling & hardening');
    await test('unknown route returns a structured 404', async () => {
      const res = await owner.get('/v1/does-not-exist');
      assertEqual(res.status, 404);
      assertEqual(res.json.error.code, 'route_not_found');
    });
    await test('malformed JSON body returns 400', async () => {
      const res = await owner.post('/v1/folders', '{"name":', { headers: { 'Content-Type': 'application/json' } });
      assertEqual(res.status, 400);
      assertEqual(res.json.error.code, 'invalid_json');
    });
    await test('wrong content type rejected', async () => {
      const res = await owner.request('POST', '/v1/folders', {
        body: 'name=x',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      assertEqual(res.status, 400);
      assertEqual(res.json.error.code, 'unsupported_media_type');
    });
    await test('zero-byte upload rejected', async () => {
      const res = await owner.post('/v1/uploads', { name: 'empty.txt', size: 0, mime: 'text/plain' });
      assertEqual(res.status, 400);
      assertEqual(res.json.error.code, 'invalid_size');
    });
    await test('CORS preflight is answered', async () => {
      const res = await owner.request('OPTIONS', '/v1/files', { token: null });
      assertEqual(res.status, 204);
      assertEqual(res.headers.get('access-control-allow-origin'), '*');
    });
    await test('health endpoint hides no secrets', async () => {
      const res = await owner.get('/health');
      const text = res.text;
      for (const secret of [SERVER_SECRET, JWT_SECRET, SUPABASE_ANON_KEY]) {
        assert(!text.includes(secret), 'no secret leaked in health output');
      }
    });
    // =====================================================================
    suite('Rate limiting & audit');
    await test('burst traffic is rate limited with Retry-After', async () => {
      let limited = null;
      for (let i = 0; i < 120; i += 1) {
        const res = await owner.get('/v1/search?q=ratelimit');
        if (res.status === 429) {
          limited = res;
          break;
        }
      }
      assert(limited, 'expected a 429 within 120 search requests (bucket = 60/min)');
      assertEqual(limited.json.error.code, 'rate_limited');
      assert(Number(limited.headers.get('retry-after')) > 0, 'Retry-After header present');
    });

  } finally {
    // Kill the whole process group: wrangler spawns workerd as a child that would otherwise
    // keep the port bound and leak between runs.
    const killGroup = (signal) => {
      try {
        process.kill(-child.pid, signal);
      } catch {
        try {
          child.kill(signal);
        } catch {
          /* already gone */
        }
      }
    };
    killGroup('SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 1500));
    killGroup('SIGKILL');
    writeFileSync(LOG_FILE, logChunks.join(''));
  }

  const passed = results.filter((result) => result.ok).length;
  const failed = results.filter((result) => !result.ok);
  const totalMs = results.reduce((sum, result) => sum + result.ms, 0);

  console.log(`\n${'─'.repeat(64)}`);
  console.log(`\x1b[1mResult:\x1b[0m ${passed}/${results.length} passed, ${failed.length} failed \x1b[90m(${totalMs}ms)\x1b[0m`);
  if (failed.length) {
    console.log('\n\x1b[31mFailures:\x1b[0m');
    for (const failure of failed) console.log(`  • [${failure.suite}] ${failure.name}\n      ${failure.error}`);
    exitCode = 1;
  }
  writeFileSync(
    join(ROOT, 'test', 'last-run.json'),
    JSON.stringify({ ranAt: new Date().toISOString(), runtime: 'workerd (wrangler dev --local)', results, passed, failed: failed.length }, null, 2)
  );
  console.log(`\x1b[90mworker log: ${LOG_FILE}\x1b[0m`);
  process.exit(exitCode);
}

main().catch((error) => {
  console.error('\x1b[31mfatal:\x1b[0m', error);
  process.exit(1);
});
