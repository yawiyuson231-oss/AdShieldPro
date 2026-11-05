/**
 * AdShield Pro — free-tier cloud backend (Cloudflare Worker + D1 + R2).
 *
 * Design rules:
 *  - The R2 bucket is PRIVATE. Object bytes only move through short-lived HMAC-signed URLs
 *    issued here after an ownership check. No credential leaves this Worker.
 *  - Every mutating route verifies the Supabase JWT (HS256, anon/ JWT secret from env) and
 *    checks row ownership before acting.
 *  - Free-tier quotas are enforced in code and never auto-upgraded to paid.
 *
 * Env vars (set with `wrangler secret put`):
 *   SUPABASE_JWT_SECRET  — your free Supabase project's JWT secret
 *   SUPABASE_URL         — https://<project>.supabase.co
 *   SUPABASE_ANON_KEY    — public anon key (used only for sign-up/sign-in proxying)
 */

const TTL_MS = () => Number((900)) * 1000; // matches wrangler.toml SIGNED_URL_TTL_SECONDS
const MAX_FILE = 1073741824n;

const BLOCKED_EXT = new Set(['apk', 'exe', 'scr', 'bat', 'cmd', 'msi', 'js', 'html', 'htm', 'svg']);
const BLOCKED_MIME = new Set(['text/html', 'image/svg+xml', 'application/x-msdownload', 'application/javascript']);

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}
function err(message, status = 400) { return json({ error: message }, status); }

async function sha256Hex(textOrBuffer) {
  const data = typeof textOrBuffer === 'string' ? new TextEncoder().encode(textOrBuffer) : textOrBuffer;
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyJwt(token, secret) {
  try {
    const [h, p, s] = token.split('.');
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sig = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const ok = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(`${h}.${p}`));
    if (!ok) return null;
    const payload = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && payload.exp * 1000 <= Date.now()) return null;
    return payload;
  } catch { return null; }
}

async function signPath(env, path, method, ttlSec) {
  const exp = Math.floor(Date.now() / 1000) + ttlSec;
  const mac = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(env.SIGNING_SECRET || env.SUPABASE_JWT_SECRET),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', mac, new TextEncoder().encode(`${method} ${path} ${exp}`));
  const sig = [...new Uint8Array(sigBuf)].map(b => b.toString(16).padStart(2, '0')).join('');
  return `${path}?exp=${exp}&sig=${sig}`;
}

async function authedUser(request, env) {
  const auth = request.headers.get('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return { error: err('Missing bearer token', 401) };
  const payload = await verifyJwt(token, env.SUPABASE_JWT_SECRET);
  if (!payload || !payload.sub) return { error: err('Invalid or expired token', 401) };
  return { userId: payload.sub, email: payload.email || '' };
}

function validateFile(name, mime) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  if (BLOCKED_EXT.has(ext)) return 'File type blocked (executable/active content).';
  if (BLOCKED_MIME.has((mime || '').toLowerCase())) return 'MIME type blocked.';
  return null;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const now = Date.now();

    // --- Auth proxy (Supabase free tier, no card) ---
    if (path === '/auth/signup' && request.method === 'POST') {
      const { email, password } = await request.json();
      if (!email || !password || password.length < 8) return err('Password must be at least 8 characters.', 422);
      const res = await fetch(`${env.SUPABASE_URL}/auth/v1/signup`, {
        method: 'POST',
        headers: { apikey: env.SUPABASE_ANON_KEY, 'content-type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const body = await res.json();
      if (!res.ok) return err(body.msg || body.error_description || 'Sign-up failed', res.status);
      await env.DB.prepare(
        'INSERT OR IGNORE INTO users (id, email, created_at) VALUES (?, ?, ?)'
      ).bind(body.user.id, email, now).run();
      return json({
        accessToken: body.access_token, refreshToken: body.refresh_token || '',
        userId: body.user.id, email, expiresAtEpochSec: body.expires_at || Math.floor(now / 1000) + 3600,
      });
    }
    if (path === '/auth/login' && request.method === 'POST') {
      const { email, password } = await request.json();
      const res = await fetch(`${env.SUPABASE_URL}/auth/v1/token?grant_type=password`, {
        method: 'POST',
        headers: { apikey: env.SUPABASE_ANON_KEY, 'content-type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const body = await res.json();
      if (!res.ok) return err(body.error_description || 'Sign-in failed', res.status);
      return json({
        accessToken: body.access_token, refreshToken: body.refresh_token || '',
        userId: body.user.id, email, expiresAtEpochSec: body.expires_at || Math.floor(now / 1000) + 3600,
      });
    }

    // --- Signed content transfer: verify HMAC, then stream to/from private R2 ---
    if (path.startsWith('/content/')) {
      const key = path.slice('/content/'.length);
      const exp = Number(url.searchParams.get('exp') || 0);
      const sig = url.searchParams.get('sig') || '';
      if (exp * 1000 <= now) return err('Signed URL expired', 403);
      if (exp * 1000 - now > TTL_MS()) return err('Signed URL TTL too long', 403);
      const method = request.method === 'PUT' ? 'PUT' : 'GET';
      const expected = await signPath(env, `/content/${key}`, method, exp - Math.floor(now / 1000));
      if (!expected.endsWith(`sig=${sig}`)) return err('Bad signature', 403);
      // ownership: key is <userId>/<fileId>; the JWT must match (checked on issue, re-checked here)
      const owner = key.split('/')[0];
      const auth = await authedUser(request, env);
      if (auth.error) return auth.error;
      if (auth.userId !== owner) return err('Not your object', 403);
      if (request.method === 'PUT') {
        const len = Number(request.headers.get('content-length') || 0);
        if (len > Number(env.MAX_FILE_BYTES)) return err('File too large', 413);
        await env.BUCKET.put(key, request.body, { customMetadata: { sha256: request.headers.get('x-sha256') || '' } });
        return json({ stored: true });
      }
      const object = await env.BUCKET.get(key);
      if (!object) return err('Not found', 404);
      return new Response(object.body, { headers: { 'content-type': object.httpMetadata?.contentType || 'application/octet-stream' } });
    }

    // --- Everything below requires auth ---
    const auth = await authedUser(request, env);
    if (auth.error) return auth.error;
    const userId = auth.userId;
    const audit = (action, target) =>
      env.DB.prepare('INSERT INTO audit_log (user_id, action, target, at) VALUES (?, ?, ?, ?)')
        .bind(userId, action, target || null, now).run();

    const ensureQuotaRow = async () => {
      await env.DB.prepare('INSERT OR IGNORE INTO users (id, email, created_at) VALUES (?, ?, ?)')
        .bind(userId, auth.email, now).run();
    };

    if (path === '/api/quota' && request.method === 'GET') {
      await ensureQuotaRow();
      const row = await env.DB.prepare('SELECT quota_bytes FROM users WHERE id = ?').bind(userId).first();
      const used = await env.DB.prepare('SELECT COALESCE(SUM(size_bytes),0) AS u, COUNT(*) AS c FROM files WHERE user_id = ? AND is_deleted = 0').bind(userId).first();
      const counters = await env.DB.prepare('SELECT COUNT(*) AS a FROM audit_log WHERE user_id = ? AND action = "upload"').bind(userId).first();
      const dls = await env.DB.prepare('SELECT COUNT(*) AS d FROM audit_log WHERE user_id = ? AND action = "download"').bind(userId).first();
      return json({
        quotaBytes: row.quota_bytes, usedBytes: used.u, fileCount: used.c,
        uploadCountAllTime: counters.a, downloadCountAllTime: dls.d,
      });
    }

    if (path === '/api/files' && request.method === 'POST') {
      const { name, folder, sizeBytes, mimeType, sha256, multipart } = await request.json();
      const typeError = validateFile(name, mimeType);
      if (typeError) return err(typeError, 422);
      if (BigInt(sizeBytes) > MAX_FILE) return err('File exceeds 1 GiB limit', 413);
      await ensureQuotaRow();
      const quota = await env.DB.prepare('SELECT quota_bytes FROM users WHERE id = ?').bind(userId).first();
      const used = await env.DB.prepare('SELECT COALESCE(SUM(size_bytes),0) AS u FROM files WHERE user_id = ? AND is_deleted = 0').bind(userId).first();
      if (BigInt(used.u) + BigInt(sizeBytes) > BigInt(quota.quota_bytes)) return err('Quota exceeded — free more space. No paid tier is auto-enabled.', 413);
      // duplicate detection: same hash+size already stored -> reference instead of re-storing bytes
      const dup = await env.DB.prepare('SELECT id FROM files WHERE user_id = ? AND sha256 = ? AND size_bytes = ? AND is_deleted = 0 LIMIT 1')
        .bind(userId, sha256, sizeBytes).first();
      const id = crypto.randomUUID();
      const key = `${userId}/${id}`;
      if (!dup) {
        await env.DB.prepare(
          'INSERT INTO files (id, user_id, name, folder_path, size_bytes, mime_type, sha256, r2_key, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)'
        ).bind(id, userId, name, folder || '/', sizeBytes, mimeType, sha256, key, now, now).run();
      } else {
        await env.DB.prepare(
          'INSERT INTO files (id, user_id, name, folder_path, size_bytes, mime_type, sha256, r2_key, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)'
        ).bind(id, userId, name, folder || '/', 0, mimeType, sha256, `${userId}/${dup.id}`, now, now).run();
      }
      await audit('upload', id);
      return json({ id, name, folderPath: folder || '/', sizeBytes, mimeType, sha256, isDeleted: false, createdAtEpochMs: now, updatedAtEpochMs: now, version: 1 });
    }

    if (path === '/api/files' && request.method === 'GET') {
      const folder = url.searchParams.get('folder') || '/';
      const rows = await env.DB.prepare('SELECT * FROM files WHERE user_id = ? AND folder_path = ? AND is_deleted = 0 ORDER BY name ASC')
        .bind(userId, folder).all();
      return json(rows.results.map(r => ({
        id: r.id, name: r.name, folderPath: r.folder_path, sizeBytes: r.size_bytes,
        mimeType: r.mime_type, sha256: r.sha256, isDeleted: !!r.is_deleted,
        createdAtEpochMs: r.created_at, updatedAtEpochMs: r.updated_at, version: r.version,
      })));
    }

    if (path === '/api/folders' && request.method === 'POST') {
      // folders are virtual: represented by folder_path on files
      const { path: p } = await request.json();
      return json({ id: 'folder:' + p, name: p, folderPath: p, sizeBytes: 0, mimeType: 'inode/directory', sha256: '', isDeleted: false, createdAtEpochMs: now, updatedAtEpochMs: now, version: 1 });
    }

    const fileMatch = path.match(/^\/api\/files\/([^/]+)(\/(rename|move|copy|restore|versions|share|sign-upload|sign-chunk|complete|sign-download))?$/);
    if (fileMatch) {
      const fileId = fileMatch[1];
      const action = fileMatch[3];
      const file = await env.DB.prepare('SELECT * FROM files WHERE id = ? AND user_id = ?').bind(fileId, userId).first();
      if (!file) return err('File not found or not yours', 404);

      if (action === 'rename' && request.method === 'POST') {
        const { name } = await request.json();
        await env.DB.prepare('UPDATE files SET name = ?, updated_at = ? WHERE id = ?').bind(name, now, fileId).run();
        return json({ ok: true });
      }
      if (action === 'move' && request.method === 'POST') {
        const { folder } = await request.json();
        await env.DB.prepare('UPDATE files SET folder_path = ?, updated_at = ? WHERE id = ?').bind(folder, now, fileId).run();
        return json({ ok: true });
      }
      if (action === 'copy' && request.method === 'POST') {
        const { folder } = await request.json();
        const newId = crypto.randomUUID();
        await env.DB.prepare(
          'INSERT INTO files (id, user_id, name, folder_path, size_bytes, mime_type, sha256, r2_key, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)'
        ).bind(newId, userId, file.name, folder || '/', file.size_bytes, file.mime_type, file.sha256, file.r2_key, now, now).run();
        return json({ id: newId, name: file.name, folderPath: folder || '/', sizeBytes: file.size_bytes, mimeType: file.mime_type, sha256: file.sha256, isDeleted: false, createdAtEpochMs: now, updatedAtEpochMs: now, version: 1 });
      }
      if (!action && request.method === 'DELETE') {
        const permanent = url.searchParams.get('permanent') === 'true';
        if (permanent) {
          await env.BUCKET.delete(file.r2_key);
          await env.DB.prepare('DELETE FROM files WHERE id = ?').bind(fileId).run();
        } else {
          await env.DB.prepare('UPDATE files SET is_deleted = 1, updated_at = ? WHERE id = ?').bind(now, fileId).run();
        }
        return json({ ok: true });
      }
      if (action === 'restore' && request.method === 'POST') {
        await env.DB.prepare('UPDATE files SET is_deleted = 0, updated_at = ? WHERE id = ?').bind(now, fileId).run();
        return json({ ok: true });
      }
      if (action === 'versions' && request.method === 'GET') {
        const rows = await env.DB.prepare('SELECT version, size_bytes, sha256, created_at FROM file_versions WHERE file_id = ? ORDER BY version DESC').bind(fileId).all();
        return json(rows.results.map(r => ({ version: r.version, sizeBytes: r.size_bytes, sha256: r.sha256, createdAtEpochMs: r.created_at })));
      }
      if (action === 'share' && request.method === 'POST') {
        const { ttlHours, maxDownloads } = await request.json();
        const shareId = crypto.randomUUID();
        const ttl = Math.min(Math.max(ttlHours || 24, 1), 168);
        await env.DB.prepare('INSERT INTO shares (id, file_id, user_id, expires_at, max_downloads, created_at) VALUES (?,?,?,?,?,?)')
          .bind(shareId, fileId, userId, now + ttl * 3600_000, Math.min(maxDownloads || 10, 1000), now).run();
        return json({ id: shareId, fileId, fileName: file.name, expiresAtEpochMs: now + ttl * 3600_000, maxDownloads: Math.min(maxDownloads || 10, 1000), downloadCount: 0, createdAtEpochMs: now });
      }
      if (action === 'sign-upload' && request.method === 'POST') {
        const signed = await signPath(env, `/content/${file.r2_key}`, 'PUT', Number(env.SIGNED_URL_TTL_SECONDS));
        return json({ url: new URL(signed, url.origin).toString(), method: 'PUT', expiresAtEpochMs: now + TTL_MS() });
      }
      if (action === 'sign-chunk' && request.method === 'POST') {
        const signed = await signPath(env, `/content/${file.r2_key}`, 'PUT', Number(env.SIGNED_URL_TTL_SECONDS));
        return json({ url: new URL(signed, url.origin).toString(), method: 'PUT', expiresAtEpochMs: now + TTL_MS() });
      }
      if (action === 'complete' && request.method === 'POST') {
        await env.DB.prepare('UPDATE files SET version = version + 1, updated_at = ? WHERE id = ?').bind(now, fileId).run();
        return json({ id: fileId, name: file.name, folderPath: file.folder_path, sizeBytes: file.size_bytes, mimeType: file.mime_type, sha256: file.sha256, isDeleted: !!file.is_deleted, createdAtEpochMs: file.created_at, updatedAtEpochMs: now, version: file.version + 1 });
      }
      if (action === 'sign-download' && request.method === 'POST') {
        await audit('download', fileId);
        const signed = await signPath(env, `/content/${file.r2_key}`, 'GET', Number(env.SIGNED_URL_TTL_SECONDS));
        return json({ url: new URL(signed, url.origin).toString(), method: 'GET', expiresAtEpochMs: now + TTL_MS() });
      }
    }

    if (path === '/api/shares' && request.method === 'GET') {
      const rows = await env.DB.prepare(
        'SELECT s.id, s.file_id, s.expires_at, s.max_downloads, s.download_count, s.created_at, f.name FROM shares s JOIN files f ON f.id = s.file_id WHERE s.user_id = ? ORDER BY s.created_at DESC'
      ).bind(userId).all();
      return json(rows.results.map(r => ({ id: r.id, fileId: r.file_id, fileName: r.name, expiresAtEpochMs: r.expires_at, maxDownloads: r.max_downloads, downloadCount: r.download_count, createdAtEpochMs: r.created_at })));
    }

    if (path === '/api/backups' && request.method === 'GET') {
      const rows = await env.DB.prepare('SELECT * FROM dns_backups WHERE user_id = ? ORDER BY created_at DESC').bind(userId).all();
      return json(rows.results.map(r => ({ id: r.id, label: r.label, sha256: r.sha256, sizeBytes: r.size_bytes, createdAtEpochMs: r.created_at, restoredAtEpochMs: r.restored_at })));
    }

    return err('Not found', 404);
  },
};
