import { Hono } from 'hono'
import { B2Client, planUpload, MIN_PART_SIZE } from './lib/b2.js'
import { requireUser, turnstileVerify } from './lib/auth.js'
import { audit, newId, now, one, many, run, countRequest, usageInWindow } from './lib/db.js'
import {
  createAccount, getAccount, usage as usageState, assertWithinQuota, quotaWarning, reconcile, DEFAULT_QUOTA_BYTES
} from './lib/quota.js'

/** 100 000 requests/day on the Workers free tier, so a per-user hourly ceiling is enforced. */
const HOURLY_REQUEST_LIMIT = 2_000
const MAX_VERSIONS_KEPT = 5
const DOWNLOAD_TTL_SECONDS = 900

export function buildApp(env) {
  const app = new Hono()
  const b2 = new B2Client({
    keyId: env.B2_KEY_ID,
    applicationKey: env.B2_APPLICATION_KEY,
    bucketId: env.B2_BUCKET_ID,
    bucketName: env.B2_BUCKET_NAME,
    apiBase: env.B2_API_BASE,
    downloadBase: env.B2_DOWNLOAD_BASE
  })

  app.get('/v1/health', (c) => c.json({
    ok: true,
    provider: 'backblaze-b2',
    mode: env.AUTH_MODE === 'test' ? 'test' : 'production',
    freeTier: {
      storageBytes: DEFAULT_QUOTA_BYTES,
      note: 'Backblaze B2 free tier: 10 GB stored, no payment method required to activate.'
    }
  }))

  /** Every /v1 route except health and public share access requires a verified Supabase JWT. */
  app.use('/v1/*', async (c, next) => {
    if (c.req.path === '/v1/health' || c.req.path.startsWith('/v1/share/')) return next()
    const claims = await requireUser(c.req.raw, env)
    if (!claims) return c.json({ error: 'unauthorized' }, 401)
    // Registration is the one authenticated route that runs before an account row exists.
    if (c.req.path === '/v1/account/register') {
      c.set('user', { ...claims, quota_bytes: DEFAULT_QUOTA_BYTES, used_bytes: 0, retention_days: 30 })
      c.set('b2', b2)
      return next()
    }
    const user = await getAccount(c.env.DB, claims.sub)
    if (!user) return c.json({ error: 'account not registered' }, 409)
    if (user.disabled) return c.json({ error: 'account disabled' }, 403)
    const used = await countRequest(c.env.DB, claims.sub)
    if (used > HOURLY_REQUEST_LIMIT) {
      return c.json({
        error: 'rate limited',
        detail: `hourly request ceiling ${HOURLY_REQUEST_LIMIT} reached to protect the free tier`
      }, 429)
    }
    c.set('user', { ...claims, ...user })
    c.set('b2', b2)
    return next()
  })

  const userOf = (c) => c.get('user')

  // ---------------------------------------------------------------- account

  app.post('/v1/account/register', async (c) => {
    const body = await c.req.json().catch(() => ({}))
    const ip = c.req.header('CF-Connecting-IP') || ''
    const claims = await requireUser(c.req.raw, env)
    if (!claims) return c.json({ error: 'unauthorized' }, 401)
    const verified = await turnstileVerify(body.turnstileToken, env, ip)
    if (!verified) return c.json({ error: 'bot protection failed' }, 403)
    const account = await createAccount(c.env.DB, { userId: claims.sub, email: claims.email })
    await audit(c.env.DB, { userId: claims.sub, action: 'signup', detail: claims.email, ip })
    return c.json({ account: publicAccount(account), usage: await usageState(c.env.DB, claims.sub) })
  })

  app.get('/v1/account', async (c) => {
    const user = userOf(c)
    const usage = await usageState(c.env.DB, user.id)
    return c.json({
      account: publicAccount(user),
      usage,
      warning: quotaWarning(usage),
      apiRequestsLast24h: await usageInWindow(c.env.DB, user.id, 24),
      limits: {
        hourlyRequests: HOURLY_REQUEST_LIMIT,
        note: 'Workers free tier allows 100 000 requests/day across all users of the account.'
      }
    })
  })

  app.post('/v1/account/reconcile', async (c) => {
    const user = userOf(c)
    const result = await reconcile(c.env.DB, b2, user.id)
    return c.json(result)
  })

  app.get('/v1/audit', async (c) => {
    const user = userOf(c)
    const rows = await many(
      c.env.DB,
      `SELECT action, detail, ip, created_at FROM audit_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 100`,
      user.id
    )
    return c.json({ entries: rows })
  })

  // ---------------------------------------------------------------- browsing

  app.get('/v1/nodes', async (c) => {
    const user = userOf(c)
    const { parentId = null, kind, search, trashed } = c.req.query()
    const params = [user.id]
    let sql = `SELECT id, parent_id, kind, name, size_bytes, content_type, sha1, created_at, updated_at, deleted_at, purge_at
               FROM nodes WHERE user_id = ?`
    if (trashed === '1') {
      sql += ` AND deleted_at IS NOT NULL`
    } else {
      sql += ` AND deleted_at IS NULL`
      sql += parentId ? ` AND parent_id = ?` : ` AND parent_id IS NULL`
      if (parentId) params.push(parentId)
    }
    if (kind && kind !== 'all') {
      sql += ` AND kind = ?`
      params.push(kind)
    } else if (kind === 'media') {
      sql += ` AND kind = 'file' AND content_type LIKE ?`
      params.push('image/%')
    }
    if (search) {
      sql += ` AND name LIKE ? ESCAPE '\\'`
      params.push(`%${search.replace(/[\\%_]/g, (m) => `\\${m}`)}%`)
    }
    sql += ` ORDER BY kind DESC, name COLLATE NOCASE ASC LIMIT 500`
    const rows = await many(c.env.DB, sql, ...params)
    return c.json({ nodes: rows.map(mapNode) })
  })

  app.get('/v1/nodes/kinds', async (c) => {
    const user = userOf(c)
    const rows = await many(
      c.env.DB,
      `SELECT
         SUM(CASE WHEN kind='file' AND content_type LIKE 'image/%' THEN 1 ELSE 0 END) AS photos,
         SUM(CASE WHEN kind='file' AND content_type LIKE 'video/%' THEN 1 ELSE 0 END) AS videos,
         SUM(CASE WHEN kind='file' AND content_type LIKE 'audio/%' THEN 1 ELSE 0 END) AS audio,
         SUM(CASE WHEN kind='file' AND (content_type LIKE '%pdf%' OR content_type LIKE '%text/%' OR content_type LIKE 'application/%') THEN 1 ELSE 0 END) AS documents,
         COUNT(*) AS total
       FROM nodes WHERE user_id = ? AND deleted_at IS NULL`,
      user.id
    )
    return c.json({ counts: rows?.[0] ?? {} })
  })

  app.post('/v1/folders', async (c) => {
    const user = userOf(c)
    const body = await c.req.json().catch(() => ({}))
    const name = cleanName(body.name)
    if (!name) return c.json({ error: 'invalid folder name' }, 400)
    const parentId = body.parentId || null
    if (parentId && !(await ownsNode(c, parentId))) return c.json({ error: 'not found' }, 404)
    const id = newId('nd')
    await run(
      c.env.DB,
      `INSERT INTO nodes (id, user_id, parent_id, kind, name, created_at, updated_at)
       VALUES (?, ?, ?, 'folder', ?, ?, ?)`,
      id, user.id, parentId, name, now(), now()
    )
    await audit(c.env.DB, { userId: user.id, action: 'folder_create', detail: name })
    return c.json({ node: { id, name, parentId, kind: 'folder' } }, 201)
  })

  app.post('/v1/nodes/:id/rename', async (c) => nodeAction(c, 'rename', async (node, body) => {
    const name = cleanName(body.name)
    if (!name) return { status: 400, error: 'invalid name' }
    await run(c.env.DB, `UPDATE nodes SET name = ?, updated_at = ? WHERE id = ?`, name, now(), node.id)
    return { status: 200, node: { id: node.id, name } }
  }))

  app.post('/v1/nodes/:id/move', async (c) => nodeAction(c, 'move', async (node, body) => {
    const parentId = body.parentId || null
    if (parentId) {
      if (parentId === node.id) return { status: 400, error: 'cannot move into itself' }
      if (!(await ownsNode(c, parentId))) return { status: 404, error: 'target not found' }
    }
    await run(c.env.DB, `UPDATE nodes SET parent_id = ?, updated_at = ? WHERE id = ?`, parentId, now(), node.id)
    return { status: 200, node: { id: node.id, parentId } }
  }))

  app.post('/v1/nodes/:id/copy', async (c) => nodeAction(c, 'copy', async (node) => {
    const id = newId('nd')
    await run(
      c.env.DB,
      `INSERT INTO nodes (id, user_id, parent_id, kind, name, size_bytes, content_type, sha1, b2_file_id, b2_key, created_at, updated_at)
       SELECT ?, user_id, parent_id, kind, name || ' (copy)', size_bytes, content_type, sha1, b2_file_id, b2_key, ?, ?
       FROM nodes WHERE id = ?`,
      id, now(), now(), node.id
    )
    return { status: 201, node: { id, name: `${node.name} (copy)` } }
  }))

  app.post('/v1/nodes/:id/delete', async (c) => nodeAction(c, 'delete', async (node) => {
    const purgeAt = now() + node.retention_days * 86_400_000
    await run(
      c.env.DB,
      `UPDATE nodes SET deleted_at = ?, purge_at = ?, updated_at = ? WHERE id = ?`,
      now(), purgeAt, now(), node.id
    )
    return { status: 200, trashed: true, purgeAt }
  }))

  app.post('/v1/nodes/:id/restore', async (c) => nodeAction(c, 'restore', async (node) => {
    if (!node.deleted_at) return { status: 400, error: 'node is not in the trash' }
    await run(
      c.env.DB,
      `UPDATE nodes SET deleted_at = NULL, purge_at = NULL, updated_at = ? WHERE id = ?`,
      now(), node.id
    )
    return { status: 200, restored: true }
  }))

  /** Permanent delete: removes the B2 object first, then the row, then frees the quota. */
  app.delete('/v1/nodes/:id', async (c) => nodeAction(c, 'purge', async (node) => {
    if (node.kind === 'file' && node.b2_file_id) {
      await b2.deleteFileVersion({ fileName: node.b2_key, fileId: node.b2_file_id }).catch(() => null)
    }
    await run(c.env.DB, `DELETE FROM versions WHERE node_id = ?`, node.id)
    await run(c.env.DB, `DELETE FROM shares WHERE node_id = ?`, node.id)
    await run(c.env.DB, `DELETE FROM nodes WHERE id = ?`, node.id)
    if (node.deleted_at == null && node.kind === 'file') {
      await run(
        c.env.DB,
        `UPDATE users SET used_bytes = MAX(0, used_bytes - ?) WHERE id = ?`,
        Number(node.size_bytes || 0), node.user_id
      )
    }
    return { status: 200, purged: true }
  }))

  app.get('/v1/nodes/:id/versions', async (c) => nodeAction(c, 'version_list', async (node) => ({
    status: 200,
    versions: (await many(
      c.env.DB,
      `SELECT version, size_bytes, sha1, created_at FROM versions WHERE node_id = ? ORDER BY version DESC`,
      node.id
    ))
  }), { readOnly: true }))

  app.get('/v1/nodes/:id/download', async (c) => nodeAction(c, 'download', async (node) => {
    if (node.kind !== 'file') return { status: 400, error: 'folders cannot be downloaded' }
    const token = await b2.getDownloadAuthorization({
      keyPrefix: node.b2_key,
      validDurationSeconds: DOWNLOAD_TTL_SECONDS
    })
    const url = b2.downloadUrl(node.b2_key, token)
    return { status: 200, url, expiresInSeconds: DOWNLOAD_TTL_SECONDS, sizeBytes: node.size_bytes, sha1: node.sha1 }
  }), { readOnly: true })

  app.get('/v1/duplicates', async (c) => {
    const user = userOf(c)
    const rows = await many(
      c.env.DB,
      `SELECT sha1, COUNT(*) AS copies, SUM(size_bytes) AS bytes,
              GROUP_CONCAT(name, '|') AS names
       FROM nodes
       WHERE user_id = ? AND deleted_at IS NULL AND kind = 'file' AND sha1 IS NOT NULL AND size_bytes > 0
       GROUP BY sha1 HAVING copies > 1
       ORDER BY bytes DESC LIMIT 100`,
      user.id
    )
    await audit(c.env.DB, { userId: user.id, action: 'scan_duplicates', detail: String(rows.length) })
    return c.json({ groups: rows.map((r) => ({ ...r, names: String(r.names || '').split('|') })) })
  })

  // ---------------------------------------------------------------- uploads

  app.post('/v1/uploads/init', async (c) => {
    const user = userOf(c)
    const body = await c.req.json().catch(() => ({}))
    const declaredSize = Number(body.size)
    if (!Number.isFinite(declaredSize) || declaredSize <= 0) {
      return c.json({ error: 'a positive declared size is required' }, 400)
    }
    const guard = await assertWithinQuota(c.env.DB, user.id, declaredSize)
    if (!guard.ok) {
      await audit(c.env.DB, { userId: user.id, action: 'quota_refused', detail: `${declaredSize} bytes` })
      return c.json({ error: guard.error, detail: guard.detail }, guard.status)
    }
    const parentId = body.parentId || null
    if (parentId && !(await ownsNode(c, parentId))) return c.json({ error: 'not found' }, 404)

    const { partSize, totalParts, multipart } = planUpload(declaredSize, Number(body.partSize))
    const nodeId = newId('nd')
    const key = objectKey(user.id, nodeId, body.name || 'file')
    const contentType = String(body.contentType || 'application/octet-stream')

    let fileId = null
    const parts = []
    if (multipart) {
      const started = await b2.startLargeFile({ key, contentType })
      fileId = started.fileId
      for (let partNumber = 1; partNumber <= totalParts; partNumber++) {
        const part = await b2.getPartUploadUrl(fileId)
        parts.push({ partNumber, uploadUrl: part.uploadUrl, token: part.authorizationToken })
      }
    } else {
      const url = await b2.getUploadUrl()
      parts.push({ partNumber: 1, uploadUrl: url.uploadUrl, token: url.authorizationToken })
    }

    const sessionId = newId('up')
    await run(
      c.env.DB,
      `INSERT INTO upload_sessions
         (id, user_id, node_id, parent_id, name, content_type, declared_size, part_size, total_parts, b2_file_id, b2_key, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`,
      sessionId, user.id, nodeId, parentId, cleanName(body.name) || 'file', contentType,
      declaredSize, partSize, parts.length, fileId, key, now(), now()
    )
    await audit(c.env.DB, { userId: user.id, action: 'upload_init', detail: `${body.name} ${declaredSize}B` })
    return c.json({
      sessionId, nodeId, key, partSize, totalParts: parts.length, multipart, parts
    }, 201)
  })

  app.get('/v1/uploads/:id', async (c) => {
    const user = userOf(c)
    const session = await one(
      c.env.DB,
      `SELECT * FROM upload_sessions WHERE id = ? AND user_id = ?`, c.req.param('id'), user.id
    )
    if (!session) return c.json({ error: 'not found' }, 404)
    const uploaded = await many(
      c.env.DB,
      `SELECT part_number, size_bytes, sha1 FROM upload_parts WHERE session_id = ? ORDER BY part_number`,
      session.id
    )
    let partUrls = []
    if (session.status === 'open' && session.b2_file_id) {
      // Resume: hand out a fresh, short-lived URL for each part the client still owes.
      const missing = []
      for (let n = 1; n <= session.total_parts; n++) {
        if (!uploaded.some((p) => Number(p.part_number) === n)) missing.push(n)
      }
      partUrls = await Promise.all(missing.map(async (partNumber) => {
        const part = await b2.getPartUploadUrl(session.b2_file_id)
        return { partNumber, uploadUrl: part.uploadUrl, token: part.authorizationToken }
      }))
    }
    return c.json({
      session: {
        id: session.id, name: session.name, status: session.status,
        declaredSize: session.declared_size, partSize: session.part_size,
        totalParts: session.total_parts, uploadedParts: uploaded.map((p) => Number(p.part_number)),
        uploadedBytes: uploaded.reduce((sum, p) => sum + Number(p.size_bytes || 0), 0)
      },
      partUrls
    })
  })

  app.post('/v1/uploads/:id/part/:number', async (c) => {
    const user = userOf(c)
    const body = await c.req.json().catch(() => ({}))
    const session = await one(
      c.env.DB, `SELECT * FROM upload_sessions WHERE id = ? AND user_id = ?`, c.req.param('id'), user.id
    )
    if (!session) return c.json({ error: 'not found' }, 404)
    if (session.status !== 'open') return c.json({ error: 'session is not open' }, 409)
    const partNumber = Number(c.req.param('number'))
    const size = Number(body.size)
    const sha1 = String(body.sha1 || '')
    if (!Number.isInteger(partNumber) || partNumber < 1 || partNumber > session.total_parts) {
      return c.json({ error: 'part number out of range' }, 400)
    }
    if (!Number.isFinite(size) || size < 0 || !/^[0-9a-f]{40}$/.test(sha1)) {
      return c.json({ error: 'size and sha1 of the uploaded part are required' }, 400)
    }
    await run(
      c.env.DB,
      `INSERT INTO upload_parts (session_id, part_number, size_bytes, sha1, created_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(session_id, part_number) DO UPDATE SET size_bytes = excluded.size_bytes, sha1 = excluded.sha1`,
      session.id, partNumber, size, sha1, now()
    )
    const total = await one(
      c.env.DB,
      `SELECT COALESCE(SUM(size_bytes), 0) AS bytes FROM upload_parts WHERE session_id = ?`, session.id
    )
    await run(
      c.env.DB,
      `UPDATE upload_sessions SET actual_size = ?, updated_at = ? WHERE id = ?`,
      Number(total?.bytes ?? 0), now(), session.id
    )
    return c.json({ partNumber, uploadedBytes: Number(total?.bytes ?? 0) })
  })

  app.post('/v1/uploads/:id/complete', async (c) => {
    const user = userOf(c)
    const session = await one(
      c.env.DB, `SELECT * FROM upload_sessions WHERE id = ? AND user_id = ?`, c.req.param('id'), user.id
    )
    if (!session) return c.json({ error: 'not found' }, 404)
    if (session.status === 'completed') {
      const existing = await one(c.env.DB, `SELECT * FROM nodes WHERE id = ?`, session.node_id)
      return c.json({ node: mapNode(existing), alreadyCompleted: true })
    }
    const parts = await many(
      c.env.DB,
      `SELECT part_number, sha1, size_bytes FROM upload_parts WHERE session_id = ? ORDER BY part_number`,
      session.id
    )
    const expected = []
    for (let n = 1; n <= session.total_parts; n++) expected.push(n)
    const present = parts.map((p) => Number(p.part_number))
    const missing = expected.filter((n) => !present.includes(n))
    if (missing.length > 0) {
      return c.json({ error: 'parts missing', missingParts: missing }, 409)
    }
    const actualSize = parts.reduce((sum, p) => sum + Number(p.size_bytes || 0), 0)
    if (actualSize > session.declared_size) {
      return c.json({ error: 'uploaded bytes exceed the declared size' }, 413)
    }
    const guard = await assertWithinQuota(c.env.DB, user.id, actualSize)
    if (!guard.ok) {
      await audit(c.env.DB, { userId: user.id, action: 'quota_refused', detail: `${actualSize} bytes at completion` })
      return c.json({ error: guard.error, detail: guard.detail }, guard.status)
    }

    let fileId = session.b2_file_id
    let sha1 = 'none'
    if (session.b2_file_id) {
      const partSha1Array = parts.map((p) => p.sha1)
      const finished = await b2.finishLargeFile(session.b2_file_id, partSha1Array)
      fileId = finished.fileId ?? session.b2_file_id
      sha1 = finished.contentSha1 ?? `sha1:${partSha1Array.join('')}`.slice(0, 120)
    } else {
      sha1 = parts[0]?.sha1 ?? 'none'
      // A single-shot upload already landed in B2; look the object up to learn its real id.
      const listed = await b2.listFileVersions({ prefix: session.b2_key, maxFileCount: 1 })
      fileId = listed.files?.[0]?.fileId ?? null
    }
    if (!fileId) return c.json({ error: 'object was not committed by the storage provider' }, 502)

    const existing = await one(
      c.env.DB,
      `SELECT * FROM nodes WHERE user_id = ? AND parent_id IS ? AND name = ? AND kind = 'file' AND deleted_at IS NULL`,
      user.id, session.parent_id, session.name
    )
    if (existing?.b2_file_id) {
      const nextVersion = await nextVersionNumber(c, existing.id)
      await run(
        c.env.DB,
        `INSERT INTO versions (id, node_id, user_id, version, size_bytes, sha1, b2_file_id, b2_key, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        newId('ver'), existing.id, user.id, nextVersion, existing.size_bytes, existing.sha1 || '',
        existing.b2_file_id, existing.b2_key, now()
      )
      await pruneVersions(c, existing.id)
      await run(
        c.env.DB,
        `UPDATE nodes SET size_bytes = ?, content_type = ?, sha1 = ?, b2_file_id = ?, b2_key = ?, updated_at = ?
         WHERE id = ?`,
        actualSize, session.content_type, sha1, fileId, session.b2_key, now(), existing.id
      )
      const added = Math.max(0, actualSize - Number(existing.size_bytes || 0))
      await run(c.env.DB, `UPDATE users SET used_bytes = used_bytes + ? WHERE id = ?`, added, user.id)
      await run(c.env.DB, `UPDATE upload_sessions SET status = 'completed', node_id = ?, updated_at = ? WHERE id = ?`,
        existing.id, now(), session.id)
      await audit(c.env.DB, { userId: user.id, action: 'upload_complete', detail: `${session.name} (new version)` })
      return c.json({ node: mapNode(await one(c.env.DB, `SELECT * FROM nodes WHERE id = ?`, existing.id)), replaced: true })
    }

    await run(
      c.env.DB,
      `INSERT INTO nodes (id, user_id, parent_id, kind, name, size_bytes, content_type, sha1, b2_file_id, b2_key, created_at, updated_at)
       VALUES (?, ?, ?, 'file', ?, ?, ?, ?, ?, ?, ?, ?)`,
      session.node_id, user.id, session.parent_id, session.name, actualSize, session.content_type,
      sha1, fileId, session.b2_key, now(), now()
    )
    await run(c.env.DB, `UPDATE users SET used_bytes = used_bytes + ? WHERE id = ?`, actualSize, user.id)
    await run(c.env.DB, `UPDATE upload_sessions SET status = 'completed', actual_size = ?, updated_at = ? WHERE id = ?`,
      actualSize, now(), session.id)
    await audit(c.env.DB, { userId: user.id, action: 'upload_complete', detail: `${session.name} ${actualSize}B` })
    return c.json({ node: mapNode(await one(c.env.DB, `SELECT * FROM nodes WHERE id = ?`, session.node_id)) }, 201)
  })

  app.post('/v1/uploads/:id/cancel', async (c) => {
    const user = userOf(c)
    const session = await one(
      c.env.DB, `SELECT * FROM upload_sessions WHERE id = ? AND user_id = ?`, c.req.param('id'), user.id
    )
    if (!session) return c.json({ error: 'not found' }, 404)
    if (session.b2_file_id) {
      await b2.cancelLargeFile(session.b2_file_id).catch(() => null)
    }
    await run(c.env.DB, `DELETE FROM upload_parts WHERE session_id = ?`, session.id)
    await run(c.env.DB, `UPDATE upload_sessions SET status = 'cancelled', updated_at = ? WHERE id = ?`, now(), session.id)
    await audit(c.env.DB, { userId: user.id, action: 'upload_cancel', detail: session.name })
    return c.json({ cancelled: true })
  })

  // ---------------------------------------------------------------- sharing

  app.post('/v1/shares', async (c) => {
    const user = userOf(c)
    const body = await c.req.json().catch(() => ({}))
    const node = await ownedNode(c, body.nodeId)
    if (!node) return c.json({ error: 'not found' }, 404)
    const ttl = clampTtl(Number(body.expiresInSeconds))
    const id = newId('sh')
    const token = randomToken()
    await run(
      c.env.DB,
      `INSERT INTO shares (id, token, node_id, user_id, permission, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      id, token, node.id, user.id, 'read', ttl ? now() + ttl * 1000 : null, now()
    )
    await audit(c.env.DB, { userId: user.id, action: 'share_create', detail: node.name })
    return c.json({
      share: { id, token, url: `/v1/share/${token}`, expiresAt: ttl ? now() + ttl * 1000 : null, permission: 'read' }
    }, 201)
  })

  app.get('/v1/shares', async (c) => {
    const user = userOf(c)
    const rows = await many(
      c.env.DB,
      `SELECT s.id, s.token, s.node_id, s.expires_at, s.created_at, s.downloads, n.name, n.size_bytes
       FROM shares s JOIN nodes n ON n.id = s.node_id
       WHERE s.user_id = ? AND s.revoked_at IS NULL ORDER BY s.created_at DESC`,
      user.id
    )
    return c.json({ shares: rows })
  })

  app.delete('/v1/shares/:id', async (c) => {
    const user = userOf(c)
    await run(
      c.env.DB,
      `UPDATE shares SET revoked_at = ? WHERE id = ? AND user_id = ?`, now(), c.req.param('id'), user.id
    )
    await audit(c.env.DB, { userId: user.id, action: 'share_revoke', detail: c.req.param('id') })
    return c.json({ revoked: true })
  })

  /** Public, unauthenticated access to a share token. Short-lived download URL only. */
  app.get('/v1/share/:token', async (c) => {
    const share = await one(
      c.env.DB,
      `SELECT s.*, n.name, n.size_bytes, n.content_type, n.b2_key, n.kind
       FROM shares s JOIN nodes n ON n.id = s.node_id WHERE s.token = ?`, c.req.param('token')
    )
    if (!share || share.revoked_at) return c.json({ error: 'link is not valid' }, 404)
    if (share.expires_at && share.expires_at < now()) {
      return c.json({ error: 'link has expired', expiredAt: share.expires_at }, 410)
    }
    const token = await b2.getDownloadAuthorization({
      keyPrefix: share.b2_key,
      validDurationSeconds: DOWNLOAD_TTL_SECONDS
    })
    await run(c.env.DB, `UPDATE shares SET downloads = downloads + 1 WHERE id = ?`, share.id)
    await audit(c.env.DB, { userId: share.user_id, action: 'share_access', detail: share.name })
    return c.json({
      name: share.name, sizeBytes: share.size_bytes, contentType: share.content_type,
      url: b2.downloadUrl(share.b2_key, token), expiresInSeconds: DOWNLOAD_TTL_SECONDS
    })
  })

  // ---------------------------------------------------------------- backups

  app.post('/v1/backups/init', async (c) => {
    const user = userOf(c)
    const body = await c.req.json().catch(() => ({}))
    const size = Number(body.size)
    if (!Number.isFinite(size) || size <= 0) return c.json({ error: 'a positive size is required' }, 400)
    const guard = await assertWithinQuota(c.env.DB, user.id, size)
    if (!guard.ok) return c.json({ error: guard.error, detail: guard.detail }, guard.status)
    const id = newId('bk')
    const key = `u/${user.id}/backups/${id}.json`
    const url = await b2.getUploadUrl()
    await run(
      c.env.DB,
      `INSERT INTO backups (id, user_id, kind, label, size_bytes, sha256, b2_key, created_at)
       VALUES (?, ?, ?, ?, 0, '', ?, ?)`,
      id, user.id, String(body.kind || 'full_config'), String(body.label || '').slice(0, 120), key, now()
    )
    return c.json({ backupId: id, key, uploadUrl: url.uploadUrl, token: url.authorizationToken }, 201)
  })

  /** Verifies the payload the client actually stored: downloaded, hashed, compared. */
  app.post('/v1/backups/:id/commit', async (c) => {
    const user = userOf(c)
    const body = await c.req.json().catch(() => ({}))
    const backup = await one(
      c.env.DB, `SELECT * FROM backups WHERE id = ? AND user_id = ?`, c.req.param('id'), user.id
    )
    if (!backup) return c.json({ error: 'not found' }, 404)
    const token = await b2.getDownloadAuthorization({ keyPrefix: backup.b2_key, validDurationSeconds: 300 })
    const response = await fetch(b2.downloadUrl(backup.b2_key, token))
    if (!response.ok) return c.json({ error: 'backup payload is not readable' }, 502)
    const bytes = new Uint8Array(await response.arrayBuffer())
    const actualSha256 = await sha256Hex(bytes)
    const claimed = String(body.sha256 || '')
    if (bytes.byteLength !== Number(body.size)) {
      return c.json({ error: 'size mismatch', expected: body.size, actual: bytes.byteLength }, 409)
    }
    if (claimed && claimed !== actualSha256) {
      return c.json({ error: 'integrity check failed', expected: claimed, actual: actualSha256 }, 409)
    }
    const listed = await b2.listFileVersions({ prefix: backup.b2_key, maxFileCount: 1 })
    await run(
      c.env.DB,
      `UPDATE backups SET size_bytes = ?, sha256 = ?, b2_file_id = ? WHERE id = ?`,
      bytes.byteLength, actualSha256, listed.files?.[0]?.fileId ?? null, backup.id
    )
    await run(c.env.DB, `UPDATE users SET used_bytes = used_bytes + ? WHERE id = ?`, bytes.byteLength, user.id)
    await audit(c.env.DB, { userId: user.id, action: 'backup_create', detail: `${backup.kind} ${bytes.byteLength}B` })
    return c.json({ backupId: backup.id, sizeBytes: bytes.byteLength, sha256: actualSha256, verified: true })
  })

  app.get('/v1/backups', async (c) => {
    const user = userOf(c)
    const rows = await many(
      c.env.DB,
      `SELECT id, kind, label, size_bytes, sha256, created_at, restored_at FROM backups
       WHERE user_id = ? ORDER BY created_at DESC LIMIT 100`, user.id
    )
    return c.json({ backups: rows })
  })

  app.get('/v1/backups/:id', async (c) => {
    const user = userOf(c)
    const backup = await one(
      c.env.DB, `SELECT * FROM backups WHERE id = ? AND user_id = ?`, c.req.param('id'), user.id
    )
    if (!backup) return c.json({ error: 'not found' }, 404)
    const token = await b2.getDownloadAuthorization({ keyPrefix: backup.b2_key, validDurationSeconds: 300 })
    return c.json({
      backup: {
        id: backup.id, kind: backup.kind, label: backup.label,
        sizeBytes: backup.size_bytes, sha256: backup.sha256, createdAt: backup.created_at
      },
      url: b2.downloadUrl(backup.b2_key, token)
    })
  })

  app.post('/v1/backups/:id/restore', async (c) => {
    const user = userOf(c)
    const backup = await one(
      c.env.DB, `SELECT * FROM backups WHERE id = ? AND user_id = ?`, c.req.param('id'), user.id
    )
    if (!backup) return c.json({ error: 'not found' }, 404)
    const token = await b2.getDownloadAuthorization({ keyPrefix: backup.b2_key, validDurationSeconds: 300 })
    await run(c.env.DB, `UPDATE backups SET restored_at = ? WHERE id = ?`, now(), backup.id)
    await audit(c.env.DB, { userId: user.id, action: 'backup_restore', detail: `${backup.kind} ${backup.id}` })
    return c.json({
      backupId: backup.id, sha256: backup.sha256, sizeBytes: backup.size_bytes,
      url: b2.downloadUrl(backup.b2_key, token)
    })
  })

  app.delete('/v1/backups/:id', async (c) => {
    const user = userOf(c)
    const backup = await one(
      c.env.DB, `SELECT * FROM backups WHERE id = ? AND user_id = ?`, c.req.param('id'), user.id
    )
    if (!backup) return c.json({ error: 'not found' }, 404)
    if (backup.b2_file_id) {
      await b2.deleteFileVersion({ fileName: backup.b2_key, fileId: backup.b2_file_id }).catch(() => null)
    }
    await run(c.env.DB, `DELETE FROM backups WHERE id = ?`, backup.id)
    await run(c.env.DB, `UPDATE users SET used_bytes = MAX(0, used_bytes - ?) WHERE id = ?`, backup.size_bytes, user.id)
    return c.json({ deleted: true })
  })

  app.notFound((c) => c.json({ error: 'not found' }, 404))
  app.onError((error, c) => {
    const status = error?.status ?? 500
    return c.json({ error: error?.message || 'internal error' }, status)
  })

  // ---- helpers bound to the request context

  async function ownsNode(c, id) {
    const row = await one(c.env.DB, `SELECT id FROM nodes WHERE id = ? AND user_id = ?`, id, userOf(c).id)
    return Boolean(row)
  }

  async function ownedNode(c, id) {
    return one(c.env.DB, `SELECT * FROM nodes WHERE id = ? AND user_id = ?`, id, userOf(c).id)
  }

  async function nextVersionNumber(c, nodeId) {
    const row = await one(
      c.env.DB, `SELECT COALESCE(MAX(version), 0) AS v FROM versions WHERE node_id = ?`, nodeId
    )
    return Number(row?.v ?? 0) + 1
  }

  /** Keeps the newest N versions and deletes the older objects so storage stays honest. */
  async function pruneVersions(c, nodeId) {
    const rows = await many(
      c.env.DB,
      `SELECT id, b2_file_id, b2_key FROM versions WHERE node_id = ? ORDER BY version DESC`, nodeId
    )
    for (const stale of rows.slice(MAX_VERSIONS_KEPT)) {
      if (stale.b2_file_id) {
        await b2.deleteFileVersion({ fileName: stale.b2_key, fileId: stale.b2_file_id }).catch(() => null)
      }
      await run(c.env.DB, `DELETE FROM versions WHERE id = ?`, stale.id)
    }
  }

  async function nodeAction(c, action, handler, { readOnly = false } = {}) {
    const user = userOf(c)
    const node = await one(
      c.env.DB, `SELECT n.*, u.retention_days FROM nodes n JOIN users u ON u.id = n.user_id
                 WHERE n.id = ? AND n.user_id = ?`, c.req.param('id'), user.id
    )
    if (!node) return c.json({ error: 'not found' }, 404)
    const body = readOnly ? {} : await c.req.json().catch(() => ({}))
    const result = await handler(node, body)
    if (!readOnly) {
      await audit(c.env.DB, { userId: user.id, action, detail: node.name })
    }
    return c.json(result, result.status ?? 200)
  }

  return app
}

export default {
  async fetch(request, env) {
    // A test-mode Worker must never be reachable with a production bucket.
    if (env.AUTH_MODE === 'test' && /backblazeb2\.com$/.test(String(env.B2_API_BASE || ''))) {
      return new Response(JSON.stringify({ error: 'refusing to run in test mode against production B2' }), {
        status: 500, headers: { 'Content-Type': 'application/json' }
      })
    }
    return buildApp(env).fetch(request, env)
  }
}

export function objectKey(userId, nodeId, name) {
  return `u/${userId}/${nodeId}/${cleanName(name) || 'file'}`
}

export function cleanName(value) {
  const raw = String(value ?? '').replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').trim()
  return raw.slice(0, 200)
}

function randomToken() {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

function clampTtl(value) {
  if (!Number.isFinite(value) || value <= 0) return 0
  return Math.min(Math.floor(value), 30 * 86_400)
}

function mapNode(row) {
  if (!row) return null
  return {
    id: row.id, parentId: row.parent_id, kind: row.kind, name: row.name,
    sizeBytes: row.size_bytes, contentType: row.content_type, sha1: row.sha1,
    createdAt: row.created_at, updatedAt: row.updated_at,
    deletedAt: row.deleted_at, purgeAt: row.purge_at
  }
}

function publicAccount(row) {
  if (!row) return null
  return {
    id: row.id, email: row.email, createdAt: row.created_at,
    quotaBytes: row.quota_bytes, usedBytes: row.used_bytes, retentionDays: row.retention_days
  }
}

export async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('')
}

export { MIN_PART_SIZE }
