import { one, run, many, now } from './db.js'

/**
 * Quota is enforced from real numbers: the free allowance is a per-user ceiling (default
 * 10 GiB, the Backblaze B2 free tier) and `used_bytes` only ever moves when a real upload
 * finishes, a real object is purged, or a reconciliation against B2 proves it wrong.
 *
 * Nothing here upgrades the user to a paid tier. When the ceiling is reached the API returns
 * 413 with the exact bytes remaining so the client can explain it instead of failing silently.
 */
export const DEFAULT_QUOTA_BYTES = 10 * 1024 * 1024 * 1024

export async function getAccount(db, userId) {
  const user = await one(db, `SELECT * FROM users WHERE id = ?`, userId)
  return user
}

export async function createAccount(db, { userId, email, quotaBytes = DEFAULT_QUOTA_BYTES }) {
  await run(
    db,
    `INSERT INTO users (id, email, created_at, quota_bytes, used_bytes) VALUES (?, ?, ?, ?, 0)
     ON CONFLICT(id) DO UPDATE SET email = excluded.email`,
    userId, String(email || ''), now(), quotaBytes
  )
  return getAccount(db, userId)
}

export async function usage(db, userId) {
  const user = await getAccount(db, userId)
  if (!user) return null
  const trashed = await one(
    db,
    `SELECT COUNT(*) AS files, COALESCE(SUM(size_bytes), 0) AS bytes
     FROM nodes WHERE user_id = ? AND kind = 'file' AND deleted_at IS NOT NULL`,
    userId
  )
  return {
    quotaBytes: user.quota_bytes,
    usedBytes: user.used_bytes,
    remainingBytes: Math.max(0, user.quota_bytes - user.used_bytes),
    percentUsed: user.quota_bytes > 0 ? Math.round((user.used_bytes / user.quota_bytes) * 1000) / 10 : 0,
    trashedFiles: Number(trashed?.files ?? 0),
    trashedBytes: Number(trashed?.bytes ?? 0)
  }
}

export async function assertWithinQuota(db, userId, additionalBytes) {
  const current = await usage(db, userId)
  if (!current) return { ok: false, status: 401, error: 'unknown account' }
  if (additionalBytes > current.remainingBytes) {
    return {
      ok: false,
      status: 413,
      error: 'quota exceeded',
      detail: {
        requestedBytes: additionalBytes,
        remainingBytes: current.remainingBytes,
        quotaBytes: current.quotaBytes,
        usedBytes: current.usedBytes
      }
    }
  }
  return { ok: true, usage: current }
}

export function quotaWarning(usageState) {
  if (usageState.remainingBytes <= 0) {
    return { level: 'blocked', message: 'Storage is full. Delete or empty the trash before uploading.' }
  }
  const ratio = usageState.usedBytes / usageState.quotaBytes
  if (ratio >= 0.9) {
    return { level: 'critical', message: 'Over 90% of the 10 GB free allowance is used.' }
  }
  if (ratio >= 0.75) {
    return { level: 'warn', message: 'Over 75% of the 10 GB free allowance is used.' }
  }
  return { level: 'ok', message: 'Within the free allowance.' }
}

/**
 * Rebuilds used_bytes from the objects B2 actually reports. Called by /v1/account/reconcile
 * and by the tests, so a counter bug can never masquerade as free space.
 */
export async function reconcile(db, b2, userId) {
  const prefix = `u/${userId}/`
  let total = 0
  let objects = 0
  let startFileName = null
  let startFileId = null
  for (let page = 0; page < 50; page++) {
    const result = await b2.listFileVersions({ prefix, maxFileCount: 1000, startFileName, startFileId })
    for (const file of result.files ?? []) {
      if (file.action !== 'upload') continue
      total += Number(file.size || file.contentLength || 0)
      objects += 1
    }
    if (!result.nextFileName && !result.nextFileId) break
    startFileName = result.nextFileName || null
    startFileId = result.nextFileId || null
  }
  // Account for every distinct stored B2 object tracked by the database:
  // live + trashed files (deduped across shallow copies), retained versions, and backups.
  const distinctObjects = await many(
    db,
    `SELECT b2_file_id, MAX(size_bytes) AS size_bytes FROM (
       SELECT b2_file_id, size_bytes FROM nodes
         WHERE user_id = ? AND kind = 'file' AND b2_file_id IS NOT NULL
       UNION ALL
       SELECT b2_file_id, size_bytes FROM versions
         WHERE user_id = ? AND b2_file_id IS NOT NULL
       UNION ALL
       SELECT b2_file_id, size_bytes FROM backups
         WHERE user_id = ? AND b2_file_id IS NOT NULL
     ) GROUP BY b2_file_id`,
    userId, userId, userId
  )
  const dbBytes = distinctObjects.reduce((sum, r) => sum + Number(r.size_bytes || 0), 0)
  await run(db, `UPDATE users SET used_bytes = ? WHERE id = ?`, total, userId)
  return {
    b2Bytes: total,
    b2Objects: objects,
    databaseBytes: dbBytes,
    driftBytes: total - dbBytes
  }
}
