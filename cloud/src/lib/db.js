/**
 * Thin D1 helpers.
 *
 * D1's prepared-statement API is the only interface the routes use, so the same code runs in
 * production (D1) and in the local test harness (a node:sqlite wrapper with identical methods).
 */
export function q(db, sql, ...binds) {
  return db.prepare(sql).bind(...binds)
}

export async function one(db, sql, ...binds) {
  return (await db.prepare(sql).bind(...binds).all()).results?.[0] ?? null
}

export async function many(db, sql, ...binds) {
  return (await db.prepare(sql).bind(...binds).all()).results ?? []
}

export async function run(db, sql, ...binds) {
  return db.prepare(sql).bind(...binds).run()
}

export function now() {
  return Date.now()
}

export function newId(prefix) {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  let hex = ''
  for (const b of bytes) hex += b.toString(16).padStart(2, '0')
  return `${prefix}_${hex}`
}

const AUDIT_ACTIONS = new Set([
  'signup', 'login', 'upload_init', 'upload_complete', 'upload_cancel', 'download',
  'folder_create', 'rename', 'move', 'copy', 'delete', 'restore', 'purge',
  'share_create', 'share_revoke', 'share_access', 'backup_create', 'backup_restore',
  'quota_refused', 'scan_duplicates', 'version_create'
])

export async function audit(db, { userId, action, detail = '', ip = '' }) {
  if (!AUDIT_ACTIONS.has(action)) throw new Error(`unknown audit action: ${action}`)
  await run(
    db,
    `INSERT INTO audit_log (id, user_id, action, detail, ip, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
    newId('aud'), userId, action, String(detail).slice(0, 500), String(ip).slice(0, 64), now()
  )
}

/** Bumps the per-hour request counter used to warn before the provider's limits are hit. */
export async function countRequest(db, userId, cost = 1) {
  const bucket = Math.floor(Date.now() / 3_600_000)
  await run(
    db,
    `INSERT INTO api_usage (user_id, bucket, requests) VALUES (?, ?, ?)
     ON CONFLICT(user_id, bucket) DO UPDATE SET requests = requests + excluded.requests`,
    userId, bucket, cost
  )
  const row = await one(db, `SELECT requests FROM api_usage WHERE user_id = ? AND bucket = ?`, userId, bucket)
  return row?.requests ?? 0
}

export async function usageInWindow(db, userId, hours = 24) {
  const from = Math.floor(Date.now() / 3_600_000) - hours + 1
  const rows = await many(db, `SELECT SUM(requests) AS total FROM api_usage WHERE user_id = ? AND bucket >= ?`, userId, from)
  return Number(rows?.[0]?.total ?? 0)
}
