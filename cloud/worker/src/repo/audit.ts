import type { Env } from '../env';
import { randomId } from '../util/core';

export interface AuditEntry {
  ownerId: string;
  action: string;
  targetType?: string;
  targetId?: string;
  success?: boolean;
  ipHash?: string;
  userAgent?: string;
  detail?: Record<string, unknown>;
}

/** Append-only audit trail. Never throws: logging must not break the request path. */
export async function logAudit(env: Env, entry: AuditEntry): Promise<void> {
  try {
    await env.DB.prepare(
      `INSERT INTO audit_logs (id, owner_id, action, target_type, target_id, success, ip_hash, user_agent, detail, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        randomId('aud'),
        entry.ownerId,
        entry.action,
        entry.targetType ?? null,
        entry.targetId ?? null,
        entry.success === false ? 0 : 1,
        entry.ipHash ?? null,
        entry.userAgent?.slice(0, 300) ?? null,
        entry.detail ? JSON.stringify(entry.detail).slice(0, 2000) : null,
        Date.now()
      )
      .run();
  } catch {
    // Audit logging is best-effort by design (a D1 write-capacity error must not fail uploads).
  }
}

export interface AuditRow {
  id: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  success: number;
  ip_hash: string | null;
  detail: string | null;
  created_at: number;
}

export async function listAudit(env: Env, ownerId: string, limit = 100): Promise<AuditRow[]> {
  const result = await env.DB.prepare(
    'SELECT id, action, target_type, target_id, success, ip_hash, detail, created_at FROM audit_logs WHERE owner_id = ? ORDER BY created_at DESC LIMIT ?'
  )
    .bind(ownerId, Math.min(Math.max(limit, 1), 500))
    .all<AuditRow>();
  return result.results ?? [];
}
