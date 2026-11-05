import type { AppConfig, Env } from '../env';
import { ApiError, quotaExceeded } from '../http';
import { randomId, utcDay } from '../util/core';
import type { AuthedUser } from '../security/auth';

/**
 * Quota + free-tier guardrails.
 *
 * Two independent ceilings are enforced so the deployment can never silently spill into a
 * paid plan or claim capacity it does not have:
 *   1. per-user quota (users.quota_bytes)
 *   2. a global safety cap (config.globalSafetyCapBytes) that sits below the provider's
 *      real free allowance (e.g. 9 GiB under R2's 10 GB)
 */
export interface QuotaSnapshot {
  quotaBytes: number;
  usedBytes: number;
  remainingBytes: number;
  percentUsed: number;
  globalCapBytes: number;
  globalUsedBytes: number;
  globalRemainingBytes: number;
  providerFreeBytes: number;
  tier: string;
  canUpload: boolean;
}

export function providerFreeBytes(config: AppConfig): number {
  return config.storageProvider === 'supabase' ? 1024 * 1024 * 1024 : 10 * 1024 * 1024 * 1024;
}

export async function getQuotaSnapshot(env: Env, config: AppConfig, user: AuthedUser): Promise<QuotaSnapshot> {
  const global = await env.DB.prepare('SELECT COALESCE(SUM(used_bytes), 0) AS used FROM users').first<{ used: number }>();
  const globalUsed = global?.used ?? 0;
  const remaining = Math.max(0, user.quotaBytes - user.usedBytes);
  const globalRemaining = Math.max(0, config.globalSafetyCapBytes - globalUsed);
  return {
    quotaBytes: user.quotaBytes,
    usedBytes: user.usedBytes,
    remainingBytes: remaining,
    percentUsed: user.quotaBytes > 0 ? Math.min(100, (user.usedBytes / user.quotaBytes) * 100) : 0,
    globalCapBytes: config.globalSafetyCapBytes,
    globalUsedBytes: globalUsed,
    globalRemainingBytes: globalRemaining,
    providerFreeBytes: providerFreeBytes(config),
    tier: user.tier,
    canUpload: remaining > 0 && globalRemaining > 0 && user.status === 'active',
  };
}

/** Throws a 507 when an upload would exceed either ceiling. */
export async function assertCapacity(
  env: Env,
  config: AppConfig,
  user: AuthedUser,
  additionalBytes: number
): Promise<QuotaSnapshot> {
  const snapshot = await getQuotaSnapshot(env, config, user);
  if (user.status !== 'active') {
    throw new ApiError(403, 'account_suspended', 'This account is suspended and cannot upload');
  }
  if (additionalBytes > snapshot.remainingBytes) {
    throw quotaExceeded(
      `Not enough cloud space. ${snapshot.remainingBytes} bytes remain of your ${snapshot.quotaBytes} byte quota.`,
      { remainingBytes: snapshot.remainingBytes, requiredBytes: additionalBytes, scope: 'user' }
    );
  }
  if (additionalBytes > snapshot.globalRemainingBytes) {
    throw quotaExceeded(
      'The shared free-tier storage pool is full. No paid storage will be enabled automatically.',
      { remainingBytes: snapshot.globalRemainingBytes, requiredBytes: additionalBytes, scope: 'global' }
    );
  }
  return snapshot;
}

export async function addUserUsage(
  env: Env,
  ownerId: string,
  deltaBytes: number,
  reason: string,
  nodeId?: string
): Promise<void> {
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET used_bytes = MAX(0, used_bytes + ?) WHERE id = ?').bind(deltaBytes, ownerId),
    env.DB.prepare(
      'INSERT INTO quota_events (id, owner_id, delta, reason, node_id, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(randomId('qev'), ownerId, deltaBytes, reason, nodeId ?? null, Date.now()),
  ]);
}

export async function recordApiUsage(
  env: Env,
  ownerId: string,
  bytesUp: number,
  bytesDown: number
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO api_usage (day, owner_id, requests, bytes_up, bytes_down) VALUES (?, ?, 1, ?, ?)
     ON CONFLICT(day, owner_id) DO UPDATE SET
       requests = requests + 1,
       bytes_up = bytes_up + excluded.bytes_up,
       bytes_down = bytes_down + excluded.bytes_down`
  )
    .bind(utcDay(), ownerId, bytesUp, bytesDown)
    .run();
}

export interface DailyUsage {
  day: string;
  requests: number;
  requestBudget: number;
  percentOfBudget: number;
  bytesUp: number;
  bytesDown: number;
  remainingRequests: number;
}

export async function getDailyUsage(env: Env, config: AppConfig, ownerId: string): Promise<DailyUsage> {
  const day = utcDay();
  const row = await env.DB.prepare('SELECT * FROM api_usage WHERE day = ? AND owner_id = ?')
    .bind(day, ownerId)
    .first<{ requests: number; bytes_up: number; bytes_down: number }>();
  const requests = row?.requests ?? 0;
  return {
    day,
    requests,
    requestBudget: config.dailyRequestBudget,
    percentOfBudget: Math.min(100, (requests / config.dailyRequestBudget) * 100),
    bytesUp: row?.bytes_up ?? 0,
    bytesDown: row?.bytes_down ?? 0,
    remainingRequests: Math.max(0, config.dailyRequestBudget - requests),
  };
}
