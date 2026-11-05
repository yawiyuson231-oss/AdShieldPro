import type { Env } from '../env';
import { ApiError } from '../http';
import { sha256Hex } from '../util/core';

/**
 * D1-backed fixed-window rate limiter.
 *
 * Counters are stored per (bucket, window) so a single atomic upsert both increments and
 * reports the current count. The key is hashed so raw IPs are never persisted.
 */
export interface RateLimitRule {
  /** logical bucket name, e.g. "upload:init" or "auth:register" */
  bucket: string;
  /** window length in seconds */
  windowSeconds: number;
  /** maximum requests allowed per window */
  limit: number;
}

export const RATE_LIMITS = {
  general: { bucket: 'api:general', windowSeconds: 60, limit: 240 },
  auth: { bucket: 'auth:token', windowSeconds: 300, limit: 30 },
  register: { bucket: 'auth:register', windowSeconds: 3600, limit: 8 },
  uploadInit: { bucket: 'upload:init', windowSeconds: 300, limit: 60 },
  uploadPart: { bucket: 'upload:part', windowSeconds: 60, limit: 600 },
  download: { bucket: 'download:issue', windowSeconds: 60, limit: 120 },
  share: { bucket: 'share:create', windowSeconds: 3600, limit: 40 },
  shareAccess: { bucket: 'share:access', windowSeconds: 300, limit: 60 },
  backup: { bucket: 'backup:write', windowSeconds: 3600, limit: 30 },
  search: { bucket: 'search', windowSeconds: 60, limit: 60 },
} as const satisfies Record<string, RateLimitRule>;

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  limit: number;
  resetAt: number;
}

export async function checkRateLimit(
  env: Env,
  rule: RateLimitRule,
  identity: string
): Promise<RateLimitResult> {
  const windowStart = Math.floor(Date.now() / 1000 / rule.windowSeconds) * rule.windowSeconds;
  const key = `${rule.bucket}:${(await sha256Hex(identity)).slice(0, 24)}`;
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits (bucket_key, window_start, count) VALUES (?, ?, 1)
     ON CONFLICT(bucket_key, window_start) DO UPDATE SET count = count + 1
     RETURNING count`
  )
    .bind(key, windowStart)
    .first<{ count: number }>();

  const count = row?.count ?? 1;
  return {
    allowed: count <= rule.limit,
    remaining: Math.max(0, rule.limit - count),
    limit: rule.limit,
    resetAt: (windowStart + rule.windowSeconds) * 1000,
  };
}

export async function enforceRateLimit(env: Env, rule: RateLimitRule, identity: string): Promise<RateLimitResult> {
  const result = await checkRateLimit(env, rule, identity);
  if (!result.allowed) {
    const retryAfter = Math.max(1, Math.ceil((result.resetAt - Date.now()) / 1000));
    throw new ApiError(429, 'rate_limited', `Too many requests. Retry in ${retryAfter}s.`, { retryAfter });
  }
  return result;
}

/** Opportunistic cleanup; called at most once per hour via a guarded WHERE clause. */
export async function pruneRateLimitWindows(env: Env): Promise<void> {
  const cutoff = Math.floor(Date.now() / 1000) - 24 * 3600;
  await env.DB.prepare('DELETE FROM rate_limits WHERE window_start < ?').bind(cutoff).run();
}
