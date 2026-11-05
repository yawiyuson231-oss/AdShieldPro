/**
 * Typed environment bindings for the CyberShield cloud worker.
 * Every value used by the API is declared here so misconfiguration fails fast.
 */
export interface Env {
  DB: D1Database;
  BUCKET?: R2Bucket;

  ENVIRONMENT: string;
  STORAGE_PROVIDER: string;

  DEFAULT_QUOTA_BYTES: string;
  GLOBAL_SAFETY_CAP_BYTES: string;
  MAX_SINGLE_UPLOAD_BYTES: string;
  PART_SIZE_BYTES: string;
  SIGNED_URL_TTL_SECONDS: string;
  TRASH_RETENTION_DAYS: string;
  DAILY_REQUEST_BUDGET: string;
  ALLOWED_ORIGINS: string;
  RATE_LIMIT_GENERAL_PER_MINUTE?: string;

  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET?: string;
  SUPABASE_URL?: string;
  SUPABASE_ANON_KEY?: string;
  SUPABASE_SERVICE_ROLE_KEY?: string;
  SUPABASE_JWT_SECRET?: string;
  SUPABASE_STORAGE_BUCKET?: string;
  SERVER_SECRET?: string;
  SCANNER_URL?: string;
}

export interface AppConfig {
  storageProvider: 'r2' | 'supabase';
  defaultQuotaBytes: number;
  globalSafetyCapBytes: number;
  maxSingleUploadBytes: number;
  partSizeBytes: number;
  signedUrlTtlSeconds: number;
  trashRetentionDays: number;
  dailyRequestBudget: number;
  rateLimitGeneralPerMinute: number;
  allowedOrigins: string[];
  environment: string;
}

function int(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function loadConfig(env: Env): AppConfig {
  const provider = (env.STORAGE_PROVIDER ?? 'r2').toLowerCase();
  return {
    storageProvider: provider === 'supabase' ? 'supabase' : 'r2',
    defaultQuotaBytes: int(env.DEFAULT_QUOTA_BYTES, 1024 * 1024 * 1024),
    globalSafetyCapBytes: int(env.GLOBAL_SAFETY_CAP_BYTES, 9 * 1024 * 1024 * 1024),
    maxSingleUploadBytes: int(env.MAX_SINGLE_UPLOAD_BYTES, 100 * 1024 * 1024),
    partSizeBytes: int(env.PART_SIZE_BYTES, 8 * 1024 * 1024),
    signedUrlTtlSeconds: int(env.SIGNED_URL_TTL_SECONDS, 300),
    trashRetentionDays: int(env.TRASH_RETENTION_DAYS, 30),
    dailyRequestBudget: int(env.DAILY_REQUEST_BUDGET, 100_000),
    rateLimitGeneralPerMinute: int(env.RATE_LIMIT_GENERAL_PER_MINUTE, 240),
    allowedOrigins: (env.ALLOWED_ORIGINS ?? '*')
      .split(',')
      .map((o) => o.trim())
      .filter(Boolean),
    environment: env.ENVIRONMENT ?? 'production',
  };
}

/** True when the deployment has every secret it needs to serve real traffic. */
export function validateEnv(env: Env): string[] {
  const problems: string[] = [];
  if (!env.DB) problems.push('D1 binding DB is missing');
  const cfg = loadConfig(env);
  if (cfg.storageProvider === 'r2' && !env.BUCKET) {
    problems.push('R2 binding BUCKET is missing (or set STORAGE_PROVIDER="supabase")');
  }
  if (cfg.storageProvider === 'supabase' && !env.SUPABASE_SERVICE_ROLE_KEY) {
    problems.push('SUPABASE_SERVICE_ROLE_KEY is required for STORAGE_PROVIDER="supabase"');
  }
  if (!env.SERVER_SECRET || env.SERVER_SECRET.length < 32) {
    problems.push('SERVER_SECRET must be at least 32 characters (HMAC key for signed URLs)');
  }
  if (!env.SUPABASE_URL) problems.push('SUPABASE_URL is required to verify user identity');
  if (!env.SUPABASE_JWT_SECRET && !env.SUPABASE_URL) {
    problems.push('SUPABASE_JWT_SECRET or SUPABASE_URL is required');
  }
  return problems;
}
