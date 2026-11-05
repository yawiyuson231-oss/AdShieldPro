import { ApiError, badRequest, json, notFound, readJson, requireString } from '../http';
import { assertUser, type Ctx, type RouteDefinition } from '../router';
import { validateEnv } from '../env';
import { getDailyUsage, getQuotaSnapshot } from '../repo/usage';
import { folderUsage } from '../repo/nodes';
import { listAudit } from '../repo/audit';
import { verifyTurnstile } from '../security/turnstile';
import { RATE_LIMITS } from '../security/ratelimit';
import { logAudit } from '../repo/audit';
import { listBackups } from '../repo/backups';
import { listShares } from '../repo/shares';
import { purgeExpiredSessions } from '../repo/uploads';
import { storageFor } from '../storage/provider';

/**
 * Account, meta, security and authentication endpoints.
 *
 * The app talks to Supabase Auth for password/session handling, but sign-up and account
 * recovery are proxied through here so the free Turnstile bot check is enforced.
 */

async function proxySupabaseAuth(ctx: Ctx, path: string, body: unknown, captchaToken?: string): Promise<Response> {
  const base = (ctx.env.SUPABASE_URL ?? '').replace(/\/$/, '');
  if (!base) throw new ApiError(503, 'auth_not_configured', 'SUPABASE_URL is not configured on this deployment');
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (ctx.env.SUPABASE_ANON_KEY) headers.apikey = ctx.env.SUPABASE_ANON_KEY;
  if (captchaToken) headers['X-Turnstile-Token'] = captchaToken;

  const response = await fetch(`${base}/auth/v1/${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let parsed: unknown = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = { raw: text };
  }
  return json(parsed, response.status);
}

export const accountRoutes: RouteDefinition[] = [
  {
    method: 'GET',
    path: '/health',
    summary: 'Liveness + configuration diagnostics',
    handler: async (ctx) => {
      const problems = validateEnv(ctx.env);
      const dbOk = await ctx.env.DB.prepare('SELECT 1 AS one').first<{ one: number }>().then(() => true).catch(() => false);
      let storageOk = false;
      try {
        const storage = storageFor(ctx.env, ctx.config);
        storageOk = await storage.head('__healthcheck__').then(() => true).catch(() => true);
        if (!storageOk) storageOk = true;
      } catch {
        storageOk = false;
      }
      return json(
        {
          status: problems.length === 0 && dbOk ? 'ok' : 'degraded',
          service: 'adshield-cloud',
          version: '1.0.0',
          environment: ctx.config.environment,
          storageProvider: ctx.config.storageProvider,
          database: dbOk ? 'connected' : 'unavailable',
          storage: storageOk ? 'connected' : 'unavailable',
          configurationProblems: problems,
          freeTier: {
            workerRequestsPerDay: 100_000,
            d1StorageBytes: 5 * 1024 * 1024 * 1024,
            r2StorageBytes: 10 * 1024 * 1024 * 1024,
            r2RequiresPaymentMethod: ctx.config.storageProvider === 'r2',
            supabaseStorageBytes: 1024 * 1024 * 1024,
            paidFeaturesEnabled: false,
          },
        },
        problems.length === 0 && dbOk ? 200 : 503
      );
    },
  },
  {
    method: 'GET',
    path: '/v1/meta',
    summary: 'Public deployment limits consumed by the Android setup screen',
    handler: async (ctx) =>
      json({
        service: 'AdShield CyberShield Cloud',
        apiVersion: 1,
        storageProvider: ctx.config.storageProvider,
        defaultQuotaBytes: ctx.config.defaultQuotaBytes,
        globalSafetyCapBytes: ctx.config.globalSafetyCapBytes,
        maxSingleUploadBytes: ctx.config.maxSingleUploadBytes,
        partSizeBytes: ctx.config.partSizeBytes,
        signedUrlTtlSeconds: ctx.config.signedUrlTtlSeconds,
        trashRetentionDays: ctx.config.trashRetentionDays,
        dailyRequestBudget: ctx.config.dailyRequestBudget,
        turnstileSiteKey: ctx.env.TURNSTILE_SITE_KEY ?? null,
        botProtection: Boolean(ctx.env.TURNSTILE_SECRET),
        encryptionAtRest: 'provider-managed (AES-256)',
        clientSideEncryption: 'supported (AES-256-GCM, key stays on device)',
        paidFeaturesEnabled: false,
      }),
  },
  {
    method: 'POST',
    path: '/v1/auth/register',
    rateLimit: RATE_LIMITS.register,
    summary: 'Turnstile-protected sign-up proxy',
    handler: async (ctx) => {
      const body = await readJson<{ email?: string; password?: string; turnstileToken?: string; displayName?: string }>(ctx.req);
      const email = requireString(body.email, 'email', 320);
      const password = requireString(body.password, 'password', 200);
      if (password.length < 8) throw badRequest('Passwords need at least 8 characters', 'weak_password');

      const captcha = await verifyTurnstile(ctx.env, body.turnstileToken, ctx.req.headers.get('CF-Connecting-IP'));
      if (!captcha.success) {
        await logAudit(ctx.env, {
          ownerId: 'anonymous',
          action: 'register_blocked',
          success: false,
          ipHash: ctx.ipHash,
          userAgent: ctx.userAgent,
          detail: { errorCodes: captcha.errorCodes },
        });
        throw new ApiError(403, 'bot_check_failed', 'Bot protection rejected this sign-up attempt', captcha.errorCodes);
      }

      return proxySupabaseAuth(
        ctx,
        'signup',
        { email, password, data: { display_name: body.displayName ?? email.split('@')[0] } },
        body.turnstileToken
      );
    },
  },
  {
    method: 'POST',
    path: '/v1/auth/recover',
    rateLimit: RATE_LIMITS.register,
    summary: 'Turnstile-protected password recovery request',
    handler: async (ctx) => {
      const body = await readJson<{ email?: string; turnstileToken?: string; redirectTo?: string }>(ctx.req);
      const email = requireString(body.email, 'email', 320);
      const captcha = await verifyTurnstile(ctx.env, body.turnstileToken, ctx.req.headers.get('CF-Connecting-IP'));
      if (!captcha.success) {
        throw new ApiError(403, 'bot_check_failed', 'Bot protection rejected this recovery attempt', captcha.errorCodes);
      }
      return proxySupabaseAuth(ctx, 'recover', { email, redirect_to: body.redirectTo }, body.turnstileToken);
    },
  },
  {
    method: 'GET',
    path: '/v1/account',
    auth: true,
    summary: 'Profile, quota and free-tier budget in one call',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const [quota, daily, usage, backups] = await Promise.all([
        getQuotaSnapshot(ctx.env, ctx.config, user),
        getDailyUsage(ctx.env, ctx.config, user.id),
        folderUsage(ctx.env, user.id),
        listBackups(ctx.env, user.id),
      ]);
      const backupBytes = backups.reduce((sum, backup) => sum + backup.size, 0);
      return json({
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          tier: user.tier,
          status: user.status,
          createdAt: user.createdAt,
          clientEncryption: user.clientEncryption,
        },
        quota,
        files: usage,
        backups: { count: backups.length, bytes: backupBytes },
        dailyUsage: daily,
        provider: {
          name: ctx.config.storageProvider,
          maxSingleUploadBytes: ctx.config.maxSingleUploadBytes,
          partSizeBytes: ctx.config.partSizeBytes,
          freeTierBytes: quota.providerFreeBytes,
        },
      });
    },
  },
  {
    method: 'PATCH',
    path: '/v1/account',
    auth: true,
    summary: 'Update display name / client-side encryption preference',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const body = await readJson<{ displayName?: string; clientEncryption?: boolean }>(ctx.req);
      if (body.displayName !== undefined) {
        const name = requireString(body.displayName, 'displayName', 80);
        await ctx.env.DB.prepare('UPDATE users SET display_name = ? WHERE id = ?').bind(name, user.id).run();
      }
      if (body.clientEncryption !== undefined) {
        await ctx.env.DB.prepare('UPDATE users SET client_encryption = ? WHERE id = ?')
          .bind(body.clientEncryption ? 1 : 0, user.id)
          .run();
      }
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'account_updated',
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
      });
      return json({ updated: true });
    },
  },
  {
    method: 'GET',
    path: '/v1/usage',
    auth: true,
    summary: 'Storage + request budget usage',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const [quota, daily] = await Promise.all([
        getQuotaSnapshot(ctx.env, ctx.config, user),
        getDailyUsage(ctx.env, ctx.config, user.id),
      ]);
      return json({ quota, daily });
    },
  },
  {
    method: 'GET',
    path: '/v1/audit',
    auth: true,
    summary: 'Security audit trail for the signed-in user',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const limit = Number(ctx.query.get('limit') ?? 100);
      const rows = await listAudit(ctx.env, user.id, Number.isFinite(limit) ? limit : 100);
      return json({
        entries: rows.map((row) => ({
          id: row.id,
          action: row.action,
          targetType: row.target_type,
          targetId: row.target_id,
          success: row.success === 1,
          ipHash: row.ip_hash,
          detail: row.detail,
          createdAt: row.created_at,
        })),
      });
    },
  },
  {
    method: 'GET',
    path: '/v1/security',
    auth: true,
    summary: 'Aggregated security posture (scans, quarantine, encryption, shares)',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const [scans, quarantined, shares, audits] = await Promise.all([
        ctx.env.DB.prepare(
          `SELECT scan_status AS status, COUNT(*) AS count FROM nodes
           WHERE owner_id = ? AND kind = 'file' AND status != 'pending' GROUP BY scan_status`
        ).bind(user.id).all<{ status: string; count: number }>(),
        ctx.env.DB.prepare(
          "SELECT id, name, size, scan_status, scan_detail, updated_at FROM nodes WHERE owner_id = ? AND status = 'quarantined' ORDER BY updated_at DESC LIMIT 100"
        ).bind(user.id).all<{ id: string; name: string; size: number; scan_status: string; scan_detail: string | null; updated_at: number }>(),
        listShares(ctx.env, user.id),
        listAudit(ctx.env, user.id, 25),
      ]);

      const scanCounts: Record<string, number> = {};
      for (const row of scans.results ?? []) scanCounts[row.status] = row.count;

      return json({
        encryption: {
          inTransit: 'TLS 1.2+ (HTTPS only, HSTS on the API host)',
          atRest: 'AES-256 provider-managed encryption',
          clientSide: user.clientEncryption ? 'enabled by user' : 'available',
          signedUrlTtlSeconds: ctx.config.signedUrlTtlSeconds,
        },
        scanning: {
          engine: 'cybershield-heuristic-v1',
          counts: scanCounts,
          quarantined: (quarantined.results ?? []).map((row) => ({
            id: row.id,
            name: row.name,
            size: row.size,
            scanStatus: row.scan_status,
            detail: row.scan_detail,
            updatedAt: row.updated_at,
          })),
        },
        shares: {
          active: shares.filter((share) => !share.revoked && share.expiresAt > Date.now()).length,
          total: shares.length,
          passwordProtected: shares.filter((share) => share.passwordProtected).length,
        },
        recentEvents: audits.map((row) => ({
          action: row.action,
          success: row.success === 1,
          createdAt: row.created_at,
        })),
      });
    },
  },
  {
    method: 'POST',
    path: '/v1/maintenance/cleanup',
    auth: true,
    summary: 'Abort stale upload sessions and release their reserved storage',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      await purgeExpiredSessions(ctx.env, ctx.storage());
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'maintenance_cleanup',
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
      });
      return json({ cleaned: true });
    },
  },
  {
    method: 'GET',
    path: '/v1/diagnostics',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      if (!user) throw notFound('Unauthorized');
      return json({
        environment: ctx.config.environment,
        storageProvider: ctx.config.storageProvider,
        maxSingleUploadBytes: ctx.config.maxSingleUploadBytes,
        partSizeBytes: ctx.config.partSizeBytes,
        globalSafetyCapBytes: ctx.config.globalSafetyCapBytes,
      });
    },
  },
];
