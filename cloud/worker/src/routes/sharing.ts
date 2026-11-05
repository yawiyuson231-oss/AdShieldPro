import { ApiError, badRequest, json, readJson, requireString } from '../http';
import { assertUser, type RouteDefinition } from '../router';
import {
  createShare,
  listShares,
  recordShareAccess,
  resolveShareToken,
  revokeShare,
  verifySharePassword,
} from '../repo/shares';
import { signToken } from '../security/tokens';
import { RATE_LIMITS } from '../security/ratelimit';
import { logAudit } from '../repo/audit';
import { policyFor } from '../util/mime';

/**
 * Secure sharing.
 *
 * Tokens are 256-bit random values; only their SHA-256 hash is stored. Optional PBKDF2
 * password, expiry, download limits and instant revocation are all enforced server-side.
 */
export const sharingRoutes: RouteDefinition[] = [
  {
    method: 'POST',
    path: '/v1/shares',
    auth: true,
    rateLimit: RATE_LIMITS.share,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const body = await readJson<{
        nodeId?: string;
        expiresInSeconds?: number;
        maxDownloads?: number;
        password?: string;
        allowPreview?: boolean;
      }>(ctx.req);
      const nodeId = requireString(body.nodeId, 'nodeId', 80);
      const result = await createShare(ctx.env, user.id, {
        nodeId,
        expiresInSeconds: body.expiresInSeconds,
        maxDownloads: body.maxDownloads,
        password: body.password,
        allowPreview: body.allowPreview,
      });
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'share_created',
        targetType: 'node',
        targetId: nodeId,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
        detail: {
          expiresAt: result.expiresAt,
          passwordProtected: Boolean(body.password),
          maxDownloads: body.maxDownloads ?? 0,
        },
      });
      return json(
        {
          share: result.share,
          token: result.token,
          shareUrl: `${ctx.url.origin}/s/${result.token}`,
          note: 'Store this URL now — the token is not recoverable later. Only its hash is kept.',
        },
        201
      );
    },
  },
  {
    method: 'GET',
    path: '/v1/shares',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      return json({ shares: await listShares(ctx.env, user.id) });
    },
  },
  {
    method: 'DELETE',
    path: '/v1/shares/:id',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      await revokeShare(ctx.env, user.id, ctx.params.id);
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'share_revoked',
        targetType: 'share',
        targetId: ctx.params.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
      });
      return json({ revoked: true });
    },
  },
  {
    method: 'GET',
    path: '/s/:token',
    rateLimit: RATE_LIMITS.shareAccess,
    summary: 'Public share metadata (no bytes without a valid download call)',
    handler: async (ctx) => {
      const { share, node } = await resolveShareToken(ctx.env, ctx.params.token);
      const policy = policyFor(node.name, node.mime ?? undefined);
      return json({
        fileName: node.name,
        size: node.size,
        mime: node.mime,
        previewable: policy.previewable && share.allow_preview === 1,
        requiresPassword: Boolean(share.password_hash),
        expiresAt: share.expires_at,
        remainingDownloads: share.max_downloads > 0 ? Math.max(0, share.max_downloads - share.download_count) : null,
      });
    },
  },
  {
    method: 'POST',
    path: '/s/:token/download',
    rateLimit: RATE_LIMITS.shareAccess,
    summary: 'Exchange a share token (+password) for a short-lived signed download URL',
    handler: async (ctx) => {
      const body = await readJson<{ password?: string }>(ctx.req).catch(() => ({ password: undefined }));
      const { share, node } = await resolveShareToken(ctx.env, ctx.params.token);
      await verifySharePassword(share, body.password);

      const ttl = Math.min(ctx.config.signedUrlTtlSeconds, 300);
      const signed = await signToken(
        ctx.env.SERVER_SECRET ?? '',
        {
          p: 'share-download',
          sub: `share:${share.id}`,
          nodeId: node.id,
          storageKey: node.storage_key ?? '',
          maxBytes: node.size,
        },
        ttl
      );
      await recordShareAccess(ctx.env, share.id, true);
      await logAudit(ctx.env, {
        ownerId: share.owner_id,
        action: 'share_downloaded',
        targetType: 'share',
        targetId: share.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
      });
      return json({
        url: `${ctx.url.origin}/d/${signed.token}`,
        expiresAt: signed.expiresAt,
        fileName: node.name,
        size: node.size,
        mime: node.mime,
        sha256: node.sha256,
      });
    },
  },
  {
    method: 'POST',
    path: '/s/:token/preview',
    rateLimit: RATE_LIMITS.shareAccess,
    handler: async (ctx) => {
      const body = await readJson<{ password?: string }>(ctx.req).catch(() => ({ password: undefined }));
      const { share, node } = await resolveShareToken(ctx.env, ctx.params.token);
      await verifySharePassword(share, body.password);
      const policy = policyFor(node.name, node.mime ?? undefined);
      if (!policy.previewable || share.allow_preview === 0) {
        throw new ApiError(415, 'preview_disabled', 'The owner disabled previews for this share');
      }
      const signed = await signToken(
        ctx.env.SERVER_SECRET ?? '',
        { p: 'preview', sub: `share:${share.id}`, nodeId: node.id, storageKey: node.storage_key ?? '', maxBytes: node.size },
        120
      );
      await recordShareAccess(ctx.env, share.id, false);
      return json({ url: `${ctx.url.origin}/d/${signed.token}`, expiresAt: signed.expiresAt, mime: node.mime });
    },
  },
  {
    method: 'PUT',
    path: '/s/:token',
    auth: true,
    summary: 'Owner-only share update placeholder (rejects anonymous edits)',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const list = await listShares(ctx.env, user.id);
      if (!list.some((share) => share.id === ctx.params.token)) {
        throw badRequest('Unknown share', 'share_not_found');
      }
      return json({ shares: list });
    },
  },
];
