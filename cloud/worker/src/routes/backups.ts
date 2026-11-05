import { badRequest, json, readJson, requireString } from '../http';
import { assertUser, type RouteDefinition } from '../router';
import {
  BACKUP_KINDS,
  deleteBackup,
  getBackup,
  listBackups,
  markBackupRestored,
  toBackupDto,
  verifyBackupIntegrity,
} from '../repo/backups';
import { initUpload } from '../repo/uploads';
import { assertCapacity } from '../repo/usage';
import { signToken } from '../security/tokens';
import { RATE_LIMITS } from '../security/ratelimit';
import { logAudit } from '../repo/audit';

/**
 * DNS / security configuration backups.
 *
 * The Android app builds a JSON snapshot of its DNS configuration, blocklists, allow/deny
 * lists, firewall settings and preferences, encrypts it on-device (AES-256-GCM, key derived
 * from a user passphrase and never uploaded) and stores the ciphertext here. The server
 * only sees an opaque blob plus its SHA-256, which is how integrity verification works.
 */
export const backupRoutes: RouteDefinition[] = [
  {
    method: 'POST',
    path: '/v1/backups/init',
    auth: true,
    rateLimit: RATE_LIMITS.backup,
    summary: 'Start an encrypted configuration backup upload',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const body = await readJson<{
        size?: number;
        sha256?: string;
        kind?: string;
        label?: string;
        appVersion?: string;
      }>(ctx.req, ctx.config);

      const kind = (body.kind ?? 'full') as (typeof BACKUP_KINDS)[number];
      if (!BACKUP_KINDS.includes(kind)) {
        throw badRequest(`kind must be one of ${BACKUP_KINDS.join(', ')}`, 'invalid_kind');
      }
      const size = Number(body.size);
      await assertCapacity(ctx.env, ctx.config, user, size);
      const label = requireString(body.label ?? `CyberShield backup ${new Date().toISOString().slice(0, 16).replace('T', ' ')}`, 'label', 120);
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');

      const result = await initUpload(ctx.env, ctx.config, user, ctx.storage(), {
        name: `backup-${kind}-${stamp}.cshield`,
        size,
        mime: 'application/x-adshield-backup',
        sha256: body.sha256,
        encrypted: true,
        purpose: 'backup',
        backupKind: kind,
        backupLabel: label,
      });

      const token = await signToken(
        ctx.env.SERVER_SECRET ?? '',
        { p: 'upload-part', sub: user.id, uploadId: result.uploadId },
        3600
      );
      return json(
        {
          ...result,
          kind,
          label,
          uploadToken: token.token,
          uploadTokenExpiresAt: token.expiresAt,
          uploadUrl: `${ctx.url.origin}/v1/upload/${result.uploadId}/content`,
          encryptionNote: 'The server stores ciphertext only. Keep your passphrase safe: without it the backup cannot be restored.',
        },
        201
      );
    },
  },
  {
    method: 'GET',
    path: '/v1/backups',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const kind = ctx.query.get('kind') ?? undefined;
      const backups = await listBackups(ctx.env, user.id, kind);
      return json({
        backups,
        totalBytes: backups.reduce((sum, backup) => sum + backup.size, 0),
        kinds: BACKUP_KINDS,
      });
    },
  },
  {
    method: 'GET',
    path: '/v1/backups/:id',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const row = await getBackup(ctx.env, user.id, ctx.params.id);
      return json({ backup: toBackupDto(row) });
    },
  },
  {
    method: 'GET',
    path: '/v1/backups/:id/download',
    auth: true,
    rateLimit: RATE_LIMITS.download,
    summary: 'Signed URL for the encrypted backup blob',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const row = await getBackup(ctx.env, user.id, ctx.params.id);
      const signed = await signToken(
        ctx.env.SERVER_SECRET ?? '',
        { p: 'backup-download', sub: user.id, storageKey: row.storage_key, maxBytes: row.size },
        ctx.config.signedUrlTtlSeconds
      );
      return json({
        url: `${ctx.url.origin}/d/${signed.token}`,
        expiresAt: signed.expiresAt,
        size: row.size,
        sha256: row.sha256,
        encrypted: row.encrypted === 1,
      });
    },
  },
  {
    method: 'POST',
    path: '/v1/backups/:id/verify',
    auth: true,
    summary: 'Recompute SHA-256 of the stored backup and compare it with the recorded hash',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const result = await verifyBackupIntegrity(ctx.env, user.id, ctx.params.id, ctx.storage());
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'backup_verified',
        targetType: 'backup',
        targetId: ctx.params.id,
        success: result.matches,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
      });
      return json({
        matches: result.matches,
        computedSha256: result.computedSha256,
        backup: result.backup,
      });
    },
  },
  {
    method: 'POST',
    path: '/v1/backups/:id/restore',
    auth: true,
    summary: 'Issue a signed URL for restoring a backup (records the restore attempt)',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const row = await getBackup(ctx.env, user.id, ctx.params.id);
      const signed = await signToken(
        ctx.env.SERVER_SECRET ?? '',
        { p: 'backup-download', sub: user.id, storageKey: row.storage_key, maxBytes: row.size },
        ctx.config.signedUrlTtlSeconds
      );
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'backup_restore_requested',
        targetType: 'backup',
        targetId: row.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
        detail: { kind: row.kind },
      });
      return json({
        url: `${ctx.url.origin}/d/${signed.token}`,
        expiresAt: signed.expiresAt,
        sha256: row.sha256,
        size: row.size,
        kind: row.kind,
        schemaVersion: row.schema_version,
      });
    },
  },
  {
    method: 'POST',
    path: '/v1/backups/:id/restored',
    auth: true,
    summary: 'Client confirms the restore was applied successfully',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      await markBackupRestored(ctx.env, user.id, ctx.params.id);
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'backup_restored',
        targetType: 'backup',
        targetId: ctx.params.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
      });
      return json({ restored: true });
    },
  },
  {
    method: 'DELETE',
    path: '/v1/backups/:id',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const result = await deleteBackup(ctx.env, user.id, ctx.params.id, ctx.storage());
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'backup_deleted',
        targetType: 'backup',
        targetId: ctx.params.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
        detail: result,
      });
      return json(result);
    },
  },
];

export function backupKindLabel(kind: string): string {
  const labels: Record<string, string> = {
    dns_config: 'DNS configuration',
    blocklists: 'Custom blocklists',
    allowlist: 'Allowlisted domains',
    denylist: 'Denylisted domains',
    firewall: 'Firewall settings',
    security_prefs: 'Security preferences',
    app_config: 'Application configuration',
    full: 'Full CyberShield snapshot',
  };
  return labels[kind] ?? kind;
}
