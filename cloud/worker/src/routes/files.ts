import { ApiError, badRequest, json, notFound, readJson, requireString } from '../http';
import { assertUser, type Ctx, type RouteDefinition } from '../router';
import {
  copyNode,
  createFolder,
  folderUsage,
  listNodes,
  listVersions,
  purgeNode,
  renameNode,
  requireNode,
  restoreNode,
  moveNode,
  toNodeDto,
  trashNode,
  type CategoryFilter,
} from '../repo/nodes';
import { logAudit } from '../repo/audit';
import { signToken } from '../security/tokens';
import { RATE_LIMITS } from '../security/ratelimit';
import { sha256Hex } from '../util/core';
import { policyFor } from '../util/mime';

/** Issues a short-lived signed URL for one object revision. Never exposes provider keys. */
export async function issueDownloadUrl(
  ctx: Ctx,
  node: { id: string; name: string; storage_key: string | null; version: number; mime: string | null; size: number },
  purpose: 'download' | 'preview',
  ttlOverride?: number
): Promise<{ url: string; expiresAt: number; purpose: string }> {
  const user = assertUser(ctx);
  if (!node.storage_key) throw notFound('This file has no stored content yet', 'object_missing');
  const ttl = ttlOverride ?? ctx.config.signedUrlTtlSeconds;
  const signed = await signToken(
    ctx.env.SERVER_SECRET ?? '',
    {
      p: purpose,
      sub: user.id,
      nodeId: node.id,
      version: node.version,
      storageKey: node.storage_key,
    },
    ttl
  );
  return {
    url: `${ctx.url.origin}/d/${signed.token}`,
    expiresAt: signed.expiresAt,
    purpose,
  };
}

function parseIntParam(value: string | null, fallback: number): number {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export const fileRoutes: RouteDefinition[] = [
  {
    method: 'GET',
    path: '/v1/files',
    auth: true,
    summary: 'List a folder (paginated, filterable by category)',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const parentParam = ctx.query.get('parentId');
      const category = (ctx.query.get('category') ?? 'all') as CategoryFilter;
      const allowed: CategoryFilter[] = ['all', 'photos', 'videos', 'documents', 'music', 'folders', 'files'];
      const parentId = parentParam === null || parentParam === 'root' ? null : parentParam;
      if (parentId) await requireNode(ctx.env, user.id, parentId);

      const page = await listNodes(ctx.env, user.id, {
        parentId: ctx.query.has('parentId') ? parentId : undefined,
        category: allowed.includes(category) ? category : 'all',
        query: ctx.query.get('q') ?? undefined,
        sort: (ctx.query.get('sort') as 'name' | 'size' | 'updated' | 'created' | null) ?? 'name',
        direction: (ctx.query.get('direction') as 'asc' | 'desc' | null) ?? 'asc',
        limit: parseIntParam(ctx.query.get('limit'), 50),
        cursor: ctx.query.get('cursor') ?? undefined,
        status: 'active',
      });
      return json(page);
    },
  },
  {
    method: 'GET',
    path: '/v1/search',
    auth: true,
    rateLimit: RATE_LIMITS.search,
    summary: 'Search the whole account by name',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const query = (ctx.query.get('q') ?? '').trim();
      if (query.length < 1) throw badRequest('Search needs at least one character', 'invalid_query');
      const page = await listNodes(ctx.env, user.id, {
        query,
        status: 'active',
        limit: parseIntParam(ctx.query.get('limit'), 50),
        sort: 'updated',
        direction: 'desc',
      });
      return json({ query, ...page });
    },
  },
  {
    method: 'GET',
    path: '/v1/trash',
    auth: true,
    summary: 'List recoverable deleted items',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const rows = await ctx.env.DB.prepare(
        "SELECT * FROM nodes WHERE owner_id = ? AND status = 'trashed' ORDER BY trashed_at DESC LIMIT 200"
      )
        .bind(user.id)
        .all();
      const retentionDays = ctx.config.trashRetentionDays;
      return json({
        retentionDays,
        purgeAfterMs: retentionDays * 24 * 3600 * 1000,
        items: (rows.results ?? []).map((row) => {
          const node = row as unknown as Parameters<typeof toNodeDto>[0];
          return { ...toNodeDto(node), purgeAt: (node.trashed_at ?? Date.now()) + retentionDays * 24 * 3600 * 1000 };
        }),
      });
    },
  },
  {
    method: 'DELETE',
    path: '/v1/trash',
    auth: true,
    summary: 'Permanently empty the trash',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const rows = await ctx.env.DB.prepare("SELECT id FROM nodes WHERE owner_id = ? AND status = 'trashed'")
        .bind(user.id)
        .all<{ id: string }>();
      let freed = 0;
      for (const row of rows.results ?? []) {
        try {
          const result = await purgeNode(ctx.env, user.id, row.id, ctx.storage());
          freed += result.freedBytes;
        } catch {
          // already purged
        }
      }
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'trash_emptied',
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
        detail: { freedBytes: freed },
      });
      return json({ freedBytes: freed });
    },
  },
  {
    method: 'GET',
    path: '/v1/files/:id',
    auth: true,
    summary: 'File or folder metadata',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const node = await requireNode(ctx.env, user.id, ctx.params.id);
      const versions = node.kind === 'file' ? await listVersions(ctx.env, user.id, node.id) : [];
      const children = node.kind === 'folder'
        ? await ctx.env.DB.prepare(
            "SELECT COUNT(*) AS count, COALESCE(SUM(size), 0) AS bytes FROM nodes WHERE owner_id = ? AND parent_id = ? AND status = 'active'"
          ).bind(user.id, node.id).first<{ count: number; bytes: number }>()
        : null;
      return json({
        node: toNodeDto(node),
        versions: versions.map((version) => ({
          id: version.id,
          version: version.version,
          size: version.size,
          sha256: version.sha256,
          createdAt: version.created_at,
        })),
        folderStats: children ?? null,
      });
    },
  },
  {
    method: 'POST',
    path: '/v1/folders',
    auth: true,
    summary: 'Create a folder',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const body = await readJson<{ name?: string; parentId?: string | null }>(ctx.req);
      const name = requireString(body.name, 'name', 180);
      const parentId = body.parentId && body.parentId !== 'root' ? body.parentId : null;
      const folder = await createFolder(ctx.env, user.id, parentId, name);
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'folder_created',
        targetType: 'node',
        targetId: folder.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
      });
      return json({ folder: toNodeDto(folder) }, 201);
    },
  },
  {
    method: 'POST',
    path: '/v1/files/:id/rename',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const body = await readJson<{ name?: string }>(ctx.req);
      const name = requireString(body.name, 'name', 180);
      const node = await renameNode(ctx.env, user.id, ctx.params.id, name);
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'file_renamed',
        targetType: 'node',
        targetId: node.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
        detail: { name },
      });
      return json({ node: toNodeDto(node) });
    },
  },
  {
    method: 'POST',
    path: '/v1/files/:id/move',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const body = await readJson<{ parentId?: string | null }>(ctx.req);
      const parentId = body.parentId && body.parentId !== 'root' ? body.parentId : null;
      const node = await moveNode(ctx.env, user.id, ctx.params.id, parentId);
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'file_moved',
        targetType: 'node',
        targetId: node.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
        detail: { parentId },
      });
      return json({ node: toNodeDto(node) });
    },
  },
  {
    method: 'POST',
    path: '/v1/files/:id/copy',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const body = await readJson<{ parentId?: string | null }>(ctx.req);
      const parentId = body.parentId && body.parentId !== 'root' ? body.parentId : null;
      const storage = ctx.storage();
      const node = await copyNode(ctx.env, user.id, ctx.params.id, parentId, storage);
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'file_copied',
        targetType: 'node',
        targetId: node.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
      });
      return json({ node: toNodeDto(node) }, 201);
    },
  },
  {
    method: 'POST',
    path: '/v1/files/:id/trash',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const result = await trashNode(ctx.env, user.id, ctx.params.id);
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'file_trashed',
        targetType: 'node',
        targetId: ctx.params.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
        detail: result,
      });
      return json(result);
    },
  },
  {
    method: 'POST',
    path: '/v1/files/:id/restore',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const result = await restoreNode(ctx.env, user.id, ctx.params.id);
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'file_restored',
        targetType: 'node',
        targetId: ctx.params.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
        detail: result,
      });
      return json(result);
    },
  },
  {
    method: 'DELETE',
    path: '/v1/files/:id',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const node = await requireNode(ctx.env, user.id, ctx.params.id);
      if (node.status !== 'trashed') {
        throw badRequest('Move the item to the trash before deleting it permanently', 'not_trashed');
      }
      const result = await purgeNode(ctx.env, user.id, node.id, ctx.storage());
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'file_purged',
        targetType: 'node',
        targetId: node.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
        detail: result,
      });
      return json(result);
    },
  },
  {
    method: 'GET',
    path: '/v1/files/:id/download',
    auth: true,
    rateLimit: RATE_LIMITS.download,
    summary: 'Issue a short-lived signed download URL',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const node = await requireNode(ctx.env, user.id, ctx.params.id);
      if (node.kind !== 'file') throw badRequest('Folders cannot be downloaded directly', 'invalid_download');
      if (node.status === 'quarantined') {
        throw new ApiError(423, 'file_quarantined', 'This file is quarantined. Release it from Cloud Security to download.', {
          scanStatus: node.scan_status,
        });
      }
      if (node.status !== 'active') throw badRequest('Only active files can be downloaded', 'node_not_active');
      if (!node.storage_key) throw notFound('Stored object missing', 'object_missing');

      const issued = await issueDownloadUrl(ctx, node, 'download');
      await ctx.env.DB.prepare('UPDATE nodes SET download_count = download_count + 1 WHERE id = ?').bind(node.id).run();
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'download_url_issued',
        targetType: 'node',
        targetId: node.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
      });
      return json({
        url: issued.url,
        expiresAt: issued.expiresAt,
        fileName: node.name,
        size: node.size,
        mime: node.mime,
        sha256: node.sha256,
        encrypted: node.encrypted === 1,
      });
    },
  },
  {
    method: 'GET',
    path: '/v1/files/:id/preview',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const node = await requireNode(ctx.env, user.id, ctx.params.id);
      const policy = policyFor(node.name, node.mime ?? undefined);
      if (!policy.previewable) {
        throw new ApiError(415, 'preview_unsupported', 'This file type has no in-app preview', { mime: node.mime });
      }
      if (node.status !== 'active') throw badRequest('Only active files can be previewed', 'node_not_active');
      const issued = await issueDownloadUrl(ctx, node, 'preview');
      return json({ url: issued.url, expiresAt: issued.expiresAt, mime: node.mime, size: node.size });
    },
  },
  {
    method: 'POST',
    path: '/v1/files/:id/verify',
    auth: true,
    summary: 'Recompute SHA-256 of the stored object and compare with the recorded hash',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const node = await requireNode(ctx.env, user.id, ctx.params.id);
      if (!node.storage_key || node.kind !== 'file') throw notFound('Stored object missing', 'object_missing');
      if (node.size > 32 * 1024 * 1024) {
        throw new ApiError(413, 'verify_too_large', 'Server-side verification is limited to 32 MB. The client verifies larger files while downloading.', {
          size: node.size,
        });
      }
      const object = await ctx.storage().get(node.storage_key);
      if (!object) throw notFound('Stored object missing', 'object_missing');
      const bytes = new Uint8Array(await new Response(object.body).arrayBuffer());
      const computed = await sha256Hex(bytes);
      const matches = node.sha256 ? computed === node.sha256.toLowerCase() : true;
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'integrity_verified',
        targetType: 'node',
        targetId: node.id,
        success: matches,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
      });
      return json({ matches, computedSha256: computed, recordedSha256: node.sha256, size: bytes.byteLength });
    },
  },
  {
    method: 'GET',
    path: '/v1/files/:id/versions',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const node = await requireNode(ctx.env, user.id, ctx.params.id);
      const versions = await listVersions(ctx.env, user.id, node.id);
      return json({
        currentVersion: node.version,
        versions: versions.map((version) => ({
          id: version.id,
          version: version.version,
          size: version.size,
          sha256: version.sha256,
          provider: version.provider,
          createdAt: version.created_at,
        })),
      });
    },
  },
  {
    method: 'POST',
    path: '/v1/files/:id/versions/:versionId/restore',
    auth: true,
    summary: 'Promote an older version back to current',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const node = await requireNode(ctx.env, user.id, ctx.params.id);
      const version = await ctx.env.DB.prepare(
        'SELECT * FROM file_versions WHERE id = ? AND node_id = ? AND owner_id = ?'
      )
        .bind(ctx.params.versionId, node.id, user.id)
        .first<{ id: string; version: number; size: number; sha256: string | null; storage_key: string; provider: string }>();
      if (!version) throw notFound('Version not found');
      if (node.version === version.version) throw badRequest('That version is already current', 'same_version');

      const nextVersion = node.version + 1;
      // Copy the historical object forward so history stays immutable.
      const newKey = `u/${user.id}/${node.id}/v${nextVersion}/${version.storage_key.split('/').pop() ?? 'object'}`;
      const storage = ctx.storage();
      await storage.copy(version.storage_key, newKey);
      const now = Date.now();
      await ctx.env.DB.batch([
        ctx.env.DB.prepare(
          'UPDATE nodes SET version = ?, size = ?, sha256 = ?, storage_key = ?, provider = ?, status = ?, updated_at = ? WHERE id = ?'
        ).bind(nextVersion, version.size, version.sha256, newKey, version.provider, 'active', now, node.id),
        ctx.env.DB.prepare(
          `INSERT INTO file_versions (id, node_id, owner_id, version, size, sha256, storage_key, provider, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(crypto.randomUUID(), node.id, user.id, nextVersion, version.size, version.sha256, newKey, version.provider, now),
      ]);
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'version_restored',
        targetType: 'node',
        targetId: node.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
        detail: { fromVersion: version.version, toVersion: nextVersion },
      });
      return json({ restoredVersion: version.version, currentVersion: nextVersion });
    },
  },
  {
    method: 'POST',
    path: '/v1/files/:id/release',
    auth: true,
    summary: 'Owner override to release a quarantined file',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const node = await requireNode(ctx.env, user.id, ctx.params.id);
      if (node.status !== 'quarantined') throw badRequest('This file is not quarantined', 'not_quarantined');
      // The scan verdict itself stays truthful ('infected'/'suspicious'); only the lock that
      // blocks downloads is lifted, and the override is written into scan_detail.
      await ctx.env.DB.prepare('UPDATE nodes SET status = ?, scan_detail = ?, updated_at = ? WHERE id = ?')
        .bind(
          'active',
          `Quarantine released by owner at ${new Date().toISOString()} (verdict at scan time: ${node.scan_status}). ` +
            `Previous detail: ${node.scan_detail ?? 'none'}`,
          Date.now(),
          node.id
        )
        .run();
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'quarantine_released',
        targetType: 'node',
        targetId: node.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
        detail: { previousScanStatus: node.scan_status },
      });
      return json({ released: true });
    },
  },
  {
    method: 'GET',
    path: '/v1/stats',
    auth: true,
    summary: 'Aggregate storage statistics for the dashboard',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const usage = await folderUsage(ctx.env, user.id);
      const byCategory = await ctx.env.DB.prepare(
        `SELECT
           SUM(CASE WHEN mime LIKE 'image/%' THEN 1 ELSE 0 END) AS photos,
           SUM(CASE WHEN mime LIKE 'video/%' THEN 1 ELSE 0 END) AS videos,
           SUM(CASE WHEN mime LIKE 'audio/%' THEN 1 ELSE 0 END) AS music,
           SUM(CASE WHEN mime LIKE 'text/%' OR mime LIKE 'application/%' THEN 1 ELSE 0 END) AS documents,
           COALESCE(SUM(size), 0) AS bytes
         FROM nodes WHERE owner_id = ? AND kind = 'file' AND status = 'active'`
      )
        .bind(user.id)
        .first<{ photos: number; videos: number; music: number; documents: number; bytes: number }>();
      const recentUploads = await ctx.env.DB.prepare(
        "SELECT * FROM nodes WHERE owner_id = ? AND kind = 'file' AND status != 'pending' ORDER BY created_at DESC LIMIT 8"
      )
        .bind(user.id)
        .all();
      const recentDownloads = await ctx.env.DB.prepare(
        `SELECT * FROM nodes WHERE owner_id = ? AND kind = 'file' AND download_count > 0 ORDER BY updated_at DESC LIMIT 8`
      )
        .bind(user.id)
        .all();
      return json({
        usage,
        byCategory: {
          photos: byCategory?.photos ?? 0,
          videos: byCategory?.videos ?? 0,
          music: byCategory?.music ?? 0,
          documents: byCategory?.documents ?? 0,
          totalBytes: byCategory?.bytes ?? 0,
        },
        recentUploads: (recentUploads.results ?? []).map((row) => toNodeDto(row as never)),
        recentDownloads: (recentDownloads.results ?? []).map((row) => toNodeDto(row as never)),
      });
    },
  },
];
