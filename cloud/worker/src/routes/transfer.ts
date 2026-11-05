import { ApiError, badRequest, json, notFound, readJson, tooLarge } from '../http';
import { assertUser, type Ctx, type RouteDefinition } from '../router';
import { signToken, verifyToken } from '../security/tokens';
import { assertCapacity, recordApiUsage } from '../repo/usage';
import {
  assertCompletable,
  finalizeUpload,
  getUpload,
  initUpload,
  initVersionUpload,
  parseParts,
  recordPart,
  type InitUploadRequest,
} from '../repo/uploads';
import { logAudit } from '../repo/audit';
import { RATE_LIMITS } from '../security/ratelimit';
import { policyFor } from '../util/mime';

/**
 * Upload + download transfer endpoints.
 *
 * Bytes always move client -> Worker -> provider in a single hop; the provider credentials
 * stay server-side. Clients receive short-lived HMAC tokens instead of signed provider
 * credentials, which keeps the APK free of any cloud secret material.
 */

/** Body size ceiling per request, so a malicious client cannot exhaust worker memory. */
function maxBodyFor(upload: { upload_type: string; part_size: number; size: number }): number {
  if (upload.upload_type === 'multipart') return upload.part_size + 1024 * 1024;
  return upload.size + 1024;
}

function contentLength(req: Request): number | null {
  const header = req.headers.get('Content-Length');
  if (!header) return null;
  const value = Number.parseInt(header, 10);
  return Number.isFinite(value) ? value : null;
}

async function authorizeUploadToken(ctx: Ctx, uploadId: string): Promise<{ ownerId: string; partNumber: number | null }> {
  const token = ctx.query.get('token') ?? ctx.req.headers.get('X-Upload-Token') ?? '';
  if (!token) throw new ApiError(401, 'upload_token_missing', 'Upload requests require a signed upload token');
  const payload = await verifyToken(ctx.env.SERVER_SECRET ?? '', token, 'upload-part');
  if (payload.uploadId !== uploadId) {
    throw new ApiError(403, 'upload_token_mismatch', 'This upload token belongs to a different session');
  }
  return { ownerId: payload.sub, partNumber: payload.partNumber ?? null };
}

/** Stores one uploaded part (or the whole single-shot body) and updates session state. */
async function handlePartUpload(ctx: Ctx, isSingle: boolean): Promise<Response> {
  const uploadId = ctx.params.uploadId;
  const auth = await authorizeUploadToken(ctx, uploadId);
  const upload = await getUpload(ctx.env, auth.ownerId, uploadId);

  if (upload.status === 'completed') {
    // Idempotent: a retried final part after a dropped response should not fail hard.
    return json({ uploadId, status: 'completed', idempotent: true });
  }
  if (upload.status !== 'pending' && upload.status !== 'in_progress') {
    throw new ApiError(409, 'upload_not_active', `Upload is ${upload.status}`);
  }
  if (upload.expires_at < Date.now()) throw new ApiError(410, 'upload_expired', 'Upload session expired');

  const declared = contentLength(ctx.req);
  const ceiling = maxBodyFor(upload);
  if (declared !== null && declared > ceiling) {
    throw tooLarge(`Chunk exceeds the ${ceiling} byte limit for this session`, 'payload_too_large', { limit: ceiling, declared });
  }

  const storage = ctx.storage();

  if (isSingle) {
    if (upload.upload_type !== 'single') throw badRequest('This session uses multipart upload', 'wrong_upload_mode');
    if (!ctx.req.body) throw badRequest('Request body is required', 'missing_body');
    if (declared !== null && declared !== upload.size) {
      throw badRequest(`Body must be exactly ${upload.size} bytes`, 'size_mismatch', { declared, expected: upload.size });
    }
    const stored = await storage.put(upload.storage_key, ctx.req.body, upload.mime ?? 'application/octet-stream', upload.size);
    await ctx.env.DB.prepare(
      "UPDATE uploads SET status = 'in_progress', bytes_received = ?, parts_done = 1, updated_at = ? WHERE id = ?"
    )
      .bind(stored.size, Date.now(), uploadId)
      .run();
    await recordApiUsage(ctx.env, upload.owner_id, stored.size, 0);
    return json({ uploadId, received: stored.size, partsDone: 1, partsTotal: 1 });
  }

  if (upload.upload_type !== 'multipart') throw badRequest('This session uses single-shot upload', 'wrong_upload_mode');
  const partNumber = Number.parseInt(ctx.params.partNumber ?? '', 10);
  if (!Number.isFinite(partNumber) || partNumber < 1 || partNumber > upload.parts_total) {
    throw badRequest(`Part number must be between 1 and ${upload.parts_total}`, 'invalid_part_number');
  }
  if (!upload.provider_upload_id) throw new ApiError(409, 'multipart_missing', 'Multipart session was not opened with the provider');

  const bytes = new Uint8Array(await ctx.req.arrayBuffer());
  if (bytes.byteLength === 0) throw badRequest('Part body is empty', 'empty_part');
  const isLast = partNumber === upload.parts_total;
  const minimum = storage.minimumPartSize;
  if (!isLast && bytes.byteLength < minimum) {
    throw badRequest(`Parts must be at least ${minimum} bytes (except the final part)`, 'part_too_small', {
      received: bytes.byteLength,
      minimum,
    });
  }

  let lastError: unknown = null;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const result = await storage.uploadPart(
        upload.storage_key,
        upload.provider_upload_id ?? '',
        partNumber,
        bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
      );
      const state = await recordPart(ctx.env, upload, partNumber, result.etag, bytes.byteLength);
      await recordApiUsage(ctx.env, upload.owner_id, bytes.byteLength, 0);
      return json({
        uploadId,
        partNumber,
        etag: result.etag,
        size: bytes.byteLength,
        ...state,
      });
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 150 * (attempt + 1)));
    }
  }
  console.error('part_upload_failed', uploadId, partNumber, (lastError as Error)?.message);
  throw new ApiError(502, 'part_upload_failed', 'The storage provider rejected this part after 3 attempts. Retry the chunk.');
}

export const transferRoutes: RouteDefinition[] = [
  {
    method: 'POST',
    path: '/v1/uploads',
    auth: true,
    rateLimit: RATE_LIMITS.uploadInit,
    summary: 'Initialise a single-shot or multipart upload (with duplicate detection)',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const body = await readJson<InitUploadRequest>(ctx.req, ctx.config);
      const size = Number(body.size);
      await assertCapacity(ctx.env, ctx.config, user, size);
      const storage = ctx.storage();
      const result = await initUpload(ctx.env, ctx.config, user, storage, body);
      if (result.duplicate) {
        await logAudit(ctx.env, {
          ownerId: user.id,
          action: 'duplicate_detected',
          targetType: 'node',
          targetId: result.nodeId ?? undefined,
          ipHash: ctx.ipHash,
          userAgent: ctx.userAgent,
          detail: { existingNodeId: result.duplicate.nodeId, name: body.name },
        });
        return json(result, 201);
      }
      const token = await signToken(
        ctx.env.SERVER_SECRET ?? '',
        { p: 'upload-part', sub: user.id, uploadId: result.uploadId },
        3600
      );
      return json(
        {
          ...result,
          uploadToken: token.token,
          uploadTokenExpiresAt: token.expiresAt,
          uploadUrls: {
            single: `${ctx.url.origin}/v1/upload/${result.uploadId}/content`,
            part: `${ctx.url.origin}/v1/upload/${result.uploadId}/parts/{partNumber}`,
          },
        },
        201
      );
    },
  },
  {
    method: 'GET',
    path: '/v1/uploads',
    auth: true,
    summary: 'List in-flight upload sessions (upload manager)',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const rows = await ctx.env.DB.prepare(
        "SELECT * FROM uploads WHERE owner_id = ? AND status IN ('pending','in_progress') ORDER BY updated_at DESC LIMIT 100"
      )
        .bind(user.id)
        .all();
      return json({
        uploads: (rows.results ?? []).map((row) => {
          const upload = row as unknown as Record<string, unknown>;
          return {
            id: upload.id,
            name: upload.name,
            size: upload.size,
            bytesReceived: upload.bytes_received,
            partsDone: upload.parts_done,
            partsTotal: upload.parts_total,
            uploadType: upload.upload_type,
            status: upload.status,
            purpose: upload.purpose,
            createdAt: upload.created_at,
            updatedAt: upload.updated_at,
            expiresAt: upload.expires_at,
          };
        }),
      });
    },
  },
  {
    method: 'GET',
    path: '/v1/uploads/:id',
    auth: true,
    summary: 'Resume state for an upload (parts already accepted + fresh token)',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const upload = await getUpload(ctx.env, user.id, ctx.params.id);
      const recorded = parseParts(upload);
      const accepted = new Map<number, { partNumber: number; size: number }>();
      for (const part of recorded) accepted.set(part.partNumber, { partNumber: part.partNumber, size: part.size });

      const token = await signToken(
        ctx.env.SERVER_SECRET ?? '',
        { p: 'upload-part', sub: user.id, uploadId: upload.id },
        3600
      );
      return json({
        id: upload.id,
        name: upload.name,
        size: upload.size,
        uploadType: upload.upload_type,
        partSize: upload.part_size,
        partsTotal: upload.parts_total,
        status: upload.status,
        bytesReceived: upload.bytes_received,
        acceptedParts: Array.from(accepted.values()).sort((a, b) => a.partNumber - b.partNumber),
        missingParts: Array.from({ length: upload.parts_total }, (_, index) => index + 1)
          .filter((partNumber) => !accepted.has(partNumber))
          .slice(0, 500),
        uploadToken: token.token,
        uploadTokenExpiresAt: token.expiresAt,
        expiresAt: upload.expires_at,
      });
    },
  },
  {
    method: 'POST',
    path: '/v1/files/:id/versions/init',
    auth: true,
    rateLimit: RATE_LIMITS.uploadInit,
    summary: 'Start a new revision of an existing file (keeps the previous version)',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const body = await readJson<{ size?: number; sha256?: string; mime?: string; encrypted?: boolean }>(ctx.req, ctx.config);
      const size = Number(body.size);
      await assertCapacity(ctx.env, ctx.config, user, size);
      const result = await initVersionUpload(ctx.env, ctx.config, user, ctx.storage(), ctx.params.id, {
        size,
        sha256: body.sha256,
        mime: body.mime,
        encrypted: body.encrypted,
      });
      const token = await signToken(
        ctx.env.SERVER_SECRET ?? '',
        { p: 'upload-part', sub: user.id, uploadId: result.uploadId },
        3600
      );
      return json(
        {
          ...result,
          uploadToken: token.token,
          uploadTokenExpiresAt: token.expiresAt,
          uploadUrls: {
            single: `${ctx.url.origin}/v1/upload/${result.uploadId}/content`,
            part: `${ctx.url.origin}/v1/upload/${result.uploadId}/parts/{partNumber}`,
          },
        },
        201
      );
    },
  },
  {
    method: 'PUT',
    path: '/v1/upload/:uploadId/content',
    summary: 'Upload the whole file in one request (signed token auth)',
    handler: async (ctx) => handlePartUpload(ctx, true),
  },
  {
    method: 'PUT',
    path: '/v1/upload/:uploadId/parts/:partNumber',
    rateLimit: RATE_LIMITS.uploadPart,
    summary: 'Upload one multipart chunk (signed token auth)',
    handler: async (ctx) => handlePartUpload(ctx, false),
  },
  {
    method: 'POST',
    path: '/v1/uploads/:id/complete',
    auth: true,
    summary: 'Finish an upload, scan content and record the version',
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const upload = await getUpload(ctx.env, user.id, ctx.params.id);
      const storage = ctx.storage();

      if (upload.status === 'completed') {
        return json({ status: 'completed', idempotent: true, nodeId: upload.node_id });
      }
      await assertCompletable(ctx.env, upload, storage);

      if (upload.upload_type === 'multipart') {
        const parts = parseParts(upload).map((part) => ({
          partNumber: part.partNumber,
          etag: part.etag,
          size: part.size,
        }));
        await storage.completeMultipart(upload.storage_key, upload.provider_upload_id ?? '', parts);
      }

      const head = await storage.head(upload.storage_key);
      if (!head) throw new ApiError(409, 'object_missing', 'No stored object was found for this upload');
      if (head.size !== upload.size) {
        throw new ApiError(
          409,
          'size_mismatch',
          `Stored size ${head.size} does not match the declared size ${upload.size}`,
          { stored: head.size, declared: upload.size }
        );
      }

      const result = await finalizeUpload(ctx.env, ctx.config, user, upload, storage);
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: upload.purpose === 'backup' ? 'backup_uploaded' : 'upload_completed',
        targetType: upload.purpose === 'backup' ? 'backup' : 'node',
        targetId: result.nodeId ?? result.backupId ?? undefined,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
        detail: { size: result.size, scan: result.scan?.verdict, sha256Verified: result.sha256Verified },
      });

      return json({
        status: 'completed',
        nodeId: result.nodeId,
        backupId: result.backupId,
        size: result.size,
        sha256: result.sha256,
        sha256Verified: result.sha256Verified,
        scan: result.scan,
        warning: result.sha256Verified
          ? null
          : `SHA-256 was not re-computed server-side for this ${result.size} byte object (CPU budget). The client must verify the hash after upload.`,
      });
    },
  },
  {
    method: 'POST',
    path: '/v1/uploads/:id/abort',
    auth: true,
    handler: async (ctx) => {
      const user = assertUser(ctx);
      const upload = await getUpload(ctx.env, user.id, ctx.params.id);
      const storage = ctx.storage();
      try {
        if (upload.provider_upload_id) await storage.abortMultipart(upload.storage_key, upload.provider_upload_id);
      } catch {
        // ignore provider-side abort failures
      }
      await ctx.env.DB.batch([
        ctx.env.DB.prepare("UPDATE uploads SET status = 'aborted', updated_at = ? WHERE id = ?").bind(Date.now(), upload.id),
        ctx.env.DB.prepare("DELETE FROM nodes WHERE id = ? AND status = 'pending'").bind(upload.node_id ?? ''),
      ]);
      await logAudit(ctx.env, {
        ownerId: user.id,
        action: 'upload_aborted',
        targetType: 'upload',
        targetId: upload.id,
        ipHash: ctx.ipHash,
        userAgent: ctx.userAgent,
      });
      return json({ aborted: true });
    },
  },
  {
    method: 'GET',
    path: '/d/:token',
    summary: 'Execute a signed download/preview URL (short-lived, ownership enforced at issue time)',
    handler: async (ctx) => {
      const payload = await verifyToken(ctx.env.SERVER_SECRET ?? '', ctx.params.token, 'download').catch(async (error) => {
        if ((error as ApiError).code === 'wrong_token_purpose') {
          // Preview and share tokens use the same executor.
          for (const purpose of ['preview', 'share-download', 'backup-download'] as const) {
            try {
              return await verifyToken(ctx.env.SERVER_SECRET ?? '', ctx.params.token, purpose);
            } catch {
              continue;
            }
          }
        }
        throw error;
      });

      if (!payload.storageKey) throw badRequest('Signed URL carries no object reference', 'invalid_token');
      const storage = ctx.storage();

      // Re-validate state at download time: a file trashed or quarantined after the URL was
      // issued must not be served.
      if (payload.nodeId) {
        const node = await ctx.env.DB.prepare('SELECT id, status, name, mime, scan_status FROM nodes WHERE id = ?')
          .bind(payload.nodeId)
          .first<{ id: string; status: string; name: string; mime: string | null; scan_status: string }>();
        if (!node) throw notFound('This file no longer exists', 'object_missing');
        if (node.status !== 'active') {
          throw new ApiError(403, 'object_unavailable', 'This file is no longer downloadable', { status: node.status });
        }
      }

      const rangeHeader = ctx.req.headers.get('Range');
      let range: { offset: number; length?: number } | undefined;
      if (rangeHeader) {
        const match = /^bytes=(\d+)-(\d*)$/.exec(rangeHeader.trim());
        if (!match) throw badRequest('Only single byte ranges are supported', 'invalid_range');
        const offset = Number.parseInt(match[1], 10);
        const end = match[2] ? Number.parseInt(match[2], 10) : undefined;
        if (end !== undefined && end < offset) throw badRequest('Invalid byte range', 'invalid_range');
        range = { offset, length: end !== undefined ? end - offset + 1 : undefined };
      }

      const object = await storage.get(payload.storageKey, range ? { range } : undefined);
      if (!object) throw notFound('Stored object is missing', 'object_missing');

      const total = payload.maxBytes ?? object.size;
      const headers = new Headers({
        'Content-Type': object.contentType ?? 'application/octet-stream',
        'Accept-Ranges': 'bytes',
        'Cache-Control': 'private, no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; sandbox",
        'Referrer-Policy': 'no-referrer',
      });

      const fileName = typeof payload.version === 'number' ? undefined : undefined;
      void fileName;
      const disposition = payload.p === 'preview' ? 'inline' : 'attachment';
      headers.set('Content-Disposition', `${disposition}`);

      let status = 200;
      if (range) {
        const start = range.offset;
        const end = range.length ? Math.min(start + range.length - 1, total - 1) : total - 1;
        headers.set('Content-Range', `bytes ${start}-${end}/${total}`);
        headers.set('Content-Length', String(end - start + 1));
        status = 206;
      } else if (total > 0) {
        headers.set('Content-Length', String(total));
      }

      return new Response(object.body, { status, headers });
    },
  },
  {
    method: 'HEAD',
    path: '/d/:token',
    handler: async (ctx) => {
      const payload = await verifyToken(ctx.env.SERVER_SECRET ?? '', ctx.params.token, 'download');
      if (!payload.storageKey) throw badRequest('Signed URL carries no object reference');
      const head = await ctx.storage().head(payload.storageKey);
      if (!head) throw notFound('Stored object is missing', 'object_missing');
      return new Response(null, {
        status: 200,
        headers: {
          'Content-Length': String(head.size),
          'Content-Type': head.contentType ?? 'application/octet-stream',
          'Accept-Ranges': 'bytes',
          'Cache-Control': 'private, no-store',
        },
      });
    },
  },
];

export { policyFor };
