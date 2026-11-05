import type { AppConfig, Env } from '../env';
import { ApiError, badRequest, conflict, notFound } from '../http';
import { fileExtension, randomId, sanitizeName, sha256Hex } from '../util/core';
import type { StorageProvider } from '../storage/provider';
import { assertAllowedUpload } from '../util/mime';
import { scanBytes, scanWithExternalEngine } from '../security/scanner';
import type { AuthedUser } from '../security/auth';
import { addUserUsage } from './usage';
import { getNode, requireNode } from './nodes';

export type UploadPurpose = 'file' | 'backup' | 'version';
export type UploadStatus = 'pending' | 'in_progress' | 'completed' | 'aborted' | 'expired';

export interface UploadRow {
  id: string;
  owner_id: string;
  node_id: string | null;
  parent_id: string | null;
  name: string;
  mime: string | null;
  size: number;
  sha256: string | null;
  provider: string;
  storage_key: string;
  upload_type: 'single' | 'multipart';
  provider_upload_id: string | null;
  part_size: number;
  parts_total: number;
  parts_done: number;
  bytes_received: number;
  uploaded_parts: string | null;
  status: UploadStatus;
  purpose: UploadPurpose;
  target_version: number;
  encrypted: number;
  backup_kind: string | null;
  backup_label: string | null;
  created_at: number;
  updated_at: number;
  expires_at: number;
}

export interface UploadPartRecord {
  partNumber: number;
  etag: string;
  size: number;
}

export interface InitUploadRequest {
  name: string;
  parentId?: string | null;
  size: number;
  mime?: string;
  sha256?: string;
  encrypted?: boolean;
  purpose?: UploadPurpose;
  backupKind?: string;
  backupLabel?: string;
  appVersion?: string;
  dedupeMode?: 'reference' | 'copy';
}

export interface InitUploadResponse {
  uploadId: string;
  mode: 'single' | 'multipart';
  partSize: number;
  partsTotal: number;
  expiresAt: number;
  nodeId: string | null;
  /** Present when an identical file already exists and dedupeMode="reference". */
  duplicate: { nodeId: string; name: string; size: number; referenceCreated: boolean } | null;
  maxSingleUploadBytes: number;
}

export function partsForSize(size: number, partSize: number): number {
  if (size <= 0) return 1;
  return Math.ceil(size / partSize);
}

/** Chooses single-shot vs multipart. Small files avoid the multipart overhead entirely. */
export function chooseUploadMode(size: number, config: AppConfig, provider: StorageProvider): {
  mode: 'single' | 'multipart';
  partSize: number;
  partsTotal: number;
} {
  const hardSingleLimit = Math.min(config.maxSingleUploadBytes, provider.maxObjectBytes);
  const needsMultipart = size > hardSingleLimit || (provider.supportsMultipart && size > config.partSizeBytes);
  if (!needsMultipart) {
    return { mode: 'single', partSize: size, partsTotal: 1 };
  }
  if (!provider.supportsMultipart) {
    throw new ApiError(
      413,
      'file_too_large_for_provider',
      `This deployment stores at most ${hardSingleLimit} bytes per file. Enable the R2 provider for large uploads.`,
      { maxBytes: hardSingleLimit }
    );
  }
  let partSize = Math.max(config.partSizeBytes, provider.minimumPartSize);
  // Never exceed R2's 10,000-part ceiling.
  while (Math.ceil(size / partSize) > 10_000) partSize *= 2;
  return { mode: 'multipart', partSize, partsTotal: partsForSize(size, partSize) };
}

/**
 * Opens an upload session that replaces an existing file's content with a new version.
 * The previous revision stays addressable in file_versions for restore/rollback.
 */
export async function initVersionUpload(
  env: Env,
  config: AppConfig,
  user: AuthedUser,
  storage: StorageProvider,
  nodeId: string,
  body: { size: number; sha256?: string; mime?: string; encrypted?: boolean }
): Promise<InitUploadResponse> {
  const node = await getNode(env, user.id, nodeId);
  if (!node) throw notFound('File not found in your cloud');
  if (node.kind !== 'file') throw badRequest('Only files can receive new versions', 'invalid_target');
  if (node.status !== 'active') throw conflict('Only active files can receive new versions', 'node_not_active');

  const size = Number(body.size);
  if (!Number.isFinite(size) || size <= 0) throw badRequest('A positive file size is required', 'invalid_size');
  const policy = assertAllowedUpload(node.name, body.mime ?? node.mime ?? undefined);
  const nextVersion = node.version + 1;
  const { mode, partSize, partsTotal } = chooseUploadMode(size, config, storage);
  const storageKey = buildStorageKey(user.id, node.id, nextVersion, node.name);
  const uploadId = randomId('upl');
  const now = Date.now();
  const expiresAt = now + 24 * 3600 * 1000;

  let providerUploadId: string | null = null;
  if (mode === 'multipart') providerUploadId = await storage.createMultipart(storageKey, policy.mime);

  await env.DB.prepare(
    `INSERT INTO uploads (id, owner_id, node_id, parent_id, name, mime, size, sha256, provider, storage_key,
                          upload_type, provider_upload_id, part_size, parts_total, parts_done, bytes_received,
                          uploaded_parts, status, purpose, target_version, encrypted, backup_kind, backup_label,
                          created_at, updated_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, '[]', 'pending', 'version', ?, ?, NULL, NULL, ?, ?, ?)`
  )
    .bind(
      uploadId,
      user.id,
      node.id,
      node.parent_id,
      node.name,
      policy.mime,
      size,
      body.sha256 && /^[a-f0-9]{64}$/i.test(body.sha256) ? body.sha256.toLowerCase() : null,
      storage.name,
      storageKey,
      mode,
      providerUploadId,
      partSize,
      partsTotal,
      nextVersion,
      body.encrypted ? 1 : 0,
      now,
      now,
      expiresAt
    )
    .run();

  return {
    uploadId,
    mode,
    partSize,
    partsTotal,
    expiresAt,
    nodeId: node.id,
    duplicate: null,
    maxSingleUploadBytes: Math.min(config.maxSingleUploadBytes, storage.maxObjectBytes),
  };
}

export function buildStorageKey(ownerId: string, nodeId: string, version: number, name: string): string {
  const safeOwner = ownerId.replace(/[^a-zA-Z0-9_-]/g, '');
  const ext = fileExtension(name);
  const suffix = ext ? `.${ext}` : '';
  return `u/${safeOwner}/${nodeId}/v${version}/${randomId('o')}${suffix}`;
}

export async function purgeExpiredSessions(env: Env, storage: StorageProvider): Promise<void> {
  const expired = await env.DB.prepare(
    "SELECT * FROM uploads WHERE status IN ('pending','in_progress') AND expires_at < ? LIMIT 20"
  )
    .bind(Date.now() - 60_000)
    .all<UploadRow>();
  for (const upload of expired.results ?? []) {
    try {
      if (upload.provider_upload_id && storage.supportsMultipart) {
        await storage.abortMultipart(upload.storage_key, upload.provider_upload_id);
      }
    } catch {
      // best effort
    }
    if (upload.node_id) {
      await env.DB.prepare("DELETE FROM nodes WHERE id = ? AND status = 'pending'").bind(upload.node_id).run();
    }
    await env.DB.prepare("UPDATE uploads SET status = 'expired', updated_at = ? WHERE id = ?")
      .bind(Date.now(), upload.id)
      .run();
  }
}

export async function getUpload(env: Env, ownerId: string, uploadId: string): Promise<UploadRow> {
  const row = await env.DB.prepare('SELECT * FROM uploads WHERE id = ? AND owner_id = ?').bind(uploadId, ownerId).first<UploadRow>();
  if (!row) throw notFound('Upload session not found');
  return row;
}

export async function initUpload(
  env: Env,
  config: AppConfig,
  user: AuthedUser,
  storage: StorageProvider,
  body: InitUploadRequest
): Promise<InitUploadResponse> {
  await purgeExpiredSessions(env, storage);

  const purpose: UploadPurpose = body.purpose === 'backup' ? 'backup' : 'file';
  const rawName = purpose === 'backup' ? sanitizeName(body.name || 'backup.cshield') : sanitizeName(body.name ?? '');
  if (!rawName) throw badRequest('A file name is required', 'invalid_name');
  const policy = assertAllowedUpload(rawName, body.mime);
  const size = Number(body.size);
  if (!Number.isFinite(size) || size <= 0) throw badRequest('A positive file size is required', 'invalid_size');
  if (size > 5 * 1024 * 1024 * 1024) throw badRequest('Files above 5 GB are not supported', 'file_too_large');

  const parentId = body.parentId && body.parentId !== 'root' ? body.parentId : null;
  if (parentId && purpose === 'file') {
    const parent = await requireNode(env, user.id, parentId);
    if (parent.kind !== 'folder') throw badRequest('Parent is not a folder', 'invalid_parent');
  }

  // ---- Duplicate detection (content addressed by SHA-256) ----
  const clientHash = typeof body.sha256 === 'string' && /^[a-f0-9]{64}$/i.test(body.sha256) ? body.sha256.toLowerCase() : null;
  if (purpose === 'file' && clientHash && (body.dedupeMode ?? 'reference') === 'reference') {
    const duplicate = await env.DB.prepare(
      `SELECT id, name, size, storage_key, provider, mime FROM nodes
       WHERE owner_id = ? AND sha256 = ? AND kind = 'file' AND status = 'active'
       ORDER BY created_at ASC LIMIT 1`
    )
      .bind(user.id, clientHash)
      .first<{ id: string; name: string; size: number; storage_key: string; provider: string; mime: string | null }>();
    if (duplicate) {
      const nodeId = randomId('fil');
      const now = Date.now();
      await env.DB.prepare(
        `INSERT INTO nodes (id, owner_id, parent_id, name, kind, mime, size, sha256, storage_key, provider, version,
                            status, encrypted, scan_status, scan_detail, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'file', ?, ?, ?, ?, ?, 1, 'active', ?, 'clean', 'deduplicated: identical content already stored', ?, ?)`
      )
        .bind(
          nodeId,
          user.id,
          parentId,
          rawName,
          duplicate.mime ?? policy.mime,
          duplicate.size,
          clientHash,
          duplicate.storage_key,
          duplicate.provider,
          body.encrypted ? 1 : 0,
          now,
          now
        )
        .run();
      await env.DB.prepare(
        `INSERT INTO file_versions (id, node_id, owner_id, version, size, sha256, storage_key, provider, created_at)
         VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)`
      )
        .bind(randomId('ver'), nodeId, user.id, duplicate.size, clientHash, duplicate.storage_key, duplicate.provider, now)
        .run();
      await addUserUsage(env, user.id, duplicate.size, 'dedupe_reference', nodeId);
      return {
        uploadId: `dedupe_${nodeId}`,
        mode: 'single',
        partSize: 0,
        partsTotal: 0,
        expiresAt: now,
        nodeId,
        duplicate: { nodeId: duplicate.id, name: duplicate.name, size: duplicate.size, referenceCreated: true },
        maxSingleUploadBytes: Math.min(config.maxSingleUploadBytes, storage.maxObjectBytes),
      };
    }
  }

  const { mode, partSize, partsTotal } = chooseUploadMode(size, config, storage);
  const nodeId = randomId('fil');
  const storageKey = buildStorageKey(user.id, nodeId, 1, rawName);
  const uploadId = randomId('upl');
  const now = Date.now();
  const expiresAt = now + 24 * 3600 * 1000;

  let providerUploadId: string | null = null;
  if (mode === 'multipart') {
    providerUploadId = await storage.createMultipart(storageKey, policy.mime);
  }

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO nodes (id, owner_id, parent_id, name, kind, mime, size, sha256, storage_key, provider, version,
                          status, encrypted, scan_status, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'file', ?, 0, ?, ?, ?, 0, 'pending', ?, 'pending', ?, ?)`
    ).bind(
      nodeId,
      user.id,
      parentId,
      rawName,
      policy.mime,
      clientHash,
      storageKey,
      storage.name,
      body.encrypted ? 1 : 0,
      now,
      now
    ),
    env.DB.prepare(
      `INSERT INTO uploads (id, owner_id, node_id, parent_id, name, mime, size, sha256, provider, storage_key,
                            upload_type, provider_upload_id, part_size, parts_total, parts_done, bytes_received,
                            uploaded_parts, status, purpose, encrypted, backup_kind, backup_label,
                            created_at, updated_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, '[]', 'pending', ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      uploadId,
      user.id,
      nodeId,
      parentId,
      rawName,
      policy.mime,
      size,
      clientHash,
      storage.name,
      storageKey,
      mode,
      providerUploadId,
      partSize,
      partsTotal,
      purpose,
      body.encrypted ? 1 : 0,
      purpose === 'backup' ? (body.backupKind ?? 'full') : null,
      purpose === 'backup' ? (body.backupLabel ?? rawName) : null,
      now,
      now,
      expiresAt
    ),
  ]);

  return {
    uploadId,
    mode,
    partSize,
    partsTotal,
    expiresAt,
    nodeId,
    duplicate: null,
    maxSingleUploadBytes: Math.min(config.maxSingleUploadBytes, storage.maxObjectBytes),
  };
}

export function parseParts(upload: UploadRow): UploadPartRecord[] {
  try {
    const parsed = JSON.parse(upload.uploaded_parts ?? '[]') as UploadPartRecord[];
    return Array.isArray(parsed) ? parsed.filter((p) => typeof p.partNumber === 'number' && typeof p.etag === 'string') : [];
  } catch {
    return [];
  }
}

export async function recordPart(
  env: Env,
  upload: UploadRow,
  partNumber: number,
  etag: string,
  byteLength: number
): Promise<{ partsDone: number; partsTotal: number }> {
  const parts = parseParts(upload).filter((p) => p.partNumber !== partNumber);
  parts.push({ partNumber, etag, size: byteLength });
  parts.sort((a, b) => a.partNumber - b.partNumber);
  const bytesReceived = parts.reduce((sum, p) => sum + p.size, 0);
  await env.DB.prepare(
    `UPDATE uploads SET uploaded_parts = ?, parts_done = ?, bytes_received = ?, status = 'in_progress', updated_at = ?
     WHERE id = ?`
  )
    .bind(JSON.stringify(parts), parts.length, bytesReceived, Date.now(), upload.id)
    .run();
  return { partsDone: parts.length, partsTotal: upload.parts_total };
}

export interface FinalizeResult {
  nodeId: string | null;
  backupId: string | null;
  scan: { verdict: string; findings: number; engine: string } | null;
  sha256: string | null;
  sha256Verified: boolean;
  size: number;
}

/**
 * Runs after all bytes are stored: content scan, optional server-side hash verification,
 * node promotion, quota accounting and (for backups) the backup record.
 */
export async function finalizeUpload(
  env: Env,
  _config: AppConfig,
  user: AuthedUser,
  upload: UploadRow,
  storage: StorageProvider
): Promise<FinalizeResult> {
  const head = await storage.readHead(upload.storage_key, 64 * 1024);
  const heuristic = scanBytes(head, {
    name: upload.name,
    mime: upload.mime ?? 'application/octet-stream',
    size: upload.size,
  });
  const external = await scanWithExternalEngine(env.SCANNER_URL, head, upload.name);
  const scan = external && external.verdict !== 'error'
    ? (external.verdict === 'infected' || heuristic.verdict === 'infected'
        ? { ...heuristic, verdict: 'infected' as const }
        : external)
    : heuristic;

  // Server-side hash verification is CPU bounded: only for reasonably small objects.
  let sha256 = upload.sha256;
  let sha256Verified = false;
  const HASH_LIMIT = 16 * 1024 * 1024;
  if (upload.size <= HASH_LIMIT) {
    try {
      const object = await storage.get(upload.storage_key);
      if (object) {
        const bytes = new Uint8Array(await new Response(object.body).arrayBuffer());
        const computed = await sha256Hex(bytes);
        if (upload.sha256) {
          sha256Verified = computed === upload.sha256.toLowerCase();
        } else {
          sha256 = computed;
          sha256Verified = true;
        }
      }
    } catch {
      sha256Verified = false;
    }
  }

  const now = Date.now();
  const quarantined = scan.verdict === 'infected' || (scan.verdict === 'suspicious' && !upload.purpose.startsWith('backup'));
  const scanStatus = scan.verdict === 'clean' ? 'clean' : scan.verdict;

  if (upload.purpose === 'backup') {
    const backupId = randomId('bak');
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO backups (id, owner_id, kind, label, schema_version, storage_key, provider, size, sha256,
                              encrypted, app_version, device_label, created_at)
         VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, NULL, ?)`
      ).bind(
        backupId,
        user.id,
        upload.backup_kind ?? 'full',
        upload.backup_label ?? upload.name,
        upload.storage_key,
        upload.provider,
        upload.size,
        upload.sha256 ?? '',
        upload.encrypted,
        null,
        now
      ),
      env.DB.prepare("UPDATE uploads SET status = 'completed', updated_at = ? WHERE id = ?").bind(now, upload.id),
      env.DB.prepare('DELETE FROM nodes WHERE id = ? AND status = ?').bind(upload.node_id, 'pending'),
    ]);
    await addUserUsage(env, user.id, upload.size, 'backup_created', backupId);
    return {
      nodeId: null,
      backupId,
      scan: { verdict: scan.verdict, findings: scan.findings.length, engine: scan.engine },
      sha256,
      sha256Verified,
      size: upload.size,
    };
  }

  if (!upload.node_id) throw new ApiError(500, 'upload_state_corrupt', 'Upload session lost its file record');
  const node = await getNode(env, user.id, upload.node_id);
  if (!node) throw notFound('Upload target file no longer exists');

  if (upload.purpose === 'version') {
    const targetVersion = upload.target_version || node.version + 1;
    // The superseded revision keeps its own row and storage object: nothing is overwritten.
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE nodes SET size = ?, sha256 = ?, storage_key = ?, version = ?, status = ?, scan_status = ?,
                          scan_detail = ?, updated_at = ? WHERE id = ?`
      ).bind(
        upload.size,
        sha256,
        upload.storage_key,
        targetVersion,
        quarantined ? 'quarantined' : 'active',
        scanStatus,
        scan.findings.length ? JSON.stringify(scan.findings).slice(0, 2000) : null,
        now,
        node.id
      ),
      env.DB.prepare(
        `INSERT INTO file_versions (id, node_id, owner_id, version, size, sha256, storage_key, provider, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(randomId('ver'), node.id, user.id, targetVersion, upload.size, sha256, upload.storage_key, upload.provider, now),
      env.DB.prepare("UPDATE uploads SET status = 'completed', updated_at = ? WHERE id = ?").bind(now, upload.id),
    ]);
    await addUserUsage(env, user.id, upload.size, 'version_upload', node.id);
    return {
      nodeId: node.id,
      backupId: null,
      scan: { verdict: scan.verdict, findings: scan.findings.length, engine: scan.engine },
      sha256,
      sha256Verified,
      size: upload.size,
    };
  }

  const finalStatus = quarantined ? 'quarantined' : 'active';
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE nodes SET size = ?, sha256 = ?, status = ?, version = 1, scan_status = ?, scan_detail = ?, updated_at = ?
       WHERE id = ?`
    ).bind(
      upload.size,
      sha256,
      finalStatus,
      scanStatus,
      scan.findings.length ? JSON.stringify(scan.findings).slice(0, 2000) : null,
      now,
      upload.node_id
    ),
    env.DB.prepare(
      `INSERT INTO file_versions (id, node_id, owner_id, version, size, sha256, storage_key, provider, created_at)
       VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)`
    ).bind(randomId('ver'), upload.node_id, user.id, upload.size, sha256, upload.storage_key, upload.provider, now),
    env.DB.prepare("UPDATE uploads SET status = 'completed', updated_at = ? WHERE id = ?").bind(now, upload.id),
  ]);

  await addUserUsage(env, user.id, upload.size, 'upload_complete', upload.node_id);

  return {
    nodeId: upload.node_id,
    backupId: null,
    scan: { verdict: scan.verdict, findings: scan.findings.length, engine: scan.engine },
    sha256,
    sha256Verified,
    size: upload.size,
  };
}

export async function assertCompletable(_env: Env, upload: UploadRow, storage: StorageProvider): Promise<void> {
  if (upload.status === 'completed') throw conflict('This upload was already completed', 'upload_completed');
  if (upload.status !== 'pending' && upload.status !== 'in_progress') {
    throw conflict(`Upload is ${upload.status}`, 'upload_not_active');
  }
  if (upload.expires_at < Date.now()) throw conflict('Upload session expired. Start a new upload.', 'upload_expired');

  if (upload.upload_type === 'multipart') {
    // Parts are tracked in D1: the Workers R2 binding has no listParts() call, and a
    // durable per-session ledger is what makes pause/resume work across devices.
    const recorded = parseParts(upload);
    const missing: number[] = [];
    for (let part = 1; part <= upload.parts_total; part += 1) {
      if (!recorded.some((p) => p.partNumber === part)) missing.push(part);
    }
    if (missing.length) {
      throw conflict('Some parts are still missing', 'upload_incomplete', { missingParts: missing.slice(0, 50) });
    }
  } else {
    const head = await storage.head(upload.storage_key);
    if (!head) throw conflict('No bytes were received for this upload', 'upload_empty');
    if (head.size !== upload.size) {
      throw conflict(`Stored size ${head.size} does not match declared size ${upload.size}`, 'size_mismatch');
    }
  }
}
