import type { Env } from '../env';
import { ApiError, badRequest, conflict, forbidden, notFound } from '../http';
import { base64UrlEncode, pbkdf2Hash, randomId, randomToken, sha256Hex } from '../util/core';
import { getNode, type NodeRow } from './nodes';

export interface ShareRow {
  id: string;
  owner_id: string;
  node_id: string;
  token_hash: string;
  expires_at: number;
  max_downloads: number;
  download_count: number;
  password_hash: string | null;
  password_salt: string | null;
  allow_preview: number;
  revoked: number;
  created_at: number;
  last_access_at: number | null;
}

export interface ShareDto {
  id: string;
  nodeId: string;
  fileName: string;
  expiresAt: number;
  maxDownloads: number;
  downloadCount: number;
  passwordProtected: boolean;
  allowPreview: boolean;
  revoked: boolean;
  createdAt: number;
  lastAccessAt: number | null;
}

export function toShareDto(row: ShareRow, fileName: string): ShareDto {
  return {
    id: row.id,
    nodeId: row.node_id,
    fileName,
    expiresAt: row.expires_at,
    maxDownloads: row.max_downloads,
    downloadCount: row.download_count,
    passwordProtected: Boolean(row.password_hash),
    allowPreview: row.allow_preview === 1,
    revoked: row.revoked === 1,
    createdAt: row.created_at,
    lastAccessAt: row.last_access_at,
  };
}

export interface CreateShareInput {
  nodeId: string;
  expiresInSeconds?: number;
  maxDownloads?: number;
  password?: string;
  allowPreview?: boolean;
}

const MAX_SHARE_TTL_SECONDS = 30 * 24 * 3600;

export async function createShare(
  env: Env,
  ownerId: string,
  input: CreateShareInput
): Promise<{ share: ShareDto; token: string; expiresAt: number }> {
  const node = await getNode(env, ownerId, input.nodeId);
  if (!node) throw notFound('File not found in your cloud');
  if (node.kind !== 'file') throw badRequest('Only files can be shared', 'invalid_share_target');
  if (node.status !== 'active') {
    throw conflict('Only active files can be shared', 'node_not_shareable');
  }

  const ttl = Math.min(Math.max(input.expiresInSeconds ?? 7 * 24 * 3600, 300), MAX_SHARE_TTL_SECONDS);
  const maxDownloads = Math.min(Math.max(input.maxDownloads ?? 0, 0), 100_000);
  const token = randomToken(32);
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  const id = randomId('shr');

  let passwordHash: string | null = null;
  let passwordSalt: string | null = null;
  if (input.password) {
    if (input.password.length < 4) throw badRequest('Share passwords need at least 4 characters', 'weak_password');
    passwordSalt = base64UrlEncode(randomToken(16));
    passwordHash = await pbkdf2Hash(input.password, passwordSalt);
  }

  await env.DB.prepare(
    `INSERT INTO shares (id, owner_id, node_id, token_hash, expires_at, max_downloads, download_count,
                         password_hash, password_salt, allow_preview, revoked, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 0, ?)`
  )
    .bind(
      id,
      ownerId,
      node.id,
      tokenHash,
      now + ttl * 1000,
      maxDownloads,
      passwordHash,
      passwordSalt,
      input.allowPreview === false ? 0 : 1,
      now
    )
    .run();

  return {
    share: toShareDto(
      {
        id,
        owner_id: ownerId,
        node_id: node.id,
        token_hash: tokenHash,
        expires_at: now + ttl * 1000,
        max_downloads: maxDownloads,
        download_count: 0,
        password_hash: passwordHash,
        password_salt: passwordSalt,
        allow_preview: input.allowPreview === false ? 0 : 1,
        revoked: 0,
        created_at: now,
        last_access_at: null,
      },
      node.name
    ),
    token,
    expiresAt: now + ttl * 1000,
  };
}

export async function listShares(env: Env, ownerId: string): Promise<ShareDto[]> {
  const result = await env.DB.prepare(
    `SELECT s.*, n.name AS node_name FROM shares s
     JOIN nodes n ON n.id = s.node_id
     WHERE s.owner_id = ? ORDER BY s.created_at DESC LIMIT 200`
  )
    .bind(ownerId)
    .all<ShareRow & { node_name: string }>();
  return (result.results ?? []).map((row) => toShareDto(row, row.node_name));
}

export async function revokeShare(env: Env, ownerId: string, shareId: string): Promise<void> {
  const share = await env.DB.prepare('SELECT * FROM shares WHERE id = ? AND owner_id = ?')
    .bind(shareId, ownerId)
    .first<ShareRow>();
  if (!share) throw notFound('Share link not found');
  await env.DB.prepare('UPDATE shares SET revoked = 1 WHERE id = ?').bind(shareId).run();
}

export interface ShareResolution {
  share: ShareRow;
  node: NodeRow;
}

/** Resolves a public bearer token into a share + verified active node. */
export async function resolveShareToken(env: Env, token: string): Promise<ShareResolution> {
  const tokenHash = await sha256Hex(token);
  const share = await env.DB.prepare('SELECT * FROM shares WHERE token_hash = ?').bind(tokenHash).first<ShareRow>();
  if (!share) throw notFound('This share link does not exist', 'share_not_found');
  if (share.revoked === 1) throw forbidden('This share link was revoked by its owner', 'share_revoked');
  if (share.expires_at <= Date.now()) {
    throw new ApiError(410, 'share_expired', 'This share link has expired');
  }
  const node = await getNode(env, share.owner_id, share.node_id);
  if (!node) throw notFound('The shared file no longer exists', 'share_target_missing');
  if (node.status !== 'active') throw forbidden('The shared file is no longer available', 'share_target_unavailable');
  if (share.max_downloads > 0 && share.download_count >= share.max_downloads) {
    throw forbidden('This share link reached its download limit', 'share_exhausted');
  }
  return { share, node };
}

export async function verifySharePassword(share: ShareRow, password: string | undefined): Promise<void> {
  if (!share.password_hash || !share.password_salt) return;
  if (!password) throw forbidden('This share link is password protected', 'share_password_required');
  const candidate = await pbkdf2Hash(password, share.password_salt);
  if (candidate !== share.password_hash) {
    throw forbidden('Incorrect share password', 'share_password_invalid');
  }
}

export async function recordShareAccess(env: Env, shareId: string, countedDownload: boolean): Promise<void> {
  await env.DB.prepare(
    `UPDATE shares SET last_access_at = ?, download_count = download_count + ? WHERE id = ?`
  )
    .bind(Date.now(), countedDownload ? 1 : 0, shareId)
    .run();
}
