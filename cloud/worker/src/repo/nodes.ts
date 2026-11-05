import type { Env } from '../env';
import { badRequest, conflict, notFound } from '../http';
import { base64UrlDecode, base64UrlEncode, fileExtension, randomId, sanitizeName } from '../util/core';

export type NodeKind = 'file' | 'folder';
export type NodeStatus = 'active' | 'trashed' | 'quarantined' | 'purging';

export interface NodeRow {
  id: string;
  owner_id: string;
  parent_id: string | null;
  name: string;
  kind: NodeKind;
  mime: string | null;
  size: number;
  sha256: string | null;
  storage_key: string | null;
  provider: string;
  version: number;
  status: NodeStatus;
  encrypted: number;
  scan_status: string;
  scan_detail: string | null;
  download_count: number;
  created_at: number;
  updated_at: number;
  trashed_at: number | null;
}

export interface NodeDto {
  id: string;
  parentId: string | null;
  name: string;
  kind: NodeKind;
  mime: string | null;
  size: number;
  sha256: string | null;
  provider: string;
  version: number;
  status: NodeStatus;
  encrypted: boolean;
  scanStatus: string;
  scanDetail: string | null;
  downloadCount: number;
  createdAt: number;
  updatedAt: number;
  trashedAt: number | null;
  extension: string;
}

export function toNodeDto(row: NodeRow): NodeDto {
  return {
    id: row.id,
    parentId: row.parent_id,
    name: row.name,
    kind: row.kind,
    mime: row.mime,
    size: row.size,
    sha256: row.sha256,
    provider: row.provider,
    version: row.version,
    status: row.status,
    encrypted: row.encrypted === 1,
    scanStatus: row.scan_status,
    scanDetail: row.scan_detail,
    downloadCount: row.download_count,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    trashedAt: row.trashed_at,
    extension: fileExtension(row.name),
  };
}

export type CategoryFilter = 'all' | 'photos' | 'videos' | 'documents' | 'music' | 'folders' | 'files';

const CATEGORY_PREDICATES: Record<Exclude<CategoryFilter, 'all' | 'folders'>, string> = {
  photos: "mime LIKE 'image/%'",
  videos: "mime LIKE 'video/%'",
  music: "mime LIKE 'audio/%'",
  documents:
    "(mime LIKE 'text/%' OR mime LIKE 'application/pdf%' OR mime LIKE 'application/msword%' " +
    "OR mime LIKE 'application/vnd.ms-%' OR mime LIKE 'application/vnd.openxmlformats-%' " +
    "OR mime LIKE 'application/vnd.oasis%' OR mime LIKE 'application/rtf%' OR mime LIKE 'application/json%' " +
    "OR mime LIKE 'application/xml%')",
  files: '1 = 1',
};

export async function getNode(env: Env, ownerId: string, nodeId: string): Promise<NodeRow | null> {
  return env.DB.prepare('SELECT * FROM nodes WHERE id = ? AND owner_id = ?').bind(nodeId, ownerId).first<NodeRow>();
}

export async function requireNode(env: Env, ownerId: string, nodeId: string): Promise<NodeRow> {
  const node = await getNode(env, ownerId, nodeId);
  if (!node) throw notFound('File not found in your cloud');
  return node;
}

/** Ownership + lifecycle guard used before every mutating action. */
export async function requireActiveNode(env: Env, ownerId: string, nodeId: string): Promise<NodeRow> {
  const node = await requireNode(env, ownerId, nodeId);
  if (node.status === 'trashed') {
    throw conflict('This item is in the trash. Restore it first.', 'node_trashed');
  }
  if (node.status === 'quarantined') {
    throw conflict('This item is quarantined. Release it from Cloud Security first.', 'node_quarantined');
  }
  return node;
}

export interface ListOptions {
  parentId?: string | null;
  status?: NodeStatus;
  category?: CategoryFilter;
  query?: string;
  sort?: 'name' | 'size' | 'updated' | 'created';
  direction?: 'asc' | 'desc';
  limit?: number;
  cursor?: string;
}

export interface NodeList {
  items: NodeDto[];
  nextCursor: string | null;
  totalSize: number;
}

export async function listNodes(env: Env, ownerId: string, options: ListOptions): Promise<NodeList> {
  const status = options.status ?? 'active';
  const category = options.category ?? 'all';
  const limit = Math.min(Math.max(options.limit ?? 50, 1), 200);
  const sortColumn = { name: 'name', size: 'size', updated: 'updated_at', created: 'created_at' }[options.sort ?? 'name'];
  const direction = (options.direction ?? 'asc').toUpperCase() === 'DESC' ? 'DESC' : 'ASC';

  const where: string[] = ['owner_id = ?', 'status = ?'];
  const bindings: unknown[] = [ownerId, status];

  if (options.parentId !== undefined) {
    if (options.parentId === null || options.parentId === 'root') {
      where.push('parent_id IS NULL');
    } else {
      where.push('parent_id = ?');
      bindings.push(options.parentId);
    }
  }

  if (category === 'folders') {
    where.push("kind = 'folder'");
  } else if (category !== 'all') {
    where.push("kind = 'file'");
    where.push(CATEGORY_PREDICATES[category]);
  }

  if (options.query && options.query.trim()) {
    where.push('LOWER(name) LIKE ?');
    const needle = options.query.trim().toLowerCase().replace(/[%_\\]/g, '');
    bindings.push(`%${needle}%`);
  }

  if (options.cursor) {
    const decoded = decodeCursor(options.cursor);
    where.push(`(${sortColumn} > ? OR (${sortColumn} = ? AND id > ?))`);
    bindings.push(decoded.sortValue, decoded.sortValue, decoded.id);
  }

  const sql =
    `SELECT * FROM nodes WHERE ${where.join(' AND ')} ` +
    `ORDER BY ${sortColumn} ${direction}, id ASC LIMIT ?`;
  const result = await env.DB.prepare(sql)
    .bind(...bindings, limit + 1)
    .all<NodeRow>();

  const rows = result.results ?? [];
  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;
  const last = page[page.length - 1];
  const sortValue = last ? (last as unknown as Record<string, number | string>)[sortColumn] : undefined;

  return {
    items: page.map(toNodeDto),
    nextCursor: hasMore && last && sortValue !== undefined
      ? encodeCursor({ sortValue: sortValue as string | number, id: last.id })
      : null,
    totalSize: page.reduce((sum, row) => sum + (row.kind === 'file' ? row.size : 0), 0),
  };
}

export function encodeCursor(payload: { sortValue: string | number; id: string }): string {
  return base64UrlEncode(JSON.stringify(payload));
}

export function decodeCursor(cursor: string): { sortValue: string | number; id: string } {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(base64UrlDecode(cursor))) as { sortValue: string | number; id: string };
    if (typeof parsed.id !== 'string' || parsed.sortValue === undefined) throw new Error('bad cursor');
    return parsed;
  } catch {
    throw badRequest('Invalid pagination cursor', 'invalid_cursor');
  }
}

/** Case-insensitive name uniqueness within the same folder. */
export async function ensureNameAvailable(
  env: Env,
  ownerId: string,
  parentId: string | null,
  name: string,
  excludeNodeId?: string
): Promise<void> {
  const row = await env.DB.prepare(
    `SELECT id FROM nodes WHERE owner_id = ? AND status != 'trashed' AND id != ?
       AND ${parentId === null ? 'parent_id IS NULL' : 'parent_id = ?'}
       AND LOWER(name) = LOWER(?) LIMIT 1`
  )
    .bind(ownerId, excludeNodeId ?? '', ...(parentId === null ? [] : [parentId]), name)
    .first<{ id: string }>();
  if (row) throw conflict(`An item named "${name}" already exists here`, 'name_taken');
}

export async function uniqueName(env: Env, ownerId: string, parentId: string | null, desired: string): Promise<string> {
  const sanitized = sanitizeName(desired);
  const dot = sanitized.lastIndexOf('.');
  const base = dot > 0 ? sanitized.slice(0, dot) : sanitized;
  const ext = dot > 0 ? sanitized.slice(dot) : '';
  let candidate = sanitized;
  for (let counter = 2; counter < 200; counter += 1) {
    const existing = await env.DB.prepare(
      `SELECT id FROM nodes WHERE owner_id = ? AND status != 'trashed'
         AND ${parentId === null ? 'parent_id IS NULL' : 'parent_id = ?'}
         AND LOWER(name) = LOWER(?) LIMIT 1`
    )
      .bind(ownerId, ...(parentId === null ? [] : [parentId]), candidate)
      .first<{ id: string }>();
    if (!existing) return candidate;
    candidate = `${base} (${counter})${ext}`;
  }
  return `${base}-${Date.now()}${ext}`;
}

export async function createFolder(
  env: Env,
  ownerId: string,
  parentId: string | null,
  rawName: string
): Promise<NodeRow> {
  const name = sanitizeName(rawName);
  if (!name) throw badRequest('Folder name is required', 'invalid_name');
  if (parentId) {
    const parent = await requireNode(env, ownerId, parentId);
    if (parent.kind !== 'folder') throw badRequest('Parent is not a folder', 'invalid_parent');
  }
  await ensureNameAvailable(env, ownerId, parentId, name);
  const now = Date.now();
  const id = randomId('fld');
  await env.DB.prepare(
    `INSERT INTO nodes (id, owner_id, parent_id, name, kind, mime, size, status, scan_status, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'folder', NULL, 0, 'active', 'not_scanned', ?, ?)`
  )
    .bind(id, ownerId, parentId, name, now, now)
    .run();
  return requireNode(env, ownerId, id);
}

export async function renameNode(env: Env, ownerId: string, nodeId: string, rawName: string): Promise<NodeRow> {
  const node = await requireActiveNode(env, ownerId, nodeId);
  const name = sanitizeName(rawName);
  if (!name) throw badRequest('A name is required', 'invalid_name');
  if (name !== node.name) {
    await ensureNameAvailable(env, ownerId, node.parent_id, name, nodeId);
  }
  await env.DB.prepare('UPDATE nodes SET name = ?, updated_at = ? WHERE id = ? AND owner_id = ?')
    .bind(name, Date.now(), nodeId, ownerId)
    .run();
  return requireNode(env, ownerId, nodeId);
}

export async function moveNode(
  env: Env,
  ownerId: string,
  nodeId: string,
  destinationParentId: string | null
): Promise<NodeRow> {
  const node = await requireActiveNode(env, ownerId, nodeId);
  if (destinationParentId) {
    const destination = await requireNode(env, ownerId, destinationParentId);
    if (destination.kind !== 'folder') throw badRequest('Destination is not a folder', 'invalid_parent');
    if (destination.id === nodeId) throw badRequest('Cannot move a folder into itself', 'invalid_move');
    // Walk up the destination chain to reject cycles.
    let cursor: string | null = destination.parent_id;
    let guard = 0;
    while (cursor && guard < 500) {
      if (cursor === nodeId) throw badRequest('Cannot move a folder into one of its children', 'invalid_move');
      const parent: { parent_id: string | null } | null = await env.DB.prepare(
        'SELECT parent_id FROM nodes WHERE id = ? AND owner_id = ?'
      )
        .bind(cursor, ownerId)
        .first<{ parent_id: string | null }>();
      cursor = parent?.parent_id ?? null;
      guard += 1;
    }
  }
  await ensureNameAvailable(env, ownerId, destinationParentId, node.name, nodeId);
  await env.DB.prepare('UPDATE nodes SET parent_id = ?, updated_at = ? WHERE id = ? AND owner_id = ?')
    .bind(destinationParentId, Date.now(), nodeId, ownerId)
    .run();
  return requireNode(env, ownerId, nodeId);
}

/** Deep copy of a node (and children) with fresh storage keys for files. */
export async function copyNode(
  env: Env,
  ownerId: string,
  nodeId: string,
  destinationParentId: string | null,
  storage: { copy: (from: string, to: string) => Promise<unknown> }
): Promise<NodeRow> {
  const source = await requireActiveNode(env, ownerId, nodeId);
  if (destinationParentId) {
    const destination = await requireNode(env, ownerId, destinationParentId);
    if (destination.kind !== 'folder') throw badRequest('Destination is not a folder', 'invalid_parent');
  }
  const name = await uniqueName(env, ownerId, destinationParentId, source.name);
  const created = await copyRecursive(env, ownerId, source, destinationParentId, name, storage);
  return created;
}

async function copyRecursive(
  env: Env,
  ownerId: string,
  source: NodeRow,
  parentId: string | null,
  name: string,
  storage: { copy: (from: string, to: string) => Promise<unknown> }
): Promise<NodeRow> {
  const now = Date.now();
  const newId = randomId(source.kind === 'folder' ? 'fld' : 'fil');
  let storageKey = source.storage_key;
  if (source.kind === 'file' && source.storage_key) {
    storageKey = `u/${ownerId}/${newId}/v1/${name}`;
    await storage.copy(source.storage_key, storageKey);
  }
  await env.DB.prepare(
    `INSERT INTO nodes (id, owner_id, parent_id, name, kind, mime, size, sha256, storage_key, provider, version,
                        status, encrypted, scan_status, scan_detail, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)`
  )
    .bind(
      newId,
      ownerId,
      parentId,
      name,
      source.kind,
      source.mime,
      source.size,
      source.sha256,
      storageKey,
      source.provider,
      source.kind === 'file' ? 1 : 0,
      source.encrypted,
      source.scan_status,
      source.scan_detail,
      now,
      now
    )
    .run();

  if (source.kind === 'file' && storageKey) {
    await env.DB.prepare(
      `INSERT INTO file_versions (id, node_id, owner_id, version, size, sha256, storage_key, provider, created_at)
       VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)`
    )
      .bind(randomId('ver'), newId, ownerId, source.size, source.sha256, storageKey, source.provider, now)
      .run();
    await env.DB.prepare('UPDATE users SET used_bytes = used_bytes + ? WHERE id = ?').bind(source.size, ownerId).run();
  }

  if (source.kind === 'folder') {
    const children = await env.DB.prepare(
      "SELECT * FROM nodes WHERE owner_id = ? AND parent_id = ? AND status = 'active'"
    )
      .bind(ownerId, source.id)
      .all<NodeRow>();
    for (const child of children.results ?? []) {
      await copyRecursive(env, ownerId, child, newId, child.name, storage);
    }
  }
  return requireNode(env, ownerId, newId);
}

/** Moves a node and all descendants to the trash (storage bytes stay counted until purge). */
export async function trashNode(env: Env, ownerId: string, nodeId: string): Promise<{ trashed: number }> {
  const node = await requireNode(env, ownerId, nodeId);
  if (node.status === 'trashed') return { trashed: 0 };
  const ids = await collectDescendantIds(env, ownerId, nodeId);
  const now = Date.now();
  const statements = ids.map((id) =>
    env.DB.prepare("UPDATE nodes SET status = 'trashed', trashed_at = ? WHERE id = ? AND owner_id = ?").bind(now, id, ownerId)
  );
  statements.push(
    env.DB.prepare('UPDATE shares SET revoked = 1 WHERE node_id IN (' + ids.map(() => '?').join(',') + ')').bind(...ids)
  );
  await env.DB.batch(statements);
  return { trashed: ids.length };
}

export async function restoreNode(env: Env, ownerId: string, nodeId: string): Promise<{ restored: number }> {
  const node = await requireNode(env, ownerId, nodeId);
  if (node.status !== 'trashed') return { restored: 0 };
  const ids = await collectDescendantIds(env, ownerId, nodeId, true);
  // If the parent is gone, restore into the root.
  const parent = node.parent_id ? await getNode(env, ownerId, node.parent_id) : null;
  const targetParent = parent && parent.status === 'active' ? node.parent_id : null;
  await env.DB.prepare("UPDATE nodes SET parent_id = ?, updated_at = ? WHERE id = ? AND owner_id = ?")
    .bind(targetParent, Date.now(), nodeId, ownerId)
    .run();
  const statements = ids.map((id) =>
    env.DB.prepare("UPDATE nodes SET status = 'active', trashed_at = NULL, updated_at = ? WHERE id = ? AND owner_id = ?")
      .bind(Date.now(), id, ownerId)
  );
  await env.DB.batch(statements);
  return { restored: ids.length };
}

export async function collectDescendantIds(
  env: Env,
  ownerId: string,
  rootId: string,
  includeTrashed = false
): Promise<string[]> {
  const collected: string[] = [];
  const queue: string[] = [rootId];
  while (queue.length && collected.length < 10_000) {
    const current = queue.shift() as string;
    collected.push(current);
    const children = await env.DB.prepare(
      `SELECT id FROM nodes WHERE owner_id = ? AND parent_id = ?${includeTrashed ? '' : " AND status != 'trashed'"}`
    )
      .bind(ownerId, current)
      .all<{ id: string }>();
    for (const child of children.results ?? []) queue.push(child.id);
  }
  return collected;
}

/**
 * Permanently deletes a node tree, its versions and any orphaned storage objects.
 * Shared storage keys (from duplicate-reference copies) are only removed once unreferenced.
 */
export async function purgeNode(
  env: Env,
  ownerId: string,
  nodeId: string,
  storage: { delete: (key: string) => Promise<void> }
): Promise<{ freedBytes: number; deletedNodes: number }> {
  await requireNode(env, ownerId, nodeId);
  const ids = await collectDescendantIds(env, ownerId, nodeId, true);
  const placeholders = ids.map(() => '?').join(',');

  const versionRows = await env.DB.prepare(
    `SELECT storage_key, size FROM file_versions WHERE node_id IN (${placeholders})`
  )
    .bind(...ids)
    .all<{ storage_key: string; size: number }>();

  const nodeRows = await env.DB.prepare(
    `SELECT storage_key, size FROM nodes WHERE id IN (${placeholders}) AND kind = 'file'`
  )
    .bind(...ids)
    .all<{ storage_key: string | null; size: number }>();

  let freedBytes = 0;
  const keys = new Set<string>();
  for (const row of versionRows.results ?? []) if (row.storage_key) keys.add(row.storage_key);
  for (const row of nodeRows.results ?? []) if (row.storage_key) keys.add(row.storage_key);

  for (const key of keys) {
    const stillReferenced = await env.DB.prepare(
      `SELECT 1 AS one FROM file_versions WHERE storage_key = ? AND node_id NOT IN (${placeholders}) LIMIT 1`
    )
      .bind(key, ...ids)
      .first<{ one: number }>();
    const referencedByNode = await env.DB.prepare(
      `SELECT 1 AS one FROM nodes WHERE storage_key = ? AND id NOT IN (${placeholders}) LIMIT 1`
    )
      .bind(key, ...ids)
      .first<{ one: number }>();
    if (!stillReferenced && !referencedByNode) {
      await storage.delete(key);
      freedBytes += (versionRows.results ?? []).find((v) => v.storage_key === key)?.size ?? 0;
    }
  }

  await env.DB.batch([
    env.DB.prepare(`DELETE FROM file_versions WHERE node_id IN (${placeholders})`).bind(...ids),
    env.DB.prepare(`DELETE FROM shares WHERE node_id IN (${placeholders})`).bind(...ids),
    env.DB.prepare(`DELETE FROM nodes WHERE id IN (${placeholders})`).bind(...ids),
  ]);

  // Every stored version consumed quota when it was uploaded, so reclaim their total.
  const usageDelta = (versionRows.results ?? []).reduce((sum, row) => sum + row.size, 0);

  if (usageDelta > 0) {
    await env.DB.prepare('UPDATE users SET used_bytes = MAX(0, used_bytes - ?) WHERE id = ?').bind(usageDelta, ownerId).run();
  }

  return { freedBytes: usageDelta, deletedNodes: ids.length };
}

export async function findDuplicate(
  env: Env,
  ownerId: string,
  sha256: string
): Promise<{ id: string; name: string; size: number; storageKey: string | null; provider: string; mime: string | null } | null> {
  const row = await env.DB.prepare(
    `SELECT id, name, size, storage_key, provider, mime FROM nodes
     WHERE owner_id = ? AND sha256 = ? AND kind = 'file' AND status = 'active'
     ORDER BY created_at ASC LIMIT 1`
  )
    .bind(ownerId, sha256.toLowerCase())
    .first<{ id: string; name: string; size: number; storage_key: string | null; provider: string; mime: string | null }>();
  if (!row) return null;
  return { id: row.id, name: row.name, size: row.size, storageKey: row.storage_key, provider: row.provider, mime: row.mime };
}

export interface VersionRow {
  id: string;
  node_id: string;
  owner_id: string;
  version: number;
  size: number;
  sha256: string | null;
  storage_key: string;
  provider: string;
  created_at: number;
}

export async function listVersions(env: Env, ownerId: string, nodeId: string): Promise<VersionRow[]> {
  const result = await env.DB.prepare(
    'SELECT * FROM file_versions WHERE node_id = ? AND owner_id = ? ORDER BY version DESC'
  )
    .bind(nodeId, ownerId)
    .all<VersionRow>();
  return result.results ?? [];
}

export async function folderUsage(env: Env, ownerId: string): Promise<{ files: number; folders: number; bytes: number }> {
  const row = await env.DB.prepare(
    `SELECT
       SUM(CASE WHEN kind = 'file' THEN 1 ELSE 0 END) AS files,
       SUM(CASE WHEN kind = 'folder' THEN 1 ELSE 0 END) AS folders,
       SUM(CASE WHEN kind = 'file' THEN size ELSE 0 END) AS bytes
     FROM nodes WHERE owner_id = ? AND status != 'trashed'`
  )
    .bind(ownerId)
    .first<{ files: number | null; folders: number | null; bytes: number | null }>();
  return { files: row?.files ?? 0, folders: row?.folders ?? 0, bytes: row?.bytes ?? 0 };
}
