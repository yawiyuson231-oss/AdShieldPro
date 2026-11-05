import type { Env } from '../env';
import { notFound } from '../http';
import { sha256Hex } from '../util/core';
import type { StorageProvider } from '../storage/provider';

export const BACKUP_KINDS = [
  'dns_config',
  'blocklists',
  'allowlist',
  'denylist',
  'firewall',
  'security_prefs',
  'app_config',
  'full',
] as const;

export type BackupKind = (typeof BACKUP_KINDS)[number];

export interface BackupRow {
  id: string;
  owner_id: string;
  kind: BackupKind;
  label: string;
  schema_version: number;
  storage_key: string;
  provider: string;
  size: number;
  sha256: string;
  encrypted: number;
  app_version: string | null;
  device_label: string | null;
  rule_count: number;
  integrity_ok: number;
  verified_at: number | null;
  restored_at: number | null;
  created_at: number;
}

export interface BackupDto {
  id: string;
  kind: string;
  label: string;
  schemaVersion: number;
  size: number;
  sha256: string;
  encrypted: boolean;
  appVersion: string | null;
  deviceLabel: string | null;
  ruleCount: number;
  integrityOk: boolean;
  verifiedAt: number | null;
  restoredAt: number | null;
  createdAt: number;
}

export function toBackupDto(row: BackupRow): BackupDto {
  return {
    id: row.id,
    kind: row.kind,
    label: row.label,
    schemaVersion: row.schema_version,
    size: row.size,
    sha256: row.sha256,
    encrypted: row.encrypted === 1,
    appVersion: row.app_version,
    deviceLabel: row.device_label,
    ruleCount: row.rule_count,
    integrityOk: row.integrity_ok === 1,
    verifiedAt: row.verified_at,
    restoredAt: row.restored_at,
    createdAt: row.created_at,
  };
}

export async function listBackups(env: Env, ownerId: string, kind?: string): Promise<BackupDto[]> {
  const statement = kind
    ? env.DB.prepare('SELECT * FROM backups WHERE owner_id = ? AND kind = ? ORDER BY created_at DESC LIMIT 200').bind(ownerId, kind)
    : env.DB.prepare('SELECT * FROM backups WHERE owner_id = ? ORDER BY created_at DESC LIMIT 200').bind(ownerId);
  const result = await statement.all<BackupRow>();
  return (result.results ?? []).map(toBackupDto);
}

export async function getBackup(env: Env, ownerId: string, backupId: string): Promise<BackupRow> {
  const row = await env.DB.prepare('SELECT * FROM backups WHERE id = ? AND owner_id = ?')
    .bind(backupId, ownerId)
    .first<BackupRow>();
  if (!row) throw notFound('Backup not found');
  return row;
}

/**
 * Recomputes the SHA-256 of the stored backup object and compares it with the value
 * recorded at upload time. Proves the object in cloud storage is byte-identical.
 */
export async function verifyBackupIntegrity(
  env: Env,
  ownerId: string,
  backupId: string,
  storage: StorageProvider
): Promise<{ backup: BackupDto; computedSha256: string; matches: boolean }> {
  const row = await getBackup(env, ownerId, backupId);
  const object = await storage.get(row.storage_key);
  if (!object) throw notFound('Backup object is missing from storage', 'backup_object_missing');
  const bytes = new Uint8Array(await new Response(object.body).arrayBuffer());
  const computed = await sha256Hex(bytes);
  const matches = row.sha256 ? computed === row.sha256.toLowerCase() : true;
  const now = Date.now();
  await env.DB.prepare('UPDATE backups SET integrity_ok = ?, verified_at = ? WHERE id = ?')
    .bind(matches ? 1 : 0, now, backupId)
    .run();
  return {
    backup: toBackupDto({ ...row, integrity_ok: matches ? 1 : 0, verified_at: now }),
    computedSha256: computed,
    matches,
  };
}

export async function markBackupRestored(env: Env, ownerId: string, backupId: string): Promise<void> {
  await env.DB.prepare('UPDATE backups SET restored_at = ? WHERE id = ? AND owner_id = ?')
    .bind(Date.now(), backupId, ownerId)
    .run();
}

export async function deleteBackup(
  env: Env,
  ownerId: string,
  backupId: string,
  storage: StorageProvider
): Promise<{ freedBytes: number }> {
  const row = await getBackup(env, ownerId, backupId);
  await storage.delete(row.storage_key);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM backups WHERE id = ? AND owner_id = ?').bind(backupId, ownerId),
    env.DB.prepare('UPDATE users SET used_bytes = MAX(0, used_bytes - ?) WHERE id = ?').bind(row.size, ownerId),
  ]);
  return { freedBytes: row.size };
}
