-- AdShield Cloud — D1 schema (migration 0001)
-- Backblaze B2 stores bytes; D1 stores every byte of *metadata*. Nothing here is invented:
-- used_bytes is maintained from real, completed uploads and reconciled with B2 on demand.

CREATE TABLE IF NOT EXISTS users (
  id                TEXT PRIMARY KEY,          -- Supabase auth user id (sub)
  email             TEXT NOT NULL DEFAULT '',
  created_at        INTEGER NOT NULL,
  quota_bytes       INTEGER NOT NULL DEFAULT 10737418240,  -- 10 GiB: the B2 free allowance
  used_bytes        INTEGER NOT NULL DEFAULT 0,
  retention_days    INTEGER NOT NULL DEFAULT 30,           -- trash retention
  disabled          INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS nodes (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL,
  parent_id     TEXT,                       -- NULL = drive root
  kind          TEXT NOT NULL,              -- 'folder' | 'file'
  name          TEXT NOT NULL,
  size_bytes    INTEGER NOT NULL DEFAULT 0,
  content_type  TEXT NOT NULL DEFAULT 'application/octet-stream',
  sha1          TEXT,
  b2_file_id    TEXT,
  b2_key        TEXT,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  deleted_at    INTEGER,                    -- soft delete (trash)
  purge_at      INTEGER                     -- when the trash entry may be purged for good
);
CREATE INDEX IF NOT EXISTS idx_nodes_user_parent ON nodes(user_id, parent_id, deleted_at);
CREATE INDEX IF NOT EXISTS idx_nodes_user_sha1   ON nodes(user_id, sha1);
CREATE INDEX IF NOT EXISTS idx_nodes_user_kind   ON nodes(user_id, kind, deleted_at);

CREATE TABLE IF NOT EXISTS versions (
  id          TEXT PRIMARY KEY,
  node_id     TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  version     INTEGER NOT NULL,
  size_bytes  INTEGER NOT NULL,
  sha1        TEXT NOT NULL DEFAULT '',
  b2_file_id  TEXT,
  b2_key      TEXT,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_versions_node ON versions(node_id, version DESC);

CREATE TABLE IF NOT EXISTS upload_sessions (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL,
  node_id       TEXT,
  parent_id     TEXT,
  name          TEXT NOT NULL,
  content_type  TEXT NOT NULL DEFAULT 'application/octet-stream',
  declared_size INTEGER NOT NULL,
  actual_size   INTEGER NOT NULL DEFAULT 0,
  part_size     INTEGER NOT NULL,
  total_parts   INTEGER NOT NULL,
  b2_file_id    TEXT,
  b2_key        TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'open',   -- open | completed | cancelled | failed
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON upload_sessions(user_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS upload_parts (
  session_id   TEXT NOT NULL,
  part_number  INTEGER NOT NULL,
  size_bytes   INTEGER NOT NULL,
  sha1         TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  PRIMARY KEY (session_id, part_number)
);

CREATE TABLE IF NOT EXISTS shares (
  id          TEXT PRIMARY KEY,
  token       TEXT NOT NULL DEFAULT '',
  node_id     TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  permission  TEXT NOT NULL DEFAULT 'read',
  expires_at  INTEGER,
  revoked_at  INTEGER,
  created_at  INTEGER NOT NULL,
  downloads   INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_shares_token ON shares(token);
CREATE INDEX IF NOT EXISTS idx_shares_node ON shares(node_id, revoked_at);

CREATE TABLE IF NOT EXISTS backups (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL,
  kind          TEXT NOT NULL,              -- 'dns_config' | 'rules' | 'full_config'
  label         TEXT NOT NULL DEFAULT '',
  size_bytes    INTEGER NOT NULL,
  sha256        TEXT NOT NULL,              -- integrity verification of the payload
  b2_file_id    TEXT,
  b2_key        TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  restored_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_backups_user ON backups(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  action     TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT '',
  ip         TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id, created_at DESC);

-- Free-tier API budget accounting. Every request writes one row per user per hour bucket;
-- the value is read back to warn (and then refuse) before the provider starts charging.
CREATE TABLE IF NOT EXISTS api_usage (
  user_id   TEXT NOT NULL,
  bucket    INTEGER NOT NULL,               -- epoch hour
  requests  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, bucket)
);
