-- AdShield Pro cloud storage — initial schema (Cloudflare D1 / SQLite)
-- All timestamps are Unix epoch milliseconds (INTEGER).
-- This schema stores *metadata only*. File bytes live in object storage (R2 or Supabase Storage).

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- Users (identity is owned by Supabase Auth; this is the local profile + quota)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                  TEXT PRIMARY KEY,          -- Supabase auth user id (JWT `sub`)
    email               TEXT,
    display_name        TEXT,
    tier                TEXT NOT NULL DEFAULT 'free',
    status              TEXT NOT NULL DEFAULT 'active',  -- active | suspended
    quota_bytes         INTEGER NOT NULL,          -- per-user quota enforced by the API
    used_bytes          INTEGER NOT NULL DEFAULT 0,
    client_encryption   INTEGER NOT NULL DEFAULT 0,
    created_at          INTEGER NOT NULL,
    last_seen_at        INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ---------------------------------------------------------------------------
-- Nodes: unified file/folder tree (folders have kind='folder', size 0)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS nodes (
    id              TEXT PRIMARY KEY,
    owner_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id       TEXT REFERENCES nodes(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('file', 'folder')),
    mime            TEXT,
    size            INTEGER NOT NULL DEFAULT 0,
    sha256          TEXT,
    storage_key     TEXT,
    provider        TEXT NOT NULL DEFAULT 'r2',
    version         INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('pending', 'active', 'trashed', 'quarantined', 'purging')),
    encrypted       INTEGER NOT NULL DEFAULT 0,
    scan_status     TEXT NOT NULL DEFAULT 'not_scanned'
                    CHECK (scan_status IN ('not_scanned', 'pending', 'clean', 'suspicious', 'infected', 'error')),
    scan_detail     TEXT,
    download_count  INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    trashed_at      INTEGER,
    purged_at       INTEGER
);
CREATE INDEX IF NOT EXISTS idx_nodes_parent   ON nodes(owner_id, parent_id, status, kind);
CREATE INDEX IF NOT EXISTS idx_nodes_recent   ON nodes(owner_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_nodes_hash     ON nodes(owner_id, sha256);
CREATE INDEX IF NOT EXISTS idx_nodes_name     ON nodes(owner_id, status, name);

-- ---------------------------------------------------------------------------
-- Immutable version history (one row per stored object revision)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS file_versions (
    id          TEXT PRIMARY KEY,
    node_id     TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    owner_id    TEXT NOT NULL,
    version     INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    sha256      TEXT,
    storage_key TEXT NOT NULL,
    provider    TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    created_by  TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_versions_node_version ON file_versions(node_id, version);
CREATE INDEX IF NOT EXISTS idx_versions_owner ON file_versions(owner_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Resumable upload sessions (single PUT or multipart)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS uploads (
    id              TEXT PRIMARY KEY,
    owner_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id         TEXT,
    parent_id       TEXT,
    name            TEXT NOT NULL,
    mime            TEXT,
    size            INTEGER NOT NULL,
    sha256          TEXT,
    provider        TEXT NOT NULL,
    storage_key     TEXT NOT NULL,
    upload_type     TEXT NOT NULL DEFAULT 'single',    -- single | multipart
    provider_upload_id TEXT,
    part_size       INTEGER NOT NULL DEFAULT 0,
    parts_total     INTEGER NOT NULL DEFAULT 0,
    parts_done      INTEGER NOT NULL DEFAULT 0,
    bytes_received  INTEGER NOT NULL DEFAULT 0,
    uploaded_parts  TEXT,                              -- JSON [{partNumber, etag, size}]
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'in_progress', 'completed', 'aborted', 'expired')),
    purpose         TEXT NOT NULL DEFAULT 'file',      -- file | backup
    encrypted       INTEGER NOT NULL DEFAULT 0,
    backup_kind     TEXT,
    backup_label    TEXT,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_uploads_owner ON uploads(owner_id, status, updated_at DESC);

-- ---------------------------------------------------------------------------
-- Share links (only a SHA-256 hash of the bearer token is stored)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS shares (
    id              TEXT PRIMARY KEY,
    owner_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id         TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    max_downloads   INTEGER NOT NULL DEFAULT 0,     -- 0 = unlimited
    download_count  INTEGER NOT NULL DEFAULT 0,
    password_hash   TEXT,
    password_salt   TEXT,
    allow_preview   INTEGER NOT NULL DEFAULT 1,
    revoked         INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    last_access_at  INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_shares_token ON shares(token_hash);
CREATE INDEX IF NOT EXISTS idx_shares_owner ON shares(owner_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Encrypted configuration backups (DNS rules, blocklists, preferences, ...)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS backups (
    id              TEXT PRIMARY KEY,
    owner_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,        -- dns_config | blocklists | allowlist | denylist |
                                          -- firewall | security_prefs | app_config | full
    label           TEXT NOT NULL,
    schema_version  INTEGER NOT NULL DEFAULT 1,
    storage_key     TEXT NOT NULL,
    provider        TEXT NOT NULL,
    size            INTEGER NOT NULL,
    sha256          TEXT NOT NULL,
    encrypted       INTEGER NOT NULL DEFAULT 1,
    app_version     TEXT,
    device_label    TEXT,
    rule_count      INTEGER NOT NULL DEFAULT 0,
    integrity_ok    INTEGER NOT NULL DEFAULT 1,
    verified_at     INTEGER,
    restored_at     INTEGER,
    created_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_backups_owner ON backups(owner_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Security audit trail
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id          TEXT PRIMARY KEY,
    owner_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    success     INTEGER NOT NULL DEFAULT 1,
    ip_hash     TEXT,
    user_agent  TEXT,
    detail      TEXT,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_owner ON audit_logs(owner_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Fixed-window rate limiting counters
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket_key   TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_key, window_start)
);

-- ---------------------------------------------------------------------------
-- Daily API usage counters (used to monitor the free-tier request budget)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_usage (
    day         TEXT NOT NULL,          -- YYYY-MM-DD (UTC)
    owner_id    TEXT NOT NULL,
    requests    INTEGER NOT NULL DEFAULT 0,
    bytes_up    INTEGER NOT NULL DEFAULT 0,
    bytes_down  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, owner_id)
);

-- ---------------------------------------------------------------------------
-- Quota ledger (append-only, used for reconciliation + audit)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS quota_events (
    id         TEXT PRIMARY KEY,
    owner_id   TEXT NOT NULL,
    delta      INTEGER NOT NULL,
    reason     TEXT NOT NULL,
    node_id    TEXT,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quota_events_owner ON quota_events(owner_id, created_at DESC);
