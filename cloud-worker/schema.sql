-- AdShield Pro cloud backend — D1 schema (free tier).
-- Apply with:  npx wrangler d1 execute adshield-cloud-db --file=schema.sql

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,            -- Supabase auth user id
    email TEXT NOT NULL,
    quota_bytes INTEGER NOT NULL DEFAULT 10737418240,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    folder_path TEXT NOT NULL DEFAULT '/',
    size_bytes INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    r2_key TEXT NOT NULL,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id, is_deleted);
CREATE INDEX IF NOT EXISTS idx_files_sha ON files(user_id, sha256, size_bytes);

CREATE TABLE IF NOT EXISTS file_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    r2_key TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS shares (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    max_downloads INTEGER NOT NULL DEFAULT 10,
    download_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_backups (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    label TEXT NOT NULL,
    file_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    restored_at INTEGER
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    at INTEGER NOT NULL
);
