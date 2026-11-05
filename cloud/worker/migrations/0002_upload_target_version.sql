-- Migration 0002: version-aware uploads
--
-- Adds the target version number to upload sessions so the API can accept a *new revision*
-- of an existing file (POST /v1/files/:id/versions/init) without creating a second node.
-- D1 applies this transactionally; existing rows default to 0 (meaning "new file").

ALTER TABLE uploads ADD COLUMN target_version INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_uploads_node ON uploads(node_id, status);
