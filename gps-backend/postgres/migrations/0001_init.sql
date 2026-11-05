-- AdShield GPS traffic aggregator — PostgreSQL 16 + PostGIS (migration 0001)
--
-- Self-hosted, zero-cost, optional. The app is fully functional with no server at all: traffic
-- then shows only this device's own observations and everything else reads UNKNOWN. This schema
-- exists so a community of drivers can pool anonymous segment speeds.
--
-- Design rules that the code depends on:
--   * No coordinates are stored per observation — only a segment reference derived from the
--     rounded segment geometry. An observation is (segment, speed, coarse bucket, token hash).
--   * A segment is a ~80 m stretch of road; ids are deterministic (cell + bearing), so two
--     independent clients produce the same id for the same street without a shared database.
--   * Reporter tokens are stored hashed (SHA-256 hex) and only for duplicate suppression. There is
--     no column that can identify a person or a device.
--   * `speed_buckets` is a permanent aggregate. Raw observations in `observations` are pruned after
--     24 h by the aggregator; aggregates keep the rolling history the app charts.

CREATE EXTENSION IF NOT EXISTS postgis;

-- ------------------------------------------------------------------ segments
CREATE TABLE IF NOT EXISTS road_segments (
  id                 TEXT PRIMARY KEY,             -- "seg-<latCell>-<lonCell>-<bearing>" from the client
  name               TEXT,
  geom               geometry(LineString, 4326) NOT NULL,
  speed_limit_kmh    REAL,
  road_class         SMALLINT NOT NULL DEFAULT 0,  -- matches OfflineRoadGraph EdgeClass ids
  country            CHAR(2),
  first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS road_segments_geom_idx ON road_segments USING GIST (geom);
CREATE INDEX IF NOT EXISTS road_segments_name_idx ON road_segments (name);

-- ------------------------------------------------------------------ raw observations
CREATE TABLE IF NOT EXISTS observations (
  id                 BIGSERIAL PRIMARY KEY,
  segment_id         TEXT NOT NULL REFERENCES road_segments (id) ON DELETE CASCADE,
  speed_kmh          REAL NOT NULL CHECK (speed_kmh >= 0 AND speed_kmh <= 250),
  accuracy_meters    REAL NOT NULL CHECK (accuracy_meters >= 0 AND accuracy_meters <= 50),
  heading_deg        REAL NOT NULL CHECK (heading_deg >= 0 AND heading_deg < 360),
  sample_count       SMALLINT NOT NULL DEFAULT 1 CHECK (sample_count BETWEEN 1 AND 6),
  -- Coarse hour bucket only: enough to learn "this street is slow at 18:00", not when *you* drove.
  hour_bucket        SMALLINT NOT NULL CHECK (hour_bucket BETWEEN 0 AND 23),
  day_of_week        SMALLINT NOT NULL CHECK (day_of_week BETWEEN 0 AND 6),
  reporter_token_hash CHAR(64) NOT NULL,
  received_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- One row per reporter per segment per 5-minute window: replaying an upload is a no-op.
  dedupe_key         CHAR(64) NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS observations_segment_recent_idx
  ON observations (segment_id, received_at DESC);

-- ------------------------------------------------------------------ incidents
CREATE TABLE IF NOT EXISTS incidents (
  id                 TEXT PRIMARY KEY,
  kind               TEXT NOT NULL CHECK (kind IN
                       ('ACCIDENT','HAZARD','CONSTRUCTION','ROAD_CLOSED','POLICE','WEATHER','BROKEN_DOWN')),
  segment_id         TEXT REFERENCES road_segments (id) ON DELETE SET NULL,
  position           geometry(Point, 4326) NOT NULL,
  road_name          TEXT,
  notes              TEXT CHECK (notes IS NULL OR length(notes) <= 280),
  reporter_token_hash CHAR(64) NOT NULL,
  confirmations      SMALLINT NOT NULL DEFAULT 0,
  reported_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at         TIMESTAMPTZ NOT NULL,
  withdrawn          BOOLEAN NOT NULL DEFAULT FALSE,
  -- One report of a kind within ~120 m per reporter: the server-side half of the client dedupe.
  dedupe_cell        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS incidents_active_idx ON incidents (expires_at) WHERE NOT withdrawn;
CREATE INDEX IF NOT EXISTS incidents_geom_idx ON incidents USING GIST (position);
CREATE UNIQUE INDEX IF NOT EXISTS incidents_dedupe_idx
  ON incidents (reporter_token_hash, kind, dedupe_cell);

CREATE TABLE IF NOT EXISTS incident_confirmations (
  incident_id        TEXT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
  reporter_token_hash CHAR(64) NOT NULL,
  confirmed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (incident_id, reporter_token_hash)
);

-- ------------------------------------------------------------------ permanent aggregates
CREATE TABLE IF NOT EXISTS speed_buckets (
  segment_id         TEXT NOT NULL REFERENCES road_segments (id) ON DELETE CASCADE,
  day_of_week        SMALLINT NOT NULL CHECK (day_of_week BETWEEN 0 AND 6),
  hour_bucket        SMALLINT NOT NULL CHECK (hour_bucket BETWEEN 0 AND 23),
  sample_count       INTEGER NOT NULL DEFAULT 0,
  speed_sum          DOUBLE PRECISION NOT NULL DEFAULT 0,
  speed_sq_sum       DOUBLE PRECISION NOT NULL DEFAULT 0,  -- for the agreement factor
  reporter_count     INTEGER NOT NULL DEFAULT 0,
  last_updated       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (segment_id, day_of_week, hour_bucket)
);

-- ------------------------------------------------------------------ rate limiting
CREATE TABLE IF NOT EXISTS client_rate (
  token_hash         CHAR(64) NOT NULL,
  window_start       TIMESTAMPTZ NOT NULL,
  request_count      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (token_hash, window_start)
);

-- ------------------------------------------------------------------ aggregate views
-- What the app reads for "live" traffic: the last 30 minutes, which is exactly the window the
-- client-side aggregator uses, so the two never disagree about what "live" means.
CREATE OR REPLACE VIEW live_segment_traffic AS
SELECT
  s.id                                                        AS segment_id,
  s.name,
  s.speed_limit_kmh,
  AVG(o.speed_kmh)::REAL                                      AS average_speed_kmh,
  SUM(o.sample_count)::INTEGER                                AS sample_count,
  COUNT(DISTINCT o.reporter_token_hash)::INTEGER               AS reporter_count,
  MAX(o.received_at)                                          AS newest_at,
  ST_AsGeoJSON(s.geom)                                        AS geojson,
  CASE
    WHEN s.speed_limit_kmh IS NULL OR s.speed_limit_kmh <= 0 THEN NULL
    ELSE AVG(o.speed_kmh) / s.speed_limit_kmh
  END                                                         AS speed_ratio
FROM road_segments s
JOIN observations o ON o.segment_id = s.id
WHERE o.received_at >= now() - INTERVAL '30 minutes'
GROUP BY s.id, s.name, s.speed_limit_kmh, s.geom;

/*
 * Congestion is deliberately NOT stored as an enum here. The client derives the level from
 * average_speed_kmh / free-flow speed and applies its own confidence threshold (0.35), so an
 * aggregate that looks authoritative never overrides "we do not have enough evidence".
 * A segment with no rows in live_segment_traffic simply does not appear — the app shows UNKNOWN.
 */

-- ------------------------------------------------------------------ account bookkeeping
CREATE TABLE IF NOT EXISTS schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT INTO schema_meta (key, value) VALUES ('version', '1')
  ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
