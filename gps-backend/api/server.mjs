// AdShield community traffic API — Node 20+, zero dependencies, zero cost.
//
// Contract: it mirrors exactly what TrafficApiClient.kt sends and expects. Nothing here invents a
// speed: when there is no evidence for a segment the row is simply absent from the response and the
// app renders UNKNOWN.
//
//   POST /v1/traffic/observations  { token, reporter_version, observations:[{segment_id, speed_kmh,
//                                   timestamp_ms, accuracy_m, samples}] }
//                                -> { accepted, rejected, stored_at_ms }
//   POST /v1/traffic/incidents     { token, kind, segment_id, lat, lon, notes, reported_at_ms }
//                                -> { id, confirmations, expires_at_ms }
//   GET  /v1/traffic/segments?ids=a,b,c      -> { segments:[{segment_id, name, avg_speed_kmh,
//                                                 free_flow_kmh, samples, confidence, updated_at_ms}] }
//   GET  /v1/health                -> { ok, version, segments_seen, observations_24h }
//
// Two transports are supported from the same handler code:
//   * Postgres (pg)      — production, uses the schema in ../postgres/migrations
//   * In-memory           — `--memory` for local testing with no database at all
//
// The in-memory mode exists so the app can be exercised end-to-end on a laptop, and it is honest
// about that: /v1/health reports storage:"memory" and the data is lost on restart.

import { createServer } from 'node:http'
import { createHash, randomUUID } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import { realpathSync } from 'node:fs'

const SAMPLE_WINDOW_MS = 30 * 60 * 1000          // matches TrafficAggregator.SAMPLE_WINDOW_MINUTES
const MIN_CONFIDENCE = 0.35                       // matches TrafficAggregator.MIN_CONFIDENCE_FOR_LEVEL
const RECENCY_HALF_LIFE_MIN = 12.0                // matches TrafficAggregator.RECENCY_HALF_LIFE_MINUTES
const MAX_SPEED_KMH = 250
const MAX_ACCURACY_M = 50
const MAX_BATCH = 50
const RATE_LIMIT_PER_MINUTE = 40
const INCIDENT_DUPLICATE_METERS = 120
const INCIDENT_WINDOW_MS = 15 * 60 * 1000

const INCIDENT_LIFETIME_MIN = {
  ACCIDENT: 90,
  HAZARD: 180,
  CONSTRUCTION: 480,
  ROAD_CLOSED: 720,
  POLICE: 45,
  WEATHER: 120,
  BROKEN_DOWN: 60
}

// --------------------------------------------------------------------- helpers

const hashToken = (token) => createHash('sha256').update(String(token ?? '')).digest('hex')

function haversine(aLat, aLon, bLat, bLon) {
  const R = 6371008.8
  const toRad = (deg) => (deg * Math.PI) / 180
  const dLat = toRad(bLat - aLat)
  const dLon = toRad(bLon - aLon)
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(aLat)) * Math.cos(toRad(bLat)) * Math.sin(dLon / 2) ** 2
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)))
}

/**
 * Confidence, identical to the client's TrafficAggregator so a value never means two things.
 * volume(1..30) x recency(12 min half-life) x agreement(unavailable server-side, fixed 0.85)
 */
function confidence(samples, reporters, ageMinutes) {
  if (samples <= 0) return 0
  const volume = Math.min(1, Math.log(1 + samples) / Math.log(31)) * 0.75 + 0.25
  const recency = Math.pow(0.5, ageMinutes / RECENCY_HALF_LIFE_MIN)
  const reporterBoost = reporters >= 5 ? 1.0 : reporters >= 2 ? 0.9 : 0.75
  return Math.min(0.99, volume * recency * 0.85 * reporterBoost)
}

const json = (res, status, body) => {
  const payload = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
    // The app talks to this from a mobile client; no browser origin is involved.
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'content-type, x-adshield-token',
    'access-control-allow-methods': 'GET, POST, OPTIONS'
  })
  res.end(payload)
}

async function readJson(req, limitBytes = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > limitBytes) {
        reject(new Error('payload too large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {})
      } catch {
        reject(new Error('invalid JSON'))
      }
    })
    req.on('error', reject)
  })
}

// ------------------------------------------------------------------ rate limit

const buckets = new Map()

function allow(tokenHash, cost = 1, now = Date.now()) {
  const windowStart = Math.floor(now / 60_000)
  const key = `${tokenHash}:${windowStart}`
  const used = buckets.get(key) ?? 0
  if (used + cost > RATE_LIMIT_PER_MINUTE) return false
  buckets.set(key, used + cost)
  // Opportunistic cleanup so the map cannot grow without bound.
  if (buckets.size > 5000) {
    for (const k of buckets.keys()) {
      if (!k.endsWith(`:${windowStart}`)) buckets.delete(k)
    }
  }
  return true
}

// -------------------------------------------------------------------- in-memory

export function createMemoryStore() {
  /** segmentId -> { name, speedLimitKmh, observations: [...] } */
  const segments = new Map()
  const incidents = new Map()

  return {
    kind: 'memory',
    async addObservations(rows) {
      let accepted = 0
      for (const row of rows) {
        const entry = segments.get(row.segment_id) ?? { observations: [] }
        entry.observations.push(row)
        segments.set(row.segment_id, entry)
        accepted += 1
      }
      return accepted
    },
    async liveSegments(ids) {
      const now = Date.now()
      const out = []
      for (const id of ids) {
        const entry = segments.get(id)
        if (!entry) continue
        const recent = entry.observations.filter((o) => now - o.received_at <= SAMPLE_WINDOW_MS)
        if (recent.length === 0) continue
        const samples = recent.reduce((sum, o) => sum + (o.samples || 1), 0)
        const reporters = new Set(recent.map((o) => o.token_hash)).size
        const avg = recent.reduce((sum, o) => sum + o.speed_kmh, 0) / recent.length
        const newest = Math.max(...recent.map((o) => o.received_at))
        const score = confidence(samples, reporters, (now - newest) / 60_000)
        if (score < MIN_CONFIDENCE) continue
        out.push({
          segment_id: id,
          name: entry.name ?? null,
          avg_speed_kmh: Number(avg.toFixed(1)),
          free_flow_kmh: entry.speedLimitKmh ?? null,
          samples,
          confidence: Number(score.toFixed(3)),
          updated_at_ms: newest
        })
      }
      return out
    },
    async addIncident(incident) {
      const existing = [...incidents.values()].find(
        (other) =>
          other.kind === incident.kind &&
          Date.now() < other.expires_at &&
          haversine(other.lat, other.lon, incident.lat, incident.lon) <= INCIDENT_DUPLICATE_METERS
      )
      if (existing) {
        if (existing.token_hash === incident.token_hash) {
          return { id: existing.id, merged: true, confirmations: existing.confirmations }
        }
        existing.confirmations += 1
        return { id: existing.id, merged: true, confirmations: existing.confirmations }
      }
      incidents.set(incident.id, incident)
      return { id: incident.id, merged: false, confirmations: 0 }
    },
    async stats() {
      const now = Date.now()
      let observations = 0
      for (const entry of segments.values()) {
        observations += entry.observations.filter((o) => now - o.received_at <= 24 * 3600_000).length
      }
      return { segments_seen: segments.size, observations_24h: observations }
    }
  }
}

// ---------------------------------------------------------------------- Postgres

export function createPostgresStore(pool) {
  return {
    kind: 'postgres',
    async addObservations(rows) {
      let accepted = 0
      for (const row of rows) {
        // Upsert the segment first: the client derives a deterministic id, so two drivers on the
        // same street register it once.
        await pool.query(
          `INSERT INTO road_segments (id, name, geom, speed_limit_kmh, road_class)
           VALUES ($1, $2, ST_SetSRID(ST_MakeLine(ST_MakePoint($3, $4), ST_MakePoint($3, $4)), 4326), $5, 0)
           ON CONFLICT (id) DO UPDATE SET updated_at = now()`,
          [row.segment_id, row.name ?? null, row.lon ?? 0, row.lat ?? 0, row.speed_limit_kmh ?? null]
        )
        const result = await pool.query(
          `INSERT INTO observations
             (segment_id, speed_kmh, accuracy_meters, heading_deg, sample_count,
              hour_bucket, day_of_week, reporter_token_hash, dedupe_key)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           ON CONFLICT (dedupe_key) DO NOTHING`,
          [
            row.segment_id,
            row.speed_kmh,
            row.accuracy_m,
            row.heading_deg ?? 0,
            Math.min(6, Math.max(1, row.samples ?? 1)),
            new Date(row.timestamp_ms).getHours(),
            new Date(row.timestamp_ms).getDay(),
            row.token_hash,
            row.dedupe_key
          ]
        )
        accepted += result.rowCount
      }
      return accepted
    },
    async liveSegments(ids) {
      if (ids.length === 0) return []
      const { rows } = await pool.query(
        `SELECT segment_id, name, average_speed_kmh, sample_count, reporter_count, newest_at,
                speed_limit_kmh
           FROM live_segment_traffic
          WHERE segment_id = ANY($1::text[])`,
        [ids]
      )
      return rows
        .map((row) => {
          const ageMinutes = (Date.now() - new Date(row.newest_at).getTime()) / 60_000
          const score = confidence(row.sample_count, row.reporter_count, ageMinutes)
          if (score < MIN_CONFIDENCE) return null
          return {
            segment_id: row.segment_id,
            name: row.name,
            avg_speed_kmh: Number(row.average_speed_kmh),
            free_flow_kmh: row.speed_limit_kmh,
            samples: row.sample_count,
            confidence: Number(score.toFixed(3)),
            updated_at_ms: new Date(row.newest_at).getTime()
          }
        })
        .filter(Boolean)
    },
    async addIncident(incident) {
      const { rows } = await pool.query(
        `INSERT INTO incidents (id, kind, position, notes, reporter_token_hash, expires_at, dedupe_cell)
         VALUES ($1,$2,ST_SetSRID(ST_MakePoint($3,$4),4326),$5,$6,to_timestamp($7/1000.0),$8)
         ON CONFLICT (reporter_token_hash, kind, dedupe_cell) DO NOTHING
         RETURNING id`,
        [
          incident.id,
          incident.kind,
          incident.lon,
          incident.lat,
          incident.notes ?? null,
          incident.token_hash,
          incident.expires_at,
          incident.dedupe_cell
        ]
      )
      if (rows.length > 0) return { id: incident.id, merged: false, confirmations: 0 }
      const existing = await pool.query(
        `SELECT id, confirmations FROM incidents
          WHERE kind = $1 AND dedupe_cell = $2 AND expires_at > now() LIMIT 1`,
        [incident.kind, incident.dedupe_cell]
      )
      if (existing.rows.length === 0) return { id: incident.id, merged: false, confirmations: 0 }
      const target = existing.rows[0]
      const confirmed = await pool.query(
        `INSERT INTO incident_confirmations (incident_id, reporter_token_hash)
         VALUES ($1,$2) ON CONFLICT DO NOTHING`,
        [target.id, incident.token_hash]
      )
      if (confirmed.rowCount > 0) {
        await pool.query(`UPDATE incidents SET confirmations = confirmations + 1 WHERE id = $1`, [target.id])
      }
      return { id: target.id, merged: true, confirmations: target.confirmations + (confirmed.rowCount > 0 ? 1 : 0) }
    },
    async stats() {
      const segments = await pool.query('SELECT count(*)::int AS n FROM road_segments')
      const observations = await pool.query(
        `SELECT count(*)::int AS n FROM observations WHERE received_at >= now() - INTERVAL '24 hours'`
      )
      return { segments_seen: segments.rows[0].n, observations_24h: observations.rows[0].n }
    }
  }
}

// ------------------------------------------------------------------------ routes

export function createApp(store) {
  return async function handle(req, res) {
    const url = new URL(req.url, 'http://localhost')
    const path = url.pathname

    if (req.method === 'OPTIONS') {
      json(res, 204, {})
      return
    }

    if (path === '/v1/health') {
      const stats = await store.stats()
      json(res, 200, { ok: true, version: 1, storage: store.kind, ...stats })
      return
    }

    const token = req.headers['x-adshield-token']
    const tokenHash = hashToken(token)
    if (!token || String(token).length < 16) {
      json(res, 401, { error: 'missing or too-short X-AdShield-Token' })
      return
    }

    if (path === '/v1/traffic/observations' && req.method === 'POST') {
      if (!allow(tokenHash, 1)) {
        json(res, 429, { error: 'rate limited', detail: 'one batch per minute per token' })
        return
      }
      let body
      try {
        body = await readJson(req)
      } catch (error) {
        json(res, 400, { error: error.message })
        return
      }
      const items = Array.isArray(body.observations) ? body.observations.slice(0, MAX_BATCH) : []
      const rows = []
      let rejected = 0
      for (const item of items) {
        const speed = Number(item.speed_kmh)
        const accuracy = Number(item.accuracy_m)
        const segmentId = typeof item.segment_id === 'string' ? item.segment_id : null
        const timestamp = Number(item.timestamp_ms)
        const plausible =
          segmentId &&
          segmentId.length <= 96 &&
          Number.isFinite(speed) &&
          speed >= 0 &&
          speed <= MAX_SPEED_KMH &&
          Number.isFinite(accuracy) &&
          accuracy >= 0 &&
          accuracy <= MAX_ACCURACY_M &&
          Number.isFinite(timestamp) &&
          Math.abs(Date.now() - timestamp) < 24 * 3600_000
        if (!plausible) {
          rejected += 1
          continue
        }
        const window = Math.floor(timestamp / (5 * 60_000))
        rows.push({
          segment_id: segmentId,
          speed_kmh: speed,
          accuracy_m: accuracy,
          samples: Math.min(6, Math.max(1, Number(item.samples) || 1)),
          heading_deg: Number(item.heading_deg) || 0,
          timestamp_ms: timestamp,
          name: typeof item.name === 'string' ? item.name.slice(0, 120) : null,
          speed_limit_kmh: Number.isFinite(Number(item.speed_limit_kmh)) ? Number(item.speed_limit_kmh) : null,
          token_hash: tokenHash,
          received_at: Date.now(),
          dedupe_key: createHash('sha256').update(`${tokenHash}|${segmentId}|${window}`).digest('hex')
        })
      }
      const accepted = rows.length ? await store.addObservations(rows) : 0
      json(res, 200, { accepted, rejected, stored_at_ms: Date.now() })
      return
    }

    if (path === '/v1/traffic/incidents' && req.method === 'POST') {
      if (!allow(tokenHash, 2)) {
        json(res, 429, { error: 'rate limited' })
        return
      }
      let body
      try {
        body = await readJson(req)
      } catch (error) {
        json(res, 400, { error: error.message })
        return
      }
      const kind = String(body.kind ?? '')
      const lifetime = INCIDENT_LIFETIME_MIN[kind]
      const lat = Number(body.lat)
      const lon = Number(body.lon)
      const notes = typeof body.notes === 'string' ? body.notes.slice(0, 280) : null
      if (!lifetime) {
        json(res, 400, { error: 'unknown incident kind' })
        return
      }
      if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) {
        json(res, 400, { error: 'invalid coordinates' })
        return
      }
      const incident = {
        id: randomUUID(),
        kind,
        lat,
        lon,
        notes,
        token_hash: tokenHash,
        expires_at: Date.now() + lifetime * 60_000,
        // ~120 m grid cell: the coarse half of duplicate suppression.
        dedupe_cell: `${lat.toFixed(3)},${lon.toFixed(3)}`
      }
      const outcome = await store.addIncident(incident)
      json(res, outcome.merged ? 200 : 201, {
        id: outcome.id,
        merged: outcome.merged,
        confirmations: outcome.confirmations,
        expires_at_ms: incident.expires_at
      })
      return
    }

    if (path === '/v1/traffic/segments' && req.method === 'GET') {
      if (!allow(tokenHash, 2)) {
        json(res, 429, { error: 'rate limited' })
        return
      }
      const ids = (url.searchParams.get('ids') ?? '')
        .split(',')
        .map((id) => id.trim())
        .filter(Boolean)
        .slice(0, 100)
      const segments = await store.liveSegments(ids)
      json(res, 200, {
        segments,
        // The app must be able to distinguish "nothing measured" from "request failed".
        unknown_count: ids.length - segments.length,
        generated_at_ms: Date.now()
      })
      return
    }

    json(res, 404, { error: 'not found' })
  }
}

// -------------------------------------------------------------------------- boot

async function main() {
  const args = process.argv.slice(2)
  const memory = args.includes('--memory')
  const port = Number(process.env.PORT ?? 8080)

  let store
  if (memory) {
    store = createMemoryStore()
  } else {
    const connectionString = process.env.DATABASE_URL
    if (!connectionString) {
      console.error(
        'DATABASE_URL is not set. Run with --memory for a throwaway test server,\n' +
          'or point DATABASE_URL at a Postgres instance with postgres/migrations applied.'
      )
      process.exit(1)
    }
    let pg
    try {
      pg = await import('pg')
    } catch {
      console.error('The "pg" package is required for Postgres mode: npm install pg')
      process.exit(1)
    }
    const pool = new pg.default.Pool({ connectionString, max: 4 })
    store = createPostgresStore(pool)
  }

  const server = createServer(createApp(store))
  server.listen(port, '0.0.0.0', () => {
    console.log(`AdShield traffic API listening on 0.0.0.0:${port} (storage=${store.kind})`)
  })
}

// Only boot when executed directly, so the tests can import createApp/createMemoryStore.
const executedDirectly = (() => {
  try {
    return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href
  } catch {
    return false
  }
})()

if (executedDirectly) {
  main().catch((error) => {
    console.error(error)
    process.exit(1)
  })
}
