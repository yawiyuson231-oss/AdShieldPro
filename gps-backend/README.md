# AdShield community traffic server

**Optional. Nothing in the app requires this.** With no server configured the GPS module still
works fully: routing, maps, offline packs, navigation and *your own* measured speeds. The traffic
map then shows UNKNOWN for every road you have not driven yourself, which is the honest answer.

Run this only if you want a group of drivers (a family, a company, a city) to pool anonymous road
speeds. It is small enough for a free tier or a home server.

## What it stores

Per observation: a road-segment id, an average speed in km/h, the fix accuracy, a *coarse* hour and
day-of-week bucket, and a hashed reporter token. Per incident: a type, a position, a lifetime, and
the same hashed token.

There is no account, no email, no device identifier, no per-user history and no full route. The
`dedupe_key` exists so a retried upload is a no-op rather than a double count. Tokens are hashed
with SHA-256 before they reach SQL, so a database dump cannot be reversed into a reporter.

## Free-tier limits this is designed for

| Resource | Free allowance | What the server does |
|---|---|---|
| Neon free Postgres | 0.5 GB storage, 190 compute-hours/month | observations pruned after 24 h; only aggregates persist |
| Supabase free Postgres | 500 MB | same pruning job |
| Fly.io / Render free instance | 256 MB RAM | the API is stateless, ~40 MB resident |
| Cloudflare Workers + Hyperdrive | 100k requests/day | endpoint is a single upsert, ~3 ms CPU |

Nothing here needs a paid plan to run at neighbourhood scale. If the community grows past the free
tier the correct fix is another volunteer server, not a paid API.

## Endpoints

All endpoints require HTTPS and the `X-AdShield-Token` header (the app's rotating anonymous token).

```
POST /v1/segments       register/refresh segment geometry (batched, idempotent)
POST /v1/observations   submit anonymous speed samples (batched, idempotent)
GET  /v1/segments?bbox=s,w,n,e       live aggregate for the visible area
POST /v1/incidents      report an incident
POST /v1/incidents/:id/confirm       confirm somebody else's report
GET  /v1/incidents?bbox=s,w,n,e      active incidents
GET  /v1/health         version + whether aggregates are warm
```

## Honesty rules enforced server-side

1. **No observations, no row.** A segment absent from `live_segment_traffic` is not returned, and
   the app renders it grey. The server never invents a baseline speed.
2. **Aggressive values are rejected.** `CHECK` constraints refuse speeds above 250 km/h or accuracy
   worse than 50 m, matching the client's `TelemetryGate`.
3. **One vote per window.** `dedupe_key` and `incidents_dedupe_idx` make repeated submissions
   idempotent an leave a single vote per reporter per segment.
4. **Confidence is a client decision.** The server returns counts; the client decides whether the
   evidence is strong enough to colour a road.

## Running it locally (no accounts, no cost)

```bash
docker run --rm -e POSTGRES_PASSWORD=dev -p 5432:5432 postgis/postgis:16-3.4
psql postgresql://postgres:dev@localhost:5432/postgres \
  -f postgres/migrations/0001_init.sql
DATABASE_URL=postgresql://postgres:dev@localhost:5432/postgres \
  node api/server.mjs      # or: npm start
```

Then in the app: **Live traffic → Backend URL → `http://10.0.2.2:8080`** (emulator) or your LAN
address. The app refuses plain HTTP outside `10.0.2.2`/localhost unless you enable the debug
override, so a real deployment needs TLS — a self-signed certificate through a free reverse proxy
(Caddy, Cloudflare Tunnel) is enough.

## What is deliberately missing

* No reverse-geocoding of segments (the client already knows the road name from its own graph).
* No long-term per-user analytics — there is no user to analyse.
* No push notifications for incidents: the client polls the visible bounding box only.
