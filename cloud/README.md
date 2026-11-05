# CyberShield Cloud — backend

The storage backend behind AdShield Pro's **Cloud** tab and the DNS backup/restore feature.
It runs on Cloudflare's free plan (Workers + D1) with object bytes in either **R2** or
**Supabase Storage**, selected per deployment by a single environment variable. There is no
second server to run and no paid service required for the default path
(see [docs/cloud/FREE_TIER.md](../docs/cloud/FREE_TIER.md) for the honest limits, including
the one case where Cloudflare asks for a card).

```
Android app  ──HTTPS──▶  Worker (this folder)  ──▶  D1   (metadata, quota ledger, audit)
      │                        │
      │                        └──────────────────▶  R2 / Supabase Storage (object bytes)
      └──signed, short-lived URL for downloads──────▶  object storage (never through the app)
```

## What the worker does

| Area | Behaviour |
| --- | --- |
| Auth | Own HS256 JWT issuer (`/v1/auth/*`), plus Supabase GoTrue passthrough when `SUPABASE_URL` is set. Refresh tokens rotate on every use. |
| Quota | Per-user 1 GiB, 9 GiB global. Every byte is metered in `quota_events`; dedupe still consumes quota. |
| Uploads | Resumable: `init` → parts → `complete`. 5–8 MiB parts, 100 MB single-PUT ceiling, `target_version` for new versions. |
| Downloads | `/v1/files/:id/download` mints a 300 s HMAC capability URL (`/d/:token`). The worker streams from storage; no credentials leave the server. |
| Versions | `POST /v1/files/:id/versions/init` + `restore`, retained per file. |
| Trash | Soft delete, 30-day retention, `purge` endpoint that also frees quota. |
| Sharing | Password-protected (PBKDF2), optional expiry + download cap, `revoke` flips to 410 Gone. |
| Backups | `init` → upload as a normal object → `verify` (SHA-256) → `restore-ticket`. Kinds: `full`, `rules`, `settings`, `allowlist`. |
| Malware | Upload-time hash/name heuristics + optional remote scanner. Infected or suspicious non-backup files are `quarantined` (download returns 423). Only the owner can `release`, and the true verdict is preserved in `scan_detail`. |
| Abuse | Per-route rate limits in D1 (general 240/min, uploads, auth, shares), hashed IPs only, Turnstile hooks. |
| Audit | Every mutating action is appended to `audit_logs` and surfaced in the app's Security section. |

## Layout

```
src/index.ts            entry + error mapping
src/router.ts           tiny path router
src/http.ts             request/response helpers, JSON, pagination, capability URLs
src/env.ts              typed bindings (BUCKET, DB, secrets, limits)
src/security/*          tokens, auth, rate limiting, turnstile, scanner
src/storage/provider.ts StorageProvider: r2 | supabase
src/repo/*              SQL for users, nodes, uploads, shares, backups, usage, audit
src/routes/*            account, files, transfer, sharing, backups
migrations/*.sql        D1 schema (apply with wrangler)
test/run-tests.mjs      65-case integration suite (real workerd + local D1 + R2)
```

## Develop

```bash
cd cloud/worker
npm install
npx tsc --noEmit                 # typecheck
npm run migrate:local            # apply migrations to the local D1
npm test                         # boots wrangler itself; 65/65 expected
```

`npm test` writes `test/last-run.json` (per-test results) and `test/worker-dev.log`
(worker stdout). Both are git-ignored.

## Deploy

See [docs/cloud/SETUP.md](../docs/cloud/SETUP.md) — about 15 minutes with two free accounts.

## API surface (v1)

```
POST /v1/auth/register | login | refresh | logout | recovery | reset
GET  /v1/account | /v1/usage | /v1/security | /v1/audit
POST /v1/account/plan
POST /v1/uploads/init            POST /v1/uploads/:id/parts
POST /v1/uploads/:id/complete    GET  /v1/uploads/:id
GET  /v1/files?category=&limit=  GET  /v1/files/:id
POST /v1/files/:id/verify | /release | /restore
POST /v1/files/:id/versions/init   GET /v1/files/:id/versions
POST /v1/files/:id/versions/:vid/restore
GET  /v1/files/:id/download      DELETE /v1/files/:id
GET  /v1/trash                   POST /v1/trash/purge
GET  /v1/search?q=
POST /v1/shares                  GET /v1/shares      DELETE /v1/shares/:id
GET  /s/:token                   POST /s/:token/unlock
GET  /d/:token
POST /v1/backups/init | /:id/verify | /:id/restore-ticket | /:id/mark-restored
GET  /v1/backups                 DELETE /v1/backups/:id
```
