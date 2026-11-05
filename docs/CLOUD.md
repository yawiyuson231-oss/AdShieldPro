# AdShield Pro — Cloud Storage (free tier)

The **Cloud** bottom-nav module integrates real cloud storage into the DNS cybersecurity app.
It costs **$0 to start and to run**: all infrastructure is on free tiers.

## What ships in the app (`app/src/main/java/com/adshield/pro/cloud/`)

- **Auth** — email/password sign-up & sign-in, proxied by your Worker to a free-tier Supabase
  project. The session JWT is stored in app-private DataStore.
- **Files** — upload, download, folders, rename, move, copy, delete (soft), restore from trash,
  search/filter by kind, version list, duplicate detection (SHA-256 + size), expiring share links.
- **Upload engine** — direct-to-cloud via short-lived signed URLs, multipart for files > 5 MiB,
  per-chunk progress, pause/resume/cancel, WorkManager background execution, SHA-256 integrity.
- **Quota management** — shows only server-reported usage; warns at 80%, blocks new uploads at 95%;
  never claims unlimited storage; never switches to paid infrastructure.
- **DNS security cloud backup** — backs up DNS config, custom block/allow lists, firewall/app
  settings as a hashed JSON object; restore verifies SHA-256 before applying and merges (never
  deletes newer local rules). **The DNS blocker works fully offline — the cloud is never required.**
- **Security** — HTTPS only, private bucket, server-side ownership checks, ≤15-minute signed
  URLs (expiry re-validated client-side), file-type gating, audit log on the Worker.

## Backend

`cloud-worker/` contains the deployable Worker + D1 schema + R2 binding. See
[cloud-worker/README.md](../cloud-worker/README.md) for the one-time free deployment.

## Honest limits

- The app operates **no backend of its own**; you deploy the free-tier Worker on your own
  Cloudflare account and enter its URL in Cloud → Settings. Until then the UI shows an explicit
  "not configured" state — nothing is simulated.
- Free-tier caps apply (R2 10 GB, Worker 100k req/day, D1 5M reads/day).
- No live malware scanning service is called; file-type validation + local scanning apply.
- The session token is not additionally encrypted at rest (app-private storage only).

## Tests

`CloudEngineTestSuite` (JVM) covers quota thresholds/blocking, signed-URL expiry validation,
dedupe keys, file-type gating, backup round-trip + tamper detection, and the extended
private-search providers (DuckDuckGo, DuckDuckGo **onion**, Brave, Google).
