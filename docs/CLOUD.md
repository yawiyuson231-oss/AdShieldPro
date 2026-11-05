# AdShield Cloud

AdShield Cloud is the remote-storage half of AdShield Pro: a Cloudflare Worker that keeps metadata
in D1 and stores bytes in **Backblaze B2**, with **Supabase Auth** for identity. The app talks to it
over HTTPS and uploads files directly to the storage provider, so large transfers never pass through
the Worker.

Everything in this document is real: the Worker code is in `cloud/src`, the SQL schema is in
`cloud/migrations`, and the Android client is in `app/src/main/java/com/adshield/pro/data/cloud`.
No capacity, progress value or upload statistic in the UI comes from anywhere but these APIs.

## Why Backblaze B2 and not Cloudflare R2

The brief asked for R2. R2's free tier (10 GB, zero egress) is real and never expires, **but
activating it requires completing a checkout with a card, PayPal or a wallet** — there is no
card-free path and no hard spending cap. That conflicts with a hard "$0, no payment method" rule, so
this build uses Backblaze B2:

| | Cloudflare R2 | Backblaze B2 (used here) |
|---|---|---|
| Free storage | 10 GB-month | 10 GB |
| Payment method to activate | **Required** | **Not required** |
| Free egress | Unlimited | 3× stored volume/day |
| Cost beyond free | $0.015/GB-mo | $0.006/GB-mo |

Switching later is a configuration change: the Worker touches the provider only through
`cloud/src/lib/b2.js`.

## What is free, and what stops it from costing money

| Service | Free allowance | Guard in the code |
|---|---|---|
| Cloudflare Workers | 100 000 requests/day, 10 ms CPU/request | per-user hourly ceiling (2 000), 429 beyond it |
| Cloudflare D1 | 5 GB, 5 M rows read/day, 100 k rows written/day | one small row per request-hour |
| Backblaze B2 | 10 GB stored | per-user quota default 10 GiB, enforced before *and* after upload |
| Supabase Auth | 50 000 MAU | no extra writes; identity lives in the JWT |
| Cloudflare Turnstile | free, unlimited | verified server-side on registration only |

Nothing in this repository provisions a paid resource, and exceeding a limit returns an error
instead of upgrading anything.

## Setup (about 20 minutes, no card)

```bash
# 1. Backblaze B2 — create a PRIVATE bucket, then an application key with read+write.
#    Note: keyID, applicationKey, bucket ID, bucket name.

# 2. Cloudflare D1 + Worker
cd cloud
npm install
npx wrangler login
npx wrangler d1 create adshield_cloud      # paste the database_id into wrangler.toml
npx wrangler d1 migrations apply adshield_cloud

# 3. Worker secrets (never committed, never shipped in the APK)
npx wrangler secret put B2_KEY_ID
npx wrangler secret put B2_APPLICATION_KEY
npx wrangler secret put TURNSTILE_SECRET

# 4. Supabase — create a project, enable email/password sign-in, copy the project URL
#    and the anon key into wrangler.toml [vars] (or set them as vars in the dashboard).

# 5. Turnstile — create a widget; put the site key in the app and the secret in the Worker.

npx wrangler deploy
```

Then, in the app: **Cloud → Settings**, fill in the API base URL, Supabase URL, anon key and
Turnstile site key, press **Save**, then **Test connection**. The header turns from
`NOT CONNECTED` to `SYNCED` only after `/v1/health` answers.

## What the app can do once connected

| Section | Backed by |
|---|---|
| Overview | `GET /v1/account`, `GET /v1/audit`, `POST /v1/account/reconcile` |
| My Files | `GET /v1/nodes`, `POST /v1/folders`, rename/move/copy/delete/restore/purge |
| Photos / Videos / Documents | `GET /v1/nodes?kind=photo\|video\|document&recursive=1`, signed download URLs |
| Backups | `POST /v1/backups/init|commit`, `GET /v1/backups`, restore, delete, daily WorkManager job |
| Shared Files | `POST /v1/shares`, `GET /v1/shares`, revoke, `GET /v1/share/:token` |
| Upload Manager | `POST /v1/uploads/init`, per-part URLs, `part/:n`, `complete`, `cancel` |
| Cloud Security | audit log, reconciliation, rate-limit counters, quarantine, session check |

Uploads are resumable: a part that the API says is already stored is never re-sent, and each part is
declared with the SHA-1 of the bytes actually streamed, which the provider verifies.

## Security model

- **No credentials in the APK.** The app only ever holds public values (Worker URL, Supabase URL and
  anon key, Turnstile site key). Bucket keys live in Worker secrets.
- **Short-lived URLs.** Downloads and share links are signed and expire in minutes.
- **Ownership checks.** Every route scopes its queries by the user id from the verified JWT.
- **Encryption.** TLS in transit; AES-256 at rest by the provider. Optionally, configuration
  backups are encrypted on the device (AES-256-GCM, PBKDF2-HMAC-SHA256, 120 000 iterations) before
  they are uploaded — the passphrase is never stored, so a forgotten passphrase is unrecoverable.
- **Client-side encryption is not applied to large file uploads.** A resumable multipart upload has
  to re-read a byte range, which an authenticated AES-GCM stream cannot provide. The Cloud Security
  screen states this instead of implying otherwise.
- **Malware scanning.** Files are scanned on the device before upload; anything rated DANGEROUS is
  refused and listed under Quarantine with the findings.
- **Audit.** Every mutating action is written to a per-user audit log and readable in the app.

## Honest limits

1. **The backend is proven against an emulation, not a live tenant.** `cloud/tests/api.test.mjs`
   runs the shipping Worker against `node:sqlite` and an HTTP stand-in that implements the B2
   native API and enforces the same SHA-1 contract. Real-cloud upload, download, backup and restore
   can only be confirmed after the steps above are completed.
2. **The Android side is compile- and unit-test-verified, not device-verified.** The API client,
   upload engine, backup codec and vault have JVM tests
   (`app/src/test/java/com/adshield/pro/CloudPlatformTestSuite.kt`); the UI has no device run in
   this environment.
3. **Onion routing needs Orbot.** AdShield Pro cannot bundle a Tor daemon. When Orbot is installed
   and connected, browser GET requests go through its SOCKS proxy and the route is confirmed by
   `check.torproject.org`. When it is not, the app says so and offers to open the store — it never
   shows a Tor toggle that only changes a label. Android does not let an app intercept POST bodies
   or some media streams, so those still use the ordinary path.
4. **The DNS blocker does not depend on any of this.** With no account, no network or no backend,
   local DNS blocking keeps working exactly as before.

## Verification commands

```bash
cd cloud && npm test                 # 19 backend tests (uploads, quota, shares, backups, audit)
./gradlew testDebugUnitTest          # JVM suites, including the cloud and onion suites
python3 tools/audit_capability_tests.py --strict
```
