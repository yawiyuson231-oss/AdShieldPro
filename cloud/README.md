# AdShield Cloud API

Backend for the Cloud module of AdShield Pro: a Cloudflare Worker that stores bytes in
**Backblaze B2** and metadata in **Cloudflare D1**, with **Supabase Auth** for identity and
**Cloudflare Turnstile** for bot protection.

Everything below is real: the Worker code, the SQL migrations and this API are what the Android
client talks to. No storage capacity is invented and no upload is simulated.

## Why Backblaze B2 and not Cloudflare R2

The brief asked for R2. **R2 cannot be switched on without completing a checkout that takes a
card, PayPal or wallet**, even though the free tier itself never expires and costs nothing inside
its limits. That conflicts with a hard "$0, no payment method" rule, so this build uses B2:

| | Cloudflare R2 | **Backblaze B2 (used here)** |
|---|---|---|
| Free storage | 10 GB-month | **10 GB** |
| Payment method to activate | **Required** | **Not required** |
| Free egress | Unlimited | 3x stored volume/day (unlimited via Cloudflare CDN) |
| API | S3-compatible | S3-compatible + native API (used here, for real multipart) |

If you later accept a card on file, switching is a config change: the Worker only touches the
provider through `src/lib/b2.js`.

## Free-tier allowances this design respects

| Service | Free allowance | Guard implemented |
|---|---|---|
| Workers | 100 000 requests/day, 10 ms CPU/request | per-user hourly ceiling of 2 000 (`HOURLY_REQUEST_LIMIT`), 429 beyond it |
| D1 | 5 GB, 5M rows read/day, 100k rows written/day | one row per request-hour, no per-file rows during transfers |
| Backblaze B2 | 10 GB stored, free egress to 3x stored volume | per-user quota default 10 GiB, enforced before **and** after upload |
| Supabase Auth | 50 000 MAU | no extra writes; identity lives in the JWT |
| Turnstile | free, unlimited | verified server-side on registration only |

Nothing here can upgrade you to a paid plan: there is no code path that provisions a paid
resource, and exceeding a limit returns an error rather than switching provider.

## Local testing (no accounts, no cost)

The suite replaces D1 with `node:sqlite` and B2 with an HTTP stub that implements the same native
API and enforces the same SHA-1 contract. The Worker, the SQL and every route are the shipping
code.

```bash
cd cloud
npm install
npm test
```

19 tests cover: registration, small and 12 MiB multipart uploads, byte-identical download,
resume after interruption, refusal of incomplete uploads, cancellation, quota refusal with exact
numbers, folder lifecycle, purge freeing quota, version history and pruning, share links
(including expiry and revocation), DNS-backup store/verify/restore/delete, integrity rejection on
digest mismatch, duplicate detection, quota reconciliation against provider truth, rate limiting,
search and the audit log.

## Provisioning (once you are ready for real infrastructure)

```bash
# 1. Backblaze B2 — create a bucket (private), then an application key with read+write.
#    Note the keyID, applicationKey, bucket ID and bucket name.

# 2. Cloudflare D1
npx wrangler d1 create adshield_cloud          # paste the database_id into wrangler.toml
npx wrangler d1 migrations apply adshield_cloud

# 3. Worker secrets (never stored in the repo or the APK)
npx wrangler secret put B2_KEY_ID
npx wrangler secret put B2_APPLICATION_KEY
npx wrangler secret put TURNSTILE_SECRET

# 4. Supabase — create a project, copy the project URL into wrangler.toml [vars].
#    Email/password sign-in is enough; the Worker verifies the JWT against the project JWKS.

# 5. Turnstile — create a widget, put the site key in the Android client config and the
#    secret key in the Worker secret above.

npx wrangler deploy
```

## API

All `/v1/*` routes except `/v1/health` and `/v1/share/:token` require
`Authorization: Bearer <Supabase access token>`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/health` | provider, mode and the honest free allowance |
| POST | `/v1/account/register` | create the account row (Turnstile protected) |
| GET | `/v1/account` | quota, usage, warning level, 24 h request count |
| POST | `/v1/account/reconcile` | rebuild `used_bytes` from what B2 actually stores |
| GET | `/v1/audit` | the user's own last 100 actions |
| GET | `/v1/nodes` | list (`parentId`, `search`, `kind`, `trashed=1`) |
| GET | `/v1/nodes/kinds` | photo/video/audio/document counts |
| POST | `/v1/folders` | create a folder |
| POST | `/v1/nodes/:id/rename` \| `/move` \| `/copy` \| `/delete` \| `/restore` | file operations |
| DELETE | `/v1/nodes/:id` | permanent delete (removes the object, frees quota) |
| GET | `/v1/nodes/:id/versions` | version history |
| GET | `/v1/nodes/:id/download` | 15-minute signed download URL |
| GET | `/v1/duplicates` | groups by real SHA-1 |
| POST | `/v1/uploads/init` | declares size, returns per-part upload URLs |
| GET | `/v1/uploads/:id` | progress + fresh URLs for the parts still owed (resume) |
| POST | `/v1/uploads/:id/part/:n` | records a part the client uploaded directly to B2 |
| POST | `/v1/uploads/:id/complete` | finishes the large file, writes metadata, moves quota |
| POST | `/v1/uploads/:id/cancel` | cancels the provider-side large file |
| POST | `/v1/shares` · GET `/v1/shares` · DELETE `/v1/shares/:id` · GET `/v1/share/:token` | sharing |
| POST | `/v1/backups/init` \| `/commit` · GET `/v1/backups` · GET `/v1/backups/:id` · POST `/restore` · DELETE | DNS/security backups with SHA-256 verification |

### Upload flow (direct to cloud)

1. Client calls `/v1/uploads/init` with the real byte size. The Worker refuses up front if the
   size exceeds the remaining quota, and issues **short-lived, single-part B2 upload URLs**.
2. Client POSTs each part straight to B2 — bytes never transit the Worker, so the 10 ms CPU limit
   is not a constraint.
3. Client records each completed part (`size` + `sha1`), so a resumed session knows what is done.
4. `/v1/uploads/:id/complete` verifies every part is present, finishes the large file, writes
   metadata and updates `used_bytes` by the real uploaded total.

Account credentials never leave the Worker. The APK holds only the Supabase project URL, the
anon key and the Turnstile site key — all of which are public by design.
