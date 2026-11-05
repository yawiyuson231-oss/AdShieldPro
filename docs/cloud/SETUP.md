# Deploying CyberShield Cloud (free, ~15 minutes)

You need one free Cloudflare account. A Supabase project is optional and only needed if you
want the cardless storage path (recommended — R2 asks for a card even on the free plan).

---

## 1. Create the database (Cloudflare D1)

```bash
npm install -g wrangler
wrangler login
cd cloud/worker
wrangler d1 create adshield_cloud
```

Copy the printed `database_id` into `wrangler.toml`:

```toml
[[d1_databases]]
binding = "DB"
database_name = "adshield_cloud"
database_id = "paste-the-id-here"
```

Apply the schema:

```bash
npm run migrate:remote
```

## 2. Choose where the bytes go

### Option A — Supabase Storage (no card, 1 GB total, 50 MB per object)

1. Create a free project at supabase.com.
2. Storage → New bucket → name it `adshield-cloud`, keep it **private**.
3. Storage → S3 access keys → create one; note the access key, secret, region and endpoint.
4. In `wrangler.toml`:

```toml
[vars]
STORAGE_PROVIDER = "supabase"
SUPABASE_URL = "https://<project>.supabase.co"
```

5. Then set the secrets:

```bash
wrangler secret put SUPABASE_S3_ENDPOINT   # https://<project>.storage.supabase.co/storage/v1/s3
wrangler secret put SUPABASE_S3_REGION     # e.g. us-east-1 (the region shown next to the bucket)
wrangler secret put SUPABASE_S3_BUCKET     # adshield-cloud
wrangler secret put SUPABASE_S3_ACCESS_KEY
wrangler secret put SUPABASE_S3_SECRET_KEY
```

### Option B — Cloudflare R2 (10 GB, needs a card on file)

```bash
wrangler r2 bucket create adshield-cloud
```

Uncomment the `[[r2_buckets]]` block in `wrangler.toml` and set
`STORAGE_PROVIDER = "r2"`. R2's free plan requires a payment method, even though the first
10 GB do not bill.

## 3. Secrets the worker needs

```bash
# 32+ random characters each; generate with: openssl rand -hex 32
wrangler secret put JWT_SECRET
wrangler secret put CAPABILITY_SECRET     # signs /d/:token download links

# Optional but recommended
wrangler secret put TURNSTILE_SECRET      # if you enable bot protection
wrangler secret put SCANNER_API_URL       # any malware-scanning HTTP endpoint
wrangler secret put SCANNER_API_KEY
```

`JWT_SECRET` and `CAPABILITY_SECRET` must be **different** values. The worker refuses to boot
on the placeholder values.

## 4. Deploy

```bash
npx tsc --noEmit      # optional sanity check
npm run deploy
```

Wrangler prints the URL, e.g. `https://adshield-cloud.<account>.workers.dev`.

Smoke test:

```bash
curl -s https://adshield-cloud.<account>.workers.dev/health
```

## 5. Point the Android app at it

Two ways, both supported:

* **Build-time (recommended for your own APK):**
  ```bash
  ./gradlew assembleDebug \
    -PcloudApiBaseUrl=https://adshield-cloud.<account>.workers.dev \
    -PcloudSupabaseUrl=https://<project>.supabase.co \
    -PcloudSupabaseAnonKey=<anon key>
  ```
  These become `BuildConfig.DEFAULT_CLOUD_*`. They are public identifiers only — never put a
  secret in the APK.

* **Runtime:** Cloud ▸ Settings ▸ *Deployment*. Paste the worker URL; it is stored in
  DataStore. The app validates HTTPS and rejects anything else.

Create an account in Cloud ▸ Sign in ▸ *Create account*. The first upload can be a DNS backup:
Cloud ▸ Backups ▸ *Back up now*.

## 6. Verify it end to end

In the app, this sequence exercises the whole stack:

1. Upload a small file → the Transfers list shows real progress and a server-side SHA-256 check.
2. Tap the file → download → the app verifies the hash locally and reports a match.
3. Backups → *Back up now* → a row appears with a real size and hash.
4. Change a DNS rule, then *Restore* that backup → the rule list changes back.
5. Security → the audit log lists `upload.complete`, `backup.created`, `backup.restored`.

If any of those steps needs a paid plan, the deployment is misconfigured — check
`STORAGE_PROVIDER` and the bucket credentials.

## Cost expectations

Zero, on the free plan, within the allowances in [FREE_TIER.md](FREE_TIER.md). R2 requires a
card on file; Supabase Storage does not.
