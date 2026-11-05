# AdShield Pro — free-tier cloud backend

This directory contains the complete backend the Android app's **Cloud** module talks to.
It runs entirely on **free tiers** — no credit card, no paid plan, no auto-upgrades:

| Component | Free allowance (as of 2026-11) | Card required? |
|---|---|---|
| Cloudflare Workers | 100,000 requests/day | No |
| Cloudflare R2 | 10 GB storage, 1M writes + 10M reads/month | No |
| Cloudflare D1 | 5M rows read/day, 100k writes/day | No |
| Supabase Auth | 50k MAU, email/password auth | No |
| Cloudflare Turnstile | Unlimited (managed challenge) | No |

## Deploy (one-time, ~10 minutes)

```bash
cd cloud-worker
npm install -g wrangler          # or: npx wrangler ...
wrangler login                   # free Cloudflare account
wrangler d1 create adshield-cloud-db
# paste the returned database_id into wrangler.toml
wrangler d1 execute adshield-cloud-db --file=schema.sql
wrangler r2 bucket create adshield-cloud-files
wrangler secret put SUPABASE_JWT_SECRET   # from your free Supabase project: Settings → API → JWT secret
wrangler secret put SUPABASE_URL          # https://<project-ref>.supabase.co
wrangler secret put SUPABASE_ANON_KEY     # public anon key
wrangler deploy
```

Then in the Android app: **Cloud → Settings → Worker backend URL** → paste the deployed
`https://adshield-cloud.<your-subdomain>.workers.dev` URL.

## Security model

- The R2 bucket is **private**; bytes only move through HMAC-signed URLs (15-minute TTL)
  that this Worker issues after verifying the Supabase JWT and checking row ownership.
- No secret is shipped in the APK — the app holds only the user's session JWT.
- Uploads are size-capped (1 GiB/file), quota-checked against D1, and executable/active
  content (`.apk .exe .html .svg` …) is rejected.
- Every mutating action is written to the `audit_log` table.

## Honest limits

- Free tiers have hard caps (table above). The app displays the server-reported usage and
  blocks uploads at 95% of the quota — it never claims unlimited storage and never switches
  to paid infrastructure.
- This Worker is source you deploy on **your own** free Cloudflare account; the app itself
  operates no backend.
