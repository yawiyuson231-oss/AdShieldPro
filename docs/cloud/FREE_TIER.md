# Free-tier math and honest limits

Everything below was checked against the providers' own pricing pages in November 2026.
**No paid plan is required for the default deployment.**

| Service | Free allowance | What it means here |
| --- | --- | --- |
| Cloudflare Workers | 100 000 requests/day, 30 ms CPU per request | The worker only does SQL + streaming; CPU per request is far below the limit. |
| Cloudflare D1 | 5 GB storage, 5 M row reads + 100 k row writes per day, 10 databases | Metadata only. A 100 GB library is still a few MB of rows. |
| Supabase Auth | 50 000 monthly active users | Optional; the worker also issues its own JWTs, so this is not needed. |
| Supabase Storage | 1 GB total, 50 MB per object, **no card required** | The cardless default: `STORAGE_PROVIDER="supabase"`. |
| Cloudflare R2 | 10 GB storage, 1 M Class A + 10 M Class B ops/month | Bigger objects and free egress, but **Cloudflare asks for a card** even on the free plan. |
| Cloudflare Turnstile | Unlimited, free | Optional bot protection on register/login. |

## How much can a user actually store?

The worker enforces **1 GiB per user** and a **9 GiB deployment-wide cap**. With Supabase
Storage (1 GB total, 50 MB per object) a deployment realistically holds ~1 GB — one heavy
user, or a handful of normal ones. With R2 the worker cap (9 GiB) fits inside the 10 GB free
bucket.

That is why the app says a number it can prove: the gauge shows *your* used bytes as reported
by the server, and the storage line shows which provider the deployment uses. There is no
"unlimited" claim anywhere.

## When a limit is hit

* Quota: uploads return `413 QUOTA_EXCEEDED` with the exact remaining bytes.
* Rate limit: `429` with `Retry-After`; the app shows the wait instead of retrying in a loop.
* Object > 50 MB on Supabase Storage: the uploader automatically uses multipart, so parts stay
  under the object limit.
