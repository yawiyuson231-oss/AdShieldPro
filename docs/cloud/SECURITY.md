# Security model

## Credentials never ship in the APK

The APK contains at most a Worker URL and a Supabase **anon** key — both public by design.
Storage keys, `JWT_SECRET`, `CAPABILITY_SECRET` and scanner keys live only in Worker secrets.
`BuildConfig.DEFAULT_CLOUD_*` is empty by default, so a stock build is unconfigured rather
than mis-keyed.

## Tokens on the device

Access and refresh tokens are sealed with an AES-256-GCM key that lives in the **Android
KeyStore** (alias `adshield_cloud_token_key`, non-exportable). The sealed blob is what
DataStore persists; a rooted-device dump of the preferences file yields ciphertext only.
Refresh tokens rotate on every use, and the client refreshes one request ahead of expiry
(five-minute window) with a single-flight lock so parallel calls cannot stampede.

## End-to-end encryption for backups

Backup payloads are encrypted **on the device** before upload:

* Container `CSHIELDV1`: magic(8) ‖ kdf(1) ‖ iterations(4, big-endian) ‖ salt(16) ‖ IV(12) ‖ AES-256-GCM.
* Key derivation PBKDF2-HMAC-SHA256, 210 000 iterations, 32-byte key, random 16-byte salt.
* Passphrase mode: the user's passphrase, never stored.
* Device mode: a KeyStore-wrapped random key (`adshield_cloud_backup_key`).
* The plaintext SHA-256 is computed first and stored as `sha256` of the *plaintext* so restore
  can prove integrity, while the worker sees only ciphertext.

The server therefore cannot read DNS rules, settings or allowlists. Restore decrypts locally
and then merges rules / replaces settings and resolver.

## Transport and links

* HTTPS only; the app rejects `http://` base URLs.
* Downloads never proxy credentials: the worker mints an HMAC capability URL with a 300 s TTL
  and a scoped, single-file payload. Tampering with the token returns 403 (covered by a test).
* Shares are PBKDF2-protected; the password hash never leaves the server, and an expired or
  revoked share returns 410 Gone.

## Abuse and malware

* Rate limits per route per user/IP, hashed IPs only (no raw IP storage).
* Upload heuristics (extension/mime/size anomalies) plus an optional `SCANNER_API_URL`.
* `infected`, or `suspicious` non-backup, files become `quarantined`; downloads return **423**.
  Only the owner may `release`, and the original scan verdict stays in `scan_detail`.
* Every mutation is written to `audit_logs` and shown in the app.

## Known limits (stated, not hidden)

* Tor mode relies on a user-provided SOCKS proxy (Orbot). The app does not bundle a Tor
  daemon, and the UI says so; no anonymity is claimed when no proxy is reachable.
* The DNS blocker keeps working offline; cloud features obviously do not.
* Server-side SHA-256 verification is capped (16 MB at finalize, 32 MB on `/verify`) to stay
  inside the Worker CPU budget. Larger objects return `sha256Verified:false` and the Android
  client hashes locally after download instead.
