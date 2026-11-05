# Verification report

## Backend — real infrastructure, not mocks

```
cd cloud/worker && node test/run-tests.mjs
Result: 65/65 passed, 0 failed (~14 s)
```

The suite boots `wrangler dev` (real workerd), applies the D1 migrations to a local D1
database, and drives the worker over HTTP with a real R2-backed `StorageProvider`. Per-test
results are written to `cloud/worker/test/last-run.json`.

What it covers:

| Group | Examples |
| --- | --- |
| Auth | register, duplicate email, weak password, login, wrong password, refresh rotation, logout invalidates the token, recovery request |
| Account | stats, plan switch, quota ledger math, audit entries |
| Upload | init → single PUT → complete, SHA-256 mismatch rejected, dedupe, quota exceeded, oversize part, version upload |
| Download | signed capability URL, tampered token → 403, expired token → 403 |
| Files | list by category, search, rename, delete → trash, restore, purge frees quota |
| Versions | create version, list, restore previous content |
| Shares | create, password-protected unlock (wrong password rejected), download cap, expiry → 410, revoke → 410 |
| Backups | init/verify/restore-ticket/mark-restored, list, delete, kind filters |
| Malware | infected upload quarantined, download → 423, owner release, audit `quarantine_released` |
| Rate limiting | `/v1/search` burst → 429 with `Retry-After` |

## Android

* `app/src/test/java/com/adshield/pro/CloudLogicTestSuite.kt` — 15 JVM tests covering the
  `CSHIELDV1` container (round-trip, wrong passphrase, tamper detection, non-determinism),
  SHA-256 known-answer + streaming + cancellation, byte formatting, session refresh windows,
  and the onion/Tor address logic (v2/v3 detection, scheme rejection, honest reachability).
* The APK itself is built by the `Build TitanShield Max APK` workflow.

## What is *not* claimed

Nothing in this report says a real 1 GB upload over mobile data was measured, because that
was not run. The numbers shown in the app come from the server's quota ledger, and the
transfers UI only displays bytes that actually moved.
