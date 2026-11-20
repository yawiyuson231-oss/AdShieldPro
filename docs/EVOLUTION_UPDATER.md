# Authenticated APK reputation updater

Updated 2026-11-20. This is a bounded, data-only updater, not executable self-modification or guaranteed detection improvement.

## Implemented app path

1. The existing Settings screen has one additive **Signed APK reputation updates** card. Consent is default-off. It explains GitHub connection metadata, exact-hash advisory scope, unchanged local verdicts and unchanged DNS behavior. A missing/invalid packaged publisher configuration prevents opting in; opting out remains available. Status, resource-constrained check-now and local rollback controls are included.
2. Startup reconciles a unique daily WorkManager job. Schedule/execution both require consent and valid packaged publisher configuration. Downloads require unmetered validated networking, battery/storage availability and the existing memory/thermal/CPU resource policy. IO/resource retries are bounded with exponential backoff. WorkManager does not promise an exact daily execution time.
3. HTTPS downloads accept at most 256 KiB and finite connect/read timeouts. At most three redirects are allowed, only from the exact dedicated GitHub channel to exact approved CDN hosts; custom publishers cannot redirect. A 30-second body deadline is checked between reads, so an individual read may extend it by its read timeout. Cancellation/consent are rechecked before transfer and staging, and again before activation. Blocking IO is not instantly aborted and these checks are not an atomic revocation barrier.
4. The complete typed payload is checked using a packaged RSA public key (2048–4096 bits), SHA256withRSA, exact purpose/schema, positive increasing sequence, issue/expiry times, maximum seven-day validity, app-version interval and strict indicator syntax. Unknown keys, malformed/trailing content, invalid signatures, incompatible, expired or future-issued data are rejected. Identical valid bytes are an unchanged poll, not a replay error.
5. A process/file lock serializes state mutations. A verified snapshot is staged with file sync and atomic rename. Only after revalidation is it atomically activated for advisory use. The single activation record retains the prior signed package. Failed staging/activation leaves the prior active record intact.
6. User-selected APK scans use the existing complete-file SHA-256 for exact local lookup. **No files, hashes, package lists or scan results are uploaded.** Opted-out scans do not query reputation. Every lookup rechecks signature, compatibility and expiry. A matched publisher label is an explicitly advisory finding: scores, threat levels, quarantine and DNS decisions are unchanged. Missing, invalid or expired reputation is not treated as evidence of safety; existing local checks still run.
7. Rollback requires a currently valid, signed, lower-sequence prior package. It atomically restores that package, retains the separate download watermark and records the rejected sequence so the next unchanged poll cannot automatically reactivate it. Only a higher signed publication can supersede that rejection. There is one rollback slot; restoring it consumes that slot. Corrupt activation metadata or missing/invalid fallback fails closed rather than guessing a recovery verdict.

## Current deployment boundary

No production public key/configuration or feed is bundled. The publisher workflow and offline signer exist, but **this build cannot enable live downloads without secure provisioning**. On 2026-11-20 an attempt to create the protected `evolution-publisher` GitHub environment returned HTTP 403 `Resource not accessible by integration`. No environment, production private key, secret, signed feed, production release or unauthorized installation was created as a fallback. No independently reviewed real indicator package has been supplied. See [GitHub publisher setup](EVOLUTION_GITHUB_PUBLISHER.md).

The app controls and advisory integration are implemented, not evidence that a live feed exists. A new authorized APK must be built and installed before an existing installed app gains this code.

## Packaged configuration

`app/src/main/assets/evolution-publisher.properties` must contain exactly: `endpoint`, `keyId`, `publicKeySpkiBase64`. For GitHub use:

`https://github.com/yawiyuson231-oss/AdShieldPro/releases/download/evolution-data/reputation.evo`

The key ID is 1–64 ASCII alphanumeric/underscore/hyphen. The public key is base64 X.509 SPKI RSA. No private key belongs in the app. Configuration/trust roots are never downloaded. The public configuration artifact must be independently checked before packaging; publishing an artifact does not itself authorize a new key. Rotation and app-version migrations require a reviewed app update/recovery plan.

## Wire format

Integers are big-endian Java DataOutputStream encodings; strings are Java modified UTF-8 (`writeUTF`). The schema restricts strings to ASCII. Envelope: payload byte length (int32), payload bytes, signature byte length (int32), signature bytes. Payload: magic `0x45564F31` (int32), purpose `adshield-reviewed-apk-reputation-v1` (UTF), key ID (UTF), sequence/issuedAt/expiresAt/minAppVersion/maxAppVersion (five int64 values), indicator count (int32), then SHA-256/category UTF pairs. Times are UTC epoch seconds, expiry exclusive. Up to 1,000 unique lowercase 64-hex APK hashes labeled `malware`, `phishing` or `unwanted` are supported. No code, scripts, models, URL actions or regex rules are accepted. Payload/envelope helpers do not approve content; verification is mandatory.

## Trust and recovery limitations

A signature authenticates key control, not label truth, benignness or independent review. The publisher format/workflow is not yet bound to the existing evolution holdout approval report. Reviewers must independently evaluate real indicators before signing. No detection-accuracy gain is claimed.

State uses `noBackupFilesDir`. Signed packets are reverified, but private activation metadata and sequence history are not hardware-backed. Clearing data, reinstalling, privileged tampering, whole-state replacement or some restore methods can erase/roll back history. Local wall-clock time and ordinary platform TLS are used; no trusted-time service is implemented. Atomic rename/file sync are not a universal power-loss durability guarantee. Corruption, key revocation or an app upgrade outside the stored package's compatibility interval fails closed and may require explicit operator recovery. There is no silent data reset.

## Validation record

18 isolated Kotlin/JVM tests passed with the documented local JUnit-compatible assertion shim. They cover signed data, key/signature tampering, malformed/oversized data, time/compatibility checks, replay after restart/expiry, file locking, restricted redirects, read-time checks, separate staging/activation, rollback/rejected-sequence persistence and failed activation preservation, plus advisory-only missing/disabled/error semantics. This is not a Gradle or Android runtime claim.

Two Android instrumentation cases are added to the existing emulator gate: settings consent/default-off behavior and Android private-filesystem activation/rollback with ephemeral test-only keys. The gate expects all four existing Agent tests plus these two updater tests. Full CI results for the source revision are recorded separately when available.

The existing 109-file boundary manifest retains its original hashes. Exactly one disclosed insertion into SettingsScreen is normalized out by the boundary checker; every remaining original byte is still pinned. Tests reject modified/duplicated insertion blocks and any unrelated boundary mutation. DNS/filter/service/manifest bytes are unchanged. The new card lives outside the frozen legacy UI directories. This is an authorized additive control, not a blanket UI rebaseline.
