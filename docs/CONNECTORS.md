# Connector platform (OMNISHIELD X intelligence layer)

This document explains how the connector platform works, what each module can really do, which
free services are used and on what terms, where Android blocks us, and how to verify the claims
yourself. The machine-generated, per-connector table lives in
[CONNECTOR_VERIFICATION.md](CONNECTOR_VERIFICATION.md) and is regenerated from source by
`tools/generate_connector_report.py` (CI fails if it is stale).

## What it is — and what it is not

* A **connector** is one concrete way of getting real intelligence: either an HTTPS endpoint whose
  response the app parses locally, or an Android API the app calls on the device.
* The registry currently contains **178 connectors, 157 of which are implemented**. 21 are declared
  but not executable: 13 need provider credentials that are never bundled, 6 have no public machine
  interface, 2 are documented API shapes without a working free endpoint. Nothing is counted twice;
  the generator rejects duplicate endpoints.
* The brief asked for up to 350 integrations (~50 per module). **That number is not reached and it
  is not faked.** Padding with duplicate URLs, renamed endpoints, HTML scraping or invented APIs
  would make the product dishonest and fragile. The gap is reported per module in
  `CONNECTOR_VERIFICATION.md`.
* There is **no AI/ML model** anywhere in this layer. Risk scores come from deterministic weights
  and local rules, and the UI says so.

## Per-module status

| Module | Listed | Implemented | Why it is not 50 |
| --- | ---: | ---: | --- |
| CYBER | 16 | 14 | Only a handful of free, key-less, machine-readable threat feeds exist (abuse.ch x3, CISA KEV, FIRST EPSS, NVD, GitHub advisories, MISP); the rest of the module is Android-side inspection (APK/signing/hash/permissions). |
| FIN | 12 | 11 | Phishing feeds are free (OpenPhish, Phishing.Database, hosts lists) but most brand/typosquat/QR intelligence vendors are paid; the remainder is generated locally from the cached domain index. |
| PRIV | 19 | 19 | Exactly the parts of app/permission/access auditing Android exposes without root or device-owner privileges. |
| NET | 15 | 15 | Android network APIs plus a small set of fair-use public services (RIPE Stat, RDAP, IP echo); no packet inspection, no VPN. |
| DEV | 19 | 19 | Android `BatteryManager`, `StorageStatsManager`, `ActivityManager`, `PowerManager`, sensor and display APIs. |
| EMRG | 11 | 7 | USGS, GDACS, NWS, ReliefWeb and EMSC publish feeds. PAGASA, NDRRMC and PHIVOLCS publish bulletins for humans, not machines; NASA FIRMS needs a free MAP_KEY. |
| AUTO | 19 | 18 | WorkManager/Room/alarm/boot/notification plumbing that is genuinely verifiable. |

## Architecture

```
engine/connectors/
  ConnectorCatalogue.kt   first-wave registry, each entry with the full metadata set
  ConnectorExpansion.kt   second-wave registry (feeds, lookups, native probes), same rules
  ConnectorParsers.kt     pure parsers (JSON/CSV/text/RSS) -> ThreatIndicator list
  ConnectorHttp.kt        OkHttp transport: HTTPS only, size cap, timeouts, ETag/Last-Modified
  ConnectorSyncEngine.kt  one sync cycle: skip/cooldown/HTTP/parse -> SyncOutcome
  NativeConnectorProbes.kt  on-device probes, each returning real observations
  NativeProbeExpansion.kt   second-wave probes (roles, admins, DRM, QR self-test, …)
  IntelLookupEngine.kt      one on-demand lookup: validate -> request -> parse -> finding
  LookupParsers.kt          pure parsers for lookup responses (RDAP, OSV, hashlookup, DoH, …)
  IndicatorRisk.kt        deterministic scoring + reasons ("why this alert")
data/repository/ConnectorRepository.kt   state, cache, dedupe, per-module sync, IOC assessment
data/local/db/ConnectorEntities.kt       Room v5: connector_state, threat_indicators
worker/ConnectorSyncWorker.kt            6 h periodic sync + daily retention prune
ui/screens/connectors/ConnectorRegistryScreen.kt   registry UI (opened from the map)
```

Every catalogue entry carries all 17 required fields: `id`, `name`, `module`, `provider`,
`endpoint`, `method`, `format`, `transport`, `handlerId`, `auth`, `freeUse`, `restrictions`,
`rateLimit`, `cacheTtlMs`, `timeoutMs`, `maxBytes`, `maxRetries`, `defaultEnabled`, `implemented`,
`verification` — the UI shows them verbatim in the connector detail sheet.

### Sync cycle

1. If the connector is disabled → `DISABLED`.
2. If it needs credentials that are absent → `NOT_CONFIGURED` (no network call).
3. If it is not implemented → `NOT_IMPLEMENTED`.
4. If `now < nextAllowedEpochMs` → cooldown, no network call (`RATE LIMITED`).
5. HTTPS GET with `If-None-Match`/`If-Modified-Since`, 10 s connect / 20 s read / 35 s total,
   response size cap (`maxBytes`).
6. `304` → success without new indicators. `429`/`5xx`/offline → retryable with backoff.
   `401`/`403`/`404`/invalid body → `ERROR` with the reason stored.
7. Indicators are normalised, deduplicated by `(source, kind, value)`, capped per feed, stamped
   with expiry = 3× TTL (clamped 6 h – 30 d), and written to Room.
8. Only after all of that does the status become `CONNECTED`.

Backoff is `30 s · 2^(n-1)` capped at 6 h. Per-connector state (etag, last success, error, HTTP
code, indicator count, next allowed time) survives restarts in `connector_state`.

## Status vocabulary

| Status | Meaning |
| --- | --- |
| `CONNECTED` | A real sync/probe succeeded and the data is still fresh (≤ 2× TTL). |
| `SYNCING` | A request is in flight right now. |
| `OFFLINE` | No network available. |
| `DEGRADED` | Last success is older than 2× TTL, or a permission/API refused part of the probe. |
| `RATE LIMITED` | Provider asked us to wait, or the local cooldown is active. |
| `ERROR` | Failed for a real reason (HTTP error, invalid payload, permission denial). |
| `DISABLED` | Switched off by the user. |
| `NOT CONFIGURED` | Needs a credential that the app deliberately does not ship. |
| `NOT IMPLEMENTED` | Declared for transparency; no public machine interface or no parser yet. |

Freshness is never inferred: `effectiveStatus` degrades a stale `CONNECTED` to `DEGRADED` and shows
how old the last success is.

## Free providers, terms and restrictions

All feeds are public HTTPS endpoints called without keys. Rate limits and terms change over time —
the catalogue text is what the app displays, and each entry is re-verified by a real sync at runtime.

| Provider | Used for | Terms / limits we rely on | If it changes |
| --- | --- | --- | --- |
| abuse.ch (URLhaus, Feodo Tracker) | malicious URLs, botnet C2 IPs | Free for non-commercial security use; bulk download endpoints are intended for automated use. | Connector turns `ERROR`; nothing else is affected. |
| abuse.ch (ThreatFox, MalwareBazaar) | IOC API, sample metadata | API now requires an Auth-Key. | `NOT CONFIGURED` — never enabled, never faked. |
| CISA KEV | exploited CVEs | US Government work, public domain. | `ERROR` + reason. |
| FIRST EPSS | exploit probability | Free public API, no key. | `ERROR` + reason. |
| NIST NVD 2.0 | latest CVEs | Without a key: 5 requests / 30 s; 100 results per page. | Cool-down on 403/429. |
| GitHub advisories | open-source vulnerabilities | 60 requests/h unauthenticated. | `RATE LIMITED` when exhausted. |
| MISP warninglists | false-positive suppression | Open lists (CC); used as *suppressions*, not threats. | Fallback to no suppression. |
| OpenPhish / Phishing.Database / StevenBlack hosts | phishing URLs/domains, ad domains | Public free feeds; OpenPhish's public feed is delayed versus its commercial feed. | `ERROR` + reason. |
| IPsum | aggregated bad IPs | Public GitHub text list. | `ERROR` + reason. |
| RIPE Stat, RDAP.org, ipify | routing/registration/public IP | Fair-use public APIs. | Diagnostic card shows `ERROR`. |
| USGS, GDACS, NWS, ReliefWeb, EMSC | earthquakes, disasters, weather | Public feeds; NWS/ReliefWeb are US/UN services, coverage outside them is partial. | `ERROR` + reason. |
| NASA FIRMS | active fire detections | Requires a free `MAP_KEY`. | `NOT CONFIGURED`. |
| PAGASA, NDRRMC, PHIVOLCS | PH official warnings | No public machine API; bulletins are HTML/social posts. | `NOT IMPLEMENTED`; the UI links out instead of pretending. |

No feed is described as unrestricted or guaranteed. The app degrades visibly rather than silently.

## Privacy and Android limitations

**Never read:** clipboard contents, contacts, SMS/MMS bodies, notification text, other apps' private
storage, screen contents, keystrokes. There is **no VPN interception** in this layer and no traffic
decryption; the existing DNS engine is untouched.

**What the app can do with normal permissions**

* Installed-app inventory, signing certificate digests, permission declarations and *requested*
  permissions (`PackageManager`).
* This app's own APK: signature scheme verification, zip inspection, SHA-256.
* Accessibility / notification-listener / usage-access / battery-optimisation state (`Settings`,
  `AppOpsManager`, `NotificationManager`) — the *state* of those toggles, not their contents.
* Connectivity, Wi-Fi (SSID only with location permission on Android 10+), DNS resolution timing,
  latency, traffic counters, battery, charging, thermal status, storage, memory, CPU cores,
  sensors (presence/vendor/power, not readings while another app uses them), display, build and
  patch level.
* WorkManager/alarm/boot/startup plumbing, Room stores, cache pruning, stale detection.

**What it cannot do**

* Enumerate runtime permission *grants* of other apps (only declarations) without
  `QUERY_ALL_PACKAGES`/privileges; no per-app network usage without `NetworkStatsManager` privileges.
* Guarantee background execution — OEM battery managers may kill work; the UI shows the last real
  success instead of assuming liveness.
* Inspect other apps' memory, keystrokes, or content; read privileged hardware telemetry.
* Detect 100 % of malware, phishing or zero-days. The risk score is a deterministic aid.

Permissions requested are the minimum for the above; each denial is a normal, explained state
(`DEGRADED`/`ERROR` with a reason), never a crash.

## Verifying it yourself

Automated (JVM, runs in CI):

```bash
./gradlew :app:testDebugUnitTest --tests "com.adshield.pro.ConnectorPlatformTestSuite"
python3 tools/generate_connector_report.py --check
```

`ConnectorPlatformTestSuite` covers catalogue integrity (unique ids/endpoints, HTTPS-only, metadata
completeness, credential connectors never enabled), every parser (valid payloads, malformed
payloads, empty bodies, dedupe, expiry), the sync state machine (success, 304, 429, 5xx, 401/403,
offline/timeout, invalid body, cooldown, disabled, not configured), backoff bounds, status honesty
(never `CONNECTED` without success, staleness, overrides) and the risk engine (weights,
corroboration, suppression, local rules, normalisation).

On device — open **Intel → Feeds & connectors**:

1. Pick a module, open a connector, press **SYNC NOW** / **RUN PROBE**.
2. Confirm the state, HTTP code, latency and indicator count match reality; kill the network and
   confirm `OFFLINE`/`RATE LIMITED` with a reason.
3. Leave the app idle for 6 h (or change the device clock) and confirm the next periodic sync runs
   and freshness updates — or reports why it did not.
4. Check **CHECK AGAINST CACHED INTELLIGENCE** with a domain from a synced feed, then with a random
   domain: results must differ and must cite the source and the disclaimer.

The 14 scenario classes from the brief (success, valid/invalid response, timeout, offline, rate
limit, cache, duplicates, permission denial, background sync, compatibility, availability,
freshness, error recovery) map onto the tests above; scenarios that need real hardware or a real
outage are listed as manual steps in [TESTING.md](TESTING.md).

## Build

```bash
./gradlew :app:assembleDebug          # debug APK
./gradlew :app:testDebugUnitTest      # unit tests
./gradlew :app:assembleRelease        # needs the CI signing keystore
```

The connector layer adds no dependency beyond the OkHttp/Room/WorkManager stack already present.
Release builds keep `isMinifyEnabled`/R8 configured; parsers avoid reflection and keep only
`kotlinx.serialization` models, so no extra keep rules are required.

## Known gaps (honest list)

* 178/350 of the brief's target; the gap is genuine, not deferred padding.
* Emergency coverage outside the US/EU feeds depends on GDACS/EMSC aggregation; Philippine official
  sources remain link-outs until they publish machine-readable feeds.
* GitHub/NVD unauthenticated limits mean a 6 h cadence is the practical ceiling.
* No keystore attestation chain validation beyond `Signature` scheme checks (needs network trust
  roots); the probe reports what it can prove.
* `QUERY_ALL_PACKAGES` is not requested, so app inventory covers launchable/queryable packages.
