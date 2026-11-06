# Testing

This repository holds two deliverables with separate suites:

| Suite | Where | Run it |
|---|---|---|
| **Android app (Kotlin)** | this document | `./gradlew test` |
| **Web platform (browser)** | [`WEB_TESTING.md`](WEB_TESTING.md) | `npm test` · `npm run verify` |

This document describes how AdShield Pro is built and how its automated tests are run.

## Requirements

| Tool | Version used by the project |
| --- | --- |
| JDK | 17 or newer (build tested with JDK 21 toolchain config) |
| Android SDK Platform | 37 (`compileSdk = 37`, `targetSdk = 36`) |
| Android build-tools | installed automatically by AGP 9.4.1 |
| Gradle | 9.7.1 via the committed wrapper (`./gradlew`) |
| Android Gradle plugin | 9.4.1 (built-in Kotlin, no `kotlin-android` plugin) |
| Kotlin / KSP | 2.4.21 / 2.3.13 |

Set `ANDROID_HOME` (or add an `sdk.dir` line to `local.properties`) before building.

## Build

```bash
./gradlew :app:assembleDebug          # installable debug APK
./gradlew :app:assembleRelease        # signed release APK (needs the keystore env vars below)
./gradlew :app:bundleRelease          # Play Store AAB
```

Release signing is configured through environment variables or Gradle properties
(see `docs/BUILD_AND_SIGNING_GUIDE.md`):

```bash
export ADSHIELD_KEYSTORE_PATH=/path/to/release.jks
export ADSHIELD_KEYSTORE_PASSWORD=…
export ADSHIELD_KEY_ALIAS=…
export ADSHIELD_KEY_PASSWORD=…
```

## Continuous integration

`.github/workflows/android-build.yml` runs on every push to `main` / agent branches and on pull
requests. It installs JDK 21 + Android SDK Platform 37.x and runs, in order:

1. Capability matrix freshness check (`tools/generate_capability_matrix.py --check`)
2. UI performance gates (`tools/check_ui_performance.py`)
3. `:app:compileDebugKotlin` — fails fast on toolchain problems
4. `:app:assembleDebug` — APK packaging
5. `:app:assembleRelease` — R8 minification + resource shrinking (throwaway CI keystore), then the
   universal ABI gate (`tools/check_universal_release.py`)
6. `:app:testDebugUnitTest` — then discovers every `@Test` case in `app/src/test` and asserts the
   JUnit XML reports the same number, with zero failures/errors/skips
7. `:app:lintDebug` — hard gate, the build fails on any lint error

The debug APK is uploaded as the `adshield-pro-<version>-debug-apk` artifact.

## Unit tests

```bash
./gradlew :app:testDebugUnitTest          # runs app/src/test/**
./gradlew :app:testDebugUnitTest --tests 'com.adshield.pro.AdShieldEngineTestSuite'
```

HTML report: `app/build/reports/tests/testDebugUnitTest/index.html`.

`AdShieldEngineTestSuite` is a pure JVM (Robolectric-free) suite. It exercises the
device-independent engine code directly, which is where all DNS, filtering and scoring
logic lives. `AetherCoreTest`, `BatteryIntelligenceTestSuite`, `DashboardPresentationTest`,
`SecurityCenterTestSuite` and `CapabilityRegistryTest` cover the decision core, battery/thermal
rules, dashboard honesty/motion rules, security scoring and capability-report constraints:

| Area | Covered behaviour |
| --- | --- |
| `DnsPacketCodec` | RFC 1035 parsing of A/AAAA questions, compression pointers, malformed/cyclic packets, NXDOMAIN and `0.0.0.0`/`::` sinkhole synthesis, SERVFAIL synthesis, transaction-ID rewriting, TTL extraction |
| UDP delivery limits | `fitResponseToUdpLimit` preserves ID/RCODE/question and sets TC=1 when an upstream answer cannot fit a single tunnel datagram; `udpPayloadCapacity` per IP version |
| `IpPacketFraming` | IPv4/IPv6 UDP and TCP parsing, IPv4 header options, TCP options, fragmentation rejection, RFC 1071 / RFC 8200 checksums (verified to recompute to zero), and segmentation of large TCP DNS answers so no packet exceeds the tunnel MTU |
| `UpstreamDnsResolver` | Upstream answers are only accepted when they are responses carrying the query's transaction ID; only NOERROR/NXDOMAIN answers are cacheable; cache keys are scoped to the active resolver endpoint; IPv6 fallback server list |
| `FilterRuleEngine` | Protection-mode category gating, custom allow/block precedence, wildcards, hosts/Adblock list parsing, duplicate counting, HTML/binary rejection, conflict analysis, snapshot rollback, concurrent evaluation |
| `BrowserContentBlocker` | Tracking-parameter stripping, request blocking, site allowlists, cosmetic script generation, DNS-label-boundary third-party detection |
| `RuleBasedOptimizationPredictor` | Healthy vs. stressed device scoring, bottleneck severities, `formatBytes` formatting |
| `DashboardPresentation` | Counter scope selection and clamping, event titles/severity, motion gating, nav scroll targeting, stable live-event ids |
| `PrivateSearch` | Provider fallback for corrupt prefs, HTTPS-only search endpoints, percent-encoding (UTF-8, reserved chars), query-injection resistance, address-vs-search resolution |
| `ScanJournal` | Strictly increasing scan ids, bounded retention, persistence round-trip incl. legacy records, honest empty report, quarantine path-traversal safety, progress clamping |

### GPS, navigation and traffic module

Six suites — `GpsEngineTest` (35), `GpsTrafficSecurityTest` (33), `GpsOfflineGraphTest` (18),
`GpsMapOverlayTest` (14), `GpsSecureStoreTest` (11) and `GpsAuditRegressionTest` (11) — cover the
whole device-independent core of the GPS module, 122 tests in total (296 for the app). Everything below runs on the JVM with no emulator, no network and no playback of recorded
traces — these are pure function/state-machine tests, not simulated driving:

| Area | Covered behaviour |
| --- | --- |
| Geodesy | Haversine distance against a hand-computed Manila→Quezon City value (10 645.97 m), bearing and destination round-trips, bounding-box containment |
| `GpsIntegrityMonitor` | Mock-provider flagging, stale-cache and stale-provider fixes, wall-clock regressions, wall-vs-monotonic drift, accuracy-scaled coordinate jumps, and impossible speed in **both** directions (a 105 km/h motorway fix stays `TRUSTED`; a stationary device claiming 90 km/h is flagged), verdict aggregation and statistics |
| Fix quality | Horizontal-accuracy bands, a missing altitude staying `null` instead of becoming 0 m, an unreported speed staying absent, and confidence dropping for mock and cached fixes |
| Stationary detection | Stopped vehicle, motorway speed, and motion inferred from displacement when the provider reports no Doppler speed |
| `RadarGeometry` | Sky-view polar placement (zenith, elevation rings at 1, 2/3, 1/3), constellation short codes, 0–100 sky score, and the distinct empty-state reasons (no permission / location off / no `GnssStatus` support / first report still pending / genuinely empty sky) |
| `MapProjection` / tiles | Web Mercator projection, tile-count estimate for a small region, rejection of polar latitudes outside the projection's limits |
| Map HUD overlay | Pixel scale at any zoom/latitude and the exact 1/cos(latitude) ratio, accuracy-circle radius from the reported error (and none when it is unknown), cardinal directions on screen, rotation with the camera bearing, antimeridian wrap, and viewport clamping for off-screen targets |
| Offline packs | Tile-budget rejection above the free 3 000-tile / 50 MB cap, acceptance of a small neighbourhood, auto-fit zoom search, route-corridor coverage, estimate growth with zoom range, degenerate-bounds rejection with a reason |
| `ADG1` offline graph | Raw, gzipped and on-disk round-trips, foreign magic / wrong version / truncated / absurd-node-count headers rejected with a reason, A* over a two-leg network, direction-aware one-way traversal, offline plan synthesis (depart, manoeuvres, arrival), refusal to route outside the pack, nearest-node and on-segment snapping, snap radius, coverage distance, honest pack description |
| `ADSE1` encrypted container | Exact-byte round-trip, plaintext never visible in the ciphertext, fresh IV per write, documented header layout, wrong key rejected, bit-flipped ciphertext **and** IV failing GCM authentication, plaintext/truncated files refused, empty payload, decryption with a key reloaded from storage |
| Routing | ETA from the measured speed, ETA falling back to the posted speed limit when stopped, ETA that still terminates with no speed information at all, road snapping to the nearest point on a segment, and distance formatting |
| Bug-sweep regressions | Segment projection across the antimeridian (the flat projection needed a wrapped longitude delta; it was off by 9x and snapped to the wrong end of the segment), a compromised position staying a distinct `FixState` instead of being relabelled healthy by the 2 s stale ticker, a stopped engine publishing an empty frame instead of keeping the last speed on screen, locale-independent distance and coordinate formatting under a comma-decimal locale, re-stamping collected trip points with the real trip id, and the append-only track archive watermark that stops a long trip losing its first half |
| Traffic | A segment with no observations reads UNKNOWN rather than green, a single noisy sample stays UNKNOWN on confidence grounds, free-flowing samples turn green, standstill turns red, samples outside the rolling window or belonging to another segment are ignored, confidence decays with age, and agreement drops when speeds scatter |
| Security | `IncidentValidator` payload rejection (compromised location, control characters, over-long notes), token-bucket rate limiting, incident lifetimes, telemetry gate (sharing off, mock position, poor accuracy), privacy defaults all off, emergency-share permission and real-coordinate/free-map-link content, coarse-coordinate rounding and timestamp expiry in trip history, permission-audit findings, and the kill switch overriding the emergency allowance |

What is still **not** covered by JVM tests, and is therefore verified on a device instead: the
Android Keystore key lifecycle behind `SecureLocationStore` (the container format itself is, above),
the MapLibre offline-pack download manager, and the platform location/GNSS callbacks. Those are
manual steps 12–18 below; there is no automated instrumentation suite for them yet — that is a real
gap, not a passing test.

Instrumentation (`androidTest`) and manual on-device checks are still required for anything
that touches Android framework services — `VpnService` tunnel establishment, the WebView
browser, notifications, WorkManager scheduling and Room migrations on a real upgrade path.
Those cannot be exercised by JVM unit tests.

## Manual smoke test (device / emulator, API 29+)

1. Install the debug APK, open the app, tap the shield and accept the VPN consent dialog.
2. Open a browser and load a page; verify `Blocked` counters increase on the Home screen.
3. Open **Statistics** and confirm queries appear in real time (requires detailed logging).
4. Add a custom block rule (`||example.com^`) in **Ad Blocker → Rules** and confirm the domain
   is blocked immediately without restarting protection.
5. Switch protection modes and confirm blocking changes take effect without a tunnel restart.
6. Reboot the device with protection enabled to verify the boot receiver restores the tunnel.
7. If the release build is used, confirm R8 did not strip Room/serialization metadata by
   opening **Statistics** and **Optimizer** (both read from Room/DataStore).
8. Run a file scan, quarantine the file, verify it, restore it to a new location and confirm the
   SHA-256 matches; then delete the quarantined copy. Try "Quarantine & delete original" on a file
   this app does not own and confirm the app reports that Android refused the deletion.
9. Enable scheduled scanning, force the job (or wait for the period) and confirm a record appears
   in Security → History with source "Scheduled".
10. Switch the private search provider in Ad Blocker → Browser → shield controls, search from the
    address bar, and confirm the chosen provider is used after an app restart.
11. Scroll Home and Live quickly with detailed logging enabled; confirm the feed stays smooth,
   the scroll-to-top button appears after scrolling, and the shield stops animating when the
   tunnel is paused or traffic is idle. Enable reduced motion / remove animations in developer
   options and confirm the shield renders statically.
12. **GPS Map.** Grant precise location, wait for a fix outdoors and confirm the cyan marker
   lands on the street you are actually standing on, the accuracy circle shrinks to roughly the
   reported radius, and the camera follows the marker while you walk. Cross-check the displayed
   latitude/longitude against any independent offline map viewer.
13. **GPS Radar.** Confirm satellites appear with real constellation codes, signal bars and
   azimuth/elevation, and that the empty state distinguishes "system location off" from
   "receiver cannot report `GnssStatus`" from "still searching". A device without GNSS status
   support must say so instead of showing a permanently blank radar.
14. **Navigation.** Search a real destination through the open geocoder, start a route and drive
   (or ride) it: turn-by-turn text and the `TextToSpeech` prompt must match the next manoeuvre,
   the ETA must fall as you progress, and deliberately missing a turn must trigger a reroute.
   With no traffic observations the route must be labelled *no traffic data*, never "clear".
15. **Live Traffic.** With the opt-in off, every segment must read UNKNOWN/grey; with it on, a
   segment may only colour after your own drive produces observations on it. Submit a hazard and
   confirm it carries your confidence and timestamp.
16. **Offline Maps.** Download a small region, import a graph built with `tools/osm_graph_builder.py`
   and confirm the import message reports real road kilometres, then switch the device to flight
   mode: tiles must still render, an area with no pack must say `NO_OFFLINE_GRAPH` instead of
   guessing, and destination search must resolve offline. Re-enable the network and confirm queued
   observations sync.
17. **Location Security.** Enable a mock-location app (developer options → select mock location
   app) and confirm the integrity verdict goes to Compromised and mock-flagged fixes are kept out
   of traffic observations and trip history. Toggle the emergency-sharing kill switch and confirm
   sharing is refused even in an emergency report.
18. **Battery and lifecycle.** Leave the GPS screen open for 30 minutes and check
   `adb shell dumpsys batterystats` plus Android Studio's profiler for a sane drain and no
   unbounded memory growth; background the app and confirm tracking pauses or continues exactly
   as the chosen mode says, respecting Android 10+ background location limits.
