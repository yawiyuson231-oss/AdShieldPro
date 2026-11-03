# Build & Test Guide

This document describes how AdShield Pro is built and how its automated tests are run.

## Requirements

| Tool | Version used by the project |
| --- | --- |
| JDK | 17 (21 also works) |
| Android SDK Platform | 36 (`compileSdk = 36`) |
| Android build-tools | installed automatically by AGP 8.9.3 |
| Gradle | via the committed wrapper (`./gradlew`) |

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

## Unit tests

```bash
./gradlew :app:testDebugUnitTest          # runs app/src/test/**
./gradlew :app:testDebugUnitTest --tests 'com.adshield.pro.AdShieldEngineTestSuite'
```

HTML report: `app/build/reports/tests/testDebugUnitTest/index.html`.

`AdShieldEngineTestSuite` is a pure JVM (Robolectric-free) suite. It exercises the
device-independent engine code directly, which is where all DNS, filtering and scoring
logic lives:

| Area | Covered behaviour |
| --- | --- |
| `DnsPacketCodec` | RFC 1035 parsing of A/AAAA questions, compression pointers, malformed/cyclic packets, NXDOMAIN and `0.0.0.0`/`::` sinkhole synthesis, SERVFAIL synthesis, transaction-ID rewriting, TTL extraction |
| UDP delivery limits | `fitResponseToUdpLimit` preserves ID/RCODE/question and sets TC=1 when an upstream answer cannot fit a single tunnel datagram; `udpPayloadCapacity` per IP version |
| `IpPacketFraming` | IPv4/IPv6 UDP and TCP parsing, IPv4 header options, TCP options, fragmentation rejection, RFC 1071 / RFC 8200 checksums (verified to recompute to zero), and segmentation of large TCP DNS answers so no packet exceeds the tunnel MTU |
| `UpstreamDnsResolver` | Upstream answers are only accepted when they are responses carrying the query's transaction ID; only NOERROR/NXDOMAIN answers are cacheable; cache keys are scoped to the active resolver endpoint; IPv6 fallback server list |
| `FilterRuleEngine` | Protection-mode category gating, custom allow/block precedence, wildcards, hosts/Adblock list parsing, duplicate counting, HTML/binary rejection, conflict analysis, snapshot rollback, concurrent evaluation |
| `BrowserContentBlocker` | Tracking-parameter stripping, request blocking, site allowlists, cosmetic script generation, DNS-label-boundary third-party detection |
| `RuleBasedOptimizationPredictor` | Healthy vs. stressed device scoring, bottleneck severities, `formatBytes` formatting |

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
