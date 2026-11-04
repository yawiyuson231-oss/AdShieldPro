# OmniShield X Infinity 5.0 — AETHER Android Security Ecosystem

OmniShield X Infinity (formerly TitanShield Max, originally AdShield Pro) is a non-root Android protection suite: device-wide DNS ad/tracker/malware filtering through a local VPN, an on-device Security Center for user-selected files, links, apps and APKs, real-data network visualization, measured battery intelligence, storage tools and a built-in privacy browser. Built with Kotlin, Jetpack Compose (Material 3), Room, DataStore, WorkManager, Hilt and Android `VpnService`.

**Release status:** development, not production-certified. See [the 5.0 evidence matrix](docs/OMNISHIELD_INFINITY_STATUS.md). The development workflow compiles and tests the app but never publishes a release. Physical-device validation is still required.

## What's new in Infinity 5.0

- AETHER now distinguishes **VERIFIED**, **SUSPECTED** and **UNKNOWN** evidence, attaches heuristic confidence and plain-language explanations, and never turns UNKNOWN into a malware verdict.
- User-controlled autonomous response, emergency Strict mode with previous-setting restoration, and manual override that leaves existing DNS protection active.
- DoH/DoT no longer downgrade to plaintext. Optional encrypted-only failover is bounded by Speed mode, autonomous response and manual override; caches are resolver-scoped and failure responses are not cached as successful answers.
- Real-data network shield, per-category DNS event feed, connectivity validation, DNS-path disclosure and conservative local IP classification.
- Battery percentage/status, current, voltage, temperature, battery-side power, optional capacity/cycle data, estimated remaining time, foreground trends and private charging sessions—with measured/computed/estimated/unavailable provenance.
- Persistent local scan history and explicit SAF file quarantine. Original deletion is claimed only when the document provider confirms it.
- Expanded **118-case** JVM test contract plus a hard Android lint and development-APK inspection gate.

## Existing foundation retained

- **Full rebrand + Deep Ocean Blue UI** — new identity, new all-blue Material 3 theme.
- **367,000+ rules bundled offline** — HaGeZi Multi Pro (ads/trackers, 176k) + HaGeZi Threat Intelligence (malware/phishing/scam, 191k) ship inside the APK; entry-level (low-RAM) devices automatically load the curated Lite set instead of the max ad list while keeping the full threat feed.
- **Bloom-filter fast path** — O(1) negative pre-check in front of the multi-million-key rule maps; clean DNS lookups short-circuit without touching hash maps.
- **NEW Security Center (anti-virus)** —
  - *Link scanner*: any URL checked against live malware/phishing intelligence + typosquat (Damerau-Levenshtein), punycode/homoglyph, credential-URL, raw-IP-login, risky-TLD, shortener and phishing-language heuristics.
  - *File scanner*: exact EICAR signature, polyglot executables (PE/ELF/DEX hidden in JPG/PNG/GIF/PDF), script droppers (PowerShell -enc, certutil, mshta, curl|sh), macro documents (vbaProject.bin), Zip-Slip traversal, double-extension bait names — bounded streaming scan, 100% on-device.
  - *APK analyzer*: real binary AndroidManifest (AXML) parser extracts package + every requested permission without installing; packer detection (jiagu/DEXHelper/…), dynamic-code-loading dropper triage, signing checks, dangerous permission-stack scoring.
  - *Installed app auditor*: MTD-style triage of every installed app (accessibility abuse, SMS interception stacks, overlay phishing capability, device-admin lockware, surveillance stacks, outdated targetSdk).
  - Security posture score + all-time malware-blocked counter.
- **Game Turbo (Zero-Lag Mode)** — real, honest optimizations for MLBB, PUBG, CODM, Free Fire, Genshin, Wild Rift, Roblox and more: cached-process trimming (two waves), master sync pause with auto-restore, DND, frozen background jobs, thermal-guard readout, and **DNS prefetch** of each game's real server domains (e.g. `aena.ms` for Mobile Legends) into the TTL cache so matchmaking connects faster.
- **Battery Intelligence (Max)** — measured drain-rate regression (%/h + time-to-empty), cell-health scoring (cycle count on Android 14+, thermal history, voltage), charge-taper time-to-full, honest recommendations, and an **Extreme Battery Saver** that stretches background work to 72h while keeping the VPN protection fully active.
- **True Deep Cleaner** — new categories: hidden/secret temp files, crash & debug logs (.log/.trace/.tombstone), orphaned empty folders, and media thumbnail caches across **all of shared storage** via opt-in All-Files-Access (Android/data and Android/obb remain protected by the OS).
- **Browser video-ad URL filtering** — EasyList-style network rule engine (`||host^`, substring rules, `$third-party`) targeting VAST/VMAP/preroll/midroll ad servers, exchanges and measurement beacons; YouTube web ad units hidden via cosmetic rules and a visible-Skip auto-clicker inside the built-in browser.
- **Six-tab navigation** with the new Security tab.

## How it works (summary)

1. **Device-wide DNS filtering** — a local `VpnService` routes only DNS into the on-device filter engine; other traffic flows at native speed. Ads, trackers and malicious domains are blocked for *every app* (games, social, browsers, utilities) without root or HTTPS decryption.
2. **Built-in Privacy Browser** — subresource interception, URL-pattern ad filtering, tracking-parameter stripping, pop-up blocking, cosmetic element hiding, cookie controls.
3. **Optimizer** — Smart Boost, RAM manager, junk cleaner (quick/deep/scheduled/custom), Game Booster + Turbo, battery modes.
4. **Security Center** — anti-virus and anti-phishing as described above, fully offline.

### Honest disclosures (unchanged physics)

- **YouTube/Facebook/TikTok in-app video ads** are served from the same first-party domains as the videos themselves; DNS blocking cannot remove them without breaking playback. The built-in browser blocks website video ads at the network layer and hides/skips YouTube web ads.
- A non-root app cannot rewrite CPU governors or force-kill live foreground apps. Game Turbo uses every mechanism Android actually grants and reports exactly what it did.
- No scanner can guarantee 100% detection of brand-new (zero-day) malware; TitanShield layers signatures, structural analysis and behavioral heuristics to maximize coverage.

## Bundled filter lists & licenses

| Asset | Source | License |
|---|---|---|
| `core_max_ads.txt` | [HaGeZi dns-blocklists — Multi Pro](https://github.com/hagezi/dns-blocklists) | GPLv3 |
| `core_max_threats.txt` | [HaGeZi Threat Intelligence Feeds — mini](https://github.com/hagezi/dns-blocklists) | GPLv3 |
| `core_lite_ads.txt` | [HaGeZi dns-blocklists — Light](https://github.com/hagezi/dns-blocklists) | GPLv3 |
| `default_blocklist.txt` | TitanShield open baseline | GPLv3/MIT compatible |

Remote sources (AdGuard DNS Filter, OISD, URLHaus, StevenBlack) remain available via in-app sync.

## Technical architecture

### Layer 1 — Wire-Format DNS Engine (`engine/dns/`)
- RFC 1035/3596 parser + response synthesizer (A, AAAA, CNAME, HTTPS, SVCB, TXT, MX), hardened against compression-pointer loops.
- DoH (RFC 8484), DoT (RFC 7858), protected UDP/TCP with TCP upgrade on truncation.
- TTL-aware LRU cache with transaction-ID rewriting; **new**: `buildStandardQuery` + `prefetchHostnames` power Game Turbo cache warming.

### Layer 2 — Local VPN Service (`service/AdShieldVpnService.kt`)
- DNS-only TUN routing, socket protection + loop prevention, per-app split tunneling, network recovery, boot restore, always-on support.

### Layer 3 — Privacy Browser Blocker (`engine/browser/BrowserContentBlocker.kt`)
- **New `UrlPatternFilter`**: compiled EasyList-subset network rules (dedicated ad hosts + video-ad manifest/bidding URL patterns, `$third-party` aware).
- Cosmetic CSS + MutationObserver collapsing, YouTube web ad selectors, visible-Skip auto-clicker, tracking-parameter sanitizer, pop-up blocker.

### Layer 4 — Lock-Free Filter Engine (`engine/filter/`)
- Immutable `FilterSnapshot` in an `AtomicReference`; priority-ordered evaluation.
- **New `BloomFilter`** (MurmurHash3, ~0.1% FP) built over all blocking keys → clean-domain lookups short-circuit; wildcards disable the fast path for correctness.
- Hosts/adblock/plain-domain parsing, wildcard regexes, allowlist exceptions, conflict analyzer.

### Layer 5 — Security Engines (`engine/security/`)
- `UrlThreatScanner`, `FileThreatScanner`, `ApkAnalyzer` (incl. binary AXML string-pool + start-tag parser), `AppRiskAuditor`, orchestrated by `SecurityEngine` against the live MALWARE-category rule set.

### Layer 6 — Optimizer & Turbo (`engine/optimizer/`, `engine/battery/`)
- `SystemOptimizerEngine`: RAM/storage/battery telemetry, junk scans with SHA-256 duplicates, deep-clean categories, Smart Boost pipeline, Extreme Battery Saver.
- `GameTurboEngine`: cached-process trimming, master-sync pause/restore, DND, WorkManager freeze, per-game DNS prefetch catalog, thermal guard.
- `BatteryAnalytics`: drain regression, charge taper model, health scoring, recommendations.

### Layer 7 — Atomic Filter Updater (`data/repository/`, `worker/`)
- Seeded built-in sources (including the on-device max lists — auto-merged into existing installs on upgrade), HTTPS sources with `.tmp`/`.bak` atomic swap + rollback, 900k-rule merge cap for memory safety, low-RAM adaptive asset selection.

## Project structure

```text
app/src/main/java/com/adshield/pro/
├── AdShieldApplication.kt / MainActivity.kt
├── data/ (Room DAO+Entities, DataStore preferences, repository)
├── di/AppModule.kt
├── domain/model/ (protection, rules, optimizer, stats models)
├── engine/
│   ├── battery/BatteryAnalytics.kt
│   ├── browser/BrowserContentBlocker.kt
│   ├── dns/ (DnsPacketCodec, IpPacketFraming, UpstreamDnsResolver)
│   ├── filter/ (FilterRuleEngine, BloomFilter)
│   ├── optimizer/ (SystemOptimizerEngine, GameTurboEngine)
│   └── security/ (SecurityEngine, UrlThreatScanner, FileThreatScanner, ApkAnalyzer, AppRiskAuditor)
├── service/ (AdShieldVpnService, BootCompletedReceiver)
├── ui/ (screens incl. SecurityScreen, theme, viewmodel)
└── worker/ (FilterUpdateWorker, SmartOptimizationWorker)
app/src/main/assets/ (default_blocklist.txt, core_max_ads.txt, core_max_threats.txt, core_lite_ads.txt)
app/src/test/java/com/adshield/pro/ (AdShieldEngineTestSuite, TitanShieldMaxEngineTestSuite)
```

## Build

```bash
./gradlew assembleDebug          # debug APK
./gradlew test                   # unit tests (both engine suites)
./gradlew assembleRelease        # requires signing env vars (see docs/BUILD_AND_SIGNING_GUIDE.md)
```

## Two platforms, one core (OmniShield X)

- **Android app** — this repository's APK (DNS VPN firewall, Security Center, in-app ad skip, optimizer).
- **Web platform** — `website/` (GitHub Pages): live Domain Checker running the real rule file with the same evaluation ladder (CI-tested), Policy Sync via the app's backup JSON, extension distribution. Everything runs locally in the browser.
- **Browser extension** — `extension/` (Manifest V3): 50,000 DNR block rules generated from the same bundled feed + cosmetic filtering. Load unpacked via developer mode.
- **No fake cloud**: there are no OmniShield servers or accounts; the platforms share rule assets, engine semantics, and the config schema offline. See `docs/OMNISHIELD_X_PLATFORMS.md`.

## Package identity

Display name: **TitanShield Max** · applicationId `com.adshield.pro` (kept for in-place update compatibility from AdShield Pro 2.x installs).

## License

Project code: GPLv3-compatible open baseline. Bundled lists are the property of their authors (see table above).
