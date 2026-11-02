# Changelog — TitanShield Max

## 3.0.0 (TitanShield Max rebrand)

### Identity & UI
- Full rebrand: AdShield Pro → **TitanShield Max** (applicationId `com.adshield.pro` kept for in-place updates).
- New **Deep Ocean Blue** Material 3 theme (ElectricBlue / SkyBlueGlow / DeepBlue palette).
- New 6-tab navigation: Home · Ad Block · **Security** · Optimizer · Statistics · Settings.

### Ad & tracker blocking (maximum)
- Bundled **367,000+ offline rules**: HaGeZi Multi Pro ads (176,107) + HaGeZi TIF mini malware (191,527); low-RAM devices auto-load the Light ad list while keeping the full threat feed.
- **Bloom-filter fast path** (MurmurHash3, ~0.1% FP) short-circuits clean-domain lookups in front of the multi-million-key rule maps.
- DNS engine: HTTPS/SVCB record support, query synthesis, prefetch APIs, refined TTL clamps.

### Video ad blocking (browser)
- New `UrlPatternFilter`: EasyList-style network rules against VAST/VMAP ad servers, exchanges and measurement beacons (`$third-party` aware).
- Cosmetic collapsing with MutationObserver re-application + YouTube web Skip auto-clicker.

### NEW: Security Center (anti-virus)
- Link scanner: threat-feed lookup + typosquat (Damerau-Levenshtein), punycode/homoglyph, credential URLs, raw-IP logins, risky TLDs, shorteners, phishing language.
- File scanner: EICAR, polyglot executables (PE/ELF/DEX in media/PDF), script droppers, macro documents, Zip-Slip, double-extension bait — bounded streaming scans, 100% on-device.
- APK analyzer: real binary AXML manifest parser (package + all permissions), packer detection, dynamic-code-loader triage, signing checks.
- Installed-app auditor: accessibility abuse, SMS interception, overlay phishing, device-admin lockware, surveillance stacks, outdated targetSdk.
- Security posture score + all-time malware-block counter.

### Optimizer (maximum)
- **Game Turbo**: cached-process trimming waves, master-sync pause with auto-restore, DND, WorkManager freeze, per-game DNS prefetch (MLBB `aena.ms`, PUBG, CODM, Free Fire, Genshin, Wild Rift, Roblox, …), thermal guard, 6h auto-restore sessions.
- **Battery Intelligence**: measured drain regression (%/h + ETA), cell health (cycles, thermal, voltage), charge-taper time-to-full, **Extreme Battery Saver** (72h background window, VPN stays on).
- **True Deep Clean**: hidden temp files, crash/debug logs, orphaned empty folders, thumbnail caches across all of shared storage (All-Files-Access opt-in), SHA-256 duplicate detection.

### Engineering
- Version 30000 / 3.0.0; new unit-test suite `TitanShieldMaxEngineTestSuite` (bloom filter, fast-path semantics, URL/file/APK scanners incl. hand-built AXML fixture, battery analytics, turbo catalog, browser URL filter).
- Docs rebrand + THIRD_PARTY_NOTICES (HaGeZi GPLv3 verified) + Security Center privacy disclosures.

## 2.2.x and earlier — AdShield Pro

See git history for the AdShield Pro 2.x line (DNS VPN filtering, privacy browser, optimizer core, statistics).
