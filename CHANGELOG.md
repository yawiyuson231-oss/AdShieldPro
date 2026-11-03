# Changelog — OmniShield X (formerly TitanShield Max)

## 4.6.0 — AETHER agent upgrade + WiFi low-latency + fastest-resolver speed mode

- **AETHER self-audit (false-positive radar):** the agent now reviews its OWN blocking from real query logs — any domain blocked 3+ times that came from a heuristic shield or belongs to the protected auth/payment catalog surfaces in the Control Center for one-tap review. Detection only; it never auto-unblocks (tested).
- **AETHER explainer:** plain-language, facts-only reason for every verdict (domain, type, detection source, rule) — no invented threat claims (tested).
- **WiFi low-latency lock:** while filtering is active, holds Android's LOW_LATENCY WifiLock (API 29+, high-perf fallback) to cut radio power-save jitter for gaming/streaming while the screen is on. Honest: reduces jitter/latency spikes; cannot increase ISP bandwidth.
- **Speed mode (opt-in, Settings):** every 15 minutes the fastest RELIABLE resolver is selected from REAL measured query latencies (switch only if ≥25% faster at ≥90% success, ≥10 probes; custom resolvers never touched; no synthetic traffic).
- **Time-saved stat (real math):** blocked lookups answered locally — estimated lookup time avoided = blocked count × your measured average allowed-lookup latency, shown in Settings.
- Universal ad-skip evidence widened: "Skip all ads", "Skip this ad", "Hide ad(s)" texts.


## 4.5.0 — Platform-spec hardening + UNIVERSAL video ad-skip

- **Universal in-app ad-skip (any video app):** the Accessibility skip engine now offers a universal mode (default ON) that applies the same strict ad-evidence rules to EVERY app — third-party video players, games, browsers — while system UIs (SystemUI, launchers, dialer, keyboard, messaging, settings) are hard-excluded in all modes. IMA-SDK skip ids added. Bare "Skip"/"✕"/"Close" and ad CTAs remain untappable (tested).
- **Strict Heuristic Shield:** random-looking (DGA) + lookalike brand domains (homoglyph fold + Damerau-Levenshtein, 30 protected brands incl. PH banks/GCash) observed in Balanced, blockable in Strict (toggle). One-tap reversal preserved.
- **New-domain (≤30d) check:** opt-in RDAP lookup (2s cap, 6h cache); unknown age NEVER blocked. Plain-language DNSSEC explainer in Settings.
- **Never cut connectivity:** DoH/DoT failure now falls back to the device's normal DNS with an amber LIVE banner — no silent outage.
- **Pause 5/15/60 minutes** with automatic resume (never left unprotected silently).
- **"Blocked in the last 60 minutes"** top-list on the LIVE tab.
- **PC agent** (pc-agent/omnishield_proxy.py): real local DNS proxy, same ladder, DoH-only upstream, self-test passing.
- **iOS profile** (ios/omnishield-dns.mobileconfig): system-wide encrypted ad-blocking DoH for iPhone; per-app exclusion honestly declared impossible.
- **Top-100 app domains acceptance test** against the real 367k-rule lists in Balanced AND Strict.


## 4.4.0 — Encrypted-DNS Bypass Shield ("working DNS in any app or website")

- Browsers/apps that hardcode their own DNS-over-HTTPS (Chrome "Secure DNS", Firefox DoH, SDK resolvers) previously bypassed any DNS firewall. Their clients must first resolve the provider's bootstrap hostname via system DNS — this release **sinkholes those bootstrap hostnames** (Cloudflare/Google/Quad9/AdGuard/OpenDNS/CleanBrowsing + `use-application-dns.net`), forcing fallback to the filtered system resolver. Browsing continues; only the bypass is cut.
- The user's own selected DoH provider is never sunk (merge-time exclusion, unit-tested).
- CUSTOM category is active in every protection mode — the shield holds in Balanced/Strict/Privacy/Custom (unit-tested).
- Toggle: Settings → Zero-Breakage card → "Encrypted-DNS Bypass Shield" (default ON). Turning it on/off re-syncs the engine instantly.


## 4.0.0 — AETHER Infinity (OmniShield X)

### Part 1 — AETHER Neural GodCore
- Central orchestration engine (`engine/aether/`) with **15 specialized agents** (X-AD, X-Video, X-DNS, X-Tracker, X-Malware, X-Domain DNA, X-App, X-Network, X-Privacy Auditor, X-Predictive Defense, X-Self-Healing, X-Verification, X-Global Learning, X-Digital Twin, X-Failsafe).
- Every agent has a defined responsibility, real performance counters, and evidence-backed findings. Blocking remains the exclusive job of the deterministic filter engine — AETHER observes, verifies (independent re-check against the Critical Protection catalog), measures, and audits. Honest label: heuristic evidence engine, NOT a neural network; nothing simulated.

### Parts 4/5 — DNS hardening
- **DNS rebinding guard** in the VPN answer path: public domains answering with private/loopback/ULA IPs are sinkholed (wire-format A/AAAA extractor, RFC 1035 compression-aware).
- **Resolver Health Monitor**: real per-resolver success/latency ranking from live traffic + watchdog probes; best-resolver surfaced on the dashboard.

### Parts 6 — Predictive defense (honest)
- DGA-style entropy detection and DNS-tunneling structure detection run in **OBSERVE mode only** — they report anomalies on the dashboard and never block on weak predictions.

### Part 7 — Digital Twin
- `RuleDigitalTwin` simulates candidate rule sets against the must-work corpus (video/auth/payments/games/messaging) in a throwaway engine and reports exact conflicts. CI runs it against the real bundled lists.

### Part 3 — Video AI
- Extended video-ad endpoint patterns in the browser URL filter (Google IMA `/ima/ads`, `videoads`, `securepubads`, `videoplaza`, …); playback domains remain protected.

### Part 12 — Control Center
- New AETHER Control Center card on Home: agents online, DNS analyzed, blocked confirmed, anomalies observed, rebinding stopped, verification overrides, auto-recoveries, best resolver, top blocked domains, safe-mode state — every number from real events.

### Brand / version
- OmniShield X (display name), versionCode 40000, versionName 4.0.0. applicationId and all engines unchanged.

### Still honest limitations (unchanged)
- No cloud/global backend network exists (Part 9 is NOT shipped — no servers are claimed). No DoQ/DNSSEC validation. No in-app YouTube/FB/TikTok ad removal (server-side). AETHER is deterministic heuristics, not an LLM/neural net.


## 3.1.0 — Global DNS Firewall hardening (Modules 1/3/4/5/6/7/11/12)

### NEW: Zero-Breakage Engine (Module 7)
- Connectivity watchdog in the VPN service probes real DNS resolution every 30s (60s in safe mode).
- 3 consecutive failures → **automatic Safe-Mode Filtering**: filter lists drop atomically, user rules + Critical Protection stay on — the internet keeps working; auto-restores on first stable probe, counted for the dashboard.
- **Shadow Mode**: filter-list blocks are reported, not enforced — validate then allowlist (user custom rules still enforce; nothing is ever silently blocked *by* automation).
- **Report-broken-site**: one tap allowlists the broken domain instantly and increments the false-positive counter.
- Emergency protection suspension via existing Pause action; Safe-Mode counters surfaced in Settings.

### NEW: Critical Content & Authentication Protection (Modules 4/5)
- `ProtectedDomainCatalog`: ~130 registrable domains (YouTube/Netflix/TikTok/FB/IG video CDNs, Google/Microsoft/Apple auth, PayPal/Stripe/GCash banking, Play/Store/OTA updates, MLBB/PUBG/Roblox/… game servers, WhatsApp/Telegram/Discord messaging) are **never blocked by filter lists in any mode**; explicit user rules still win.
- Fully explainable: blocked/allowed decisions carry the protecting group label.

### NEW: DNS Leak & Exposure assessment (Modules 1/6)
- Honest on-device report: tunnel captures all system DNS; DoH/DoT = encrypted upstream; plaintext = visible on-path; hardcoded private-DoH apps bypass any DNS VPN (disclosed, not faked).

### Module 11: Automated compatibility gate
- New `DnsFirewallCompatibilityTest` loads the **real bundled 367k-rule production lists** into the real engine in CI and verifies YouTube/Netflix/TikTok/Facebook/Instagram/Play/Banking/Games/Messaging are never blocked while ads/trackers/malware still are — plus watchdog, shadow-mode, protection-layer and leak-report unit tests (13 new tests, 43 total).

### Module 12
- Configuration import/export confirmed working (JSON backup + restore in Settings); Zero-Breakage card added to Settings.

### Honest limitations (unchanged physics)
- DNS-over-QUIC and full DNSSEC chain validation are not implemented (no QUIC stack in Android/Kotlin stdlib; documented, not faked).
- In-app first-party video ads (YouTube/Facebook/TikTok apps) cannot be DNS-blocked — built-in browser blocks website video ads instead.


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
