# AdShield Pro — Infinity DNS Future Roadmap

**Version:** 3.0.0 Infinity DNS Edition  
**Date:** 2026-11-17  
**Horizon:** 2026–2029

---

## 1. Immediately Implementable (v3.1 — 1–2 months)

These require no new infrastructure, no paid APIs, and no architectural rewrite.

| Feature | Requirements | Cost | Limitations | Dependencies |
|---------|-------------|------|-------------|--------------|
| **Per-domain intelligence overlay in Activity log** | Add `InfinityDnsCoordinator.fullIntelligenceReport()` call for each blocked domain's detail sheet | Dev only | Extra ~50µs per log entry | Infinity engines (done) |
| **CNAME post-upstream blocking** | Wire `CnameIntelligenceEngine.evaluate()` into `AdShieldVpnService.processDnsQuery()` after upstream returns CNAME | Dev only | Requires upstream CNAME parsing; adds ~1ms to CNAME responses | DnsPacketCodec CNAME extraction (done) |
| **Compatibility Guard UI indicator** | Show shield icon in Rules tab when a domain is compatibility-protected | Dev only | Visual only | CompatibilityGuard (done) |
| **Threat intelligence batch import** | Load `infinity_threat_intel.txt` + HaGeZi TIF into `ThreatIntelligenceManager` on startup | Dev only | Memory +~2MB for index | ThreatIntelligenceManager (done) |
| **Performance dashboard** | Expose `DnsPerformanceOptimizer.getMetrics()` + cache stats in Settings → Diagnostics | Dev only | Needs UI wiring | Optimizer + InfinityDnsCache |
| **Cache hit metrics in notification** | Include cache hit rate in VPN notification subtitle | Dev only | Trivial | InfinityDnsCache stats |

**Feasibility:** All GREEN — code already exists, only wiring needed.

---

## 2. Near-Future (v3.2–v3.3 — 3–6 months)

| Feature | Requirements | Cost | Limitations | Dependencies | Feasibility |
|---------|-------------|------|-------------|-------------|-------------|
| **TTL-aware InfinityDnsCache as primary cache** | Replace `LinkedHashMap` in `UpstreamDnsResolver` with `InfinityDnsCache` | Dev only | Needs migration + testing for cache-key compatibility | InfinityDnsCache (done) | GREEN |
| **Incremental filter list updates** | Support diff/patch updates (e.g., `Expires` + `If-None-Match` ETag) to avoid full re-download | Dev only | Server must send ETag; fallback to full download | HTTP layer | GREEN |
| **DoH JSON + ODoH exploration** | Add Oblivious DoH support for privacy (proxy hides client IP from resolver) | Dev only | Requires ODoH proxy (e.g., Cloudflare's); not all providers support it | DoH transport | YELLOW — spec exists but proxy needed |
| **DNS query prefetch for top domains** | Prefetch top 20 domains on app launch (when charging + Wi-Fi) | Dev only | Battery on cellular | BatteryOptimization | GREEN |
| **Wildcard filtering expansion** | Support `*\*.ads.*` patterns from newer AdGuard lists | Dev only | Must validate not to break `VIDEO_UNSAFE` rules | FilterRuleEngine wildcard compiler | GREEN |
| **EDNS Client Subnet toggle per-profile** | Allow user to toggle ECS forwarding per DNS profile | Dev only | Privacy trade-off must be disclosed | DnsProviderPreset.forwardsClientSubnet | GREEN |
| **Automated compatibility test suite** | CI job that resolves 200 essential domains + 200 ad domains and asserts correct verdicts | Dev only | Network in CI | Tests | GREEN |

---

## 3. Advanced AI & Intelligence (v3.4–v4.0 — 6–18 months)

| Feature | Requirements | Cost | Limitations | Dependencies | Feasibility |
|---------|-------------|------|-------------|-------------|-------------|
| **On-device TinyML classifier** | Train lightweight model (TF Lite, ~200KB) on lexical features to classify unknown domains | Dev + training data | Needs labeled dataset (~50k domains); initial accuracy ~85% | DomainIntelligenceEngine features as input | YELLOW — feasible with TFLite, needs dataset curation |
| **Adaptive threat scoring** | Learn from user's allow/block overrides to personalize risk thresholds | Dev only | Privacy: must stay on-device; needs explicit consent | Intelligence history | GREEN |
| **Predictive DGA detection** | Real-time DGA family identification (conficker, suppobox, etc.) | Dev + ML model | DGA families evolve; model needs periodic retraining | Entropy + ML | YELLOW |
| **Homograph attack visualization** | Show punycode vs Unicode rendering for IDN domains | Dev only | Requires ICU library ~1MB | IDN handling | GREEN |
| **Collaborative threat sharing (opt-in)** | Anonymous, aggregated threat reports (no PII, no URLs) | Dev + opt-in consent flow | Must be fully anonymous + GDPR-compliant | Privacy review | YELLOW — legal review needed |
| **AI-powered false-positive auto-correction** | Detect when user immediately allows a blocked domain and suggest global allowlist | Dev only | Must not auto-allow without user confirmation | Event history | GREEN |

**AI constraints honored:**
- No cloud AI required — all runs locally
- No expensive APIs (OpenAI, etc.)
- No automatic blocking without verification
- User autonomy ceiling always respected

---

## 4. Long-Term DNS Technology (v4.0+ — 12–36 months)

| Feature | Requirements | Cost | Limitations | Dependencies | Feasibility |
|---------|-------------|------|-------------|-------------|-------------|
| **DNS-over-QUIC (DoQ, RFC 9250)** | QUIC transport for DNS (lower latency than DoT, connection migration) | Dev only | Few public DoQ resolvers yet (AdGuard, NextDNS experimental) | QUIC library (Cronet/quiche) | YELLOW — spec stable, resolver support limited |
| **DNS-over-HTTP/3** | DoH over QUIC/HTTP3 | Dev only | Same as DoQ — ecosystem not mature | HTTP/3 stack | YELLOW |
| **ECH (Encrypted Client Hello)** | Hide SNI from network observers | Dev only | Requires TLS 1.3 + server support; very few resolvers support ECH for DNS | TLS stack | RED — experimental |
| **Local DNSSEC chain validation** | Validate RRSIG locally instead of trusting upstream AD bit | Dev only | Needs trust anchor management + key rollover; complex | DNSSEC knowledge | YELLOW — possible but high complexity |
| **BGP-aware provider selection** | Select provider based on network path latency | Dev + network measurement | Needs active probing; battery impact | Network diagnostics | YELLOW |
| **Multi-path DNS (parallel transports)** | Query DoH + DoT simultaneously, use fastest | Dev only | Double bandwidth for small gain | Transport layer | GREEN — hedged requests already implement subset |

---

## 5. Experimental Technologies

| Feature | Description | Requirements | Risk |
|---------|-------------|-------------|------|
| **DNS-over-Tor** | Route DNS through Tor for maximum privacy | Orbot/Arti integration | High latency; needs Tor daemon |
| **Blockchain DNS (ENS, Handshake)** | Resolve decentralized names | Blockchain light client | Speculative; no mainstream adoption |
| **WASM filter engine** | Port filter engine to WASM for cross-platform (Android + browser extension) | Rust/Kotlin WASM | Significant port effort |
| **Peer-to-peer blocklist sync** | Share block rules via P2P (IPFS, libp2p) | P2P stack | Complexity; trust model needed |
| **Quantum-resistant DNS** | Post-quantum TLS for DoT/DoH | PQ TLS library | No standard yet |

---

## 6. Technically Impossible or Unsupported

These cannot be achieved via DNS filtering alone. Documented honestly:

| Feature | Why Impossible | Alternative |
|---------|---------------|-------------|
| **Universal YouTube ad removal via DNS** | YouTube serves ads from `googlevideo.com` — same domain as content. DNS cannot distinguish ad segments from video segments on the same host. | Browser extension with request-body inspection or YouTube Premium |
| **Removing ads already in video stream (server-side ad insertion)** | Ad is spliced into video bytes server-side before delivery. DNS only resolves names, not content. | Client-side ad skip (SponsorBlock) — not DNS |
| **Blocking ads in apps with hardcoded DNS (DoH/QUIC bypass)** | Apps using internal DoH/QUIC ignore system DNS entirely. Local VPN cannot intercept. | Requires per-app proxy or OS-level firewall (not available non-root) |
| **Cosmetic filtering in external browsers** | Android sandboxing prevents injecting CSS into other apps' WebViews | Only inside built-in Privacy Browser |
| **Increasing ISP bandwidth** | DNS only resolves names; throughput is ISP-controlled | None — honest disclosure in UI |
| **Zero-latency guarantee** | Network physics + upstream resolver distance impose minimum latency | Minimize, not eliminate |
| **100% block rate** | New ad domains registered daily; lists update periodically. Zero-day ad domains exist between updates. | Maximize coverage + fast updates; never claim 100% |
| **Guaranteed zero false positives with aggressive blocking** | Aggressive lists may include shared infrastructure (analytics + auth on same domain) | Compatibility Guard + allowlist fallback |

---

## 7. Architecture Extensibility Guarantees

Infinity DNS is built for future without rewrites:

- **Independent detection modules:** Each engine (`CnameIntelligence`, `DomainIntelligence`, `VideoAd`, `Threat`, `Security`, `Compatibility`, `Performance`) is a `@Singleton` Hilt module with no cross-dependencies except `FilterRuleEngine` for CNAME
- **Pluggable filtering providers:** `FilterListSource` with `asset://` or `https://` URLs; new sources added via `buildDefaultFilterSources()` with no engine change
- **Versioned filtering rules:** `FullConfigurationBackup.version` for migration; `FilterSourceEntity.etagOrHash` for incremental updates
- **Automated compatibility tests:** `InfinityDnsTestSuite` covers all engines; CI gate on every PR
- **Safe rule updates:** Atomic `.tmp → .bak → active` with rollback on failure
- **Backward-compatible migrations:** Room migrations + DataStore with defaults; old configs load with new code

Adding a new capability = add new engine class → add to `InfinityDnsModule` → wire into `InfinityDnsCoordinator` if needed. No existing file modified beyond DI registration.

