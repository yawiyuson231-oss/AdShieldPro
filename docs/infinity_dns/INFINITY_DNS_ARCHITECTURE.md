# AdShield Pro — INFINITY DNS Architecture

> The most advanced, intelligent, reliable, privacy-focused DNS filtering engine possible within the existing Android application.

**Version:** 3.0.0 — Infinity DNS Edition  
**Date:** 2026-11-17  
**Compatibility:** Android 10+ (API 29–37), no root, no VPN server, no paid APIs

---

## 1. Architectural Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Android VpnService (DNS-Only)                │
│  TUN: 10.215.173.2/32  fd00:ad5:1e1d::2/128                      │
│  Non-DNS traffic → physical network (zero throughput impact)     │
└──────────────────────────┬──────────────────────────────────────┘
                           │ DNS query (UDP/TCP port 53)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│               INFINITY DNS Intelligence Pipeline                │
│                                                                 │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ Compatibility│  │   Filter     │  │  CNAME Intelligence    │  │
│  │   Guard      │→ │   Rule       │→ │  Engine                │  │
│  │ (essential   │  │   Engine     │  │  (cloaking detection)  │  │
│  │  allowlist)  │  │  (layers)    │  │                        │  │
│  └─────────────┘  └──────────────┘  └────────────────────────┘  │
│          │                 │                    │                │
│          ▼                 ▼                    ▼                │
│  ┌──────────────┐ ┌──────────────┐  ┌────────────────────────┐  │
│  │   Domain     │ │   Video Ad   │  │  Threat Intelligence   │  │
│  │ Intelligence │ │ Intelligence │  │  Manager               │  │
│  │ (ML+heur.)   │ │ (platform)   │  │  (malware/phishing)    │  │
│  └──────────────┘ └──────────────┘  └────────────────────────┘  │
│          │                 │                    │                │
│          └─────────────────┼────────────────────┘                │
│                            ▼                                    │
│              ┌────────────────────────┐                          │
│              │   Infinity DNS Cache   │                          │
│              │  TTL-aware LRU + stale │                          │
│              │  -while-revalidate     │                          │
│              └────────────┬───────────┘                          │
│                           │ miss                                 │
│                           ▼                                      │
│              ┌────────────────────────┐                          │
│              │  Upstream Resolver     │                          │
│              │  DoH / DoT / UDP+TCP   │                          │
│              │  + hedged failover     │                          │
│              │  + DNSSEC reporting    │                          │
│              └────────────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

### Layer Responsibilities

| Layer | Module | Purpose |
|-------|--------|---------|
| **L0** | `CompatibilityGuard` | Never break essential services (banking, Play Services, streaming) |
| **L1** | `FilterRuleEngine` | 367k+ rules, 4 protection modes, lock-free lookup |
| **L2** | `CnameIntelligenceEngine` | Follow CNAME chains, detect cloaking |
| **L3** | `DomainIntelligenceEngine` | ML-assisted classification, DGA/typosquat detection |
| **L4** | `VideoAdIntelligence` | Platform-specific video ad infrastructure |
| **L5** | `ThreatIntelligenceManager` | Malware/phishing feeds |
| **L6** | `DnsSecurityEngine` | Hijacking, leak, anomaly detection |
| **Cache** | `InfinityDnsCache` | TTL-aware LRU with metrics |
| **Transport** | `UpstreamDnsResolver` | Encrypted DNS with failover |
| **Perf** | `DnsPerformanceOptimizer` | Latency/battery/memory optimization |

---

## 2. DNS Packet Processing

### 2.1 Wire Format (DnsPacketCodec)

- Full RFC 1035 / RFC 3596 parser
- Supports A, AAAA, CNAME, HTTPS, SVCB, TXT, MX
- Hardened against truncated headers, cyclic compression pointers (max 16 jumps)
- Response synthesis: NXDOMAIN, sinkhole (0.0.0.0 / ::), SERVFAIL, truncated (TC=1)
- **NEW:** `extractCnameTargets()` — parse CNAME records from responses
- **NEW:** `extractAllTtls()` — TTL extraction for cache & anomaly detection
- **NEW:** `detectSuspiciousResponse()` — fast-flux, large response, mixed types

### 2.2 IP Packet Framing (IpPacketFraming)

- IPv4 + IPv6 with extension header support
- UDP/TCP port 53 with RFC 1071 checksums
- TCP state machine: SYN → SYN+ACK → PSH+ACK → FIN+ACK
- MTU-aware segmentation for large DNS-over-TCP answers
- UDP truncation → TCP fallback

### 2.3 Upstream Resolution (UpstreamDnsResolver)

- **DoH** (RFC 8484) — wireformat POST with bootstrap DNS
- **DoT** (RFC 7858) — TLS with SNI + hostname verification
- **UDP/TCP 53** — protected sockets with TC upgrade
- Hedged requests: 250ms head start, race 2 providers in parallel
- Circuit breaker: 3 failures → 30s cooldown
- Health monitoring with EWMA latency
- TTL-aware LRU cache (1024 entries) with transaction ID rewrite
- Media-aware provider ordering (ECS forwarding for video CDN accuracy)
- DNSSEC reporting (AD bit, RRSIG detection)

---

## 3. Intelligence Engines

### 3.1 CNAME Intelligence

Detects CNAME cloaking where a first-party name hides a tracker:

```
analytics.example.com CNAME oajs.openx.net  → BLOCKED (tracker cloaked)
tracker.shop.com CNAME cname.eulerian.net   → BLOCKED (cloaked tracker)
cdn.example.com CNAME dualstack.cloudfront.net → ALLOWED (legitimate CDN)
```

- Parses CNAME records from upstream responses
- Walks chains up to 8 hops, detects loops
- Cross-references canonical targets against filter engine
- Checks known cloaked tracker registry (28 domains)
- Reports suspicious chains (cross-TLD, long chains, short TTL)

### 3.2 Domain Intelligence (AI-Assisted)

Offline, lightweight classification:

- **Lexical:** entropy, length, hyphen/digit counts, label structure
- **TLD risk:** high-risk (.tk, .ml, .zip, .mov) vs suspicious vs normal
- **DGA detection:** entropy + length + digit ratio heuristics
- **Typosquatting:** Levenshtein distance + homoglyph normalization
- **Infrastructure mapping:** ad/tracker/analytics patterns
- **Risk scoring:** 0-100 with confidence, recommendation

No cloud AI required. All heuristics run locally in microseconds.

### 3.3 Video Ad Intelligence

Platform-aware video ad detection:

| Platform | Blockable Infrastructure |
|----------|------------------------|
| YouTube | `pubads.g.doubleclick.net`, `s0.2mdn.net`, `imasdk.googleapis.com` |
| TikTok | `analytics.tiktok.com`, `log.byteoversea.com`, `mcs.tiktokv.com` |
| Twitch | `ads.twitch.tv`, `spade.twitch.tv` |
| Generic | `pubmatic.com`, `rubiconproject.com`, `spotx.tv`, `freewheel.tv` |
| K-Drama | `ads.viki.com`, `ad.kakao.com` |
| Mobile SDK | `unityads.unity3d.com`, `applovin.com`, `vungle.com` |

**Never blocks media delivery:** `googlevideo.com`, `nflxvideo.net`, `ttvnw.net`, etc.

### 3.4 Threat Intelligence

- **Bundled:** HaGeZi TIF (191k threat domains) — offline, no network needed
- **Remote:** URLhaus, StevenBlack (HTTPS sync with validation)
- **Heuristic:** phishing keyword + TLD + structure analysis
- Subdomain inheritance for malware/phishing (parent → child)
- Confidence scoring and severity classification

### 3.5 Security Engine

- Phishing/malware/scam detection
- DNS hijacking detection (IP range comparison for known domains)
- DNS leak detection (configured vs observed resolvers)
- Response anomaly detection (TTL, record types, size, tunneling)
- DNSSEC status assessment (AD bit reporting)

### 3.6 Compatibility Guard

70+ protected domains across 11 categories:

- Connectivity checks, Play Services, auth/SSO
- Banking (GCash, Maya, BDO, BPI, PayPal, Stripe)
- Messaging (WhatsApp, Telegram, Signal)
- Gaming (Mobile Legends)
- Streaming playback (YouTube, Netflix)
- Email, OS updates, CDN

Validates proposed blocks never break essentials.

---

## 4. Caching (InfinityDnsCache)

Advanced TTL-aware LRU:

| Feature | Detail |
|---------|--------|
| Capacity | 2048 entries / 4 MB (configurable) |
| TTL | From DNS response, clamped 15s–3600s |
| Negative cache | NXDOMAIN cached 30s (not forever) |
| Stale-while-revalidate | Serve stale 5s while revalidating |
| Eviction | LRU + memory-bounded |
| Thread safety | Read-write lock (high read concurrency) |
| Metrics | Hit rate, p50/p95/p99 latency, per-provider stats |
| Maintenance | `evictExpired()` + `trimToSize()` |

---

## 5. Performance Optimization

### 5.1 Latency

- Hedged requests (250ms stagger) eliminate tail latency
- Fastest-healthy provider ranking (EWMA)
- Cache hit <1µs, miss path <5µs evaluation
- UDP timeout 2.5s (fail fast)

### 5.2 Battery

Adaptive based on battery level:

| State | Cache | Sync | Prefetch |
|-------|-------|------|----------|
| Low power (<15%) | 512 | 24h | off |
| Low battery (<30%) | 1024 | 12h | off |
| Normal | 2048 | 12h | off |
| Charging | 2048 | 6h | on |

### 5.3 Memory

- Lite list on low-RAM devices (core_lite_ads.txt)
- Bounded caches prevent OOM
- Atomic filter snapshots avoid copying

### 5.4 Network Transitions

- Wi-Fi ↔ mobile: re-probe health, retain cache on Wi-Fi, clear stale on cellular
- Offline: serve stale cache, queue updates
- Underlying network binding via `setUnderlyingNetworks()`

---

## 6. Security Model

- No plaintext downgrade (DoH/DoT failure → SERVFAIL, never UDP fallback unless configured)
- Bootstrap DNS uses literal IPs (no recursive lookup through tunnel)
- UDP response validation (transaction ID, source IP, QR bit)
- TLS hostname verification for DoT
- Filter list validation (HTML/binary rejection, size limits, hash verification)
- Atomic updates with rollback (.tmp → .bak → active)

---

## 7. Module Dependencies

```
AdShieldVpnService
├── FilterRuleEngine ← AdShieldRepository (Room + DataStore)
├── UpstreamDnsResolver ← DnsProviderHealthMonitor + InfinityDnsCache
├── CnameIntelligenceEngine ← FilterRuleEngine
├── DomainIntelligenceEngine (standalone)
├── VideoAdIntelligence (standalone)
├── ThreatIntelligenceManager (standalone)
├── DnsSecurityEngine (standalone)
├── CompatibilityGuard (standalone)
└── DnsPerformanceOptimizer (standalone)
```

All engines are `@Singleton` Hilt modules. New engines can be added without modifying existing ones (pluggable architecture).

---

## 8. Data Flow Example

**Query: `ads.example.com` (video ad)**

1. TUN captures UDP packet → `IpPacketFraming.parseIpPacket()`
2. Extract domain → `DnsPacketCodec.parseQuery()` → `ads.example.com`
3. `CompatibilityGuard.check()` → not protected → continue
4. `FilterRuleEngine.evaluate()` → `||ads.example.com^` match → BLOCKED
5. Synthesize NXDOMAIN → `buildUdpResponsePacket()` → write to TUN
6. Record event → daily stats + intelligence event (if malware)

**Query: `tracker.example.com` (CNAME cloaked)**

1. Same steps 1-3
2. `FilterRuleEngine.evaluate()` → no direct match → ALLOWED
3. `UpstreamDnsResolver.resolve()` → upstream returns `CNAME tracker.adnetwork.com`
4. `CnameIntelligenceEngine.evaluate()` → detects cloaking → BLOCKED
5. Synthesize NXDOMAIN → return to app

**Query: `googlevideo.com` (media delivery)**

1. Same steps 1-3
2. `CompatibilityGuard.check()` → PROTECTED (streaming) → ALLOW
3. Direct upstream resolution → return media CDN IPs
4. Video plays without interruption

