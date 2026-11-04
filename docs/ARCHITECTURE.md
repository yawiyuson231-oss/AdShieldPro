# OmniShield X — Architecture (v5.0.1, AETHER AI Evolution)

This document describes the shipped code. Every claim here is backed by a module in the
repository and by a test in `tests/`.

## 1. Deployment shape

OmniShield X is a **static, local-first web platform**. There is no backend, no account
system and no telemetry endpoint. It is deployed as plain files (GitHub Pages compatible):
ES modules, one HTML shell, one service worker.

```
index.html          page shell + design system (all pages, all controls)
app.js              application controller: boot, router, renderers, event wiring
engine.js           deterministic filter engine (the only component that blocks)
ui/dom.js           DOM helpers — textContent only, no innerHTML
dns/                encrypted resolution stack
aether/             threat intelligence and reputation scoring
security/           firewall AI, monitor, feeds, backup, privacy, sha256, storage
assets/             bundled rule feeds (GPLv3, HaGeZi) + curated supplements + icon
sw.js               offline caching (never caches DoH)
scripts/verify.mjs  static architecture + honesty-claim verification
tests/              unit (137) + integration (15) + static gates
```

## 2. Data flow of a single lookup

```
user input (URL / host / IP)
      │
      ▼
engine.normalizeDomain()  ── invalid ──────────────────────────► explicit "invalid" result
      │
      ▼
engine.evaluate()  ── blocked ─────────────────────────────────► BLOCK (no packet leaves)
      │                    reasons[] + matched rule + category
      ▼ allowed
DnsCache.get()  ── fresh ──► serve (cached: true)
      │                     └─ stale → serve now + background refresh
      ▼ miss
DnsCache.singleFlight()  ← N identical lookups collapse to 1 network request
      │
      ▼
ResolverPool.query()
      │   health-ordered resolver list (EWMA latency + circuit breaker)
      ├─ DohTransport (JSON, or RFC 8484 wire when the operator has no JSON endpoint)
      └─ on failure → next resolver → … → explicit error, never plaintext fallback
      ▼
assessDnssec()  (AD bit / RRSIG inspection; see docs/UNSUPPORTED.md §3)
      │
      ▼
DnsCache.set()  (positive TTL, or RFC 2308 negative TTL from SOA minimum)
      │
      ▼
onObservation → SecurityMonitor (metrics) → PrivateAnalytics (k-anonymous counts)
              → Aether.observe() (first-seen) → FirewallAI.observe() (behaviour)
```

The pipeline returns a report object containing, for every request: status, addresses,
TTL, resolver, transport, DNSSEC verdict, latency, and the ordered `pipeline[]` of the
steps that actually ran. The UI renders that object; it never invents fields.

## 3. Enforcement model

Three separate layers, deliberately not merged:

| Layer | Component | Can block? | Evidence |
|---|---|---|---|
| Deterministic rules | `engine.js` | **yes**, only on a real rule match | matched rule + feed + category |
| Advisory scoring | `aether/reputation.js` | no — `advisoryIsEnforced: false` | weighted signals, 0–100 |
| Behavioural analysis | `security/firewall-ai.js` | recommends; user policy decides | detectors + thresholds |

Safe defaults: reputation never blocks; the firewall only recommends a block when two
independent signals fire (or the user has an explicit deny policy), otherwise `monitor`.

## 4. Filter engine (`engine.js`)

Ladder, highest priority first (unchanged from v4, extended):

1. user allow (exact, suffix, wildcard)
2. user block (exact, suffix, wildcard)
3. system safety allowlist (captive portals, connectivity checks, bootstrap resolvers)
4. feed exceptions (`@@||domain^`)
5. feed block rules (exact, suffix, wildcard — category-tagged)

Implementation notes:
- Suffix walk is O(labels) per query; no list is ever scanned.
- Wildcards compile to anchored RegExp and are only consulted after the literal walk misses.
- A wildcard that could match everything (`*`, `*.*`) is rejected at load time.
- Verdicts are memoised in a bounded cache invalidated on any mutation.
- Formats: Adblock (`||d^`), hosts (`0.0.0.0 d`), plain domains, `!`/`#` comments, cosmetic
  rules are counted as invalid (not applicable to DNS).
- Every verdict carries `reasons[]`; the UI renders them verbatim.

Measured: 79,801 rules evaluate at well under the 0.5 ms/op budget asserted in
`tests/unit/engine.test.mjs`.

## 5. Encrypted resolution (`dns/`)

- `codec.js` — RFC 1035/6891 wire codec. Bounds-checked, compression-pointer loop guard,
  forward-pointer rejection, 16 record types. Validated against a hand-assembled packet
  and NIST-style vectors, not against its own encoder.
- `cache.js` — TTL LRU with RFC 2308 negative caching, stale-while-revalidate, single-flight.
- `resolvers.js` — 5 real public resolvers (Cloudflare, Google, Quad9, AdGuard, Mullvad) with
  quoted operator policies; DoH JSON + DoH wire transports; EWMA health + circuit breaker;
  `DotTransport` implements RFC 7858 framing and reports that browsers cannot use it.
- `dnssec.js` — reports `VALIDATED_UPSTREAM | SIGNED_UNVERIFIED | UNSIGNED | BOGUS_SUSPECTED |
  UNKNOWN`; never upgrades one to another; refuses to call SERVFAIL "bogus".
- `client.js` — orchestrates the pipeline and the counters used by the dashboard.

## 6. AETHER (`aether/`)

See `docs/AETHER.md` for the full methodology, weights and measured metrics.

## 7. Firewall AI (`security/firewall-ai.js`)

Five detectors over real observation streams: beaconing (coefficient of variation of
inter-arrival times), DNS tunnelling (label length, entropy, unique-subdomain ratio,
nesting), rate anomaly (EWMA baseline + z-score), fan-out (distinct registrable domains
per window), plus explicit per-app allow/deny policy. All thresholds live in
`DEFAULT_CONFIG` and are shown in the UI. Insufficient data returns `insufficient-data`,
never a guess.

## 8. Monitoring and analytics

- `monitor.js` — bounded ring buffer of events, minute buckets, per-domain counters,
  measured latency percentiles. Metrics are derived from recorded events only.
- `privacy.js` — salted SHA-256 bucket hashes, k-anonymity suppression (k = 10),
  date-bucket retention. No hostname is ever persisted or reported in clear.
- `power.js` — `PowerGovernor` derives the repaint cadence from the Battery Status API
  (1x charging/normal, 2x below 25 %, 4x below 10 %, clamped to 250 ms–60 s). It touches
  only the monitor timer — never a verdict, score or rule. When the API is missing (Safari,
  jsdom, some WebViews) it reports `supported: false` with the reason and keeps the default
  cadence. The monitor loop is the app's only `setInterval`; every other timer is a one-shot
  (model training, snapshot debounce, a single deferred feed check) and the loop does nothing
  in a hidden tab.

## 9. Integrity, recovery and updates

- `sha256.js` — FIPS 180-4 implementation verified against 5 NIST vectors.
- `feedmanager.js` — conditional GET (ETag / If-Modified-Since), structural validation,
  SHA-256 integrity, 40 % shrink guard, retained last-good copy, explicit failure reasons.
- `backup.js` — hashed immutable snapshots (ring of 4), write verification, schema
  migration v1→v3, newest-valid-first recovery that skips corrupt snapshots and reports
  what it skipped.

## 10. Security posture of the app itself

- No `innerHTML`, no `eval`, no `document.write` anywhere in the UI (enforced by
  `scripts/verify.mjs` and an integration test that imports a hostile backup containing
  `<img onerror=…>` and asserts a literal-text DOM).
- All resolver requests use `credentials: 'omit'`, `referrerPolicy: 'no-referrer'`,
  `cache: 'no-store'`, and HTTPS-only endpoints.
- The service worker never intercepts or caches cross-origin DoH traffic.
- Imported configuration is treated as untrusted text and validated before use.
