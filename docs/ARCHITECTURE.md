# OmniShield X — Architecture (v5.1, World Monitor v2 + AETHER)

This document describes the shipped code. Every claim here is backed by a module in the
repository and by a test in `tests/`.

## 1. Deployment shape

OmniShield X is a **static, local-first web platform**. There is no backend, no account
system and no telemetry endpoint. It is deployed as plain files (GitHub Pages compatible):
ES modules, one HTML shell, one service worker.

```
index.html          page shell and navigation
ui/theme.css        shared responsive design system
app.js              application controller: boot, router, renderers, event wiring
engine.js           deterministic filter engine (the only component that blocks)
ui/dom.js           DOM helpers — textContent only, no HTML interpolation
ui/shell.js         keyboard commands, theme, browser history
world/              shared World Monitor v2; public sources, local storage, map, country views
dns/                encrypted resolution stack
aether/             threat intelligence and reputation scoring
security/           firewall AI, monitor, feeds, backup, privacy, sha256, storage
assets/             bundled rule feeds (GPLv3, HaGeZi) + curated supplements + icon
sw.js               offline caching (never caches DoH)
scripts/verify.mjs  static architecture + honesty-claim verification
tests/              unit + real-UI / packaged-Android-entry integration + static gates
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

### Redirect-chain audit (`dns/chain.js`)

`auditChain()` walks the resolver's CNAME links (bounded to 12), resolves each link's
registrable domain, and asks the filter engine and the reputation engine about every hop.
A link that leaves the queried site's registrable domain *and* is blocked or scores ≥ 45/100
is reported as CNAME cloaking, with the rule or score attached. The function returns
advisory data only — it has no `blocked` or `action` field, so it cannot enforce. The DNS lab
renders the chain as a table plus the evidence list, and always prints the scope line
("HTTP redirects are invisible to a DNS filter").

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
- The dashboard's **Measure filtering cost** control runs 5,000 real
  `engine.evaluate()` calls with `performance.now()` and reports p50/p05-in-µs
  latency and throughput measured on the user's device. The result is kept in
  state so the once-per-second repaint cannot erase it, and it is never a
  hard-coded benchmark.
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

## 9b. Browser extension (`extension/`, `scripts/build-extension.mjs`)

The ZIP served at `/omnishield-x-extension.zip` is a build artifact, not a hand-made
download:

- `extension/src/` holds the reviewed sources — `background.js` (counts from
  `onRuleMatchedDebug`, with an explicit "unsupported" path), `popup.html/js` (renders
  measured counts or `—` plus the reason), `content.js` (cosmetic CSS only), `icon.png`.
- `scripts/build-extension.mjs` extracts `||domain^` rules from the bundled feeds
  (curated supplement first, then the light list, in feed order), removes duplicates and
  anything on the system safety allowlist, caps the result at **30,000** static rules
  (Chrome's `GUARANTEED_MINIMUM_STATIC_RULES`), splits them into ruleset files, generates
  the MV3 manifest from `package.json`'s version, and writes a deterministic ZIP
  (fixed timestamps, sorted entries, no dependencies — the writer and reader are ~120
  lines of `zlib` + CRC-32 in the script).
- It also emits `assets/extension-facts.json`, which the Extension page fetches so the
  numbers shown in the UI come from the shipped archive rather than from copy.
- `npm run verify` re-reads the ZIP, checks the rule count is inside the limit, that all
  domains are unique, that the manifest is MV3 and matches the app version, and that the
  facts file has not drifted. `tests/unit/extension.test.mjs` tests the selection,
  capping, ZIP round-trip and manifest generation against synthetic feeds.

## 9c. Publishing (`scripts/stage-site.mjs`, `.github/workflows/deploy-website.yml`)

One artifact, two entry points. The workflow calls `node scripts/stage-site.mjs`, which
builds `_site/` deterministically:

- `_site/` ← `docs/` (the existing marketing site and APK links, unchanged),
- `_site/app/` ← the web platform (`index.html`, `app.js`, `engine.js`, `sw.js`, the
  `ui/`, `dns/`, `aether/`, `security/`, `assets/` trees, and the extension ZIP),
- anything development-only (`tests/`, `node_modules/`, `package.json`) is rejected if it
  appears in `/app/`,
- every entry in the service worker's precache list is checked against the staged tree, so a
  missing module fails the deploy instead of producing an app that cannot start offline.

The same script runs locally (`npm run stage`), and `tests/unit/stage.test.mjs` asserts that
the real repository stages and that a missing precache target is caught. The staged app was
also booted under a `/app/` base URL in a DOM harness: 79,739 rules load and the extension
facts fetch resolves.

## 10. Security posture of the app itself

- No `innerHTML`, no `eval`, no `document.write` anywhere in the UI (enforced by
  `scripts/verify.mjs` and an integration test that imports a hostile backup containing
  `<img onerror=…>` and asserts a literal-text DOM).
- All resolver requests use `credentials: 'omit'`, `referrerPolicy: 'no-referrer'`,
  `cache: 'no-store'`, and HTTPS-only endpoints.
- The service worker never intercepts or caches cross-origin DoH traffic.
- Imported configuration is treated as untrusted text and validated before use.

## World Monitor v2

The shared web/Android implementation, origin-restricted document/export integration, constrained
native daily job, country data licences, concurrency and cache limits are documented in
[WORLD_MONITOR_V2.md](WORLD_MONITOR_V2.md). Gradle copies the reviewed `world/` and its minimal UI/
asset dependencies into generated APK assets; there is no remote bootstrap or second untested UI.
The worker's fixed provider allowlist is generated by `scripts/sync-world-providers.mjs` and checked
in both web and Android CI. Country and source failures cannot affect the existing DNS/VPN engines.
