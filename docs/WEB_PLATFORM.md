# OmniShield X web platform — AETHER AI Evolution (v5.0.1)

> Part of the [AdShield Pro repository](../README.md). The Android app lives in
> [`app/`](../app); this document covers the browser platform that sits beside it.

A local-first DNS security, ad/tracker filtering and threat-intelligence platform that runs
entirely in your browser. No backend, no accounts, no telemetry endpoint. Deployed as static
files (GitHub Pages compatible); works offline once visited.

> **Honesty first.** This is DNS filtering plus explainable threat intelligence — not an
> antivirus, not a VPN, and not universal ad blocking. Every capability, including the ones
> that do **not** work here, is listed in [`UNSUPPORTED.md`](UNSUPPORTED.md) and in
> the app's **Capabilities** page.

## Quick start

```bash
npm install        # jsdom, used only by the integration tests
npm test           # 166 unit + 19 integration tests
npm run verify     # 86 static architecture, claim, artifact and packaging gates
npm run lint       # house lint rules for shipped runtime code
npm run stage      # assemble the deployable _site/ (site at /, app at /app/)
npm run serve      # http://localhost:8080  (ES modules require HTTP, not file://)
npm run build:extension  # regenerate omnishield-x-extension.zip + assets/extension-facts.json
```

## What this release adds

This is an **upgrade of the existing application**, not a rebuild. The v4 filter engine,
evaluation ladder, bundled feeds and Android policy format are preserved; every existing
page still works.

| Area | What is now real |
|---|---|
| **AETHER AI** | Reputation scoring with 11 published signals (weights sum to 100), evidence floors, popularity/allowlist guardrails, per-signal feedback adaptation |
| **Lexical model** | Multinomial Naive Bayes trained on-device from the bundled feeds, with holdout AUC/precision/recall/specificity shown in the UI |
| **Typosquatting** | Damerau–Levenshtein with transpositions, homoglyph folding, RFC 3492 punycode decoding, brand-in-subdomain and brand-affix detection |
| **DNS stack** | RFC 1035/6891 wire codec, DoH JSON + RFC 8484 wire transports, 5 real resolvers with health-based fallback and circuit breakers, TTL/negative cache with single-flight |
| **DNSSEC** | Honest five-state assessment (validated upstream / signed-unverified / unsigned / bogus-suspected / unknown) |
| **Firewall AI** | Beaconing, DNS tunnelling, rate-anomaly and fan-out detectors over real observation streams, with `monitor` as the safe default |
| **Monitoring** | Live dashboard built from measured events only — no synthetic traffic |
| **Feeds** | Conditional GET, structural validation, SHA-256 integrity, 40 % shrink guard, last-good retention |
| **Recovery** | Hashed snapshot ring, write verification, schema migration v1→v3, newest-valid-first auto-recovery |
| **Privacy** | k-anonymous local analytics (k = 10), salted hashes, retention limits, nothing uploaded |
| **Offline** | Service worker caches the shell and bundled rules; never caches DoH |

### Bugs fixed from v4

- **Broken test suite.** `engine.test.mjs` read `../app/src/main/assets/core_lite_ads.txt`,
  a path from the Android repository that does not exist here — so this deployment had zero
  effective test coverage. The suite now runs against `assets/`.
- **Stored XSS.** `app.js` rendered imported backup JSON and user input with `innerHTML`.
  The UI layer now uses `textContent` only; an integration test imports a hostile backup and
  asserts it renders as literal text.
- **Undo did not undo.** `removeUserRule` used `||` between two `Set.delete` calls, so the
  suffix entry survived and the domain stayed allowlisted.
- **Single-flight cache key.** `DnsCache.singleFlight` parsed the key as `name|type` while
  `DnsCache.key` builds `TYPE|name`, so results were stored under the wrong key.
- **Negative-TTL parsing.** The SOA minimum was only read from binary records, never from the
  text form that DoH JSON actually returns.
- **Misleading dashboard figures.** Rule counts copied from the Android APK were displayed for
  files not present in this deployment; numbers are now measured at runtime.

## Architecture at a glance

```
index.html  app.js  engine.js          shell, controller, deterministic filter ladder
dns/       codec · cache · resolvers · dnssec · client
aether/    reputation · classifier · typosquat · lexical · domain · data
security/  firewall-ai · monitor · feedmanager · backup · privacy · sha256 · storage
ui/dom.js  safe DOM construction (no innerHTML)
tests/     161 unit + 18 integration   scripts/verify.mjs  static gates
```

Full detail: [`ARCHITECTURE.md`](ARCHITECTURE.md) ·
AETHER methodology: [`AETHER.md`](AETHER.md) ·
Testing: [`WEB_TESTING.md`](WEB_TESTING.md).

## Enforcement model (important)

- **Only the deterministic engine blocks**, and only when a real rule matches
  (yours, a feed's, or a list exception). Every block shows the matched rule and category.
- **AETHER advises.** `advisoryIsEnforced` is always `false`; scores never cause a block.
- **Firewall AI recommends.** It requires two independent signals (or your explicit deny
  policy) before suggesting a block; the default is `monitor`.
- Every action is reversible: allow/block from the UI, and false-positive reports undo cleanly.

## Integrating with the Android core

The shared contract is unchanged: the same rule files, the same JSON backup schema.

1. In the Android app: *Settings → Configuration Backup* → export JSON.
2. Here: **Backup & Sync → Import** to audit/patch rules, then **Export merged config**.
3. Import the exported file back on any device. Custom rules, AETHER state (including model
   weights) and firewall policies travel in the same file; schema migrations handle v1/v2.

To feed real behavioural data into Firewall AI, export an observation log from the native
core as `[{ "domain": "...", "app": "...", "timestamp": 0 }]` and use
**Firewall AI → Import observation log**. Without that file the browser only analyses what it
performed itself — it cannot capture other apps' traffic (see `docs/UNSUPPORTED.md` §1).

## Data provenance

- Bundled rule feeds: **HaGeZi DNS blocklists**, GPLv3 (<https://github.com/hagezi/dns-blocklists>).
  The bundled light list contains 79,665 rules; its header states the upstream version and date.
- `assets/core_supplement_ads.txt` — **hand-curated by this project** (136 apex ad/tracker
  domains the light feed omits), with provenance and safety policy at the top of the file.
- `assets/core_supplement_aggressive.txt` — optional, ships **disabled**, because it can break sites.
- `aether/data.js` — curated popular-domain corpus, high-abuse TLD list and look-alike tables,
  each documented as reference data rather than detections.

## License

GPL-3.0-or-later (inherited from the bundled GPLv3 feeds).
