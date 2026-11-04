# Testing

Everything below runs locally with Node 22 and no network access.

```bash
npm install      # dev dependency: jsdom (integration DOM only)
npm test         # unit + integration suites
npm run verify   # static architecture + honesty gates
npm run serve    # http://localhost:8080 (needed: ES modules require HTTP)
```

## 1. Layers

| Layer | Location | What it proves |
|---|---|---|
| Unit | `tests/unit/*.test.mjs` | algorithms are correct in isolation, including negative cases |
| Integration | `tests/integration/ui.test.mjs` | the real `app.js` boots in a real DOM (jsdom), driven through real clicks |
| Static gates | `scripts/verify.mjs` | module graph, routing, precache, XSS sinks, claim policy, weights = 100, assets, manifest |

## 2. Coverage map (requirement → test)

| Requirement | Tests |
|---|---|
| Engine ladder, formats, wildcards, undo symmetry | `unit/engine.test.mjs` |
| Production feed does not break working services | `unit/engine.test.mjs` (21 must-work hosts, real feed) |
| DNS wire codec, hostile packets | `unit/codec.test.mjs` (hand-assembled packet + RFC vectors) |
| TTL / negative cache / single-flight / LRU | `unit/cache.test.mjs` |
| DoH JSON + wire, DoT codec, timeouts, breaker, fallback | `unit/dns-transport.test.mjs` |
| DNSSEC honest classification | `unit/dns-transport.test.mjs` |
| Full pipeline: filter-before-network, cache, dual-stack, error honesty | `unit/dns-client.test.mjs` |
| Lexical features, IDN/punycode, typosquat, corpus false positives | `unit/lexical.test.mjs` |
| Classifier determinism, holdout metrics, thresholds, serialization | `unit/classifier.test.mjs` |
| Reputation weights, floors, guardrails, feedback, state round-trip | `unit/reputation.test.mjs` |
| Firewall AI detectors (positive **and** negative), policy precedence | `unit/firewall.test.mjs` |
| Monitor counters, buckets, percentiles, bounded memory | `unit/monitor.test.mjs` |
| SHA-256, storage failures, feeds, backup/recovery, k-anonymity | `unit/infrastructure.test.mjs` |
| Whole app: boot, navigation, AETHER, false positives, DNS lab, feeds, snapshots, XSS, capability honesty | `integration/ui.test.mjs` |
| Architecture and claim policy | `scripts/verify.mjs` |

## 3. Non-obvious tests worth knowing about

- **XSS regression.** A backup file containing `<img src=x onerror=…>` is imported through the
  real file input; the test asserts no `img`/`script` node exists and the payload appears as
  literal text. This is the bug the previous version of `app.js` had.
- **Compatibility gate.** The real 79k-rule light feed is loaded and 21 "must work" hosts
  (video delivery, auth, payments, app stores, CDNs) are asserted unblocked.
- **Negative detector tests.** Beaconing must ignore jittered traffic; tunnelling must ignore
  normal CDN subdomains; rate anomaly must ignore steady traffic. A detector that only fires
  in positive tests is not tested.
- **Undo symmetry.** `addUserRule` / `removeUserRule` must restore the previous verdict.
  (This caught a real `||` short-circuit bug that left the suffix rule behind.)
- **Determinism.** Training twice with the same seed must produce identical metrics
  (timing fields excluded).
- **Honesty.** `verify.mjs` fails on fabricated claims and on any reappearance of the old
  hardcoded `367,000` statistic that was not measured in this deployment.

## 4. Current results

Run `npm test` and `npm run verify` for live numbers. At the time of writing:

- 153 unit tests, 16 integration tests — all passing.
- Static verification: 73 checks passing (module graph, routing, precache, XSS sinks, claim policy, weights = 100, assets, manifest, accessibility landmarks).
- Extension builder (`tests/unit/extension.test.mjs`): rule selection/dedup, safety-allowlist
  exclusion, static-rule cap, deterministic ZIP round-trip, manifest generation, and the
  repository archive being inside Chrome's guaranteed limit.
- Power governor (`tests/unit/power.test.mjs`): band thresholds, interval clamping, subscriber
  cleanup and the *unsupported* Battery Status API path (must degrade, not pretend).
- Classifier holdout (measured in `tests/unit/classifier.test.mjs`, three-way split): AUC ≈ 0.86,
  precision ≈ 0.986, specificity 0.898, recall ≈ 0.663 at threshold 0.96. The 0.9 specificity
  target is not reached out-of-sample and the UI reports that instead of the target.
- Base-rate precision (converted from recall/specificity): ≈ 0.06 at a 1% malicious base rate,
  ≈ 0.42 at 10%. This is why the model is weighted 7/100 and can never block.
- Engine throughput: > 2,000 evaluations/ms budget; the test asserts < 0.5 ms/op.

## 5. What the suite does not cover

- Real network behaviour against live resolvers (tests use a deterministic fetch mock).
- Real browser rendering/CSS (jsdom has no layout engine; charts degrade gracefully).
- Service-worker runtime semantics (only its file list is verified statically).
- Real-world feed drift (upstream content changes daily; the shrink guard is what protects you).
