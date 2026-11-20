# Evolution audit and phased delivery

Audit date: 2026-11-20. Base: `4fbc131ca4f4d0bd4e93eca2f73013e9cd867452`.

This document preserves the initial audit findings. For current implemented scope and subsequent real Android CI/research results, see [the system guide](EVOLUTION_SYSTEM.md) and [validation record](EVOLUTION_VALIDATION.md).

## Scope and assurance

Repository-wide architecture/build/test inventory and targeted security-boundary source review, not a line-by-line review of all code or a penetration-test certification. The Android application has 215 Kotlin production files, plus generated TDLib Java bindings; the repository also contains a static web app, browser extension, and Cloudflare API. No Android runtime, JDK, emulator, APK-signing tool or Google Maven access was available in this environment. Checked-in `.ci` logs are historical evidence, not results of this audit. No new advisory feed was fetched and no claim of current global threat coverage is made.

## Existing capabilities to reuse, not duplicate

| Area | Evidence and current boundary | Evolution action |
|---|---|---|
| Android DNS | `engine/dns`, `engine/filter`, `service/AdShieldVpnService`; manifest already declares a local DNS VPN service | Freeze behavior. No new VPN, resolver, routing or filtering changes. Use offline adapters in a later phase. |
| Detection | `engine/security/{ApkAnalyzer,AppRiskAuditor,FileThreatScanner,UrlThreatScanner,SecurityEngine}` and `engine/aether/DomainRiskAnalyzer` | Reuse detectors. Heuristics and APK metadata are not proof of malware. |
| Learning | `AetherTaskModel`, `tools/train_aether_tasks.py`, train/holdout TSVs; web `aether/classifier.js` already calculates holdout metrics | Add versioned independent evaluation, not a second classifier. Lexical classification does not inspect page content. |
| Intelligence | `IntelligenceModels`, event sanitization/aggregation, Room `IntelligenceEventEntity`, connector indicators | Existing live map is not a provenance-complete knowledge graph. Extend this vocabulary and Room migrations later. |
| Persistence | `AdShieldDatabase` version 6, explicit migrations, bounded `ScanJournal` | Existing history is not a tamper-evident evolution ledger. Keep engineering evidence separate from private device scan history. |
| Recovery | WorkManager scheduled scans, filter updates, connector sync, boot receiver, quarantine verification | Test actual recovery on a device before changing scheduling or claiming resilience. |
| Resources | Battery telemetry/repository, optimizer, worker constraints | Reuse measured telemetry. Never suspend essential protection to improve benchmarks. |
| Trust | AETHER security review/phone agent and platform capability registry | Missing readings must remain unknown, not interpreted as secure. Use historical snapshots later. |
| Delivery | Android CI compiles/tests/lints/builds; release config requires signing credentials; public signer audit and delivery tooling exist | Reuse signing checks. An engineering approval record must not install an APK. |
| Web/cloud/extension | Separate JS runtime and tests, cloud API tests, extension build gates | Preserve interfaces and UI. They are separate trust boundaries, not Android device capabilities. |

## Findings and priorities

1. **High — missing cross-cycle governance.** Existing tests and model metrics do not together enforce DISCOVER → EXPERIMENT → VERIFY → DEPLOY with matched evidence. Phase 1 adds an offline journal and conservative comparison gate.
2. **High — evaluation can hide regressions.** Aggregate gains may conceal worse APK, phishing or false-positive performance. Phase 1 rejects any per-category FP/FN increase and refuses missing positive/negative coverage or unchanged performance.
3. **High — no independently demonstrated runtime resilience for this change.** JVM/device tests, database migration fault injection, reboot/background recovery, thermal and low-memory tests remain required before app integration.
4. **Medium — provenance graph gap.** Events/indicators are useful foundations, but not all required relationships carry source, observation timestamp, confidence and verification status. Plan a migration, retention policy and source-license registry; do not relabel existing events as verified knowledge.
5. **Medium — research trust and licensing gap.** Public findings must remain proposals until source provenance, license, relevance and human review are recorded. No autonomous download/execution of research samples.
6. **Medium — audit-chain trust limits.** Hash chains detect edits, not an attacker replacing the entire database and its head. Export heads to separately controlled CI artifacts; stronger signing/key custody is a later requirement.
7. **Medium — release evidence trust.** Phase 1 accepts reviewer attestations. They are not cryptographic proofs of testing/signing and must not be wired to unattended release publication.

8. **Medium — negative-control coverage needs expansion before detection changes.** Source review of `DomainRiskAnalyzer` finds substring brand matching that includes the one-character brand `x`; this can overstate lexical suspicion for ordinary hostnames. This is a code-review risk, not a measured shipping false-positive rate. The detector participates in DNS assessment, so its behavior was deliberately not patched under the DNS-freeze requirement. Add independently labeled benign short-brand/IDN cases before any future detection promotion.

These are architecture gaps/review findings, not verified exploitable vulnerabilities. The initial audit did not claim runtime fixes; the later emulator-discovered initialization race and its verified repair are recorded separately in the validation guide.

## Phase 1 — implemented: offline evolution governance

`tools/evolution/core.py` provides matched dataset/prediction comparison, hashes of evaluated inputs, confusion matrices, category metrics, blind-spot reasons, failed-cycle priorities, strict boolean labels and predictions, and rejection of unverified/unsourced labels. Evaluation does not train a model or change protection.

`Journal` uses SQLite transactions, integrity checks, monotonic stages and a SHA-256 event chain. It records evidence and UTC timestamps per transition. VERIFY requires detection improvement plus strict positive attestations for regressions, unchanged DNS/UI, privacy, performance, dependencies, signing, rollback and independent holdout. DEPLOY requires reviewer approval bound to the exact verified evidence. **DEPLOY records authorization only; it never publishes or installs software.** Rejected candidates remain EXPERIMENT records containing the comparison reasons; the caller must record an experiment before attempting VERIFY.

Usage:

```sh
python3 -m unittest discover -s tools/tests -v
python3 -m tools.evolution samples.json baseline.json candidate.json
```

CLI exit codes: 0 eligible for further review, 1 unsuccessful/insufficient comparison, 2 invalid input. Eligibility alone is never deployment approval.

Samples are JSON objects with `id`, `category`, boolean `malicious`, nonempty `source`, and `verification: "verified"`. Categories: `domain`, `phishing`, `apk_metadata`, `dns_filter`, `configuration`. Baseline and candidate files map exactly those sample IDs to boolean detections. Use reserved `.test` domains and metadata-only APK fixtures; never query malicious infrastructure, generate working malware or install samples. The `malicious` label on configuration cases means an intentionally unsafe test configuration, not executable malware.

Keep datasets independent of training and version sources/licenses externally. The engine validates the supplied verification label; it cannot establish ground truth or independent provenance itself. It cannot verify that a prediction came from a claimed executable. A trusted adapter, immutable build identity, authenticated reviewers, minimum real holdout sizes and statistical uncertainty are prerequisites for production use. Current category gates are intentionally conservative and do not constitute drift detection.

Journal databases must stay outside version control, hold no user telemetry, and use restrictive host filesystem access. Call `verify(expected_tip)` with a separately stored head to detect truncation. Use a new cycle ID for each retry after verification; rollback requires a new evaluated/approved cycle rather than rewriting historical events. Close the journal after use. No scheduler, network requests, runtime plugin loader or silent executable update is introduced.

## Remaining independently gated phases

| Phase | Scope | Required evidence before integration |
|---|---|---|
| 2 | Isolated JVM adapters and 26 safe domain/URL/APK-metadata/config fixtures implemented; see [Phase 2 status](EVOLUTION_PHASE_2.md). Android execution passed; independent holdouts pending. | Real detector predictions, hashes of model/build and dataset; negative controls; DNS golden regressions; demonstrated category improvement. No fabricated performance gains. |
| 3 | Offline provenance graph and reviewed research proposal intake implemented; see [Phase 3 status](EVOLUTION_PHASE_3.md). Bounded public Maven advisory collection added later; Android graph integration remains pending. | Source/timestamp/confidence/status on every edge; license/source reliability review; TTL/capacity limits; Room migration and device retention tests remain required; no unverified indicators promoted to protection. |
| 4 | Reviewed feedback, exact train/holdout separation, advisory distribution-shift checks, versioned model metadata and rollback history implemented | Private independent holdouts, authenticated reviewers and source/model authenticity still require external evidence; no shipping model switch. |
| 5 | Bounded Android audit pacing/cache, startup recovery fix, saved-control and declared-permission change observations implemented; SQLite crash rollback tested | Wider-device corruption/reboot/Doze/thermal/performance testing remains required. Essential DNS protection and all frozen boundaries remain unchanged. |
| 6 | Fixed check/build pipeline, read-only pinned-signer verifier, JSON-only data-module contract, source-bound production approval and frozen-boundary gates implemented | No dynamic code loading. Production remains blocked pending real independent evidence, protected-environment approval and signer custody. |

## Measured validation in this workspace

- `npm run ci`: passed; 262 JS unit/integration tests, 102 static verification checks, existing house lint passed.
- `python3 -m unittest discover -s tools/tests -v`: passed, 57 tests through the Phase 3 checkpoint (11 Phase 1 evolution tests, 10 fixture/artifact tests, 17 knowledge/research tests, and 19 existing delivery-tool tests).
- Evolution tests demonstrate synthetic confusion-matrix improvement (one missed positive → zero) and rejection of unchanged models, hidden category regressions, false positives, incomplete/unverified evidence, invalid stage transitions, altered deployment evidence, journal edits and truncation with a pinned head. **This is gate validation, not a measured improvement in the shipping detectors.**
- At the initial local audit checkpoint, Android compilation/lint/JVM/instrumentation/signing tests were unavailable. Subsequent branch Android CI has executed them; see [current validation](EVOLUTION_VALIDATION.md). Production signing and wider-device performance remain unverified.
