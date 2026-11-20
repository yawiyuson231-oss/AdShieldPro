# OMNISHIELD X — governed evolution system

Delivery date: 2026-11-20. This is an additive evolution of the existing application, not a rebuild. This guide is the current operational entry point; the audit and individual phase documents also preserve earlier checkpoints.

## What runs where

**Android application:** existing detectors, filters, DNS/VPN service, intelligence map, Room storage, workers and release updater are reused. New runtime changes are deliberately narrow:

1. Installed-app metadata audits adapt cooperative pacing to available RAM, battery, thermal state, app-process CPU usage and storage. Every visible app is still visited; protection has no resource-driven off switch.
2. A bounded, memory-only cache avoids repeating the deterministic risk calculation for an identical *complete freshly read* metadata profile. Permission/source/binding changes invalidate the key. Files are not skipped based on timestamps.
3. Opted-in scan scheduling is reconciled at application startup, not only dashboard creation. The explicit user toggle still schedules/cancels the same existing WorkManager job.
4. Existing bounded intelligence history records which saved security controls changed, without storing resolver addresses or package lists. It does not claim to have probed live routing.
5. Repeated completed app audits compare requested-permission/component-binding sets in a bounded process-local history. A changed count is recorded without package/permission details. These are declarations, not permission grants or observed behavior. Unseen/reinstalled/evicted apps establish an unknown baseline, not fabricated changes.
6. A real emulator-discovered startup race was fixed by moving ViewModel collector startup after all state-holder initializers. This changes initialization safety, not UI design or DNS decisions.

**Engineering workstation / CI:** `tools/evolution` evaluates candidates, stores public research/verified feedback, records cycles, validates data-module contracts and checks release evidence. It does not run downloaded code, silently replace Android executables, change filters/models, publish releases, or install packages.

## Phases and implementation map

| Phase | Implemented | Safety boundary |
|---|---|---|
| 1: Governance | Exact-ID baseline/candidate comparisons; per-category FP/FN gates; coverage checks; incorrect-classification IDs; unsuccessful-cycle priorities; transactional hash-chained cycle ledger | An unchanged or regressing candidate is not an improvement. VERIFY must retain the EXPERIMENT report; DEPLOY records explicit evidence-bound approval only. |
| 2: Adversarial evaluation | 26 harmless domain, phishing, APK-metadata, DNS and configuration fixtures; real Kotlin detector adapters; source/dataset-bound prediction artifacts | Synthetic intent labels are not confirmed malware. Public regression fixtures cannot satisfy independent-holdout release approval. |
| 3: Knowledge/research | Eight typed entities, source-complete immutable edges, confidence/status/timestamps, append-only source/license reviews, expiry/retraction handling, DISCOVER-only research proposals | No imported claim can verify itself. Research store is separate from Android Room and never changes protection. |
| 4: Verified feedback | Separate train/holdout/regression membership, exact-content leakage rejection, reviewed labels, conflicting-label exclusion, advisory distribution-shift checks, immutable model metadata and reviewed selection/rollback history | No automatic retraining, executable loading, or shipping model switch. Selection recomputes metrics, pins candidate model digest, and requires ≥20 reviewed examples per class in every category. |
| 5: Resilience/resources/trust | Runtime changes above; existing WorkManager/recovery/quarantine/backup mechanisms reused; SQLite integrity/version checks; transaction crash test; bounded caches/history | No new permissions, timers, wake locks or services. Essential DNS protection is untouched. Missing readings stay unknown. |
| 6: Engineering/extensibility | Fixed-command check/build plan; signer verification with independently pinned certificate; frozen boundary gate; isolated versioned JSON-only module contract with compatibility/privacy/performance/removal evidence | No arbitrary patch scripts, dynamic executable modules, installer, unreviewed permission expansion or automatic release publication. |

## Recursive governance

```text
DISCOVER  -> reviewed opportunity, source or observed failure
EXPERIMENT -> predictions + dataset/model/source identity + failures retained
VERIFY     -> unchanged experiment report + no measured slice regression
              + privacy/performance/regression/holdout/rollback/signing evidence
DEPLOY     -> named reviewer approval bound to the exact verified evidence
```

DEPLOY is an authorization record, **not** installation or publication. The existing production release workflow still requires reviewed `main`, its protected release environment and the approved Secure signing key. No production release was requested or published by this work.

Production also now fails closed unless the protected `android-secure-release` environment supplies
`ADSHIELD_EVOLUTION_APPROVAL_JSON`. This is an aggregate **non-secret approval record**, not signing
material or private holdout data. Its schema is `{schema: 1, source_commit, report, checks, approval}`.
Use a real independently reviewed holdout comparison for `report`, add `independent_holdout: true`
only after that review, and provide the strict boolean checks required by `gate`. The approval is
`{reviewer, evidence_sha256}`, with `evidence_sha256 = digest({source_commit, report, checks})`.
The gate binds the exact main source commit, validates aggregate/slice counts, requires matched
class counts and ≥20 examples per class/category, rejects per-category FP/FN regression and
requires a measured detection improvement. A public synthetic comparison, unchanged detection,
missing approval, mismatched commit or fabricated/inconsistent counts blocks signing. This is
intentionally conservative: the present reliability-only improvement does **not** justify inventing
a detection gain to unlock a release. Updating the protected environment record is an authorized
maintainer review step, not something the evolution engine performs. Environment access and main
review authenticate the attestation; the gate cannot independently prove supplied aggregate labels.
Existing signer pinning, Secure-key continuity and installation checks still run afterward.

Use a new cycle ID for a new experiment. A failure stays recorded at EXPERIMENT with its comparison reasons; use `priorities` to rank repeated failures and missing coverage rather than deleting unsuccessful cycles. The journal verifies SQLite integrity and its event chain on append. Pin/export the returned head separately; a local attacker replacing a whole database and its head is outside the hash-chain guarantee.

## Main commands

Run from the repository root:

```sh
# All available local checks. Writes a non-release verification report under ignored .cache/.
python3 -m tools.evolution.pipeline

# Print commands without executing; add --android on a configured Android build host.
python3 -m tools.evolution.pipeline --plan --android
python3 -m tools.evolution.pipeline --android

# Byte-for-byte DNS/VPN/manifest/UI boundary protection (109 files).
python3 -m tools.evolution.boundaries

# Safe fixture reproducibility and all evolution/delivery Python tests.
python3 -m tools.evolution.fixtures --check
python3 -m unittest discover -s tools/tests -v

# Raw prediction evaluation / real Android evidence validation.
python3 -m tools.evolution samples.json baseline.json candidate.json
python3 -m tools.evolution.artifacts validate .ci/evolution/current.json
python3 -m tools.evolution.artifacts compare /trusted/baseline.json .ci/evolution/current.json
```

The boundary manifest was generated from the original audited base commit `4fbc131ca4f4d0bd4e93eca2f73013e9cd867452`. It protects DNS/filter/service implementation, Android permissions/manifest, screens/components/themes/resources, primary Activity, and browser DNS/UI entry files. Added, removed or modified protected files fail the gate. It is enforced in Android, offline governance and production regression checks. Deliberately changing this baseline requires explicit source review; there is no automatic rebaselining command in CI.

A fixed check plan returning success is not an independently verified release. Android signing is false until a real APK has passed `apksigner verify` and the observed signer matches an independently supplied trusted certificate digest. Existing `tools/release_signing.sh` remains the production key-custody/signing implementation; `verify_apk_signer` is a reusable read-only candidate check, not another signer.

## Research collection

```sh
mkdir -p .cache/evolution
# Explicit API read, no credentials in command arguments:
python3 -m tools.evolution.research .cache/evolution/research.sqlite --fetch-github
# Or an offline saved response:
python3 -m tools.evolution.research .cache/evolution/research.sqlite --input /path/to/advisories.json
```

The collector reads at most the **latest 100 Maven GitHub advisories**, intersects exact coordinates with the existing Gradle version catalog, and stores only unverified references. Cross-ecosystem entries in a Maven-filtered advisory response are ignored, not misinterpreted. A package-name match is `related_to`, not proof that the installed dependency version is affected. Full version-range, transitive, Android OS, native library and historical advisory coverage is **not** claimed.

References carry `NOASSERTION` licensing and confidence 0.5; they cannot become eligible proposals without independent source/license/relevance review. Raw advisory descriptions, exploits and code are not imported. Withdrawn advisory IDs are surfaced for review, never made new proposals. Prior observations remain bounded by an 8-day TTL; this is not instantaneous withdrawal propagation.

`evolution-research.yml` supports manual collection and a weekly schedule **on the default branch only after review/merge**. It restores branch-isolated public research history and uploads a review artifact; it has read-only repository permissions and never commits intelligence to the app. GitHub cache eviction can lose CI history: export/archive important evidence independently. Local collection updates an existing local graph transactionally. Failures/capacity limits fail closed without deleting prior evidence.

The current live read examined 100 advisories and found zero exact catalog-coordinate matches in that bounded page. That is **not** evidence that dependencies or Android are vulnerability-free.

## Verified feedback and rollback

`LearningRegistry` stores only reviewed dataset and model-selection metadata. Typical sequence:

1. `add_sample(category, features, split)` assigns a content hash. The same exact features cannot occur in train and holdout (or in conflicting categories). This is exact-duplicate detection, not a semantic near-duplicate detector.
2. `submit_feedback(sample, boolean_label, source, rationale)` records a pending claim. Pending feedback is not included in verified datasets and cannot override a prior accepted label.
3. `review_feedback(..., accepted=True/False)` records the reviewer decision. Contradictory accepted labels exclude the sample until reviewers reject obsolete claims; arrival order never wins silently.
4. `dataset('holdout')` returns reviewed labeled examples with decision evidence. Reviewer identities and independence are local attestations, not an authenticated multi-user approval service.
5. `register_version(version, model_sha256, training_dataset_sha256)` pins immutable metadata. Training and model digests must come from the actual reviewed build process; this API does not train or load the model bytes.
6. `select(...)` requires gate approval, exact registered candidate hash, current reviewed holdout hash, recomputed baseline/candidate metrics from supplied predictions, independent-holdout attestation and class/category coverage. It records an engineering selection, not a runtime app change.
7. `rollback(reviewer, rationale)` records a return to a previously selected version. It cannot select an unapproved new version. Deployment, freshness/revocation review, and any app-model replacement remain a separate reviewed release.

`drift(reference_bins, observed_bins)` computes total-variation distance over the **same caller-defined bins** with a minimum count. Insufficient data returns unknown. A shift is a review recommendation, not proof of concept drift or permission to retrain/disable protection.

The store uses SQLite transactions/FKs/integrity checks and bounded record counts (50k samples, 100k feedback claims, 200k decisions, 10k versions, 50k selections). Keep it under ignored private `.cache/`, use restrictive filesystem permissions, and never commit private holdouts or personal telemetry.

## Resource and trust policy limits

- CPU readings are elapsed **app-process** CPU time normalized by available cores, not system-wide utilization. Unavailable RAM/battery/thermal readings use conservative bounded pacing.
- Audits yield after 4–16 apps with at most 50 ms cooperative delay per batch; no app is omitted because of resources. Cancellation remains honored.
- Metadata memoization holds at most 128 entries, or zero under memory/storage pressure. Every permission/binding/installer/profile is re-read before a cache lookup. No content scan is skipped merely because size/mtime stayed the same.
- The optional research-sync policy requires validated unmetered networking and healthy readings, but is **not wired to alter existing Android DNS/feed synchronization**. Existing workers retain their original network constraints.
- Permission baselines are process-local and capped at 512 apps. Eviction, process death, unavailable metadata and reinstallation reset comparison coverage. Historical change **events** use the existing bounded Room history, not a new private device inventory.
- Saved-setting changes and declaration changes do not verify active DNS routing, grant status, malware execution or network safety. Existing AETHER receipt/network/integrity readings retain their original platform limits. Android offers no unrestricted access to other apps' private data.
- No new process-survival guarantee: force-stop, Doze, OS restrictions, user opt-out and device policy can prevent background execution. Existing WorkManager jobs and boot recovery are reused, not bypassed.

## Secure future data modules

`validate_module(manifest, payload_bytes, measurements)` accepts only API v1 `knowledge_bundle` JSON with no permissions, a pinned SHA-256, compatible Android API floor and ≤4 MiB payload. It validates payload provenance in an isolated in-memory graph. Unknown fields, executable interfaces, duplicate JSON keys, remote entrypoints, permission requests or digest mismatches fail.

Compatibility/security/privacy/removal attestations must be strictly true. Supplied measured budgets must be finite and within 32 MiB peak RAM / 1000 ms wall time. These are explicit research parser budgets, **not automatically measured Android benchmarks**. The validator does not install a module, authenticate a benchmark or load code. Executable capability expansion still requires normal reviewed source changes and an APK release; retraction/removal must not delete historical evidence or affect DNS.

## Verification and operational gates

Local checks passed: 87 Python tests, 262 web JavaScript tests, 22 cloud API tests, 102 static verification checks, existing model reproducibility, UI performance gates, and all 109 frozen boundary hashes. Install the existing test dependencies first (`npm install` and `npm install --prefix cloud --omit=dev --ignore-scripts`); the fixed-command runner never silently installs tools.

Android CI is separately exercised on this branch, including debug/release builds (throwaway CI release key), JVM tests, lint, package verification and Android 10 emulator smoke tests. See the current run references and final result in `EVOLUTION_VALIDATION.md`; a throwaway CI signer is not a production signer.

**Remaining operational requirements, not hidden capabilities:** independent private real-world holdouts; wider-device/OS and low-memory/thermal/reboot fault tests; authenticated reviewers and externally pinned evidence; full dependency/native/OS advisory and license coverage; Android graph migration/privacy/retention review if that separate integration is desired; production key approval and reviewed release. These cannot be truthfully replaced by synthetic tests, a public-page advisory scan, a hash of caller-supplied metadata or an instruction to evolve autonomously.
