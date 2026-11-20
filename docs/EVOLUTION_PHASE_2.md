# Phase 2 — isolated detector evaluation harness

Status: the adapter has now compiled and executed in Android CI; source-bound evidence validation passed. See the current [validation record](EVOLUTION_VALIDATION.md) and [system guide](EVOLUTION_SYSTEM.md). This phase does not claim improved shipping detection accuracy. Phase 2 itself did not modify production Kotlin, UI, DNS routing or resolver code; later bounded runtime changes are documented separately.

## What was added

- `tools/evolution/fixtures.py`: reproducible corpus generator, with a `--check` gate.
- `tools/evolution/fixtures/synthetic-v1.json`: 26 metadata/string-only fixtures across all five Phase 1 categories. Every category includes positive and negative cases. Each fixture records source, timestamp, license, synthetic label scope and rationale.
- `EvolutionDetectorEvidenceTest.kt`: test-only adapters calling the real Android `DomainRiskAnalyzer`, `AppRiskAuditor`, `FilterRuleEngine`, and `AetherDnsPolicyReview` implementations. No parallel detector implementation.
- `tools/evolution/artifacts.py`: strict evidence validation and matched baseline/candidate comparison, including incorrect-classification IDs.
- Android CI validation and report artifact retention, plus reproducibility checks in offline governance CI.

## Isolation and safety

Inputs are `.test` hostnames, reserved-host URLs, synthetic app metadata and in-memory saved policies. There are no APK binaries, malicious infrastructure lookups, sockets, APK installations or changes to device settings. Each DNS fixture constructs a fresh, in-memory engine with a tiny synthetic blocklist, never the production DNS service. User allow precedence and suffix-boundary behavior are asserted as golden regressions.

APK adapter results mean **elevated metadata risk**, not confirmed malware. Permissions are requested/declarations only, never assumed grants or observed behavior. Configuration positives mean a deliberately saved coverage gap, not a compromised device. Domain/phishing positives are synthetic risk expectations, not ground-truth real malware labels. The `verification` field verifies fixture intent only.

The domain/phishing score threshold of 25 is an immutable v1 **evaluation adapter policy**, not a production blocking threshold. Known challenging examples (punycode alone and generic credential lures) intentionally probe possible false negatives. The test does not demand perfect classification or silently relabel failures as clean. Prediction inference receives only category and input; labels are not passed to detectors.

## Evidence contract

The JUnit test exports `.ci/evolution/current.json` only after execution and its golden assertions pass. It contains:

- schema, adapter identity, public-synthetic scope and timezone-aware creation timestamp;
- SHA-256 of exact dataset bytes;
- a source manifest covering all production Kotlin files, the adapter test and selected Gradle configuration;
- one strictly boolean prediction per sample ID.

Validation requires the current manifest to exactly match the working tree inventory and hashes. Baseline manifests may differ, but baseline and candidate must use exactly the same dataset bytes and adapter test bytes. An adapter change requires a fresh baseline. Unexpected IDs, missing predictions, duplicate JSON keys, nonfinite values, invalid hashes and traversal-style manifest paths are rejected. Artifact paths are never executed or used as arbitrary source-file read instructions.

**Trust boundary:** hashes bind supplied bytes; they do not prove who executed a build, authenticate a baseline, verify dependency binaries, or establish label correctness. The source manifest is not a full reproducible-build attestation (generated sources, native runtime, dependency binaries and toolchain are not covered). Retain artifacts from a trusted CI run and independently pin their hashes before comparisons. Signing, holdout review, device regression and release approval remain separate gates.

## Running

From the repository root:

```sh
python3 -m tools.evolution.fixtures --check
python3 -m unittest discover -s tools/tests -v

# Requires JDK and Android SDK / Gradle dependencies:
./gradlew :app:testDebugUnitTest --tests com.adshield.pro.EvolutionDetectorEvidenceTest
python3 -m tools.evolution.artifacts validate .ci/evolution/current.json
```

To compare a retained, trusted baseline with a subsequent run on the same corpus and adapter:

```sh
python3 -m tools.evolution.artifacts compare /trusted/baseline.json .ci/evolution/current.json
```

`validate` exits 0 for a structurally/source-consistent artifact, 2 for invalid evidence. `compare` exits 0 for measured regression-suite improvement, 1 for no improvement/regression/insufficient coverage, 2 for invalid evidence. An unchanged model is **not** an improvement; comparing an artifact with itself must exit 1.

Comparison output includes per-category and aggregate confusion matrices, incorrect-classification IDs, dataset/prediction hashes, and artifact/source-manifest digests. It always sets `independent_holdout: false` and `release_eligible: false`. Phase 1 governance rejects that explicit non-holdout status even if a caller supplies positive review attestations. Do not promote these fixtures into a private holdout or use them for model training.

## Validation actually performed

- 40 Python tests passed, including 10 new fixture/artifact tests: reproducibility, category/negative coverage, safe inputs, source and dataset mutation, changed adapter, invalid schemas/paths, duplicate keys, CLI exit codes, and synthetic-result release rejection.
- Existing web validation rerun: 262 JS tests, 102 verification checks and lint passed.
- `git diff --check` passed.
- New Kotlin test, Android build/lint, detector output and device behavior: **not executed in this workspace** because Java/Android tooling is unavailable. Python artifact tests use explicitly fake artifacts to test the contract; they are not represented as Android detector results.

## Next acceptance gate

Run Android CI successfully, inspect real misclassification evidence, and retain that run as a reviewed baseline. Then create independently reviewed, versioned holdouts and fault-injection/device regressions before proposing any detection change. No thresholds, labels or filters should be adjusted merely to make the public regression corpus score higher.
