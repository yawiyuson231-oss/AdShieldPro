# Evolution validation record

Updated 2026-11-20. Results are tied to source revisions; historical `.ci` mirrors must not be mistaken for current evidence after code changes.

## Actual Android runs

1. [Initial evolution run 44684842957](https://github.com/yawiyuson231-oss/AdShieldPro/actions/runs/44684842957), source `bcfca975d0243067a5fd7dfaa7c434c4b2c93648`:
   - Kotlin compilation, debug/instrumentation APK assembly, debug identity/signature/packaging checks, throwaway-key release build, release package checks, **399 JVM tests**, detector evidence validation and Android lint passed.
   - Debug APK installed and launched on Android 10 / API 29 / x86_64.
   - Existing Agent instrumentation: **3 of 4 passed**. One exposed a startup `NullPointerException`: a Room-flow collector accessed `_malwareBlocks` before that state holder was initialized.
   - The existing failure-mirror workflow recorded logs/JUnit/evidence in `.ci` at `ff16d0e4d561df91161e427425cef28c0fefa569`.

2. [Recovery/resource run 44685462668](https://github.com/yawiyuson231-oss/AdShieldPro/actions/runs/44685462668), source `f889fc58c2f555bc5020311540b8064c35a30282`:
   - **Whole Android workflow passed**, including Kotlin compilation, debug/instrumentation APK builds, debug signer/identity/universal packaging, throwaway-key R8 release build, release package verification, JVM tests, fresh detector evidence validation, lint, expected-test-count checks, emulator installation and **all 4 Agent instrumentation tests**.
   - Source contains 407 JVM test declarations, and CI's exact-count/no-skip gate passed.
   - Collector startup now occurs after all ViewModel state-holder initializers. Resource pacing/cache and headless schedule-reconciliation changes were included in this passing source.
   - No public preview or production release was requested. Reports/debug APK are Actions artifacts; they are not signed production releases.

Additional permission-history and final engineering/research/release gates are being validated in the next source checkpoint; do not attribute unrun changes to the earlier successful workflow.

## Actual detection evidence

The first Android run exported real predictions for the 26 synthetic fixtures. Artifact arithmetic: **TP=14, FN=1, FP=0, TN=11**. The missed case was `phishing:generic-lure`. This remains a visible blind spot; its label was not changed and no heuristic/blocking threshold was adjusted merely to improve the score.

These public fixtures are development regressions, not a private holdout or evidence of real-world protection. Comparing the same artifact to itself is rejected as no measured improvement. Changes in this delivery are primarily governance, coverage and reliability improvements; no increase in shipping detection accuracy is claimed.

## Local checks

Local checks passed: 87 Python evolution/delivery tests, fixture reproducibility, the 109-file frozen DNS/VPN/manifest/UI gate, bundled AETHER model reproducibility, UI-performance source gates, `npm run ci` (262 web JS tests and 102 static verification checks), and 22 cloud API tests. The aggregate fixed-command runner covers these checks; no tool/dependency installation, publication or APK installation is performed by that runner.

The Phase 3 process-crash test deliberately exits a subprocess during an uncommitted SQLite transaction, then verifies original graph rows and integrity. This is a real SQLite transaction-recovery check, not an Android crash/reboot certification.

## Research read

An explicit authenticated public GitHub API read examined the latest 100 Maven advisories, with cross-ecosystem entries safely filtered. Zero exact Gradle-catalog coordinate matches were found in that bounded page. Withdrawn advisory IDs were surfaced for review. No claims of exhaustive dependency/OS/native coverage or absence of vulnerabilities follow from this result. Raw responses/database/report remain under ignored `.cache/`.

## Remaining release/device gates

- No independently verified private holdout or source-bound production evolution approval has been supplied. Production release now additionally requires `ADSHIELD_EVOLUTION_APPROVAL_JSON` in the protected release environment; absence blocks release before signing.
- No production signing credentials were requested, created, changed or published. CI's throwaway signer must never be used for production.
- No device-matrix, thermal/battery/performance benchmark, full reboot/Doze/force-stop recovery certification, unrestricted Android integrity guarantee or full dependency/native/OS advisory assurance is claimed.
- Reviewer/source/license independence and aggregate evidence correctness remain human trust boundaries. Authentication/key custody and final release approval are not replaced by a local metadata hash.
