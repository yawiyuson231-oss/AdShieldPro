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

3. [Complete runtime/source run 44687547750](https://github.com/yawiyuson231-oss/AdShieldPro/actions/runs/44687547750), source `3846a315aaeeaa7740e41f3146f91718d343548d`:
   - **Whole Android workflow passed**, including **409 JVM tests**, all 4 Android 10 Agent tests, both APK builds, package/signature checks, detector evidence validation, lint, and the new 109-file frozen-boundary gate.
   - Includes declared-permission history, source-bound production approval workflow and bounded research/module/check tooling.
   - Web CI, offline evolution governance and website assembly checks also passed on this source. Website assembly on the working branch does not deploy a production website.

4. [Final engineering checkpoint 44689879657](https://github.com/yawiyuson231-oss/AdShieldPro/actions/runs/44689879657), source `c5a41f7e7c52b02ed7fa7e00f930f07c044ad6ab`:
   - **Whole Android workflow passed**, including 409 JVM tests, all 4 Android 10 Agent instrumentation tests, Kotlin compilation, debug/instrumentation and throwaway-key R8 release builds, package/signature checks, lint, detector evidence, emulator installation and the 109-file frozen-boundary gate.
   - Evolution governance (44689879680), web CI (44689879704) and website assembly (44689879687) also passed on this exact source.
   - Final engineering review hardened explicit confidence assessment (without rewriting imported evidence), streaming file hashes, and APK snapshot/certificate binding against a concurrently replaced build output. These changes preserve Android runtime/build input bytes relative to the prior passing checkpoint and are covered by 89 local Python tests.
   - Subsequent validation/audit documentation updates do not change tested executable inputs. No production release, public APK preview or main-branch merge was performed.

5. [Opt-in updater and public test APK run 44700560932](https://github.com/yawiyuson231-oss/AdShieldPro/actions/runs/44700560932), source `6df673e0c4057bbb8a71ff40939854b08594799e`:
   - **Whole Android workflow passed**, including **427 JVM tests** (source declaration count and CI exact-count/no-skip assertion), lint, debug/instrumentation and throwaway-key R8 release builds, signatures/packages and detector evidence.
   - **All six Android 10 instrumentation cases passed**: four existing Agent cases plus consent/default-off and private-filesystem activation/rollback checks. This is not a live publisher/CDN, broad device-matrix or production-signing certification.
   - Push-triggered Android run 44700552068 also passed; evolution governance 44700552024, web CI 44700552026 and website assembly 44700552133 passed on the same source.
   - The original 109 boundary hashes stay pinned. Only the exact disclosed additive consent-card insertion is normalized out of SettingsScreen; tests reject modified/duplicated insertions. DNS/filter/service/manifest bytes are unchanged.
   - Explicitly requested [public debug test APK](https://github.com/yawiyuson231-oss/AdShieldPro/releases/tag/preview-v2.11.1-run.44700560932.1) was published, separate from production and not Latest. APK SHA-256: `761ab06466f21cfcbe6e043552f995f63329c7077579d92eaa5b49aadb7e75ff`.
   - Protected publisher-environment provisioning was attempted but denied by GitHub HTTP 403 `Resource not accessible by integration`. No production key, secret, publisher environment, real indicator feed, main merge or production APK release was created. Advisory updates remain unavailable until secure publisher configuration and reviewed data are provided.
   - Downloading full Actions logs locally returned EOF; workflow step conclusions, source test-count gate and published release provenance were available. Historical `.ci` files are not substituted as logs for this run.

## Actual detection evidence

The first Android run exported real predictions for the 26 synthetic fixtures. Artifact arithmetic: **TP=14, FN=1, FP=0, TN=11**. The missed case was `phishing:generic-lure`. This remains a visible blind spot; its label was not changed and no heuristic/blocking threshold was adjusted merely to improve the score.

These public fixtures are development regressions, not a private holdout or evidence of real-world protection. Comparing the same artifact to itself is rejected as no measured improvement. Changes in this delivery are primarily governance, coverage and reliability improvements; no increase in shipping detection accuracy is claimed.

## Local checks

Latest local checks passed: 96 Python evolution/delivery tests, fixture reproducibility, the 109-file original-boundary gate with the exact disclosed consent insertion exception, bundled AETHER model reproducibility, UI-performance source gates, `npm run ci` (262 web JS tests and 102 static verification checks), and 22 cloud API tests. The aggregate fixed-command runner covers these checks; no tool/dependency installation, publication or APK installation is performed by that runner.

The Phase 3 process-crash test deliberately exits a subprocess during an uncommitted SQLite transaction, then verifies original graph rows and integrity. This is a real SQLite transaction-recovery check, not an Android crash/reboot certification.

## Research read

An explicit authenticated public GitHub API read examined the latest 100 Maven advisories, with cross-ecosystem entries safely filtered. Zero exact Gradle-catalog coordinate matches were found in that bounded page. Withdrawn advisory IDs were surfaced for review. No claims of exhaustive dependency/OS/native coverage or absence of vulnerabilities follow from this result. Raw responses/database/report remain under ignored `.cache/`.

## Remaining release/device gates

- No independently verified private holdout or source-bound production evolution approval has been supplied. Production release now additionally requires `ADSHIELD_EVOLUTION_APPROVAL_JSON` in the protected release environment; absence blocks release before signing.
- No production signing credentials were requested, created, changed or published. CI's throwaway signer must never be used for production.
- No device-matrix, thermal/battery/performance benchmark, full reboot/Doze/force-stop recovery certification, unrestricted Android integrity guarantee or full dependency/native/OS advisory assurance is claimed.
- Reviewer/source/license independence and aggregate evidence correctness remain human trust boundaries. Authentication/key custody and final release approval are not replaced by a local metadata hash.
