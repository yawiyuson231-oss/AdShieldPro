# Test & certification guide

Everything in this project that can be verified without a physical device is verified
automatically by `.github/workflows/certify-release.yml`. That pipeline is the single gate:
if it is green, the release is published; if it is red, nothing ships.

## What runs, and where

| Layer | Command | Runs locally? | Runs in CI? |
| --- | --- | --- | --- |
| Kotlin / JVM unit tests (84 cases) | `./gradlew :app:testDebugUnitTest` | needs JDK 17 + Android SDK | yes |
| Web engine ladder vs. the real 79k-rule assets | `node website/engine.test.mjs` | yes | yes |
| PC agent DNS ladder / packet builders | `python3 pc-agent/omnishield_proxy.py --selftest` | yes | yes |
| Kotlin source balance check | `python3 tools/check_kotlin_syntax.py app/src` | yes | yes |
| JS syntax of the site + extension | `node --check <file>` | yes | yes |
| JSON validity (extension manifest, rule packs) | `python3 -c "import json; json.load(open(f))"` | yes | yes |

## The Kotlin suite

`app/src/test/java/com/adshield/pro/` holds 9 source files that compile into 11 test
classes — **84 test cases**, asserted by exact count in CI (not just "zero failures"),
so a suite that silently stops running fails the build.

| Suite | Covers |
| --- | --- |
| `AdShieldEngineTestSuite` | DNS wire format, sinkhole synthesis, UDP/TCP framing, filter precedence, blocklist parsing safety |
| `TitanShieldMaxEngineTestSuite` | 3.0 engines: Bloom filter, Game Turbo, battery analytics, deep clean, security scanners |
| `AetherInfinityTest` / `AetherThreatModelTest` / `AetherAgentUpgradeTest` | AETHER agent: threat scoring weights, DGA/lookalike/age fusion, self-audit false-positive radar, explainer text |
| `DnsFirewallCompatibilityTest` | resolver compatibility, protected-domain catalog, leak guard |
| `InAppAdDefenseTest` | in-app ad-skip decision engine and notification classifier |
| `PlatformSpecAcceptanceTest` | the "must-work" domain list and protection-mode acceptance |
| `UpdateAssetSelectionTest` | the self-updater never picks a debug or non-APK release asset |

Android-framework behaviour (`VpnService` tunnel, WebView, notifications, WorkManager,
Room migrations on a real upgrade path) still needs an on-device smoke test — see the
manual checklist in the release guide.

## Release certification

CI builds both APKs, unpacks each one and checks it actually contains `AndroidManifest.xml`,
a `classes*.dex` and `resources.arsc`, and that the release APK ships the bundled rule sets
(`assets/core_max_ads.txt`, `assets/core_max_threats.txt`). Only then is the signed release
published, once per version:

- tag `vX.Y.Z`, title `OmniShield X X.Y.Z — Certified Build`
- assets: `OmniShieldX-X.Y.Z-release.apk`, its `.sha256`, and `ci-release.keystore`
- publishing is **publish-once** — an existing tag is never overwritten, so a later
  docs-only commit cannot replace an already-certified APK. Bump `versionName` in
  `app/build.gradle.kts` and `RELEASE_TAG` in the workflow to ship new binaries.

The CI keystore is generated per build (`alias titan-shield`, store password
`titanshield30000`) and is attached to the release so later builds can upgrade-install over
an earlier one. Replace it with a real release key (via repository secrets) before
distributing to users.

## In-app updates

`GitHubReleaseClient` reads `BuildConfig.GITHUB_UPDATE_REPOSITORY`
(default `yawiyuson231-oss/AdShieldPro`, overridable with `-PgithubUpdateRepository` or the
`GITHUB_UPDATE_REPOSITORY` env var) and only accepts an asset that
`UpdateAssetSelection.isInstallableReleaseApk` approves: an `.apk` whose name does not
contain `debug`, from `https://github.com/**/releases/download/**`.

## Running the JVM suite when the build directory is redirected

`app/build.gradle.kts` moves `layout.buildDirectory` to
`$TMPDIR/adshield_pro_build/app` (a OneDrive file-locking workaround) and mirrors
`outputs`, `reports` and `test-results` back into `app/build/`. On CI `TMPDIR` is not
`/tmp`, which is why the certification step discovers JUnit XML by searching
`app/build/test-results`, `$TMPDIR`, `$RUNNER_TEMP`, `/tmp` and `$HOME` rather than
hard-coding a path.
