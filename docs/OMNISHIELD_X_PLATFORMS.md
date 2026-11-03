# OmniShield X — Two Platforms, One Core

## Architecture (honest, as-built)

```
                ┌──────────────────────────────┐
                │   SHARED INTELLIGENCE CORE   │
                │  • Bundled rule feeds        │
                │    (HaGeZi ADS + TIF, GPLv3) │
                │  • Filter ladder spec        │
                │    (allow→block→safety→lists)│
                │  • Config JSON schema v2     │
                │  • AETHER decision heuristics│
                └──────────┬─────────┬─────────┘
                           │         │
        ┌──────────────────┴─┐     ┌─┴───────────────────┐
        │  ANDROID APP (APK) │     │  WEB PLATFORM       │
        │  · DNS VPN firewall│     │  · Domain Checker   │
        │  · Security Center │     │  · Policy Sync UI   │
        │  · In-app ad skip  │     │  · Extension distro │
        │  · Browser engine  │     │  · Docs/dashboard   │
        │  Independent build │     │  Independent deploy │
        └────────────────────┘     └─────────────────────┘
```

- **Android app** (`app/`): Kotlin/Compose. Builds independently; never depends on the website.
- **Web platform** (`website/`): static site (GitHub Pages). Ports the filter engine 1:1 to
  JavaScript (`website/engine.js`) and runs it in CI (`website/engine.test.mjs`) against the
  **same rule files** the APK bundles.
- **Browser extension** (`extension/`): Manifest V3, 50,000 declarativeNetRequest block rules
  generated **from the same bundled feed** by `tools/generate_extension_rules.py`, cosmetic
  selectors shared with the app's browser engine.
- **Sync**: file-based, using the app's existing backup JSON schema
  (`FullConfigurationBackup`: version, protectionMode, customRules, browserSiteExceptions,
  excludedAppPackages). Export on Android → import on the web → export → import anywhere.

## Honest status of the "unified backend"

There is **no cloud backend yet** — no servers, no accounts, no central database. Rather than
fake one, the platforms share the core **offline**: identical rule assets, an identical
evaluation ladder enforced by tests on both platforms, and a common configuration schema.
The website states this on its Account & Security page. When a backend is later deployed
(auth, device registry, signed rule distribution), both clients already speak the same
schema and the site's sync page is the natural place to add account login.
