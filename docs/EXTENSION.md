# Chrome extension

The repository ships a Manifest V3 ad-blocking extension, `omnishield-x-extension.zip`, built from
the same bundled feeds as the Android app. It is local-only: static rules, no servers, no analytics.

## Building

```bash
npm install --no-audit --no-fund   # jsdom, used only by the test suite
npm test                           # extension builder and archive tests
npm run build:extension            # rewrite omnishield-x-extension.zip
npm run check:extension            # verify the checked-in archive without rebuilding
```

`npm run build:extension` is reproducible: entries are sorted, timestamps are fixed, so rebuilding
an unchanged tree produces a byte-identical archive. That is what makes the checked-in ZIP
reviewable — a diff means the rules or the sources actually changed.

## What goes into the archive

| Input | Role |
|---|---|
| `assets/core_supplement_ads.txt` | Curated supplement, read first |
| `assets/core_lite_ads.txt` | Main bundled list, read second |
| `extension/src/*` | Reviewed extension sources, copied verbatim |

Only `||domain^` rules are extracted. Anything on the app's system safety allowlist (captive
portals, connectivity checks, DoH endpoints — see `SAFETY_ALLOWLIST` in
`scripts/build-extension.mjs`) is dropped, so the extension cannot break network connectivity.
Rules are deduplicated, then split across ruleset files.

## Why the rule count is capped

Chrome only *guarantees* 30,000 static `declarativeNetRequest` rules per extension
(`GUARANTEED_MINIMUM_STATIC_RULES`). Anything above that is shared with every other installed
blocker, and on a crowded profile rulesets can silently fail to enable — which looks exactly like
"the extension does nothing". The builder therefore caps at `MAX_STATIC_RULES` (30,000) and splits
into 15,000-rule files, and both the tests and `--check` fail if the archive crosses the limit.

## Loading it locally

1. Unzip `omnishield-x-extension.zip` to a directory.
2. Open `chrome://extensions`, enable **Developer mode**.
3. **Load unpacked** and select the unzipped directory.

## Verifying a release archive

`npm run check:extension` inspects the checked-in ZIP without writing anything: manifest presence and
version, that every declared file exists, and that the static rule count is inside the limit.
