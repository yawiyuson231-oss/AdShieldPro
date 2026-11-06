# Video-ad blocking and the playback guarantee

Pure APK. There is no WebView, no in-app browser and no browser extension in this path: blocking
happens in the native `VpnService` → `FilterRuleEngine`, which sees every DNS question from every
app on the device. That is why a video ad blocked here is also blocked inside the YouTube app,
Chrome, TikTok and a podcast player.

## What is blocked

Third-party video-ad infrastructure, by hostname:

| Layer | Examples | Effect |
|---|---|---|
| VAST / VPAID / OpenRTB ad servers | `pubads.g.doubleclick.net`, `securepubads.g.doubleclick.net`, `cdn.adsafeprotected.com`, `ads.pubmatic.com` | The player's ad call never resolves, so the pre-roll has nothing to fetch. |
| Video-ad SDK APIs | `imasdk.googleapis.com`, `www.googletagservices.com`, `s0.2mdn.net` | IMA / GPT ad requests fail; the player falls back to the video. |
| SSAI / stitcher vendor APIs | `ssai.google.com`, `api.ssai.yospace.com`, `ssai.bcovlive.io` | The vendor's ad-decision API is unreachable. |
| Ad verification beacons | `doubleverify.com`, `adsafeprotected.com`, `imrworldwide.com`, `scorecardresearch.com` | Viewability/attention pings are dropped. |
| Ad exchanges / SSPs | `adnxs.com`, `rubiconproject.com`, `openx.net`, `spotx.tv`, `springserve.com` | Bid requests die before an ad is chosen. |

Two rule sets apply: the bundled `video_ad_network.txt` (71 curated host rules, hand-reviewed, not
an upstream feed) and the HaGeZi Multi Pro layer in `core_max_ads.txt`, which already covers the
DoubleClick family. On a low-RAM device the Pro layer is swapped for LITE, which covers less of the
DoubleClick family — the curated layer is what closes that gap.

## What cannot be blocked, stated plainly

**Ads stitched into the video itself** — YouTube, TikTok, Facebook/Instagram Reels, and any
server-side ad insertion (SSAI). The ad and the video arrive in the *same* stream. DNS resolves a
hostname and gets bytes back; it cannot pick a frame out of that stream. The only way to remove these
is to block the video, which is exactly what the product refuses to do.

No DNS blocker, VPN, or system-wide app removes them. Tools that appear to do so either patch the
client app (a YouTube-specific mod, not a blocker) or intercept TLS to rewrite the manifest (breaks
the app's trust model, and AdShield deliberately does not do TLS interception). **If a product claims
otherwise, it is not telling the truth.**

## How "video must not break" is enforced, not just promised

1. **A real allowlist above every filter list.** `MediaPlaybackGuard.PROTECTED_DELIVERY_HOSTS` — 49
   delivery/platform hosts: `googlevideo.com`, `youtube.com`, `nflxvideo.net`, `ttvnw.net`,
   `tiktokcdn.com`, `aiv-cdn.net`, `fbcdn.net`, `jwplatform.com`, `brightcove.net`, … `evaluate()`
   returns *allowed* for them at **priority 79**, above filter lists at **50**. A hostile feed cannot
   win. A user's own explicit block (priority 90) still can — the user outranks the system.
2. **Every shipped list is checked against every protected host.** `shippedListsNeverBlockAPlaybackHost`
   parses `default_blocklist.txt`, `core_lite_ads.txt`, `core_max_ads.txt`, `core_max_threats.txt`
   and `video_ad_network.txt` with the production parser and fails the build if any one of them
   blocks any protected host. Today: **zero offenders in all five**.
3. **The ad list is structurally incapable of breaking playback.** `videoAdListNeverNamesAPlaybackHostAndHasNoDangerousWildcard`
   rejects any rule that is not a plain `||host^` — no wildcards, so nothing can swallow a CDN by
   accident — and rejects a rule that names a playback host or that both allows and blocks one host.
4. **Subdomains, not just apexes.** `r1---sn-…googlevideo.com`, `video-edge-….nflxvideo.net` and
   `usher.ttvnw.net` are tested, because that is what a player actually talks to.
5. **Lookalikes are not exempted.** `notyoutube.com` and `youtube.com.evil.example` are blocked as
   normal hosts; `googlevideo.site` too. Exempting by naive substring would open a hole.
6. **Generic ad-carrying CDNs stay blocked.** `cloudfront.net`, `fastly.net`, `akamaihd.net` serve
   plenty of ads and are *not* exempted — the guarantee costs as little blocking as it can.
7. **Every protection mode.** The exemption is verified under STANDARD, STRICT and PRIVACY, because
   STRICT is where a user is most likely to break their own playback.

## The trade-off, honestly

Exempting a host exempts everything on it. `tiktokv.com` carries the API, telemetry and video; the
video wins. That is a deliberate product decision, recorded in the code, not an oversight.

## Verification

```bash
./gradlew :app:testDebugUnitTest --tests 'com.adshield.pro.MediaPlaybackGuardTestSuite'
```

Nine tests, all on the production `FilterRuleEngine` path. They run in CI on every push, and
`tools/audit_capability_tests.py --strict` fails if a capability names a test that does not exist.
