# Video adverts: what DNS can remove, and what it cannot

This page is the honest boundary of the "block video ads without breaking playback" work. Every
claim here maps to code in `app/src/main/java/com/adshield/pro/engine/filter/` and to a test whose
name is listed at the end.

## 1. The two kinds of video advert

| Where the advert comes from | Reachable by DNS filtering? | Why |
| --- | --- | --- |
| A third-party ad server, exchange, verification vendor or measurement pixel | **Yes** | The player resolves a separate hostname for it. Removing the answer removes the advert. |
| An advert served from the same host as the video (`youtube.com`, `tiktok.com`, `instagram.com`, `googlevideo.com`) | **No** | No lookup happens, so no name exists for the filter to judge. Blocking the host would block the video as well. |

Nothing in this app claims to remove the second kind. The first kind is where a DNS filter can be
world-class, and that is what the baseline below does.

## 2. The built-in baseline (`VideoAdNetworkCatalog`)

`engine/filter/VideoAdNetworkCatalog.kt` carries a curated list of whole zones that serve adverts,
ad verification or audience measurement. It is enforced **before** the upstream lookup, so it works
with no filter list installed and with a list that predates the network.

Two risk tiers, enforced differently:

| Tier | Contents | Blocked by |
| --- | --- | --- |
| `SAFE` | Ad serving and programmatic exchanges (`doubleclick.net`, `2mdn.net`, `googlesyndication.com`, `adsrvr.org`, `rubiconproject.com`, `pubmatic.com`, `adnxs.com`, `smartadserver.com`, video SSPs such as `spotxchange.com` and `tremorhub.com`, `teads.tv`), native recommendation adverts (`taboola.com`, `outbrain.com`), and verification/measurement (`moatads.com`, `adsafeprotected.com`, `doubleverify.com`, `imrworldwide.com`, `scorecardresearch.com`, `quantserve.com`) | Every filtering mode |
| `CONDITIONAL` | Hosts that also ship player or rewarded-ad code: `fwmrm.net`, `freewheel.tv`, rewarded-video networks (`unityads.unity3d.com`, `applovin.com`, `vungle.com`, `adcolony.com`, `chartboost.com`, `ironsrc.com`, `inmobi.com`) | Strict and Custom only (`ProtectionMode.enforceConditionalVideoAds`) |

A failed fetch of a `SAFE` host is ignored by players, which is why it is safe to block in every
mode. A failed fetch of a `CONDITIONAL` host can surface as a stalled "loading advert" step in a
few apps, which is why the balanced modes leave it alone.

## 3. Playback safety is structural, not a promise

Three independent layers keep the baseline from breaking a stream:

1. **No media zone can be in the catalogue.** `VideoAdNetworkCatalogTest.testNoCatalogueZoneCanBePlaybackInfrastructure`
   fails the build if an entry is a protected playback zone, a shared CDN zone, or an entity-level
   domain.
2. **The playback guard is consulted anyway.** `VideoAdNetworkCatalog.matchForEnforcement` returns
   "not blocked" whenever `DnsMediaPlaybackGuard.isProtectedPlaybackHost` says the host carries
   playback, so a future entry cannot bypass that rule.
3. **The existing Video Safety rules still apply.** Rules that would remove a media zone
   (`||googlevideo.com^`), substring wildcards and blanket shared-CDN rules are still rejected when
   a list is parsed (`DnsMediaPlaybackGuard.isVideoUnsafeRule`).

## 4. Precedence

The baseline is the lowest-priority blocker. In order:

1. Paused protection — everything passes through unfiltered.
2. Emergency allowlist-only policy — only explicit allows resolve.
3. Per-app `BLOCK_ALL` — everything from that app is blocked.
4. Unprotected transport — that lookup is not filtered.
5. Per-app `ALLOW_ALL` — the app bypasses domain filtering, including the baseline.
6. User allowlist and custom allow rules — an explicit allow wins over the baseline.
7. Filter lists and the built-in baseline.

The baseline records its blocks with `sourceList = "Video ad infrastructure"` and
`matchedRule = <zone>`, so a blocked entry in the DNS activity log always says which zone and which
network it belonged to.

## 5. What is still not possible

- **In-feed and pre-roll adverts served from the media host** (YouTube, TikTok, Instagram, Facebook
  video, Twitch within `twitch.tv`). DNS cannot distinguish them from content.
- **Apps with their own encrypted resolver** — an app that talks DoH/QUIC to its own resolver never
  asks the tunnel, so nothing here sees the lookup.
- **Hardcoded ad IP addresses** — no lookup occurs.
- **Ad blockers inside the app's own content code**, e.g. an advert that arrives in the same HTTP
  response as the video manifest.
- **Guaranteed absence of a break.** The tiering plus the catalogue invariant tests make it
  unlikely, but a site that treats a failed ad fetch as a fatal error can still fail. Reporting it
  is one tap away in the DNS activity log, which names the zone that was blocked.

## 6. Verification

| Test | Asserts |
| --- | --- |
| `VideoAdNetworkCatalogTest.testSafeAdInfrastructureIsBlockedInEveryMode` | eight representative ad hosts are matched and blocked with `allowConditional = false` |
| `VideoAdNetworkCatalogTest.testConditionalTierNeedsTheAggressiveModes` | FreeWheel is left alone in balanced modes and blocked with the aggressive flag |
| `VideoAdNetworkCatalogTest.testModeFlagsMatchTheDocumentedTiering` | only Strict and Custom enable the conditional tier |
| `VideoAdNetworkCatalogTest.testNoCatalogueZoneCanBePlaybackInfrastructure` | no entry is a protected, shared-CDN or entity-level zone, and zones are unique |
| `VideoAdNetworkCatalogTest.testPlaybackHostsAreNeverMatchedThroughAMediaDomain` | media nodes never match, advert slots under a media domain still do |
| `VideoAdNetworkCatalogTest.testMatchingRespectsLabelBoundariesAndNormalisesInput` | no `notdoubleclick.net`, no `doubleclick.net.example.com`, URLs and ports normalise |

The enforcement path itself (`AdShieldDnsService`) is device-verified only: the JVM suite cannot
execute a `VpnService`.
