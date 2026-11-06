# Unsupported capabilities — explicit list

This file is the authoritative list of things OmniShield X **does not do**. It exists so
that no part of the product can imply otherwise. The same content is rendered in the app
under **Capabilities**.

## 1. Operating-system / browser limits

| Not supported | Why | What exists instead |
|---|---|---|
| Filtering other applications' DNS | A browser sandbox cannot intercept system traffic. That requires a `VpnService` (Android) or a system resolver change. | The Android core performs device-wide filtering; this site manages policies and intelligence for it. |
| Passive capture of network traffic | No raw-socket or packet-capture API in browsers. | Only traffic OmniShield X itself performs, or an observation log you explicitly import, is analysed. |
| Blocking traffic inside other browsers | Each browser sandboxes its own network stack. | The MV3 extension filters Chrome/Edge/Brave; see `/extension`. |
| DoT (DNS over TLS) from the browser | Browsers cannot open TCP sockets on port 853. | The RFC 7858 framing codec is implemented and unit-tested for the native core; the web app refuses to silently downgrade and says why. |
| Installing a certificate / TLS interception | Would break the security it claims to provide. | Deliberately never implemented. |
| Background protection while the tab is closed | Service workers are evicted by the OS. | Offline caching keeps the app usable; continuous filtering is the native client's job. |

## 2. Filtering limits

| Not supported | Why |
|---|---|
| Universal / guaranteed ad blocking | Ads served from the page's own (first-party) domain cannot be identified by DNS. No technology guarantees this. |
| Blocking ads **stitched into the video stream** (YouTube, TikTok, Facebook, SSAI) | The ad and the video arrive in the same stream — there is no separate request for DNS to resolve. Removing them would mean blocking the video itself, which breaks playback. |
| Guaranteeing playback on a **user-synced** third-party list | AdShield cannot vet a feed it did not write. The bundled layers are verified against every protected playback host; a synced feed is checked at sync time and reported if it would block one. |
| Malware detection inside files or pages | This is DNS filtering, not an antivirus and not a file scanner. |
| Content-based phishing detection | No page content, DOM or certificate inspection is performed. Only hostname evidence. |
| Full Public Suffix List | A focused subset (`aether/domain.js`) covers common ccTLD layouts. Exotic suffixes may be mis-split when computing registrable domains. |
| Wildcards matching across label boundaries | `||ads*.example^` matches within labels by design; `*` is not a cross-domain glob. |
| Cosmetic / element hiding in DNS rules | Not applicable to DNS; such lines are counted and reported as skipped, not silently applied. |

### 2.1 What video-ad blocking actually does

The Android core blocks **third-party video-ad infrastructure** device-wide, at the DNS layer, so
it applies in every app (Chrome, YouTube, TikTok, podcast players) with no WebView or extension
involved: VAST/VPAID ad servers, ad exchanges, video-ad SDK APIs, SSAI/stitcher vendor APIs and
ad-verification beacons.

It does **not** and cannot remove ads that are stitched into the video itself. To keep that
boundary honest in code as well as in prose:

- **Playback hosts are exempted above every filter list** (`MediaPlaybackGuard`, priority 79 vs.
  filter lists at 50), so no bundled layer can take video down;
- every protected delivery host is checked test-time against **every shipped list**;
- the video-ad list is checked to contain **no playback host and no wildcard** that could swallow one;
- a deliberate user block still wins, because the user's own decision outranks built-in lists.

## 3. DNSSEC

- **Local chain-of-trust validation is not implemented.** Verifying signatures from the root
  KSK down requires fetching DNSKEY/DS records and performing RSA/ECDSA verification, which
  is a native-client feature today.
- What is implemented: requesting DNSSEC records (DO bit), inspecting RRSIG presence,
  signer, covered type and validity window, and reporting the **AD bit set by the upstream
  validating resolver** — attributed to that resolver by name.
- `SERVFAIL` with DNSSEC requested is reported as *"could be bogus or simply unreachable"*.
  OmniShield X never asserts that a signature was proven invalid.

## 3b. Redirects and CNAME chains

- **HTTP redirects are not visible.** A DNS filter sees names, not HTTP responses, so a
  301/302/JavaScript redirect to a malicious site is outside what this app can observe.
- **What is analysed:** the CNAME chain returned by the resolver. If a first-party-looking
  hostname resolves through an off-site link that the filter blocks or that AETHER scores
  ≥ 45/100, the DNS lab reports **CNAME cloaking** and names the target and the rule. This is
  advisory evidence, not enforcement, and it never blocks the queried name.

## 3c. Android DNS enforcement limits

The Android core adds upstream failover, strict response validation, DNSSEC *reporting*,
per-app/per-network/emergency DNS policy (`docs/DNS_SECURITY_ARCHITECTURE.md`). The following
remain explicitly unsupported:

| Not supported | Why |
| --- | --- |
| Local DNSSEC chain validation | No DNSKEY/DS fetch or signature verification on device; only upstream AD/RRSIG evidence is reported. |
| External DNS leak testing | Would require an unaudited third-party echo service. Settings diagnostics run a real query against the configured resolver and say so. |
| General IP/TCP/UDP firewalling | The tunnel routes DNS addresses only, so non-DNS sockets are never seen. Per-app and per-network controls are DNS decisions. |
| YARA rules / native YARA / ClamAV | No rule parser ships in this build. The file scanner uses signature and structural checks only (EICAR, polyglot containers, script droppers, macro documents, zip-slip). |
| DoH3 / Oblivious DoH | Only DoH (RFC 8484), DoT (RFC 7858) and explicit plaintext port 53 are implemented. |

## 3e. Safe GPS (Android, v2.10)

| Not supported | Why | What exists instead |
|---|---|---|
| Live / continuous location sharing | Needs a relay server and a live session; a lost or stolen phone would keep broadcasting. | A converged fix turned into fixed text you send yourself. |
| Background location (`ACCESS_BACKGROUND_LOCATION`) | Deliberately not declared. Capture runs only while the Safe GPS screen is open. | On-demand capture with a visible Stop button. |
| Proof of location / anti-spoof guarantee | No reliable attestation source for an ordinary app. | Android's mock flag is surfaced and blocks emergency sharing; implied-speed plausibility is shown as a hint only. |
| Emergency calls or automatic contact alerts | An app cannot place a 911 call for you or guarantee an alert. | An emergency message to copy or send via SMS, naming 911 and asking a bystander to call. |
| Map tiles / offline maps | No map SDK is bundled; tiles would add a provider and a licence. | A `geo:` URI or OpenStreetMap link you choose to open, with the provider named. |
| Reverse geocoding (street address) | Would send coordinates to a third party without being asked. | Coordinates, a spoken reference, and a landmark-based sharing habit. |
| Screen-lock / SIM-lock state | Android does not expose it to apps. | The checklist shows "cannot read" rather than assuming the device is locked. |

## 4. Intelligence limits

- The lexical classifier sees **only the hostname string**. It is a 7/100-weight signal with
  a measured operating point (see `docs/AETHER.md`); it cannot block anything.
- No WHOIS, registration-age, ASN, reputation-blocklist, or certificate-transparency lookups.
- "First seen" means *first seen by this browser profile*, not domain registration date.
- Feed content is trusted as published by its maintainers. Hash and shrink checks catch
  corruption and truncation, not a compromised upstream.
- The classifier's negative corpus is small (541 curated domains). Unfamiliar legitimate
  domains can be flagged as ad-like; guardrails and weight bounds limit the damage, and the
  measured false-positive rate is displayed rather than hidden.

## 5. Platform / deployment limits

- No accounts, no cloud sync, no multi-device policy push. Transfers are files you move yourself.
- `localStorage` quota (typically 5 MB) bounds how many snapshots and how much model state
  can be kept; the app prunes and reports failures instead of pretending a save succeeded.
- No background feed refresh while the tab is closed.
- Battery-aware throttling depends on the Battery Status API, which Safari does not expose.
  Where it is missing the app keeps the default repaint cadence and says so on the dashboard;
  it never reports an optimisation it cannot perform.
- Nothing here is a substitute for a maintained antivirus, EDR, or enterprise DNS gateway.

## 5b. Browser extension limits

- **Static rules are capped at 30,000.** Chrome only guarantees that many
  `declarativeNetRequest` static rules per extension; the rest is shared with every other
  installed blocker. The bundled feeds contain 79,739 rules, so the extension ships the
  first 30,000 by feed order. Popularity ordering is not available offline, so this is a
  breadth trade-off, not a claim that the shipped 30,000 are the "best" ones.
- **Third-party requests only.** Rules use `domainType: "thirdParty"`, so ads served from
  a site's own domain are not blocked by DNR.
- **Per-tab counts need a dev install.** `onRuleMatchedDebug` requires the
  `declarativeNetRequestFeedback` permission and an unpacked/development install. Where it
  is unavailable the popup shows `—` and the reason instead of a fabricated `0`.
- **One browser at a time.** The extension filters the browser it is installed in. It
  cannot filter other applications or other browsers.

## 6. Claims policy

The following are never claimed anywhere in the product, and `scripts/verify.mjs` fails the
build if the strings appear:

`military-grade`, `unhackable`, `guaranteed protection`, `100% block`, `blocks 100%`,
`eliminates all ads`, `protects against all`, `total anonymity`, `bank-level encryption`,
`AI-powered antivirus`, `military grade encryption`.

"Antivirus" may only appear in a disclaimer sentence; a line containing it without
`not an antivirus` / `never` / `does not` fails verification.
