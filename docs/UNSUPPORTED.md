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
| Background protection while the tab is closed | Browser extensions only see tabs that exist. | Continuous device-wide filtering is the native client's job. |

## 2. Filtering limits

| Not supported | Why |
|---|---|
| Universal / guaranteed ad blocking | Ads served from the page's own (first-party) domain cannot be identified by DNS. No technology guarantees this. |
| Blocking ads inside video streams (server-side stitched) | Same-origin delivery — invisible to DNS. |
| Malware detection inside files or pages | This is DNS filtering, not an antivirus and not a file scanner. |
| Content-based phishing detection | No page content, DOM or certificate inspection is performed. Only hostname evidence. |
| Full Public Suffix List | Android resolves registrable domains through its own DNS path; exotic suffix layouts can be mis-split by services that rely on a bundled list. |
| Wildcards matching across label boundaries | `||ads*.example^` matches within labels by design; `*` is not a cross-domain glob. |
| Cosmetic / element hiding in DNS rules | Not applicable to DNS; such lines are counted and reported as skipped, not silently applied. |

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

The following are never claimed anywhere in the product, and the release checklist fails the
build if the strings appear:

`military-grade`, `unhackable`, `guaranteed protection`, `100% block`, `blocks 100%`,
`eliminates all ads`, `protects against all`, `total anonymity`, `bank-level encryption`,
`AI-powered antivirus`, `military grade encryption`.

"Antivirus" may only appear in a disclaimer sentence; a line containing it without
`not an antivirus` / `never` / `does not` fails verification.
