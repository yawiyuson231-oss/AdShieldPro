# On-demand lookups

AdShield Pro can ask several free public providers about one value you paste in. This is the only
place in the app that makes a network request because of a user action rather than a scheduled feed,
so it is documented separately.

Open it from **Intel → Registry → "Check against cached intelligence"**. The same panel always runs
the local check first (cached indicators on the device) and then the live providers, so an offline
phone still gives an answer.

## What you can look up

| Field | Accepted shape | Example |
| --- | --- | --- |
| `DOMAIN` | registrable hostname (IDNA/punycode converted) | `example.com` |
| `URL` | absolute `http(s)` URL | `https://example.com/login` |
| `IP` | IPv4 address | `203.0.113.10` |
| `CVE` | `CVE-YYYY-NNNN` | `CVE-2024-3400` |
| `SHA-256` | exactly 64 hex characters | `e3b0c442…` |
| `PACKAGE` | `ecosystem:name@version` | `npm:lodash@4.17.21` |

A value that does not fit is rejected before any request is made; the panel says why.

## Providers that answer without a key

These answer a real request today and are marked implemented in
[`CONNECTOR_VERIFICATION.md`](CONNECTOR_VERIFICATION.md):

| Connector | Field | Endpoint | Terms / limits |
| --- | --- | --- | --- |
| `cyber.circl.hashlookup` | SHA-256 | `hashlookup.circl.lu` | Free, public, rate-limited; CIRCL asks for no key. |
| `cyber.cveorg` | CVE | `cveawg.mitre.org` | Free CVE Services API; US Government work. |
| `cyber.osv.query` | PACKAGE | `api.osv.dev` | Free, no key; Google/OSS-Fuzz. |
| `cyber.depsdev` | PACKAGE | `api.deps.dev` | Free, no key; Maven package versions only in this build. |
| `fin.urlscan.domain` | DOMAIN | `urlscan.io/api/v1/search` | Community scans; unauthenticated search is rate-limited. |
| `net.ripe.prefix` | IP | `stat.ripe.net` | Free RIPEstat; fair-use limits. |
| `net.ripe.whois` | IP | `stat.ripe.net` | Same service, different dataset. |
| `net.rdap.domain` | DOMAIN | `rdap.org` | Free RDAP redirector; per-registry availability varies. |
| `net.ipinfo` | IP | `ipinfo.io/{ip}/json` | Free tier without a token; low quota, may answer `429`. |
| `net.arin.whois` | IP | `whois.arin.net/rest` | Free ARIN REST; ARIN-registered space only. |
| `net.doh.cloudflare` | DOMAIN | `cloudflare-dns.com/dns-query` | Free DoH resolver. |
| `net.doh.google` | DOMAIN | `dns.google/resolve` | Free DoH resolver. |

## Providers that need a key (never bundled)

`cyber.urlhaus.api`, `cyber.malwarebazaar.api`, `cyber.threatfox.api`, `cyber.virustotal`,
`cyber.abuseipdb`, `cyber.sonatype.ossindex`, `fin.phishtank.api`, `fin.safebrowsing` all require an
account or key owned by the user (abuse.ch now requires an Auth-Key for API access). They ship with
`implemented = false`, are never contacted, and stay **NOT CONFIGURED** in the registry. The lookup
panel does not list them as answers.

## Caching, cost and privacy

* Results are cached in the local Room table `lookup_cache`, keyed by connector + field + canonical
  value, for each connector's stated TTL (15 minutes to 7 days).
* A fresh cache entry is served without a request. An expired entry is refreshed; if the provider is
  unreachable the cached answer is shown and explicitly labelled `CACHED`, with the failure text.
* No account, key, payment or proxy is involved. The providers are free public services, not
  guaranteed: they can rate-limit, change schema, or disappear. Failures are shown as errors.
* Only the value you typed is sent, and only to providers that accept that field. Nothing else from
  the device (identifiers, apps, location, history) is attached.
* Lookups never run in the background; scheduled sync only touches the default-enabled feeds.

## What the numbers mean

Each provider answer carries a local risk weight computed on the device:

* hash 48, URL 40, IP / IP-range / malware family 34, domain 30, certificate SHA-1 26, JA3 24,
  CVE 22, alert 10;
* +5 per additional corroborating provider, capped at +15 for lookups.

These are deterministic weights defined in `IndicatorRisk.kt`. They are **not** provider verdicts,
not a probability of malice, and not a malware verdict. "No match" means the provider had nothing on
that value today, not that the value is safe.

## Android-specific lookups (no network at all)

Native probes answer local questions — installed-app provenance, default roles, device
administrators, private-DNS mode, VPN transport, battery counters, camera inventory, DRM security
level and so on. They report exact Android restrictions instead of guessing, and are covered by
[`CONNECTORS.md`](CONNECTORS.md).

### QR images

A QR code hides a URL. AdShield decodes a **user-selected** image entirely on the device with the
bundled ZXing core (Apache-2.0) and hands the payload to the normal URL analyser. It does not read
the screen, the gallery or the clipboard, never opens the link automatically, and reports a decode
failure as "no code found" rather than "safe".
