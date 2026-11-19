# DNS and threat-scanning hardening (Android core)

This document describes the cybersecurity slice added on top of the existing Android
application: resilient upstream DNS resolution, strict response validation, honest DNSSEC
reporting and deterministic DNS-only policy enforcement.

Everything below is DNS-level or file-level on-device behaviour. The tunnel still routes
**only** `10.215.173.2/32` and `fd00:ad5:1e1d::2/128`; no non-DNS socket is inspected, and
nothing here makes AdShield Pro a general-purpose IP firewall.

## 1. Upstream provider plan and failover

`engine/dns/DnsProviderRegistry.kt` turns configuration into an explicit ordered plan:

| Behaviour | Implementation |
| --- | --- |
| Ordered plan | Primary preset first, then the user-selected failover providers, in the configured order. Duplicates are removed. |
| Opt-in only | Without `failoverEnabled`, the plan is exactly one provider. |
| No silent downgrade | Plaintext UDP/TCP 53 never appears as a fallback for a DoH or DoT configuration, and no provider outside the user's selection is contacted. |
| No response merging | The first provider that returns a validated answer wins; answers are never combined. |
| Health ordering | `DnsProviderHealthMonitor` records real success/failure counts and EWMA latency per provider+protocol. When selected, fastest-healthy ordering sorts by measured EWMA; unmeasured providers keep their relative order. |
| Circuit breaking | After 3 consecutive failures a provider is skipped until a 30 s cooldown elapses. Caller cancellation and strict AD policy rejections do not count as outages. An open circuit is skipped; if all are cooling down the app returns local SERVFAIL until a provider is eligible again. |
| Hedged failover | A fast failure advances immediately. A slow request gets a 250 ms head start before a selected backup may also receive the name. The first validated answer wins, and the losing HTTP call or socket is canceled without counting that cancellation as a failure. An attempt is bounded to 6.5 s and the complete plan to 12 s. |
| Media-aware ordering | For media hostnames only, providers that forward EDNS Client Subnet (`DnsProviderPreset.forwardsClientSubnet`) are moved to the front, because the authoritative server chooses the video CDN edge from that subnet. Ordinary names keep the configured order. Controlled by `preferGeoAccurateMediaDns`. |
| Video Safety | `DnsMediaPlaybackGuard` refuses entity-level, substring-wildcard and shared-CDN rules at parse time (counted in `rejectedVideoUnsafeRules`), and installs media delivery domains as exceptions. Advert delivery hosts stay blocked. See `docs/DNS_AND_VIDEO_SAFETY.md`. |

Supported presets include NextDNS (`https://dns.nextdns.io/dns-query`) and Control D
(`p0.freedns.controld.com`) in addition to the previous providers. The custom preset accepts
explicit IPv4 **and** IPv6 endpoints. Within the selected provider, later configured addresses
get a chance after a short head start even if an earlier address stalls. A matching truncated UDP
reply gets a separate same-address TCP window, still bounded by the overall provider deadline.
Losing requests are canceled.

## 2. Strict response validation

`engine/dns/DnsResponseValidator.kt` validates every upstream answer before it can enter the
cache or reach an application. A response is rejected when:

- the transaction ID, opcode, complete single question, QR flag or reserved bit is wrong;
- the response is truncated. In plaintext mode, only a datagram from the contacted endpoint with a
  matching ID and question can trigger TCP to that same endpoint;
- the full RCODE (including the EDNS extension) is not NOERROR or NXDOMAIN. A refusal or server
  error can advance to an opted-in backup instead of being accepted as a healthy answer;
- resource records or common RDATA are malformed, compression points forward or loops, or bytes
  remain after the last record. Unknown RR types stay opaque;
- EDNS OPT placement, version, or option lengths are invalid. Extended DNS Error **codes** are
  surfaced in diagnostics; resolver-supplied free text is not shown.

Cached replies expire against a
monotonic clock that includes time spent asleep. Hits return only remaining record TTLs and leave
EDNS flags alone. A whole wire reply is only reused for the same query bytes, excluding the rewritten
transaction ID; different DNSSEC flags or EDNS options do not share replies. Zero-TTL replies are
not stored. Negative results require an authority SOA, with a lifetime no greater than its TTL or
SOA.MINIMUM. Custom DoH paths and query strings are cache-keyed case-sensitively.

## 3. DNSSEC: reporting, not local validation

The resolver reports upstream evidence only:

| Reported status | Meaning |
| --- | --- |
| `UPSTREAM_AUTHENTICATED` | The upstream resolver set the Authenticated Data (AD) bit. |
| `SIGNATURES_PRESENT_UNVALIDATED` | RRSIG records are present; no local cryptographic validation was performed. |
| `NOT_AUTHENTICATED` | No AD bit and no RRSIG observed. |

Two modes are offered:

- **Report upstream DNSSEC status** (default): normal unsigned resolution continues and the
  evidence is displayed in Settings diagnostics.
- **Strict: require AD on answers**: positive answers without the AD bit are rejected. This
  intentionally breaks unsigned domains. It is *not* local chain-of-trust validation — no
  DNSKEY/DS fetch and no signature verification happens on the device.

## 4. DNS-only policy: per-app, per-network, emergency

`engine/dns/DnsFirewallPolicyDecider.kt` is pure and deterministic. For every DNS query the
VPN service supplies the owning package and the active transport (`ConnectivityManager`), then
applies, in order:

1. **Emergency allowlist-only** — when enabled, every answer is blocked unless it came from a
   `User Allowlist`, `System Safety Allowlist`, or a non-blocking `User Custom Rule` decision.
   Ordinary blocklist matches never become allow exceptions. The Settings control asks for
   explicit confirmation because this blocks nearly all DNS.
2. **Per-app policy** — `BLOCK_ALL` blocks every DNS query from that package; `ALLOW_ALL`
   bypasses domain filtering for that package.
3. **Per-network policy** — a transport that is not in `protectedTransports` passes through
   without domain filtering, and the UI states that clearly.
4. Otherwise the normal filter-engine decision is used.

This governs DNS decisions only. Apps that use hardcoded IPs, HTTP DNS, or their own encrypted
transport are unaffected, because those packets never enter the tunnel.

### DNS Alias Shield

**Settings → DNS Alias Shield** (under **Encrypted Upstream DNS Protocol**) extends the
original CNAME feature to HTTPS and SVCB (RFC 9460). It is on by default and respects
any previous opt-out. A first-party name can look harmless in the question but name a tracker
or other blocked destination in the reply.

- After upstream validation, the VPN checks aliases reachable from the question in the Answer
  section, including on cache hits. It follows CNAME and service-binding aliases already present
  in the reply and checks named ServiceMode destinations for the queried record type. Unrelated
  records, additional records and opaque service parameters aren't used as blocking evidence.
- It checks the active rules rather than treating all third-party services as trackers. Explicit
  allowlists, app/network passthrough and playback safeguards are preserved. No extra queries
  are sent. DNS activity identifies the record type, destination and matching rule for a block.
- When an HTTPS or SVCB lookup is blocked at this stage, the app returns **NOERROR with no answers
  (NODATA)** for that type. This suppresses the entire binding reply, including address hints,
  without telling the device that the hostname itself doesn't exist. Any subsequent A/AAAA
  lookup is still filtered independently. CNAME blocks for address queries keep the configured
  NXDOMAIN or sinkhole behavior.

The shield can only inspect targets actually included in the received reply; it does not
resolve unseen links or inspect connections to addresses already known by an app.

## 5. Resolver diagnostics

Settings sends a new A query with EDNS0 and DO through the configured upstream plan. It does not
read or change the normal reply cache and does not apply the VPN’s local domain filters. It shows
the answering provider and transport, total elapsed time, answer/NODATA/NXDOMAIN or local SERVFAIL,
DNSSEC and EDNS evidence, and any observed provider failures. The separate DNS benchmark tests the
configured protocol directly against each listed resolver and never changes the active provider.

**Neither check is a DNS leak test or local DNSSEC validation.** The contacted resolvers see the
query name. No third-party echo service or AI service is used.

## 6. Local file scanning (no YARA)

`FileThreatScanner` keeps the pre-existing, purely local checks: exact signature matches
(industry-standard EICAR test string), polyglot/steganographic executables hidden inside image
and PDF containers, script-based droppers (PowerShell `-enc`, `certutil -urlcache`, `mshta`,
`curl | sh`), macro-laden Office documents, zip-slip archive entries and suspicious
double-extension naming.

A YARA-compatible rule subset was implemented and then **removed** at the maintainer's request,
together with its tests, its capability row and its documentation. The scanner therefore does
**not** support YARA rules: no rule parser ships in this build, and native YARA and ClamAV are
not integrated. Detection remains signature- and structure-based, which the honest limitation
below repeats.

## 7. Verification evidence

JVM tests in `app/src/test/java/com/adshield/pro/CybersecurityPlatformTestSuite.kt`:

| Test | Asserts |
| --- | --- |
| `providerPlanIsExplicitAndNeverCrossFailsPlaintextDns` | plan ordering, preset endpoints, no plaintext failover |
| `healthCircuitOpensClosesAndUsesOnlyMeasuredLatency` | 3-strike circuit, cooldown, EWMA arithmetic from recorded samples |
| `validatorRejectsWrongQuestionTruncationServfailAndTrailingData` | question mismatch, TC bit, SERVFAIL, trailing bytes |
| `dnssecModeReportsUpstreamAdAndStrictModeRejectsUnsignedPositiveAnswers` | AD reporting and strict rejection |
| `resolverFailsOverOnlyAfterValidationAndDoesNotDowngrade` | real failover to the selected provider after a validated answer |
| `resolverCircuitSkipsKnownOpenProviderWithoutExtendingIt` | open circuit is skipped without inflating failure counts |
| `appNetworkAndEmergencyPoliciesAreDeterministic` | per-app, per-transport and emergency decisions |
| `diagnosticQueryUsesEdns0AndNormalisesCase` | EDNS0/DO diagnostic query construction and input validation |
| `fileScannerFlagsEncodedPowerShellDropper` | scanner verdict is driven by a real dropper-pattern match |

`DnsResolverHardeningTest` also covers UDP truncation eligibility, RDATA and EDNS framing, full RCODE
and Extended DNS Errors, cancellation of a losing hedge, live cache-independent diagnostics, and
HTTPS content-type and size checks with simulated replies.

## 8. Encrypted transport and limits

- DoH is HTTPS-only, does not follow redirects, and accepts bounded `application/dns-message`
  replies. Built-in endpoints use literal bootstrap IPs; a custom HTTPS endpoint may need a
  separate system lookup **of the endpoint hostname only**, with bounded wait and worker count.
- DoT verifies the configured hostname during the TLS handshake. Plaintext UDP/TCP is used only
  when explicitly selected. A failure to protect an active VPN socket fails the exchange rather
  than sending it into the tunnel again.
- Unit fixtures and APK launch tests do not prove handset VPN routing, attribution, or live resolver
  interoperability. See [device checks](TESTING.md). No external leak test, local DNSSEC validator,
  DoQ or general IP-level firewall is included.

## 9. Browser DNS lab (separate from the Android VPN)

The web lab issues explicit DoH lookups using browser HTTPS. It checks the expected question and,
for wire replies, the transaction ID, flags and EDNS framing. HTTPS redirects are refused, and time
and size limits cover the entire response body. Unusable RCODEs advance to another HTTPS resolver;
a canceled hedge is not an outage. The lab uses whole-answer, in-memory caching. Zero-TTL and
unproven negative lifetimes are not cached; negative entries require an SOA and expire without a
stale grace period. Positive stale results are labeled and refreshed in the background.

The web lab does not install DNS system-wide, open DoT sockets, verify DNSSEC locally, or emulate
Android Alias Shield and VPN policy. Its tests use in-memory DoH response fixtures.
