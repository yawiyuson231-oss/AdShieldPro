# OmniShield X Infinity 5.0 — implementation and release status

This is the evidence matrix for the Android app in this branch. **Source implementation is not
production certification.** The development CI gate must pass and every framework-dependent item
must still be exercised on a physical Android device before a release is published.

## Preservation

- Existing package `com.adshield.pro`, Room schema/version and migration, DataStore keys, filter
  lists, custom rules, VPN consent flow, browser, optimizer, scanners and update integration remain.
- New settings are additive DataStore keys with defaults. No existing preference is renamed.
- The development workflow builds and inspects a debug APK only; it cannot publish a release.

## Modules and real data sources

| Module | Source implementation | Evidence / data source | Explicit limitation |
| --- | --- | --- | --- |
| AETHER security core | `engine/aether/` | Deterministic agents over filter decisions, DNS answers, resolver measurements and compatibility catalog | Not a neural network or cloud AI. Confidence is heuristic, not a probability of malware. |
| VERIFIED / SUSPECTED / UNKNOWN | `AetherTypes.kt` | Concrete rule/source/category vs heuristic-only or absent evidence | A verified DNS rule is not a file-malware verdict. |
| User-controlled response | `AutonomousResponsePolicy.kt`, Security Center | DataStore opt-in, emergency mode restore point, manual override, measured recovery state | Manual override never silently disables existing DNS rules. |
| DNS firewall | `engine/dns/`, `AdShieldVpnService` | Wire-format local DNS, DoH, DoT, explicit UDP/TCP, TTL LRU cache, per-app UID where Android supplies it | Apps using private DoH/DoQ or hardcoded IP connections can bypass OS DNS. |
| Encrypted failover | `UpstreamDnsResolver` | Known encrypted providers, only when Speed mode + autonomous response are enabled; custom resolvers are not replaced | No plaintext downgrade. Exhausted encrypted candidates return SERVFAIL. |
| DNS-over-QUIC | Not enabled | Capability disclosed in DNS Settings | No audited QUIC transport is bundled; DoQ is not presented as active. |
| Adaptive ad/tracker blocker | `FilterRuleEngine`, `BrowserContentBlocker` | Bundled and HTTPS-updated lists, custom allow/block precedence, protected-domain catalog | Same-domain video ads cannot be reliably removed by DNS. No universal video-ad claim. |
| File/APK/link Security Center | `engine/security/` | Local SHA-256, EICAR/signature and structural checks, binary APK manifest analysis, PackageManager metadata, URL/list heuristics | Static analysis cannot guarantee detection of new malware or access other apps' private files. No cloud hash reputation is configured. |
| Quarantine | `SecurityLocalStore` | User-selected SAF document copied to app-private storage with size cap and SHA-256 verification | Original deletion occurs only if its document provider permits it; the UI reports both outcomes. |
| Scan history | `SecurityLocalStore` | Newest 100 records in app-private JSON storage | History is local; it is not a cloud report. |
| Live network visualization | `LiveNetworkModel`, `LiveNetworkScreen` | VPN state, real DNS log, rule categories, measured latency and available app aggregates | No simulated events or decorative traffic counts. Empty/offline states are explicit. |
| Battery intelligence | `engine/battery/`, `BatteryIntelligenceRepository` | `ACTION_BATTERY_CHANGED`, `BatteryManager`, optional vendor counters, app-foreground samples and private session history | Unsupported sensors show unavailable/unsupported. Power is battery-side V×|I|, not charger-side output. No continuous stopped-app monitoring claim. |
| Network intelligence | `NetworkIntelligenceRepository`, `IpReputationAnalyzer` | ConnectivityManager validation/captive portal/transport/system DNS; literal private/reserved/public IP classification | Wi-Fi encryption is UNKNOWN without a supported API/permission set. Public IP reputation is UNVERIFIED without a configured provider. DNS leak test cannot see private app DoH. |
| Privacy and reliability | Existing DataStore/Room + new private stores | HTTPS encrypted updates, no API keys, bounded logs/cache, VPN socket protection, duplicate-service lifecycle guards | DataStore is OS-sandboxed, not separately encrypted at rest. Physical-device performance remains to be measured. |

## Verification contract

- JVM test contract: **125 tests**, zero failures/errors/skips (development CI asserts the count).
- Hard gates: Kotlin compile, debug APK packaging, JVM suite, Android lint, APK DEX/manifest/resource
  and bundled-rule inspection.
- Physical device: **not yet tested in this environment**. VPN consent/coexistence, IPv4/IPv6,
  resolver outage/failover, reboot recovery, SAF quarantine deletion behavior, WebView filtering,
  notification behavior, Room upgrade, battery sensors and thermal alerts require device runs.

## Release gate (Phase 9)

Do not publish until all are true:

1. Development CI is green on the exact commit.
2. A release build is signed with the existing production key (never a replacement key) and passes
   R8/resource-shrinking checks.
3. The physical-device checklist in `docs/TESTING.md` is completed and recorded.
4. No open capability is presented above its measured evidence or Android permission boundary.
