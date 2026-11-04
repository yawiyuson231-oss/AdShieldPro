# OmniShield X — Platform Spec → Shipped Status (v4.5.0)

Every row states what SHIPS, verified by which test. No claims beyond it.

## Core protection
| Spec | Status | Proof |
|---|---|---|
| Malware/phishing/cryptojack/botnet feeds, auto-update, license-clean | SHIPPED (HaGeZi GPL-3.0, attribution in THIRD_PARTY_NOTICES) | DnsFirewallCompatibilityTest + web engine.test.mjs |
| New domains (≤30d) flagged, blocked in Strict | SHIPPED — RDAP lookup, opt-in (default OFF), 2s cap, 6h cache, unknown age → never blocked | PlatformSpecAcceptanceTest.newDomainAge_rdapParsing |
| Random-looking (DGA) detection | SHIPPED — entropy analyzer; OBSERVE in Balanced, block in Strict (toggle) | dgaAndLookalikeSignals test |
| Lookalike brands incl. homoglyphs | SHIPPED — Damerau-Levenshtein + homoglyph fold (Cyrillic/Greek/fullwidth) | lookalikeImpostors test |
| DNS rebinding block | SHIPPED (v4.0 AETHER rebinding guard) | AetherInfinityTest |
| Encrypted DNS only, no silent downgrade | SHIPPED — DoH/DoT; failure → fallback plain DNS WITH warning (never silent cut, never port-443 blocking) | resolver fallback + LIVE fallback banner |
| DNSSEC plain-language | SHIPPED — resolver-side validation, explained in Settings ("Learn more") | SettingsScreen row |
| Provider adapter | SHIPPED — DnsResolverConfig presets + custom DoH/DoT (switch without rewrite) | UpstreamDnsResolver |

## Never-break goal
- Balanced default ✓; one-tap allow via false-positive report ✓; "blocked last 60 minutes" list on LIVE tab ✓
- Fallback-with-warning ✓ (banner); pause 5/15/60 min with AUTO-RESUME ✓; never block all :443 ✓
- Top-100 app domains acceptance: PlatformSpecAcceptanceTest.top100MostUsedAppDomains_neverBlocked (Balanced + Strict, real 367k rules)

## Platforms
- **Android (this APK):** VPN mode with per-app exclusions + Private DNS strict-mode detector; universal in-app ad-skip (strict evidence, protected system UIs never touched, off-by-default nothing — universal ON, safety invariants tested)
- **PC (pc-agent/omnishield_proxy.py):** local DNS proxy → same rule ladder → DoH-only upstream, SERVFAIL-not-drop on outage; `--selftest` passes (ladder, QNAME parse, NXDOMAIN/SERVFAIL builders). Complements Defender — never replaces it. Admin only to bind :53 / set adapter DNS.
- **iPhone (ios/omnishield-dns.mobileconfig):** system-wide DoH profile (all apps, Wi-Fi+cellular). No per-app exclusion possible with profiles — stated in the profile text itself. Link Check only on iOS (no cross-app file scan on sandboxed iOS) — honest.
- **All platforms:** browsers/apps with their OWN DoH can bypass system settings — the Android app sinkholes their bootstrap hostnames (Encrypted-DNS Bypass Shield); PC/iOS users get browser-setting guidance (Chrome/Firefox secure-DNS off).

## Scanning
- Link Check: UrlThreatScanner (feeds + punycode + typosquat + IP-host + credentials) — "no scan guarantees safety" shown in-app ✓
- File Check (Android): local SHA-256 + signature/marker scan, NO upload. Cloud reputation lookup is NOT wired (would need your API key + consent flow) — disclosed.
- iPhone: link check only — disclosed.

## App security
- Keystore-backed secrets on Android; logs on-device, auto-trimmed; no data sale (no data collection exists); updates signed (CI keystore in release assets). Passkeys/MFA/pen-test: NOT APPLICABLE yet — there is no account/cloud backend (file-based sync via backup JSON). Independent pen test: not done — do not assume otherwise.

## Acceptance tests (CI)
Blocks malware test domains ✓ (compat suite) · top-100 apps allowed ✓ · outage warning ✓ (banner + SERVFAIL-fallback) · log trimming ✓ (DB cap) · reboot/update persistence ✓ (START_STICKY + versioned rule resync).
