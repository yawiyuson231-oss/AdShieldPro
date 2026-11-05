# CyberShield AI — Global VPN module

New **VPN** bottom-navigation destination (design reference: `docs/images/cybershield-vpn-reference.jpg`).

## Architecture (Android one-VPN rule honored)

Android allows a single `VpnService` per profile. The global VPN therefore **shares the existing
`AdShieldVpnService`** — there is exactly one tunnel. `ACTION_START_GLOBAL_VPN` switches the same
service into full-tunnel mode (`0.0.0.0/0` + `::/0`, `setBlocking(true)` = kill switch). The DNS
engine is untouched and keeps working; DNS-only mode remains the default for the Home tab.

## What is real

- Server catalog the user populates with real endpoints (add dialog / WireGuard `.conf` import via
  `WireGuardConfigParser`). It starts empty — no fake servers.
- Latency: actual TCP connect timing per server (`VpnLatencyProber`); fastest-server selection uses
  only measured values; unmeasured servers show "not measured".
- Public IP verification over HTTPS (api.ipify.org) and a DNS-leak probe — both report "not run /
  not verified" instead of guessing.
- Threat feed records only real events (e.g. connection failures). It is never pre-filled.
- Kill switch (blocking mode), per-app split tunneling, full-tunnel routing.
- The dashboard shows an explicit **Honest Feature Status** panel (WORKING / SERVER REQUIRED /
  NOT IMPLEMENTED / ANDROID LIMITATION).

## What requires a server (disclosed, not faked)

The app ships no VPN servers and no wireguard-go/OpenVPN library, and no free public VPN backend
exists that this project operates. Connecting to an endpoint therefore reports
**SERVER REQUIRED** until the user configures their own WireGuard/OpenVPN backend. Multi-hop,
QUIC/MASQUE and traffic obfuscation are **NOT IMPLEMENTED**.

## Tests

`VpnEngineTestSuite` (JVM): fastest-server selection from measured latencies only, display
sorting with honest nulls, WireGuard parser accept/reject, feature-status labels.
