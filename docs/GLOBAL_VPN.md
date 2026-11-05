# Global VPN (next-generation upgrade)

This document describes the **Global VPN** feature added to AdShield Pro. It is a separate,
isolated layer under `app/src/main/java/com/adshield/pro/globalvpn/`. It does **not** modify the
existing local DNS-filtering system (`service.AdShieldVpnService`, `engine.dns.*`, `engine.filter.*`,
the DNS settings, rules, logs, or the DNS capability registry).

## Design rules

1. **Real or clearly unavailable.** Every capability is either genuinely implemented or marked
   unavailable in `GlobalVpnFeatureMatrix` (rendered verbatim in the Security tab). Nothing is
   simulated: no fake servers, no fake connection state, no fake "AI", no fake quantum crypto.
2. **One active VPN.** Android permits a single active `VpnService`. When the user explicitly
   connects Global VPN, the controller sends the DNS service its own public `ACTION_STOP_VPN`
   intent as a runtime hand-off. No DNS code or setting is changed; the DNS tunnel resumes its
   normal behavior when Global VPN disconnects.
3. **No paid SDKs / subscriptions.** The tunnel engine is the official open-source
   `com.wireguard.android:tunnel` (Apache-2.0, wireguard-go userspace).

## Tunnel engine

- `WireGuardEngine` wraps `GoBackend`. It establishes a real WireGuard tunnel, reads real rx/tx
  byte counters and handshake timestamps, and exposes Always-on / lockdown detection.
- `WireGuardConfigHardener` adjusts imported configs for full-tunnel routing, DNS-through-tunnel,
  IPv6 handling and per-app split tunneling. It never invents keys or endpoints.
- `GlobalVpnService` is a lightweight foreground keeper (notification + background monitoring).
  The actual tunnel is owned by the library's `GoBackend$VpnService` (declared by the AAR).

## Providers (five free sources, honest status)

| Provider | Integration | Protocol | Connectable in-app |
|---|---|---|---|
| Self-hosted WireGuard | Import official client `.conf` (encrypted at rest) | WireGuard | **Yes** |
| Proton VPN (free) | Import official WireGuard config from your account | WireGuard | **Yes** |
| VPN Gate | Live discovery via official public CSV API; export `.ovpn` | OpenVPN | No (engine not bundled) |
| RiseupVPN | Live discovery via official LEAP API | OpenVPN | No (engine not bundled) |
| Windscribe (free) | Marked unavailable — manual configs are paid-only, no free API | — | No |

### Why OpenVPN is not dialed in-app

The mature Android OpenVPN core (ics-openvpn) is GPL-licensed and is not a clean embeddable
library. Bundling it would relicense this application under the GPL. To avoid that licensing change
without faking a tunnel, VPN Gate and RiseupVPN are integrated for **real discovery and config
export**, and the in-app OpenVPN engine is explicitly marked unavailable. If you accept GPL
relicensing, the OpenVPN engine can be embedded as a follow-up to make those two sources connectable.

### Why Windscribe is unavailable

Windscribe's free tier does not expose manual WireGuard/OpenVPN configuration generation (a paid
feature) and has no official free third-party API. Rather than invent servers or scrape a private
API, the source is marked unavailable. A legitimately obtained Windscribe WireGuard config can be
imported under Self-hosted.

## Intelligent selection (transparent, not simulated AI)

- `LatencyProber` performs real reachability/latency probes (TCP connect for OpenVPN TCP, ICMP
  reachability for WireGuard UDP). Unreachable servers report `null` latency, never a guess.
- `ServerScorer` ranks servers with an inspectable heuristic (latency, load, jitter, failure
  history, preferences). Every scoring factor is returned as a human-readable reason. This is a
  heuristic, **not** a trained ML model, and the UI says so.
- `ProbeHistory` keeps an EWMA of latency and flags rising congestion. Automatic reconnection and
  failover use real handshake-timeout and network-change signals.

## Security

- **Kill switch:** WireGuard blocking mode is on while connected. A device-wide kill switch requires
  Android Always-on VPN + "Block connections without VPN" (lockdown); the app detects this and guides
  the user to enable it (it cannot be forced without device-owner rights).
- **IP/DNS leak protection:** full-tunnel routing with DNS forced through the tunnel; the public IP is
  re-checked after connect and compared to the pre-connect baseline to verify the exit changed.
- **IPv6 leak protection:** when a tunnel has no IPv6 address, IPv6 is blocked rather than leaked.
- **Secure storage:** imported configs (private keys) are sealed with an Android Keystore AES-256-GCM
  key; only non-secret metadata is stored in plaintext.

## UI

A new **Global VPN** tab is added to the existing bottom navigation. It contains: Dashboard
(schematic animated globe, central connect button, live stats), Server explorer, Provider manager,
Security dashboard (honesty matrix + diagnostics), Analytics, Split tunneling, Advanced settings, and
Connection history. Animations are draw-state only and run only while connected with system animations
enabled (battery-efficient). All long lists are lazy and keyed.

## Tests

JVM unit tests cover config hardening, server scoring/ranking, VPN Gate CSV parsing, and the honesty
matrix (ensuring unavailable features stay marked unavailable). Run with `:app:testDebugUnitTest`.

## Known limitations

- OpenVPN tunneling is not bundled (see above); VPN Gate / Riseup are discovery + export only.
- Windscribe free is unavailable.
- Multi-hop and quantum-resistant crypto are marked unavailable (not supported by the integrated
  free configurations / WireGuard's Curve25519).
- "AI-assisted" recommendation is a transparent heuristic, not a trained model.
