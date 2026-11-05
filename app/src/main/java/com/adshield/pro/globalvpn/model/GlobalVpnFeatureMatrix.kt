package com.adshield.pro.globalvpn.model

/**
 * Single source of truth for what the Global VPN feature actually does. The UI renders this
 * verbatim so no capability is implied that is not genuinely implemented. Nothing here is
 * simulated: "AI" is a transparent on-device heuristic, and quantum-resistant crypto is marked
 * unavailable because WireGuard's Noise IK uses Curve25519, not a post-quantum KEM.
 */
object GlobalVpnFeatureMatrix {

    val features: List<FeatureAvailability> = listOf(
        FeatureAvailability(
            "Real WireGuard tunnel", AvailabilityStatus.IMPLEMENTED,
            "Open-source wireguard-go userspace engine (com.wireguard.android:tunnel, Apache-2.0). " +
                "No simulated connections."
        ),
        FeatureAvailability(
            "Self-hosted WireGuard import", AvailabilityStatus.IMPLEMENTED,
            "Import .conf / paste / QR text. Private keys are encrypted at rest with an Android " +
                "Keystore AES-GCM key."
        ),
        FeatureAvailability(
            "Proton VPN (free)", AvailabilityStatus.IMPLEMENTED,
            "Import the official WireGuard configuration downloaded from your Proton account. " +
                "Free-plan server limits are respected; no account credentials are collected."
        ),
        FeatureAvailability(
            "VPN Gate discovery", AvailabilityStatus.IMPLEMENTED,
            "Live server list, country, ping, load and OpenVPN configs from the official public CSV API."
        ),
        FeatureAvailability(
            "RiseupVPN discovery", AvailabilityStatus.IMPLEMENTED,
            "Gateway list and locations from the official LEAP provider/eip-service JSON API."
        ),
        FeatureAvailability(
            "Windscribe (free)", AvailabilityStatus.UNAVAILABLE,
            "Manual WireGuard/OpenVPN configs require a paid plan and there is no official free " +
                "third-party API. Marked unavailable rather than faked."
        ),
        FeatureAvailability(
            "In-app OpenVPN tunnel engine", AvailabilityStatus.UNAVAILABLE,
            "The mature Android OpenVPN core (ics-openvpn) is GPL and not a clean library; bundling it " +
                "would relicense this app. VPN Gate / Riseup configs are exported for an OpenVPN client instead."
        ),
        FeatureAvailability(
            "Country / city selection", AvailabilityStatus.IMPLEMENTED,
            "Built only from real imported configs and live provider discovery. No invented locations."
        ),
        FeatureAvailability(
            "Fastest-server selection", AvailabilityStatus.IMPLEMENTED,
            "Real reachability/latency probes plus provider-reported ping and load, ranked on-device."
        ),
        FeatureAvailability(
            "Adaptive / 'AI-assisted' recommendation", AvailabilityStatus.PARTIAL,
            "A transparent, inspectable heuristic (latency, jitter, load, failure history). It is not a " +
                "trained ML model; no AI is simulated."
        ),
        FeatureAvailability(
            "Predictive congestion detection", AvailabilityStatus.PARTIAL,
            "EWMA trend over measured latency/loss flags rising congestion. Heuristic, not a forecast model."
        ),
        FeatureAvailability(
            "Automatic reconnection & failover", AvailabilityStatus.IMPLEMENTED,
            "Handshake-timeout and network-change detection trigger reconnect, then failover to the next " +
                "best real server."
        ),
        FeatureAvailability(
            "Kill switch", AvailabilityStatus.PARTIAL,
            "WireGuard blocking mode is always on while the tunnel is up. A true device-wide kill switch " +
                "requires Android Always-on VPN + 'Block connections without VPN' (lockdown), which the app " +
                "detects and guides you to enable; it cannot be forced without device-owner rights."
        ),
        FeatureAvailability(
            "IP / DNS leak protection", AvailabilityStatus.IMPLEMENTED,
            "Full-tunnel routing (0.0.0.0/0, ::/0) with DNS forced through the tunnel; public IP is " +
                "re-checked after connect to verify the exit changed."
        ),
        FeatureAvailability(
            "IPv6 leak protection", AvailabilityStatus.PARTIAL,
            "When a tunnel has no IPv6 address, IPv6 is blocked rather than leaked. Full IPv6 routing " +
                "depends on the imported configuration."
        ),
        FeatureAvailability(
            "Split tunneling / per-app routing", AvailabilityStatus.IMPLEMENTED,
            "WireGuard included/excluded application lists applied to the real tunnel."
        ),
        FeatureAvailability(
            "Multi-hop VPN", AvailabilityStatus.UNAVAILABLE,
            "Not supported by the free configurations integrated here; no chained tunnel is simulated."
        ),
        FeatureAvailability(
            "Quantum-resistant cryptography", AvailabilityStatus.UNAVAILABLE,
            "WireGuard uses Curve25519 (not post-quantum). No compatible free provider offers a PQ KEM, " +
                "so this is marked unavailable instead of claimed."
        ),
        FeatureAvailability(
            "Bandwidth / speed monitoring", AvailabilityStatus.IMPLEMENTED,
            "Real rx/tx byte counters from the WireGuard engine, sampled into live up/down rates."
        ),
        FeatureAvailability(
            "Connection diagnostics & history", AvailabilityStatus.IMPLEMENTED,
            "On-device session log, handshake age, latency method, and IP-change verification."
        ),
        FeatureAvailability(
            "Battery-efficient background operation", AvailabilityStatus.IMPLEMENTED,
            "Adaptive polling cadence, idle-safe draw-state animation, and no busy loops."
        )
    )

    fun byStatus(status: AvailabilityStatus): List<FeatureAvailability> =
        features.filter { it.status == status }
}
