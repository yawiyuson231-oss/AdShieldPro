package com.adshield.pro.globalvpn.model

import kotlinx.serialization.Serializable

/**
 * Global VPN domain model.
 *
 * This layer is deliberately isolated from the existing local DNS-filtering VPN
 * (`service.AdShieldVpnService`, `engine.dns.*`, `engine.filter.*`). Nothing here reads or
 * writes the DNS system's settings, rules, logs or service. Android permits only one active
 * VpnService at a time, so the Global VPN UI states clearly that connecting it replaces the
 * local DNS tunnel for the duration of the session; it never edits the DNS system itself.
 */

enum class VpnProtocol(val label: String) {
    WIREGUARD("WireGuard"),
    OPENVPN("OpenVPN")
}

enum class ProviderId(val label: String) {
    PROTON("Proton VPN"),
    WINDSCRIBE("Windscribe"),
    VPNGATE("VPN Gate"),
    RISEUP("RiseupVPN"),
    SELF_HOSTED("Self-hosted WireGuard")
}

/** How a provider is integrated. Every value is rendered honestly in the provider manager. */
enum class ProviderIntegration(val label: String, val detail: String) {
    REAL_WIREGUARD_IMPORT(
        "Real tunnel · official config import",
        "Connects through the open-source WireGuard engine using an official configuration you import."
    ),
    REAL_DISCOVERY_EXPORT_ONLY(
        "Real server discovery · OpenVPN engine not bundled",
        "Servers and configurations are fetched from the provider's official public API. The in-app " +
            "OpenVPN tunnel engine is not bundled (the mature Android OpenVPN core is GPL and would " +
            "relicense this app), so these configs are exported for use with an OpenVPN client."
    ),
    UNAVAILABLE_FREE_PLAN(
        "Unavailable on the free plan",
        "This provider does not expose manual WireGuard/OpenVPN configurations on its free tier, and " +
            "there is no official free third-party API. No servers are invented."
    )
}

enum class SplitTunnelMode(val label: String) {
    OFF("Route all apps"),
    EXCLUDE_SELECTED("Exclude selected apps"),
    INCLUDE_SELECTED("Only selected apps")
}

enum class TunnelPhase {
    IDLE,
    PREPARING,
    CONNECTING,
    CONNECTED,
    RECONNECTING,
    DISCONNECTING,
    ERROR
}

@Serializable
data class StoredTunnel(
    val id: String,
    val name: String,
    val provider: ProviderId,
    val protocol: VpnProtocol,
    val countryCode: String,
    val countryName: String,
    val city: String? = null,
    val endpointHost: String,
    val endpointPort: Int,
    val addedAtEpochMs: Long,
    val lastUsedEpochMs: Long = 0L
)

data class VpnServer(
    val id: String,
    val provider: ProviderId,
    val protocol: VpnProtocol,
    val displayName: String,
    val countryCode: String,
    val countryName: String,
    val city: String? = null,
    val endpointHost: String,
    val endpointPort: Int,
    val loadPercent: Int? = null,
    val reportedPingMs: Int? = null,
    val reportedSpeedMbps: Double? = null,
    val measuredLatencyMs: Long? = null,
    val isConnectable: Boolean,
    val unavailableReason: String? = null,
    val configRef: String? = null
)

data class ServerProbe(
    val serverId: String,
    val reachable: Boolean,
    val latencyMs: Long?,
    val method: String,
    val atEpochMs: Long
)

data class TunnelStats(
    val rxBytes: Long,
    val txBytes: Long,
    val latestHandshakeEpochMs: Long
)

data class GlobalVpnState(
    val phase: TunnelPhase = TunnelPhase.IDLE,
    val server: VpnServer? = null,
    val connectedSinceEpochMs: Long? = null,
    val baselinePublicIp: String? = null,
    val tunnelPublicIp: String? = null,
    val ipChangeVerified: Boolean = false,
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val rxBytesPerSec: Long = 0L,
    val txBytesPerSec: Long = 0L,
    val latencyMs: Long? = null,
    val latencyMethod: String? = null,
    val handshakeAgeMs: Long? = null,
    val healthScore: Int = 0,
    val alwaysOnEnabled: Boolean = false,
    val lockdownEnabled: Boolean = false,
    val killSwitchRequested: Boolean = false,
    val dnsLeakProtected: Boolean = false,
    val ipv6LeakProtected: Boolean = false,
    val errorMessage: String? = null,
    val statusNote: String? = null
) {
    val isConnected: Boolean get() = phase == TunnelPhase.CONNECTED
    val killSwitchActive: Boolean get() = killSwitchRequested && lockdownEnabled
}

@Serializable
data class ConnectionHistoryEntry(
    val id: String,
    val serverName: String,
    val provider: ProviderId,
    val countryCode: String,
    val protocol: VpnProtocol,
    val startedAtEpochMs: Long,
    val endedAtEpochMs: Long? = null,
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val outcome: String = "connected"
)

@Serializable
data class GlobalVpnSettings(
    val selectedServerId: String? = null,
    val preferredProvider: ProviderId? = null,
    val preferredCountryCode: String? = null,
    val autoSelectFastest: Boolean = true,
    val autoReconnect: Boolean = true,
    val autoFailover: Boolean = true,
    val killSwitch: Boolean = true,
    val leakProtection: Boolean = true,
    val blockIpv6WhenUnsupported: Boolean = true,
    val splitTunnelMode: SplitTunnelMode = SplitTunnelMode.OFF,
    val splitTunnelPackages: Set<String> = emptySet(),
    val batterySaver: Boolean = false,
    val autoConnectOnBoot: Boolean = false,
    val protocolPreference: VpnProtocol = VpnProtocol.WIREGUARD
)

enum class AvailabilityStatus(val label: String) {
    IMPLEMENTED("Implemented"),
    PARTIAL("Partial"),
    UNAVAILABLE("Unavailable")
}

data class FeatureAvailability(
    val feature: String,
    val status: AvailabilityStatus,
    val detail: String
)
