package com.adshield.pro.vpn

import kotlinx.serialization.Serializable

/**
 * Global VPN module models.
 *
 * Honesty contract (mirrors the app-wide capability rules): nothing here is invented.
 * - A [VpnServer] exists only if the user added a real endpoint (host + port) or imported one.
 * - Latency values come from real TCP connect measurements ([VpnLatencyProber]).
 * - Threat events are only recorded when something actually happened on the device.
 * - [FeatureStatus] tells the UI exactly what works on this build.
 */
@Serializable
data class VpnServer(
    val id: String,
    val name: String,
    val country: String,
    val city: String,
    val host: String,
    val port: Int,
    val protocol: VpnProtocol,
    val measuredLatencyMs: Long? = null,   // null = not measured yet
    val loadPercent: Int? = null,          // null = server does not report load
    val isFavorite: Boolean = false,
    val lastUsedEpochMs: Long? = null
)

enum class VpnProtocol { WIREGUARD, OPENVPN }

enum class VpnConnectionState { DISCONNECTED, CONNECTING, CONNECTED, FAILED }

enum class FeatureStatus {
    WORKING, PARTIAL, NOT_IMPLEMENTED, SERVER_REQUIRED, PERMISSION_REQUIRED, ANDROID_LIMITATION, ERROR;

    val label: String get() = when (this) {
        WORKING -> "WORKING"
        PARTIAL -> "PARTIALLY WORKING"
        NOT_IMPLEMENTED -> "NOT IMPLEMENTED"
        SERVER_REQUIRED -> "SERVER REQUIRED"
        PERMISSION_REQUIRED -> "PERMISSION REQUIRED"
        ANDROID_LIMITATION -> "ANDROID LIMITATION"
        ERROR -> "ERROR"
    }
}

@Serializable
data class VpnThreatEvent(
    val id: Long,
    val epochMs: Long,
    val severity: Severity,
    val title: String,
    val detail: String
) {
    enum class Severity { LOW, MEDIUM, HIGH, CRITICAL }
}

@Serializable
data class VpnStats(
    val connectedSinceEpochMs: Long?,
    val bytesIn: Long,
    val bytesOut: Long,
    val publicIp: String?,          // from a real IP echo service, null = not verified
    val dnsLeakTestResult: String?, // real resolver-seen answer, null = not run
    val killSwitchActive: Boolean,
    val serverId: String?
)

/** Parsed WireGuard profile — only fields the app actually reads. */
data class WireGuardProfile(
    val serverName: String,
    val endpointHost: String,
    val endpointPort: Int,
    val publicKey: String
)

object WireGuardConfigParser {
    /**
     * Parses the subset of a WireGuard .conf the app needs. Returns null when the file is not
     * a usable WireGuard profile — the caller must refuse it rather than pretend.
     */
    fun parse(raw: String): WireGuardProfile? = runCatching {
        var endpoint: Pair<String, Int>? = null
        var publicKey: String? = null
        var name = "Imported profile"
        for (line in raw.lineSequence()) {
            val l = line.trim()
            if (l.isEmpty() || l.startsWith("#")) continue
            val key = l.substringBefore('=').trim().lowercase()
            val value = l.substringAfter('=').trim()
            when (key) {
                "endpoint" -> {
                    val host = value.substringBeforeLast(':')
                    val port = value.substringAfterLast(':').toIntOrNull() ?: 51820
                    endpoint = host to port
                }
                "publickey" -> publicKey = value
            }
        }
        val ep = endpoint ?: return null
        WireGuardProfile(
            serverName = name,
            endpointHost = ep.first,
            endpointPort = ep.second,
            publicKey = publicKey ?: return null
        )
    }.getOrNull()
}

object VpnServerSelection {
    /** Fastest = lowest real measured latency among servers that answered. Never a guess. */
    fun fastest(servers: List<VpnServer>): VpnServer? =
        servers.filter { it.measuredLatencyMs != null }
            .minByOrNull { it.measuredLatencyMs!! }

    /** Servers sorted for display: measured first by latency, unmeasured last (honest nulls). */
    fun sortedForDisplay(servers: List<VpnServer>): List<VpnServer> =
        servers.sortedWith(
            compareBy<VpnServer> { it.measuredLatencyMs == null }
                .thenBy { it.measuredLatencyMs ?: Long.MAX_VALUE }
                .thenBy { it.country }.thenBy { it.city }
        )

    /** Distinct countries present in the catalog, for the global filter row. */
    fun countriesOf(servers: List<VpnServer>): List<String> =
        servers.map { it.country }.distinct().sorted()

    /** Fastest measured server within one country; null when none measured there. */
    fun fastestInCountry(servers: List<VpnServer>, country: String): VpnServer? =
        fastest(servers.filter { it.country.equals(country, ignoreCase = true) })

    /**
     * Deterministic pseudo-geographic pin position for the globe (0..1 range). Stable per
     * server id so pins don't jump between recompositions. Pure — unit-tested.
     */
    fun globePin(id: String): Pair<Float, Float> {
        var h = 0
        for (c in id) h = (h * 31 + c.code)
        val x = ((h and 0x3FFF).toFloat() / 0x3FFF.toFloat()).coerceIn(0.05f, 0.95f)
        var h2 = 0
        for (c in id.reversed()) h2 = (h2 * 37 + c.code)
        val y = ((h2 and 0x3FFF).toFloat() / 0x3FFF.toFloat()).coerceIn(0.12f, 0.88f)
        return x to y
    }

    /** Nearest server pin to a tapped globe point (0..1 coords), within [tolerance]; null if none. */
    fun nearestPin(servers: List<VpnServer>, x: Float, y: Float, tolerance: Float = 0.09f): VpnServer? {
        return servers.minByOrNull { s ->
            val (px, py) = globePin(s.id)
            val dx = px - x; val dy = py - y
            dx * dx + dy * dy
        }?.takeIf { s ->
            val (px, py) = globePin(s.id)
            val dx = px - x; val dy = py - y
            dx * dx + dy * dy <= tolerance * tolerance
        }
    }
}
