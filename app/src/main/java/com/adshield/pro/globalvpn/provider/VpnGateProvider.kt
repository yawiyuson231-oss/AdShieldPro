package com.adshield.pro.globalvpn.provider

import com.adshield.pro.globalvpn.model.ProviderId
import com.adshield.pro.globalvpn.model.ProviderIntegration
import com.adshield.pro.globalvpn.model.VpnProtocol
import com.adshield.pro.globalvpn.model.VpnServer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * VPN Gate (University of Tsukuba) public volunteer relay directory. Discovery is real and uses the
 * official public CSV API. The relays speak OpenVPN, and the in-app OpenVPN engine is not bundled,
 * so these entries are discovery + export only and are clearly labelled as not connectable in-app.
 */
@Singleton
class VpnGateProvider @Inject constructor() : VpnProviderAdapter {
    override val id: ProviderId = ProviderId.VPNGATE
    override val integration: ProviderIntegration = ProviderIntegration.REAL_DISCOVERY_EXPORT_ONLY
    override val protocols: List<VpnProtocol> = listOf(VpnProtocol.OPENVPN)

    override val freePlanNotes: String =
        "Free, no account. Volunteer-operated relays: availability, speed and logging policy vary by " +
            "operator and are shown as published. Treat volunteer relays as untrusted for sensitive traffic."

    override val setupInstructions: List<String> = listOf(
        "Refresh to load the live public relay list.",
        "Pick a country/server and export its official OpenVPN configuration.",
        "Open the exported .ovpn in an OpenVPN client (the in-app OpenVPN engine is not bundled)."
    )

    private val configs = ConcurrentHashMap<String, String>()

    override suspend fun discover(): List<VpnServer> = withContext(Dispatchers.IO) {
        val request = Request.Builder().url(OFFICIAL_CSV_URL).get().build()
        ProviderHttp.client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) error("VPN Gate API returned HTTP ${response.code}")
            val body = response.body?.string() ?: error("Empty VPN Gate response")
            val entries = VpnGateCsvParser.parse(body)
            configs.clear()
            entries.map { entry ->
                configs[entry.id] = entry.openVpnConfig
                VpnServer(
                    id = entry.id,
                    provider = ProviderId.VPNGATE,
                    protocol = VpnProtocol.OPENVPN,
                    displayName = "${entry.countryLong} · ${entry.hostName}",
                    countryCode = entry.countryShort,
                    countryName = entry.countryLong,
                    city = null,
                    endpointHost = entry.ip,
                    endpointPort = entry.port,
                    loadPercent = null,
                    reportedPingMs = entry.pingMs,
                    reportedSpeedMbps = entry.speedMbps,
                    isConnectable = false,
                    unavailableReason = "OpenVPN engine not bundled — export the config to an OpenVPN client.",
                    configRef = entry.id
                )
            }
        }
    }

    override fun exportConfig(serverId: String): String? = configs[serverId]

    companion object {
        const val OFFICIAL_CSV_URL = "https://www.vpngate.net/api/iphone/"
    }
}
