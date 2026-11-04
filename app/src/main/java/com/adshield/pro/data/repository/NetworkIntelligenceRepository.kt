package com.adshield.pro.data.repository

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/** Live network facts available without location, Wi-Fi SSID, or packet-capture privileges. */
@Singleton
class NetworkIntelligenceRepository @Inject constructor(
    @ApplicationContext private val context: Context
) {
    data class NetworkAudit(
        val transport: String = "Unknown",
        val validated: Boolean? = null,
        val captivePortalDetected: Boolean = false,
        val systemDnsServers: List<String> = emptyList(),
        val wifiSecurityAssessment: String = "No active Wi-Fi assessment available.",
        val dnsConsistency: String = "No active network DNS data.",
        val measuredAtEpochMs: Long = 0L
    )

    private val _audit = MutableStateFlow(NetworkAudit())
    val audit: StateFlow<NetworkAudit> = _audit.asStateFlow()

    suspend fun refresh(): NetworkAudit = withContext(Dispatchers.IO) {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val network = manager?.activeNetwork
        val capabilities = if (manager != null && network != null) manager.getNetworkCapabilities(network) else null
        val link = if (manager != null && network != null) manager.getLinkProperties(network) else null
        val transport = when {
            capabilities == null -> "Offline / unavailable"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
            else -> "Other transport"
        }
        val validated = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        val captive = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) == true
        val servers = link?.dnsServers?.mapNotNull { it.hostAddress }?.distinct().orEmpty()
        val isWifi = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        val result = NetworkAudit(
            transport = transport,
            validated = validated,
            captivePortalDetected = captive,
            systemDnsServers = servers,
            wifiSecurityAssessment = when {
                !isWifi -> "Wi-Fi is not the active transport."
                captive -> "Android reports a captive portal. Complete sign-in before relying on encrypted DNS."
                else -> "Wi-Fi transport detected. Android does not expose the access-point encryption type through this permission set; WPA/WPA2/WPA3 is therefore UNKNOWN, not assumed secure."
            },
            dnsConsistency = when {
                capabilities == null -> "No active network to assess."
                servers.isEmpty() -> "Android exposed no system DNS server list; leak status is UNKNOWN. Private app DoH can still bypass system DNS."
                else -> "System DNS path: ${servers.joinToString()}. OmniShield's local tunnel receives apps using OS DNS; hardcoded app DoH/DoQ remains outside its visibility."
            },
            measuredAtEpochMs = System.currentTimeMillis()
        )
        _audit.value = result
        result
    }
}
