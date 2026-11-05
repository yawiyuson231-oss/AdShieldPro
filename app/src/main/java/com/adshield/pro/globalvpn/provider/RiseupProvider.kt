package com.adshield.pro.globalvpn.provider

import com.adshield.pro.globalvpn.model.ProviderId
import com.adshield.pro.globalvpn.model.ProviderIntegration
import com.adshield.pro.globalvpn.model.VpnProtocol
import com.adshield.pro.globalvpn.model.VpnServer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Request
import javax.inject.Inject
import javax.inject.Singleton

/**
 * RiseupVPN gateway discovery via the official LEAP public API. Gateways speak OpenVPN and require
 * per-client certificates provisioned over a pinned CA; neither the OpenVPN engine nor that
 * certificate provisioning is bundled, so entries are discovery-only and clearly labelled.
 */
@Singleton
class RiseupProvider @Inject constructor() : VpnProviderAdapter {
    override val id: ProviderId = ProviderId.RISEUP
    override val integration: ProviderIntegration = ProviderIntegration.REAL_DISCOVERY_EXPORT_ONLY
    override val protocols: List<VpnProtocol> = listOf(VpnProtocol.OPENVPN)

    override val freePlanNotes: String =
        "Free, donation-run collective. Gateways are real and published by the LEAP API. Connecting " +
            "requires the official RiseupVPN client (OpenVPN + certificate provisioning), which is not bundled."

    override val setupInstructions: List<String> = listOf(
        "Refresh to list the live LEAP gateways and their locations.",
        "For an actual RiseupVPN session use the official RiseupVPN app (in-app OpenVPN engine is not bundled)."
    )

    private val json = Json { ignoreUnknownKeys = true }

    override suspend fun discover(): List<VpnServer> = withContext(Dispatchers.IO) {
        val apiBase = fetchApiBase()
        val eipUrl = apiBase.trimEnd('/') + "/config/eip-service.json"
        val request = Request.Builder().url(eipUrl).get().build()
        ProviderHttp.client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) error("Riseup LEAP API returned HTTP ${response.code}")
            val body = response.body?.string() ?: error("Empty Riseup response")
            val root = json.parseToJsonElement(body).jsonObject
            val gateways = root["gateways"]?.jsonArray ?: return@use emptyList()
            gateways.mapNotNull { element ->
                val gateway = element.jsonObject
                val host = gateway["host"]?.jsonPrimitive?.content ?: return@mapNotNull null
                val ip = gateway["ip_address"]?.jsonPrimitive?.content ?: host
                val location = gateway["location"]?.jsonPrimitive?.content ?: "Unknown"
                val transport = gateway["capabilities"]?.jsonObject?.get("transport")?.jsonArray
                val openVpn = transport?.firstOrNull {
                    it.jsonObject["type"]?.jsonPrimitive?.content == "openvpn"
                }?.jsonObject ?: return@mapNotNull null
                val ports = openVpn["ports"]?.jsonArray?.mapNotNull { it.jsonPrimitive.content.toIntOrNull() }
                val port = ports?.firstOrNull() ?: 443
                VpnServer(
                    id = "riseup-$host-$port",
                    provider = ProviderId.RISEUP,
                    protocol = VpnProtocol.OPENVPN,
                    displayName = "Riseup · $location",
                    countryCode = "UN",
                    countryName = location,
                    city = location,
                    endpointHost = ip,
                    endpointPort = port,
                    isConnectable = false,
                    unavailableReason = "OpenVPN engine + Riseup certificate provisioning not bundled.",
                    configRef = null
                )
            }
        }
    }

    private fun fetchApiBase(): String {
        val request = Request.Builder().url(PROVIDER_JSON_URL).get().build()
        return runCatching {
            ProviderHttp.client.newCall(request).execute().use { response ->
                val body = response.body?.string()
                val apiUri = body?.let {
                    json.parseToJsonElement(it).jsonObject["api_uri"]?.jsonPrimitive?.content
                }
                apiUri ?: DEFAULT_API_BASE
            }
        }.getOrDefault(DEFAULT_API_BASE)
    }

    companion object {
        const val PROVIDER_JSON_URL = "https://riseup.net/provider.json"
        const val DEFAULT_API_BASE = "https://api.black.riseup.net/3"
    }
}
