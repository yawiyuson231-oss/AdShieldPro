package com.adshield.pro.globalvpn.provider

import com.adshield.pro.globalvpn.model.ProviderId
import com.adshield.pro.globalvpn.model.ProviderIntegration
import com.adshield.pro.globalvpn.model.VpnProtocol
import com.adshield.pro.globalvpn.model.VpnServer

/**
 * A provider adapter never fabricates servers. [discover] returns only real entries: imported
 * official configurations, or live data from a provider's official public API. When a provider
 * cannot be used on a free plan it returns an empty list and its [integration] explains why.
 */
interface VpnProviderAdapter {
    val id: ProviderId
    val integration: ProviderIntegration
    val protocols: List<VpnProtocol>
    val freePlanNotes: String
    val setupInstructions: List<String>

    suspend fun discover(): List<VpnServer>

    /** Returns a real configuration for export when the in-app engine cannot dial it. */
    fun exportConfig(serverId: String): String? = null
}
