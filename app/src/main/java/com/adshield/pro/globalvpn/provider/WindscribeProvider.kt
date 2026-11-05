package com.adshield.pro.globalvpn.provider

import com.adshield.pro.globalvpn.model.ProviderId
import com.adshield.pro.globalvpn.model.ProviderIntegration
import com.adshield.pro.globalvpn.model.VpnProtocol
import com.adshield.pro.globalvpn.model.VpnServer
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Windscribe's free tier does not expose manual WireGuard/OpenVPN configurations (config generation
 * is a paid feature) and there is no official free third-party API. Rather than invent servers or
 * scrape a private API, this adapter is honestly marked unavailable. If the user already has a
 * legitimately obtained Windscribe WireGuard config, they can import it under Self-hosted.
 */
@Singleton
class WindscribeProvider @Inject constructor() : VpnProviderAdapter {
    override val id: ProviderId = ProviderId.WINDSCRIBE
    override val integration: ProviderIntegration = ProviderIntegration.UNAVAILABLE_FREE_PLAN
    override val protocols: List<VpnProtocol> = listOf(VpnProtocol.WIREGUARD, VpnProtocol.OPENVPN)

    override val freePlanNotes: String =
        "Windscribe Free gives 10 GB/month in the official app, but manual WireGuard/OpenVPN config " +
            "generation requires a paid plan. No official free third-party API exists, so this source " +
            "is marked unavailable instead of faked."

    override val setupInstructions: List<String> = listOf(
        "Use the official Windscribe app for the free tier, or",
        "If you have a paid plan, download a WireGuard config and import it under Self-hosted WireGuard."
    )

    override suspend fun discover(): List<VpnServer> = emptyList()
}
