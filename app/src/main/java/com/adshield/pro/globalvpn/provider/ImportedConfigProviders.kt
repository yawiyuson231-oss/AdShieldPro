package com.adshield.pro.globalvpn.provider

import com.adshield.pro.globalvpn.data.SecureTunnelVault
import com.adshield.pro.globalvpn.model.ProviderId
import com.adshield.pro.globalvpn.model.ProviderIntegration
import com.adshield.pro.globalvpn.model.VpnProtocol
import com.adshield.pro.globalvpn.model.VpnServer
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Base for providers whose supported third-party path is importing an official WireGuard
 * configuration. Servers come only from the encrypted vault — nothing is invented.
 */
abstract class ImportedConfigProvider(
    private val vault: SecureTunnelVault,
    override val id: ProviderId
) : VpnProviderAdapter {

    override val integration: ProviderIntegration = ProviderIntegration.REAL_WIREGUARD_IMPORT
    override val protocols: List<VpnProtocol> = listOf(VpnProtocol.WIREGUARD)

    override suspend fun discover(): List<VpnServer> =
        vault.list()
            .filter { it.provider == id && it.protocol == VpnProtocol.WIREGUARD }
            .map { stored ->
                VpnServer(
                    id = stored.id,
                    provider = id,
                    protocol = VpnProtocol.WIREGUARD,
                    displayName = stored.name,
                    countryCode = stored.countryCode,
                    countryName = stored.countryName,
                    city = stored.city,
                    endpointHost = stored.endpointHost,
                    endpointPort = stored.endpointPort,
                    isConnectable = true,
                    configRef = stored.id
                )
            }
}

@Singleton
class ProtonProvider @Inject constructor(
    vault: SecureTunnelVault
) : ImportedConfigProvider(vault, ProviderId.PROTON) {

    override val freePlanNotes: String =
        "Proton VPN Free allows a limited set of free servers and one device. Import the official " +
            "WireGuard configuration for a FREE server; paid-only servers are not bypassed."

    override val setupInstructions: List<String> = listOf(
        "Sign in at account.protonvpn.com in a browser.",
        "Open Downloads → WireGuard configuration.",
        "Choose a FREE server, create the configuration and download the .conf file.",
        "Import that .conf here. The private key is stored encrypted on this device only."
    )
}

@Singleton
class SelfHostedProvider @Inject constructor(
    vault: SecureTunnelVault
) : ImportedConfigProvider(vault, ProviderId.SELF_HOSTED) {

    override val freePlanNotes: String =
        "Your own WireGuard server (for example on an always-free cloud VM). You control the exit " +
            "country and there are no third-party data limits."

    override val setupInstructions: List<String> = listOf(
        "Install WireGuard on a server you control (wg-quick / wg-easy / PiVPN).",
        "Generate a client configuration and note its public endpoint and country.",
        "Import the client .conf (or paste it) here.",
        "Connect. The tunnel terminates at your server, so the exit IP is yours."
    )
}
