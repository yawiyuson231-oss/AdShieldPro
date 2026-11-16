package com.adshield.pro.domain.model

/**
 * The exact tunnel this app installs, described once.
 *
 * [com.adshield.pro.service.AdShieldDnsService] builds its `VpnService.Builder` from these values
 * and the in-app "How protection works" screen renders the same list. Keeping one source means the
 * explanation cannot drift away from the routes that are actually routed into the tunnel: change a
 * value here and both the tunnel and the screen change with it.
 */
object ProtectionArchitecture {

    /** Local IPv4 address handed to the TUN interface. */
    const val IPV4_CLIENT_ADDRESS = "10.215.173.1"
    const val IPV4_CLIENT_PREFIX = 30

    /** The single virtual IPv4 DNS address routed into the tunnel — a /32, never a default route. */
    const val IPV4_DNS_ADDRESS = "10.215.173.2"
    const val IPV4_DNS_PREFIX = 32

    /** Local IPv6 address, used only when IPv6 DNS is enabled in settings. */
    const val IPV6_CLIENT_ADDRESS = "fd00:ad5:1e1d::1"
    const val IPV6_CLIENT_PREFIX = 126

    /** The single virtual IPv6 DNS address routed into the tunnel — a /128, never a default route. */
    const val IPV6_DNS_ADDRESS = "fd00:ad5:1e1d::2"
    const val IPV6_DNS_PREFIX = 128

    /** The only transport port the packet loop answers on, for both UDP and TCP. */
    const val DNS_PORT = 53

    data class TunnelRoute(
        val address: String,
        val prefixLength: Int,
        val family: String
    ) {
        val cidr: String get() = "$address/$prefixLength"

        /**
         * A default route (0.0.0.0/0 or ::/0) would pull every packet on the device into the
         * tunnel. This app must never install one, and the JVM suite asserts it.
         */
        val isDefaultRoute: Boolean get() = prefixLength == 0
    }

    /** Every address routed into the TUN interface. Non-DNS traffic matches none of them. */
    val routes: List<TunnelRoute> = listOf(
        TunnelRoute(IPV4_DNS_ADDRESS, IPV4_DNS_PREFIX, "IPv4"),
        TunnelRoute(IPV6_DNS_ADDRESS, IPV6_DNS_PREFIX, "IPv6")
    )
}
