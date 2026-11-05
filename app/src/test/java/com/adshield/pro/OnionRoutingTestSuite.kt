package com.adshield.pro

import com.adshield.pro.engine.onion.OnionRoutingManager
import com.adshield.pro.engine.onion.TorState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetSocketAddress
import java.net.Proxy

/**
 * Onion routing tests.
 *
 * These cover the parts that decide whether a "Tor" claim is honest: the SOCKS proxy must be
 * unresolved (so .onion names never reach the device resolver) and Orbot's status broadcast must
 * map to states that can only be CONNECTED when Orbot itself says the circuit is up.
 */
class OnionRoutingTestSuite {

    @Test
    fun orbotStatusBroadcastMapsToHonestStates() {
        assertTrue(OnionRoutingManager.parseStatus("ON", null, null).isConnected)
        assertEquals(TorState.STARTING, OnionRoutingManager.parseStatus("STARTING", null, null).state)
        assertEquals(TorState.STOPPED, OnionRoutingManager.parseStatus("OFF", null, null).state)
        assertEquals(TorState.STOPPED, OnionRoutingManager.parseStatus(null, null, null).state)
        assertEquals(TorState.STOPPED, OnionRoutingManager.parseStatus("garbage", null, null).state)
        // Lower-case and mixed case arrive from different Orbot versions.
        assertEquals(TorState.CONNECTED, OnionRoutingManager.parseStatus("on", null, null).state)
        assertFalse(OnionRoutingManager.parseStatus("OFF", null, null).isConnected)
    }

    @Test
    fun proxyPortsFromOrbotAreUsedAndInvalidOnesFallBackToTheDefaults() {
        val custom = OnionRoutingManager.parseStatus("ON", 9150, 8119)
        assertEquals(9150, custom.socksPort)
        assertEquals(8119, custom.httpPort)

        val defaults = OnionRoutingManager.parseStatus("ON", 0, -1)
        assertEquals(OnionRoutingManager.DEFAULT_SOCKS_PORT, defaults.socksPort)
        assertEquals(OnionRoutingManager.DEFAULT_HTTP_PORT, defaults.httpPort)
    }

    @Test
    fun socksProxyIsUnresolvedSoOnionNamesNeverReachTheDeviceResolver() {
        val proxy = OnionRoutingManager.socksProxy(9050)
        assertEquals(Proxy.Type.SOCKS, proxy.type())
        val address = proxy.address() as InetSocketAddress
        assertTrue(address.isUnresolved)
        assertEquals(OnionRoutingManager.PROXY_HOST, address.hostString)
        assertEquals(9050, address.port)
    }

    @Test
    fun torIsVerifiedAgainstTorsOwnCheckService() {
        assertTrue(OnionRoutingManager.TOR_CHECK_URL.startsWith("https://check.torproject.org/"))
        assertEquals(
            listOf("org.torproject.android", "org.torproject.torbrowser_alpha"),
            OnionRoutingManager.KNOWN_TOR_PACKAGES
        )
        assertEquals(9050, OnionRoutingManager.DEFAULT_SOCKS_PORT)
        assertEquals(8118, OnionRoutingManager.DEFAULT_HTTP_PORT)
    }
}
