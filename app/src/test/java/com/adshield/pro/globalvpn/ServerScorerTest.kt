package com.adshield.pro.globalvpn

import com.adshield.pro.globalvpn.engine.ServerScorer
import com.adshield.pro.globalvpn.model.GlobalVpnSettings
import com.adshield.pro.globalvpn.model.ProviderId
import com.adshield.pro.globalvpn.model.ServerProbe
import com.adshield.pro.globalvpn.model.VpnProtocol
import com.adshield.pro.globalvpn.model.VpnServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerScorerTest {

    private fun server(
        id: String,
        latency: Long? = null,
        load: Int? = null,
        connectable: Boolean = true
    ) = VpnServer(
        id = id,
        provider = ProviderId.SELF_HOSTED,
        protocol = VpnProtocol.WIREGUARD,
        displayName = id,
        countryCode = "US",
        countryName = "United States",
        endpointHost = "$id.example.com",
        endpointPort = 51820,
        loadPercent = load,
        measuredLatencyMs = latency,
        isConnectable = connectable
    )

    @Test
    fun lowerLatencyRanksHigher() {
        val fast = server("fast", latency = 20)
        val slow = server("slow", latency = 300)
        val ranked = ServerScorer.rank(listOf(slow, fast), emptyMap(), GlobalVpnSettings())
        assertEquals("fast", ranked.first().server.id)
    }

    @Test
    fun lowerLoadRanksHigher() {
        val busy = server("busy", latency = 50, load = 95)
        val idle = server("idle", latency = 50, load = 10)
        val ranked = ServerScorer.rank(listOf(busy, idle), emptyMap(), GlobalVpnSettings())
        assertEquals("idle", ranked.first().server.id)
    }

    @Test
    fun fastestConnectableSkipsNonConnectable() {
        val openVpn = server("ovpn", latency = 5, connectable = false)
        val wg = server("wg", latency = 80, connectable = true)
        val best = ServerScorer.fastestConnectable(listOf(openVpn, wg), emptyMap(), GlobalVpnSettings())
        assertEquals("wg", best?.server?.id)
    }

    @Test
    fun fastestConnectableNullWhenNone() {
        val openVpn = server("ovpn", connectable = false)
        assertNull(ServerScorer.fastestConnectable(listOf(openVpn), emptyMap(), GlobalVpnSettings()))
    }

    @Test
    fun probeHistoryTracksFailures() {
        val history = ServerScorer.ProbeHistory()
            .record(ServerProbe("s", false, null, "tcp", 0))
            .record(ServerProbe("s", false, null, "tcp", 1))
        assertEquals(2, history.failures)
    }

    @Test
    fun probeHistoryDetectsRisingCongestion() {
        var history = ServerScorer.ProbeHistory()
        repeat(5) { history = history.record(ServerProbe("s", true, 20, "tcp", it.toLong())) }
        repeat(5) { history = history.record(ServerProbe("s", true, 120, "tcp", it.toLong())) }
        assertEquals(ServerScorer.CongestionTrend.RISING, history.trend())
    }

    @Test
    fun jitterIsAverageAbsoluteDifference() {
        assertEquals(10L, ServerScorer.jitterMs(listOf(10, 20, 30)))
    }

    @Test
    fun scoreIsBounded() {
        val scored = ServerScorer.score(server("s", latency = 1, load = 0), null, GlobalVpnSettings())
        assertTrue(scored.score in 0..100)
    }
}
