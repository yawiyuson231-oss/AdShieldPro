package com.adshield.pro

import com.adshield.pro.vpn.FeatureStatus
import com.adshield.pro.vpn.VpnProtocol
import com.adshield.pro.vpn.VpnServer
import com.adshield.pro.vpn.VpnServerSelection
import com.adshield.pro.vpn.WireGuardConfigParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * JVM coverage for the global VPN module's pure logic: fastest-server selection is driven only
 * by real measured latency, the WireGuard parser refuses garbage, and feature statuses are the
 * honest enum (never a simulated "WORKING").
 */
class VpnEngineTestSuite {

    private fun server(id: String, latency: Long?) = VpnServer(
        id = id, name = id, country = "X", city = "Y",
        host = "192.0.2.$id", port = 51820, protocol = VpnProtocol.WIREGUARD,
        measuredLatencyMs = latency
    )

    @Test
    fun testFastest_picksLowestMeasuredLatencyOnly() {
        val servers = listOf(server("a", 120L), server("b", 45L), server("c", null), server("d", 300L))
        assertEquals("b", VpnServerSelection.fastest(servers)?.id)
    }

    @Test
    fun testFastest_isNullWhenNothingMeasured() {
        assertNull(VpnServerSelection.fastest(listOf(server("a", null), server("b", null))))
        assertNull(VpnServerSelection.fastest(emptyList()))
    }

    @Test
    fun testDisplaySort_measuredFirstThenUnmeasured() {
        val sorted = VpnServerSelection.sortedForDisplay(
            listOf(server("c", null), server("a", 120L), server("b", 45L))
        )
        assertEquals(listOf("b", "a", "c"), sorted.map { it.id })
    }

    @Test
    fun testWireGuardParser_acceptsValidProfile() {
        val conf = """
            [Interface]
            PrivateKey = cPRIVATE=
            Address = 10.0.0.2/32
            [Peer]
            PublicKey = cHVibGljMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=
            Endpoint = vpn.example.com:51820
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()
        val profile = WireGuardConfigParser.parse(conf)
        assertNotNull(profile)
        assertEquals("vpn.example.com", profile!!.endpointHost)
        assertEquals(51820, profile.endpointPort)
        assertEquals("cHVibGljMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=", profile.publicKey)
    }

    @Test
    fun testWireGuardParser_rejectsGarbage() {
        assertNull(WireGuardConfigParser.parse("not a config"))
        assertNull(WireGuardConfigParser.parse("[Peer]\nPublicKey = abc"))
        assertNull(WireGuardConfigParser.parse(""))
    }

    @Test
    fun testCountryList_coversAllCountriesAndValidates() {
        // near-complete ISO 3166-1 coverage, all unique
        org.junit.Assert.assertTrue(com.adshield.pro.vpn.CountryList.ALL.size >= 190)
        org.junit.Assert.assertEquals(
            com.adshield.pro.vpn.CountryList.ALL.size,
            com.adshield.pro.vpn.CountryList.ALL.toSet().size
        )
        org.junit.Assert.assertTrue(com.adshield.pro.vpn.CountryList.isValid("Philippines"))
        org.junit.Assert.assertTrue(com.adshield.pro.vpn.CountryList.isValid("Japan"))
        org.junit.Assert.assertFalse(com.adshield.pro.vpn.CountryList.isValid("Atlantis"))
    }

    @Test
    fun testFastestInCountry_scopedSelection() {
        val servers = listOf(
            server("a", 120L).copy(country = "Japan"),
            server("b", 45L).copy(country = "Japan"),
            server("c", 10L).copy(country = "Philippines")
        )
        assertEquals("b", VpnServerSelection.fastestInCountry(servers, "Japan")?.id)
        assertEquals("c", VpnServerSelection.fastestInCountry(servers, "philippines")?.id)
        assertNull(VpnServerSelection.fastestInCountry(servers, "Germany"))
        assertEquals(listOf("Japan", "Philippines"), VpnServerSelection.countriesOf(servers))
    }

    @Test
    fun testGlobePin_isDeterministicAndInBounds() {
        val p1 = VpnServerSelection.globePin("server-1")
        val p2 = VpnServerSelection.globePin("server-1")
        org.junit.Assert.assertEquals(p1, p2)
        org.junit.Assert.assertTrue(p1.first in 0.05f..0.95f)
        org.junit.Assert.assertTrue(p1.second in 0.12f..0.88f)
        org.junit.Assert.assertNotEquals(p1, VpnServerSelection.globePin("server-2"))
    }

    @Test
    fun testNearestPin_hitAndMiss() {
        val s = server("a", 50L)
        val (px, py) = VpnServerSelection.globePin("a")
        assertEquals("a", VpnServerSelection.nearestPin(listOf(s), px, py)?.id)
        assertEquals("a", VpnServerSelection.nearestPin(listOf(s), px + 0.03f, py)?.id)
        assertNull(VpnServerSelection.nearestPin(listOf(s), 0.01f, 0.01f))
        assertNull(VpnServerSelection.nearestPin(emptyList(), px, py))
    }

    @Test
    fun testFeatureStatus_labelsAreHonest() {
        assertEquals("SERVER REQUIRED", FeatureStatus.SERVER_REQUIRED.label)
        assertEquals("ANDROID LIMITATION", FeatureStatus.ANDROID_LIMITATION.label)
        assertEquals("NOT IMPLEMENTED", FeatureStatus.NOT_IMPLEMENTED.label)
        assertEquals("WORKING", FeatureStatus.WORKING.label)
    }
}
