package com.adshield.pro

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.ProtectionArchitecture
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.ui.model.ExplainerPoint
import com.adshield.pro.ui.model.ProtectionExplainer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guards the "How protection works" screen against the two ways an explainer goes wrong: it drifts
 * away from the tunnel the app actually installs, or it flatters the product into claiming a
 * capability (IP masking, traffic inspection) that no line of code implements.
 */
class ProtectionExplainerTest {

    private fun allPoints(): List<ExplainerPoint> =
        ProtectionExplainer.ROUTES +
            ProtectionExplainer.WHY_THE_KEY_ICON +
            ProtectionExplainer.CAN_DO +
            ProtectionExplainer.CANNOT_DO +
            ProtectionExplainer.BLOCK_ANSWERS +
            ProtectionExplainer.UPSTREAM_MODES

    @Test
    fun testRoutesNeverIncludeADefaultRoute() {
        val routes = ProtectionArchitecture.routes
        assertEquals("both address families must be described", 2, routes.size)
        assertTrue(
            "a default route would pull every packet into the tunnel",
            routes.none { it.isDefaultRoute }
        )
        assertEquals(
            "IPv4 must stay a single-address /32",
            ProtectionArchitecture.IPV4_DNS_ADDRESS + "/32",
            routes.first { it.family == "IPv4" }.cidr
        )
        assertEquals(
            "IPv6 must stay a single-address /128",
            ProtectionArchitecture.IPV6_DNS_ADDRESS + "/128",
            routes.first { it.family == "IPv6" }.cidr
        )
        // The rendered sentence must name every routed address, so the screen cannot describe
        // a tunnel different from the one the service builds.
        routes.forEach { route ->
            assertTrue(
                "route sentence omits ${route.cidr}",
                ProtectionExplainer.ROUTE_SENTENCE.contains(route.cidr)
            )
        }
        assertTrue(
            "the sentence must say non-DNS traffic is not routed",
            ProtectionExplainer.ROUTE_SENTENCE.contains("no route")
        )
    }

    @Test
    fun testEveryProtectionModeAndProtocolIsExplained() {
        assertEquals(
            "every protection mode must have a blocked-answer row",
            ProtectionMode.entries.size,
            ProtectionExplainer.BLOCK_ANSWERS.size
        )
        ProtectionMode.entries.forEach { mode ->
            val row = ProtectionExplainer.BLOCK_ANSWERS.first { it.title == mode.title }
            assertEquals(
                "${mode.name}: sinkhole answer must match blockSinkholeZeroIp",
                mode.blockSinkholeZeroIp,
                row.detail.contains("0.0.0.0")
            )
            if (!mode.blockSinkholeZeroIp) {
                assertTrue("${mode.name}: NXDOMAIN modes must say NXDOMAIN", row.detail.contains("NXDOMAIN"))
            }
            assertEquals(
                "${mode.name}: cloaking wording must match enforceCnameCloaking",
                mode.enforceCnameCloaking,
                row.detail.contains("blocked tracker")
            )
        }

        assertEquals(
            "every upstream protocol must be listed",
            DnsProtocol.entries.size,
            ProtectionExplainer.UPSTREAM_MODES.size
        )
        DnsProtocol.entries.forEach { protocol ->
            assertTrue(
                "missing upstream mode ${protocol.name}",
                ProtectionExplainer.UPSTREAM_MODES.any { it.title == protocol.label }
            )
        }
        assertTrue(
            "the plaintext option must never be described as the default",
            ProtectionExplainer.UPSTREAM_MODES
                .first { it.title == DnsProtocol.UDP_TCP.label }
                .detail
                .contains("UDP/TCP")
        )
    }

    @Test
    fun testExplainerNeverClaimsIpMasking() {
        val positiveClaims = ProtectionExplainer.CAN_DO.map { "${it.title} ${it.detail}".lowercase() }
        val forbidden = listOf("hide your ip", "change your location", "unblock", "exit server")
        forbidden.forEach { phrase ->
            assertFalse(
                "the can-do list must not claim '$phrase'",
                positiveClaims.any { it.contains(phrase) }
            )
        }
        // ...and the limits must say it explicitly instead of leaving it ambiguous.
        assertTrue(
            "IP masking must appear as an explicit limitation",
            ProtectionExplainer.CANNOT_DO.any { it.title.contains("IP address", ignoreCase = true) }
        )
        assertTrue(
            "decryption must appear as an explicit limitation",
            ProtectionExplainer.CANNOT_DO.any { it.title.contains("HTTPS", ignoreCase = true) }
        )
        assertTrue(
            "the summary must state there is no remote server",
            ProtectionExplainer.SUMMARY.contains("no remote VPN server", ignoreCase = true)
        )
    }

    @Test
    fun testAllExplainerTextIsNonBlank() {
        allPoints().forEach { point ->
            assertTrue("blank title", point.title.isNotBlank())
            assertTrue("blank detail for '${point.title}'", point.detail.isNotBlank())
        }
        assertTrue("flow must be described", ProtectionExplainer.FLOW.size >= 4)
        assertTrue("flow steps must be non-blank", ProtectionExplainer.FLOW.none { it.isBlank() })
        assertTrue("why-the-key-icon section must not be empty", ProtectionExplainer.WHY_THE_KEY_ICON.isNotEmpty())
        assertTrue("limits section must not be empty", ProtectionExplainer.CANNOT_DO.isNotEmpty())
        assertTrue(
            "the upstream note must explain the no-downgrade rule",
            ProtectionExplainer.UPSTREAM_NOTE.contains("plaintext", ignoreCase = true)
        )
        assertTrue(
            "the client-subnet note must name the option it removes",
            ProtectionExplainer.CLIENT_SUBNET_NOTE.contains("EDNS Client Subnet")
        )
        assertTrue(
            "resilience must be described as behaviour, not a promise",
            ProtectionExplainer.RESILIENCE_POINTS.size >= 3 &&
                ProtectionExplainer.RESILIENCE_POINTS.all { it.detail.isNotBlank() }
        )
        assertTrue(
            "the resilience note must name the fallback instead of hiding it",
            ProtectionExplainer.RESILIENCE_NOTE.contains("stale", ignoreCase = true)
        )
        assertTrue(
            "the rebinding note must name the modes that enforce it",
            ProtectionExplainer.REBINDING_NOTE.contains("Strict and Custom")
        )
        assertTrue(
            "the video-ad note must state the in-host limitation",
            ProtectionExplainer.VIDEO_ADS_NOTE.contains("YouTube") &&
                ProtectionExplainer.VIDEO_ADS_NOTE.contains("no DNS filter")
        )
        assertTrue(
            "the client-subnet note must keep the streaming exception honest",
            ProtectionExplainer.CLIENT_SUBNET_NOTE.contains("streaming", ignoreCase = true)
        )
    }
}
