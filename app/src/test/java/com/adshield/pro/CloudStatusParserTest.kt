package com.adshield.pro

import com.adshield.pro.engine.cloud.CloudConnection
import com.adshield.pro.engine.cloud.CloudProvider
import com.adshield.pro.engine.cloud.CloudStatusParser
import com.adshield.pro.engine.cloud.CloudStatusState
import com.adshield.pro.engine.cloud.ServiceIndicator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Cloud status is the provider's own published operational data. Unchecked providers must stay
 * "not connected"; incidents must map to the right indicator; malformed payloads must raise.
 */
class CloudStatusParserTest {

    private val operationalFixture = """
        {
          "page": {
            "id": "kctbh9vrtdwd",
            "name": "GitHub",
            "url": "https://www.githubstatus.com",
            "time_zone": "Etc/UTC",
            "updated_at": "2024-05-01T12:00:00.000Z"
          },
          "status": {
            "indicator": "none",
            "description": "All Systems Operational"
          },
          "components": [
            { "name": "Git Operations", "status": "operational" },
            { "name": "API Requests", "status": "operational" },
            { "name": "Actions", "status": "degraded_performance" }
          ]
        }
    """.trimIndent()

    @Test
    fun operationalPayload_parsesIndicatorComponentsAndProviderTimestamp() {
        val status = CloudStatusParser.parse(CloudProvider.GITHUB, operationalFixture, fetchedAtEpochMs = 123L)
        assertEquals(CloudConnection.CONNECTED, status.connection)
        assertEquals(ServiceIndicator.NONE, status.indicator)
        assertTrue(status.indicator.operational)
        assertEquals("All Systems Operational", status.description)
        assertEquals(3, status.components.size)
        assertEquals(1, status.components.count { !it.healthy })
        assertEquals("2024-05-01T12:00:00.000Z", status.providerUpdatedAt)
        assertEquals(123L, status.fetchedAtEpochMs)
    }

    @Test
    fun incidentIndicators_mapToNonOperational() {
        listOf("minor" to ServiceIndicator.MINOR, "major" to ServiceIndicator.MAJOR, "critical" to ServiceIndicator.CRITICAL).forEach { (raw, expected) ->
            val payload = """{"status":{"indicator":"$raw","description":"Incident"},"components":[]}"""
            val status = CloudStatusParser.parse(CloudProvider.CLOUDFLARE, payload, 1L)
            assertEquals(expected, status.indicator)
            assertFalse(status.indicator.operational)
        }
        val maintenance = CloudStatusParser.parse(
            CloudProvider.NPM,
            """{"status":{"indicator":"maintenance","description":"Maintenance"},"components":[]}""",
            1L
        )
        assertEquals(ServiceIndicator.MAINTENANCE, maintenance.indicator)
        assertTrue(maintenance.indicator.operational)
    }

    @Test
    fun unknownIndicator_isNotAssumedOperational() {
        val status = CloudStatusParser.parse(
            CloudProvider.BITBUCKET,
            """{"status":{"indicator":"weird","description":"?"},"components":[]}""",
            1L
        )
        assertEquals(ServiceIndicator.UNKNOWN, status.indicator)
        assertFalse(status.indicator.operational)
    }

    @Test
    fun malformedPayloads_raiseTypedException() {
        listOf("", "   ", "not json", "[1,2]", """{"no_status":true}""").forEach { raw ->
            try {
                CloudStatusParser.parse(CloudProvider.GITHUB, raw, 1L)
                throw AssertionError("expected CloudParseException for: $raw")
            } catch (e: CloudStatusParser.CloudParseException) {
                assertTrue(e.message!!.contains("GitHub"))
            }
        }
    }

    @Test
    fun defaultState_isNotConnectedAndClaimsNothing() {
        val state = CloudStatusState()
        assertEquals(CloudProvider.entries.size, state.services.size)
        assertTrue(state.services.all { it.connection == CloudConnection.NOT_CHECKED })
        assertEquals(0, state.connectedCount)
        assertEquals(0, state.incidentCount)
    }

    @Test
    fun incidentCount_onlyCountsConnectedProvidersWithIncidents() {
        val state = CloudStatusState(
            services = listOf(
                CloudStatusParser.parse(CloudProvider.GITHUB, operationalFixture, 1L),
                CloudStatusParser.parse(
                    CloudProvider.CLOUDFLARE,
                    """{"status":{"indicator":"major","description":"Outage"},"components":[]}""",
                    1L
                ),
                com.adshield.pro.engine.cloud.CloudServiceStatus(CloudProvider.NPM)
            )
        )
        assertEquals(2, state.connectedCount)
        assertEquals(1, state.incidentCount)
    }
}
