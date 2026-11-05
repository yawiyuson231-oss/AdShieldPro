package com.adshield.pro

import com.adshield.pro.engine.intel.IndicatorKind
import com.adshield.pro.engine.intel.IntelIndicator
import com.adshield.pro.engine.intel.IntelSource
import com.adshield.pro.engine.intel.ThreatIntelAggregation
import com.adshield.pro.engine.intel.ThreatIntelParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Feed parsers are tested against captured fixture payloads. Malformed input must raise a
 * typed exception (so the repository keeps its cache) rather than producing fake indicators.
 */
class ThreatIntelParserTest {

    private val feodoFixture = """
        [
          {
            "ip_address": "185.220.101.4",
            "port": 443,
            "status": "online",
            "hostname": "",
            "as_number": 60729,
            "as_name": "EXAMPLE-AS",
            "country": "RU",
            "first_seen_utc": "2024-01-01 00:00:00",
            "last_online": "2024-05-01",
            "malware": "QakBot"
          },
          {
            "ip_address": "45.155.205.99",
            "port": 8080,
            "status": "offline",
            "hostname": null,
            "as_number": 12345,
            "as_name": "OTHER-AS",
            "country": "US",
            "first_seen_utc": "2024-02-01 00:00:00",
            "last_online": "2024-04-01",
            "malware": "Emotet"
          },
          {
            "ip_address": "103.85.24.17",
            "port": 443,
            "status": "online",
            "country": "RU",
            "malware": "QakBot"
          },
          { "not_an_indicator": true },
          { "ip_address": "" }
        ]
    """.trimIndent()

    private val urlhausFixture = """
        {
          "123456": [
            {
              "id": "123456",
              "dateadded": "2024-05-01 12:00:00 UTC",
              "url": "http://malware.example.com/payload.exe",
              "url_status": "online",
              "threat": "malware_download",
              "tags": ["exe", "opendir"],
              "urlhaus_link": "https://urlhaus.abuse.ch/url/123456/",
              "reporter": "anonymous"
            }
          ],
          "123457": [
            {
              "id": "123457",
              "dateadded": "2024-05-01 13:00:00 UTC",
              "url": "https://bad.example.net:8443/dropper",
              "url_status": "offline",
              "threat": "malware_download",
              "tags": null,
              "urlhaus_link": "https://urlhaus.abuse.ch/url/123457/",
              "reporter": "abuse_ch"
            }
          ],
          "broken": "not-an-array"
        }
    """.trimIndent()

    @Test
    fun feodoParser_extractsIndicatorsWithCountryAndSkipsMalformedEntries() {
        val indicators = ThreatIntelParser.parseFeodo(feodoFixture)
        assertEquals(3, indicators.size)
        val first = indicators.first { it.value == "185.220.101.4" }
        assertEquals("RU", first.country)
        assertEquals("QakBot", first.malwareFamily)
        assertEquals(443, first.port)
        assertEquals(IndicatorKind.BOTNET_C2, first.kind)
        assertEquals(IntelSource.FEODO_TRACKER.id, first.sourceId)
        assertEquals("online", first.status)
        assertTrue(first.referenceUrl!!.contains("185.220.101.4"))
    }

    @Test
    fun feodoParser_rejectsNonArrayPayload() {
        try {
            ThreatIntelParser.parseFeodo("""{"unexpected": "object"}""")
            throw AssertionError("expected IntelParseException")
        } catch (e: ThreatIntelParser.IntelParseException) {
            assertTrue(e.message!!.contains("not a JSON array"))
        }
    }

    @Test
    fun feodoParser_rejectsMalformedJson() {
        try {
            ThreatIntelParser.parseFeodo("[{broken")
            throw AssertionError("expected IntelParseException")
        } catch (e: ThreatIntelParser.IntelParseException) {
            assertTrue(e.message!!.contains("malformed JSON"))
        }
    }

    @Test
    fun feodoParser_rejectsEmptyPayload() {
        try {
            ThreatIntelParser.parseFeodo("   ")
            throw AssertionError("expected IntelParseException")
        } catch (e: ThreatIntelParser.IntelParseException) {
            assertTrue(e.message!!.contains("empty"))
        }
    }

    @Test
    fun urlhausParser_extractsUrlsWithoutInventingGeolocation() {
        val indicators = ThreatIntelParser.parseUrlhaus(urlhausFixture)
        assertEquals(2, indicators.size)
        val first = indicators.first { it.host == "malware.example.com" }
        assertEquals(IndicatorKind.MALWARE_URL, first.kind)
        assertNull("URLhaus publishes no country; none may be invented", first.country)
        assertEquals("exe", first.malwareFamily)
        assertEquals("https://urlhaus.abuse.ch/url/123456/", first.referenceUrl)
        val second = indicators.first { it.host == "bad.example.net" }
        assertEquals("bad.example.net", second.host)
    }

    @Test
    fun urlhausParser_rejectsNonObjectPayload() {
        try {
            ThreatIntelParser.parseUrlhaus("[1,2,3]")
            throw AssertionError("expected IntelParseException")
        } catch (e: ThreatIntelParser.IntelParseException) {
            assertTrue(e.message!!.contains("not a JSON object"))
        }
    }

    @Test
    fun hostExtraction_handlesPortsCredentialsAndIpv6() {
        assertEquals("example.com", ThreatIntelParser.hostOf("https://user:pass@Example.com:8443/path?q=1"))
        assertEquals("::1", ThreatIntelParser.hostOf("http://[::1]:8080/x"))
        assertEquals("bare.host", ThreatIntelParser.hostOf("bare.host"))
    }

    @Test
    fun countryAggregation_countsOnlyGeolocatedIndicators() {
        val indicators = listOf(
            indicator("1.1.1.1", "RU", "QakBot", "online"),
            indicator("2.2.2.2", "RU", "Emotet", "offline"),
            indicator("3.3.3.3", "US", "QakBot", "online"),
            indicator("4.4.4.4", null, null, "online")
        )
        val countries = ThreatIntelAggregation.byCountry(indicators)
        assertEquals(2, countries.size)
        assertEquals("RU", countries.first().countryCode)
        assertEquals(2, countries.first().count)
        assertEquals(1, countries.first().onlineCount)
        assertEquals(listOf("Emotet", "QakBot"), countries.first().malwareFamilies)
        assertEquals(1, ThreatIntelAggregation.unmappedCount(indicators))
    }

    @Test
    fun countryAggregation_emptyInputProducesNoMarkers() {
        assertTrue(ThreatIntelAggregation.byCountry(emptyList()).isEmpty())
        assertEquals(0, ThreatIntelAggregation.unmappedCount(emptyList()))
    }

    private fun indicator(ip: String, country: String?, family: String?, status: String) = IntelIndicator(
        key = "feodo:$ip",
        sourceId = IntelSource.FEODO_TRACKER.id,
        kind = IndicatorKind.BOTNET_C2,
        value = ip,
        host = ip,
        country = country,
        malwareFamily = family,
        status = status
    )
}
