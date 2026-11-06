package com.adshield.pro

import com.adshield.pro.domain.connectors.ConnectorAuth
import com.adshield.pro.domain.connectors.ConnectorFormat
import com.adshield.pro.domain.connectors.ConnectorRuntime
import com.adshield.pro.domain.connectors.ConnectorSnapshot
import com.adshield.pro.domain.connectors.ConnectorSpec
import com.adshield.pro.domain.connectors.ConnectorStatus
import com.adshield.pro.domain.connectors.ConnectorTransport
import com.adshield.pro.domain.connectors.FeedParseException
import com.adshield.pro.domain.connectors.IndicatorKind
import com.adshield.pro.domain.connectors.SyncOutcome
import com.adshield.pro.domain.connectors.ThreatIndicator
import com.adshield.pro.domain.connectors.VerificationClass
import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.engine.connectors.ConnectorCatalogue
import com.adshield.pro.engine.connectors.ConnectorParsers
import com.adshield.pro.engine.connectors.ConnectorSyncEngine
import com.adshield.pro.engine.connectors.ConnectorTransport as FeedTransport
import com.adshield.pro.engine.connectors.IndicatorRisk
import com.adshield.pro.engine.connectors.TransportResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Connector platform verification.
 *
 * These tests are intentionally adversarial: they check that the catalogue cannot become
 * decorative (duplicate endpoints, non-HTTPS URLs, missing metadata, impossible statuses), that
 * every parser rejects garbage instead of reporting success, and that the sync state machine maps
 * real HTTP/network behaviour to the honest status the UI shows.
 */
class ConnectorPlatformTestSuite {

    private val now = 1_800_000_000_000L

    // ------------------------------------------------------------------ catalogue integrity

    @Test
    fun testCatalogueIdsAndEndpointsAreUnique() {
        val ids = ConnectorCatalogue.all.map { it.id }
        assertEquals(ids.size, ids.toSet().size)

        val httpKeys = ConnectorCatalogue.feeds.map { it.method + " " + it.endpoint }
        assertEquals(httpKeys.size, httpKeys.toSet().size)
    }

    @Test
    fun testEveryImplementedFeedIsHttpsAndHasMetadata() {
        ConnectorCatalogue.feeds.filter { it.implemented }.forEach { spec ->
            assertTrue("non-HTTPS endpoint: ${spec.id}", spec.endpoint.startsWith("https://"))
            assertTrue(spec.name.isNotBlank())
            assertTrue(spec.provider.isNotBlank())
            assertTrue(spec.freeUse.isNotBlank())
            assertTrue(spec.restrictions.isNotBlank())
            assertTrue(spec.rateLimit.isNotBlank())
            assertTrue(spec.cacheTtlMs >= 60_000L)
            assertTrue(spec.maxBytes in 100_000..20_000_000)
            assertTrue(spec.handlerId != "none")
        }
    }

    @Test
    fun testEveryModuleHasRealConnectorsAndHonestGaps() {
        IntelligenceModule.nodes.forEach { module ->
            val items = ConnectorCatalogue.forModule(module)
            assertTrue("no connectors for ${module.id}", items.isNotEmpty())
            val implemented = items.count { it.implemented }
            assertTrue("too few implemented for ${module.id}: $implemented", implemented >= 6)
        }
        // Total is reported honestly rather than padded to a slogan number.
        val implemented = ConnectorCatalogue.all.count { it.implemented }
        assertTrue(implemented in 60..350)
    }

    @Test
    fun testCredentialRequiringConnectorsAreNotEnabledAndNotImplemented() {
        ConnectorCatalogue.all.filter { it.requiresKey }.forEach { spec ->
            assertFalse("key-required connector must not be enabled: ${spec.id}", spec.defaultEnabled)
            assertFalse(spec.implemented)
            assertEquals(ConnectorStatus.NOT_CONFIGURED, ConnectorRuntime.initial(spec).status)
        }
    }

    @Test
    fun testUnavailableSourcesAreLabelledUnavailable() {
        val unavailable = ConnectorCatalogue.all.filter { it.verification == VerificationClass.SOURCE_UNAVAILABLE }
        assertTrue(unavailable.isNotEmpty())
        unavailable.forEach {
            assertFalse(it.implemented)
            assertEquals(ConnectorStatus.NOT_IMPLEMENTED, ConnectorRuntime.initial(it).status)
        }
    }

    @Test
    fun testOnlyDefaultEnabledFeedsAreScheduled() {
        val defaultEnabled = ConnectorCatalogue.all.filter { it.defaultEnabled }
        assertTrue(defaultEnabled.isNotEmpty())
        assertTrue(defaultEnabled.size <= 8)
        defaultEnabled.forEach {
            assertTrue(it.implemented)
            assertTrue(it.isFeed)
            assertFalse(it.requiresKey)
        }
    }

    // ------------------------------------------------------------------ parsers

    @Test
    fun testUrlhausCsvParserProducesUrlAndDomain() {
        val payload = """
            # comment line
            id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
            "3160001","2026-01-01 00:00:00","https://bad.example/payload.bin","online","2026-01-01","malware_download","elf,arm","https://urlhaus.abuse.ch/url/3160001/","tester"
        """.trimIndent()
        val parsed = ConnectorParsers.parse("urlhaus-csv", feed("urlhaus-csv"), payload, now)
        assertTrue(parsed.indicators.any { it.kind == IndicatorKind.URL && it.value == "https://bad.example/payload.bin" })
        assertTrue(parsed.indicators.any { it.kind == IndicatorKind.DOMAIN && it.value == "bad.example" })
        assertTrue(parsed.indicators.first().attribution.contains("urlhaus"))
        assertTrue(parsed.indicators.all { it.expiresAtEpochMs > now })
    }

    @Test
    fun testFeodoCsvParsesOnlyValidIPv4() {
        val payload = """
            first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
            "2026-01-01 00:00:00","203.0.113.9","443","online","2026-01-01","Emotet"
            "2026-01-01 00:00:01","not-an-ip","80","online","2026-01-01","Emotet"
        """.trimIndent()
        val parsed = ConnectorParsers.parse("feodo-csv", feed("feodo-csv"), payload, now)
        assertEquals(1, parsed.indicators.size)
        assertEquals(IndicatorKind.IP, parsed.indicators.first().kind)
        assertEquals("203.0.113.9", parsed.indicators.first().value)
    }

    @Test
    fun testCisaKevParserAndInvalidShape() {
        val payload = """
            {"vulnerabilities":[
              {"cveID":"CVE-2024-3400","vendorProject":"Palo Alto","product":"PAN-OS","vulnerabilityName":"Command injection"},
              {"cveID":"not-a-cve","vendorProject":"X","product":"Y","vulnerabilityName":"bad"}
            ]}
        """.trimIndent()
        val parsed = ConnectorParsers.parse("cisa-kev", feed("cisa-kev"), payload, now)
        assertEquals(1, parsed.indicators.size)
        assertEquals("CVE-2024-3400", parsed.indicators.first().value)
        assertEquals(95, parsed.indicators.first().confidence)

        try {
            ConnectorParsers.parse("cisa-kev", feed("cisa-kev"), "<html>captive portal</html>", now)
            fail("expected parse failure")
        } catch (expected: FeedParseException) {
            assertTrue(expected.message!!.isNotBlank())
        }
    }

    @Test
    fun testEpssNvdAndGithubParsers() {
        val epss = """
            {"data":[{"cve":"CVE-2025-0001","epss":"0.42","percentile":"0.97"}]}
        """.trimIndent()
        val epssParsed = ConnectorParsers.parse("epss", feed("epss"), epss, now)
        assertEquals("CVE-2025-0001", epssParsed.indicators.first().value)
        assertTrue(epssParsed.indicators.first().confidence >= 90)

        val nvd = """
            {"vulnerabilities":[{"cve":{"id":"CVE-2025-1111","descriptions":[{"lang":"en","value":"Buffer overflow"}]}}]}
        """.trimIndent()
        assertEquals(1, ConnectorParsers.parse("nvd-cves", feed("nvd-cves"), nvd, now).indicators.size)

        val gh = """
            [{"ghsa_id":"GHSA-aaaa-bbbb-cccc","cve_id":"CVE-2025-2222","severity":"critical","summary":"RCE in lib"}]
        """.trimIndent()
        val ghParsed = ConnectorParsers.parse("github-advisories", feed("github-advisories"), gh, now)
        assertEquals("CVE-2025-2222", ghParsed.indicators.first().value)
        assertEquals(92, ghParsed.indicators.first().confidence)
    }

    @Test
    fun testMispListClassifiesValuesAndIgnoresJunk() {
        val payload = """
            {"name":"special-use-domain","values":[
              {"value":"example.local","description":"reserved"},
              {"value":"198.51.100.7","description":"reserved ip"},
              {"value":"https://example.org/x","description":"url — not stored here"}
            ]}
        """.trimIndent()
        val parsed = ConnectorParsers.parse("misp-list", feed("misp-list"), payload, now)
        assertEquals(2, parsed.indicators.size)
        assertTrue(parsed.indicators.any { it.kind == IndicatorKind.DOMAIN })
        assertTrue(parsed.indicators.any { it.kind == IndicatorKind.IP })
    }

    @Test
    fun testDomainBlocklistsAndIpsum() {
        val hosts = """
            # hosts file
            0.0.0.0 ads.example.com
            127.0.0.1 tracker.example.net
            0.0.0.0 localhost
            not a domain line
        """.trimIndent()
        val parsed = ConnectorParsers.parse("stevenblack-hosts", feed("stevenblack-hosts"), hosts, now)
        assertEquals(2, parsed.indicators.size)
        assertEquals("ads.example.com", parsed.indicators.first().value)

        val ipsum = """
            # comment
            198.51.100.9	7
            203.0.113.5	1
            bogus	9
        """.trimIndent()
        val ipsumParsed = ConnectorParsers.parse("ipsum", feed("ipsum"), ipsum, now)
        assertEquals(1, ipsumParsed.indicators.size)
        assertEquals(83, ipsumParsed.indicators.first().confidence)
    }

    @Test
    fun testTextUrlFeedsRejectNonUrlsAndDeduplicate() {
        val payload = """
            https://phish.example/login
            https://phish.example/login
            javascript:alert(1)
            ftp://files.example/x
            https://second.example/verify
        """.trimIndent()
        val parsed = ConnectorParsers.parse("openphish", feed("openphish"), payload, now)
        val urls = parsed.indicators.filter { it.kind == IndicatorKind.URL }
        assertEquals(2, urls.size)
        assertTrue(urls.none { it.value.startsWith("javascript") })
    }

    @Test
    fun testEmergencyFeedParsers() {
        val usgs = """
            {"features":[{"properties":{"mag":5.1,"place":"55 km N of Sacol","url":"https://usgs/1","code":"us1"}}]}
        """.trimIndent()
        val quake = ConnectorParsers.parse("usgs-quakes", feed("usgs-quakes"), usgs, now)
        assertEquals(1, quake.indicators.size)
        assertTrue(quake.indicators.first().label.contains("5.1"))

        val gdacs = """
            <rss><channel>
              <item><title>TC in Philippines</title><link>https://gdacs/1</link><description>x</description></item>
              <item><title>Flood in Region II</title><link>https://gdacs/2</link></item>
            </channel></rss>
        """.trimIndent()
        val alerts = ConnectorParsers.parse("gdacs-rss", feed("gdacs-rss"), gdacs, now)
        assertEquals(2, alerts.indicators.size)
        assertTrue(alerts.indicators.all { it.kind == IndicatorKind.ALERT })

        val nws = """
            {"features":[{"properties":{"id":"urn:nws:1","event":"Tornado Warning","areaDesc":"King County","severity":"Extreme"}}]}
        """.trimIndent()
        val weather = ConnectorParsers.parse("nws-alerts", feed("nws-alerts"), nws, now)
        assertEquals(1, weather.indicators.size)
        assertEquals(95, weather.indicators.first().confidence)

        val relief = """
            {"data":[{"id":"1234","fields":{"name":"Flood - Philippines"}}]}
        """.trimIndent()
        assertEquals(1, ConnectorParsers.parse("reliefweb-disasters", feed("reliefweb-disasters"), relief, now).indicators.size)

        val emsc = """
            {"features":[{"properties":{"unid":"20260101_0001","mag":4.2,"flynn_region":"Mindanao"}}]}
        """.trimIndent()
        assertEquals(1, ConnectorParsers.parse("seismicportal", feed("seismicportal"), emsc, now).indicators.size)
    }

    @Test
    fun testDiagnosticFeedsValidateResponseAndProduceNoThreats() {
        val ripe = """{"data":{"resource":"1.1.1.1","records":[{"x":1},{"x":2}]}}"""
        val parsed = ConnectorParsers.parse("ripe-bgp-state", feed("ripe-bgp-state"), ripe, now)
        assertEquals(1, parsed.indicators.size)
        assertTrue(parsed.indicators.first().value.startsWith("diagnostic:"))

        val rdap = """{"handle":"NET-1-1-1-0","country":"AU","status":["active"]}"""
        assertEquals(1, ConnectorParsers.parse("rdap-lookup", feed("rdap-lookup"), rdap, now).indicators.size)

        val ipify = """{"ip":"203.0.113.10"}"""
        assertEquals(1, ConnectorParsers.parse("ipify", feed("ipify"), ipify, now).indicators.size)

        try {
            ConnectorParsers.parse("ipify", feed("ipify"), """{"ip":"not-an-ip"}""", now)
            fail("expected parse failure")
        } catch (expected: FeedParseException) {
            // expected
        }
    }

    @Test
    fun testParserRejectsEmptyAndUnknown() {
        listOf("urlhaus-csv", "cisa-kev", "usgs-quakes", "gdacs-rss").forEach { parser ->
            try {
                ConnectorParsers.parse(parser, feed(parser), "   ", now)
                fail("expected failure for $parser")
            } catch (expected: FeedParseException) {
                // expected
            }
        }
        try {
            ConnectorParsers.parse("does-not-exist", feed("x"), "data", now)
            fail("expected failure for unknown parser")
        } catch (expected: FeedParseException) {
            // expected
        }
    }

    // ------------------------------------------------------------------ sync state machine

    @Test
    fun testSuccessfulSyncParsesAndCaps() {
        val csv = """
            id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
            "1","2026-01-01","https://one.example/a","online","2026-01-01","malware_download","x","l","r"
        """.trimIndent()
        val engine = ConnectorSyncEngine(
            transport = FakeTransport(TransportResult.Response(200, csv, "etag-1", null, null, 42L)),
            now = { now }
        )
        val outcome = engine.sync(feed("urlhaus-csv"), ConnectorRuntime.initial(feed("urlhaus-csv")))
        assertTrue(outcome is SyncOutcome.Success)
        val success = outcome as SyncOutcome.Success
        assertEquals(200, success.httpCode)
        assertEquals(42L, success.latencyMs)
        assertTrue(success.indicators.isNotEmpty())
        assertEquals("etag-1", success.etag)
    }

    @Test
    fun testNotModifiedIsSuccessWithoutIndicators() {
        val engine = ConnectorSyncEngine(
            transport = FakeTransport(TransportResult.Response(304, null, "etag", null, null, 12L)),
            now = { now }
        )
        val outcome = engine.sync(feed("urlhaus-csv"), ConnectorRuntime.initial(feed("urlhaus-csv")))
        assertTrue(outcome is SyncOutcome.Success)
        assertTrue((outcome as SyncOutcome.Success).notModified)
        assertTrue(outcome.indicators.isEmpty())
    }

    @Test
    fun testRateLimitProviderErrorAndAuthFailures() {
        fun syncWith(response: TransportResult): SyncOutcome {
            val engine = ConnectorSyncEngine(FakeTransport(response), now = { now })
            return engine.sync(feed("cisa-kev"), ConnectorRuntime.initial(feed("cisa-kev")))
        }
        val limited = syncWith(TransportResult.Response(429, null, null, null, 60_000L, 5L))
        assertTrue(limited is SyncOutcome.Retryable)
        assertEquals(60_000L, (limited as SyncOutcome.Retryable).retryAfterMs)

        val server = syncWith(TransportResult.Response(503, "down", null, null, null, 5L))
        assertTrue(server is SyncOutcome.Retryable)
        assertEquals(503, (server as SyncOutcome.Retryable).httpCode)

        val auth = syncWith(TransportResult.Response(403, "no", null, null, null, 5L))
        assertTrue(auth is SyncOutcome.Failed)
        assertEquals(403, (auth as SyncOutcome.Failed).httpCode)
    }

    @Test
    fun testOfflineTimeoutAndInvalidBody() {
        val offline = ConnectorSyncEngine(
            FakeTransport(TransportResult.Failure(offline = true, reason = "timeout", latencyMs = 8L)),
            now = { now }
        ).sync(feed("urlhaus-csv"), ConnectorRuntime.initial(feed("urlhaus-csv")))
        assertTrue(offline is SyncOutcome.Retryable)
        assertTrue((offline as SyncOutcome.Retryable).offline)

        val invalid = ConnectorSyncEngine(
            FakeTransport(TransportResult.Response(200, "<html>not json</html>", null, null, null, 9L)),
            now = { now }
        ).sync(feed("cisa-kev"), ConnectorRuntime.initial(feed("cisa-kev")))
        assertTrue(invalid is SyncOutcome.Failed)
        assertTrue((invalid as SyncOutcome.Failed).reason.startsWith("invalid response"))
    }

    @Test
    fun testCooldownSkipsNetworkEntirely() {
        var calls = 0
        val transport = object : FeedTransport {
            override fun get(spec: ConnectorSpec, etag: String?, lastModified: String?): TransportResult {
                calls++
                return TransportResult.Response(200, "{}", null, null, null, 1L)
            }
        }
        val runtime = ConnectorRuntime.initial(feed("cisa-kev")).copy(
            status = ConnectorStatus.ERROR,
            nextAllowedEpochMs = now + 120_000L,
            enabled = true
        )
        val outcome = ConnectorSyncEngine(transport, now = { now }).sync(feed("cisa-kev"), runtime)
        assertTrue(outcome is SyncOutcome.Retryable)
        assertEquals(0, calls)
    }

    @Test
    fun testDisabledAndKeyRequiredAreSkipped() {
        val disabled = ConnectorRuntime.initial(feed("cisa-kev")).copy(enabled = false)
        val outcome = ConnectorSyncEngine(
            FakeTransport(TransportResult.Response(200, "{}", null, null, null, 1L)),
            now = { now }
        ).sync(feed("cisa-kev"), disabled)
        assertEquals(SyncOutcome.Skipped, outcome)

        val keySpec = ConnectorCatalogue.find("cyber.threatfox")!!
        assertEquals(SyncOutcome.NotConfigured,
            ConnectorSyncEngine(FakeTransport(TransportResult.Response(200, "{}", null, null, null, 1L)), now = { now })
                .sync(keySpec, ConnectorRuntime.initial(keySpec)))
    }

    @Test
    fun testBackoffIsExponentialAndBounded() {
        assertEquals(30_000L, ConnectorSyncEngine.backoffFor(1))
        assertEquals(60_000L, ConnectorSyncEngine.backoffFor(2))
        assertEquals(240_000L, ConnectorSyncEngine.backoffFor(4))
        assertTrue(ConnectorSyncEngine.backoffFor(30) <= ConnectorSyncEngine.MAX_BACKOFF_MS)
        assertEquals(0L, ConnectorSyncEngine.backoffFor(0))
    }

    // ------------------------------------------------------------------ freshness / status honesty

    @Test
    fun testStatusIsNeverConnectedWithoutSuccessAndGoesStale() {
        val spec = feed("cisa-kev")
        val initial = ConnectorSnapshot(spec, ConnectorRuntime.initial(spec), now)
        assertTrue("never attempted must not be CONNECTED", initial.effectiveStatus != ConnectorStatus.CONNECTED)

        val fresh = ConnectorSnapshot(
            spec,
            ConnectorRuntime.initial(spec).copy(
                status = ConnectorStatus.CONNECTED,
                lastSuccessEpochMs = now - 1_000L,
                enabled = true
            ),
            now
        )
        assertEquals(ConnectorStatus.CONNECTED, fresh.effectiveStatus)
        assertFalse(fresh.isStale)

        val stale = ConnectorSnapshot(
            spec,
            ConnectorRuntime.initial(spec).copy(
                status = ConnectorStatus.CONNECTED,
                lastSuccessEpochMs = now - spec.cacheTtlMs * 2 - 1L,
                enabled = true
            ),
            now
        )
        assertEquals(ConnectorStatus.DEGRADED, stale.effectiveStatus)
        assertTrue(stale.isStale)
    }

    @Test
    fun testDisabledAndNotConfiguredOverrideOldSuccess() {
        val keySpec = ConnectorCatalogue.find("cyber.threatfox")!!
        val snapshot = ConnectorSnapshot(
            keySpec,
            ConnectorRuntime.initial(keySpec).copy(status = ConnectorStatus.CONNECTED, enabled = true),
            now
        )
        assertEquals(ConnectorStatus.NOT_CONFIGURED, snapshot.effectiveStatus)

        val notImplemented = ConnectorCatalogue.find("emrg.pagasa")!!
        val unavailable = ConnectorSnapshot(notImplemented, ConnectorRuntime.initial(notImplemented), now)
        assertEquals(ConnectorStatus.NOT_IMPLEMENTED, unavailable.effectiveStatus)
    }

    // ------------------------------------------------------------------ risk engine

    @Test
    fun testRiskEngineExplainsAndCorroborates() {
        val none = IndicatorRisk.assess(emptyList())
        assertEquals(IndicatorRisk.Verdict.NO_MATCH, none.verdict)
        assertEquals(0, none.score)

        val single = IndicatorRisk.assess(listOf(indicator("cyber.feodo.c2", IndicatorKind.IP, "203.0.113.9", 88)))
        assertEquals(IndicatorRisk.Verdict.SUSPICIOUS, single.verdict)
        assertTrue(single.reasons.any { it.contains("cyber.feodo.c2") })

        val corroborated = IndicatorRisk.assess(
            listOf(
                indicator("cyber.feodo.c2", IndicatorKind.IP, "203.0.113.9", 88),
                indicator("net.ipsum", IndicatorKind.IP, "203.0.113.9", 80)
            )
        )
        assertTrue(corroborated.score > single.score)
        assertTrue(corroborated.reasons.any { it.contains("independent sources") })
    }

    @Test
    fun testRiskEngineHonoursSuppressionAndLocalRisk() {
        val suppressed = IndicatorRisk.assess(listOf(indicator("cyber.misp.special-use", IndicatorKind.DOMAIN, "example.local", 0)))
        assertEquals(IndicatorRisk.Verdict.SUPPRESSED, suppressed.verdict)
        assertEquals(0, suppressed.score)

        val withLocal = IndicatorRisk.assess(
            listOf(indicator("fin.stevenblack.hosts", IndicatorKind.DOMAIN, "evil.example", 70)),
            localRisk = 100
        )
        assertTrue(withLocal.score > 25)
        assertTrue(withLocal.reasons.any { it.contains("Local deterministic rules") })
    }

    @Test
    fun testValueNormalisationAndKindDetection() {
        assertEquals("https://example.com/a", IndicatorRisk.normalise(" HTTPS://Example.COM/A "))
        assertEquals(IndicatorKind.URL, IndicatorRisk.kindForValue("https://example.com/a"))
        assertEquals(IndicatorKind.DOMAIN, IndicatorRisk.kindForValue("example.com"))
        assertEquals(IndicatorKind.IP, IndicatorRisk.kindForValue("203.0.113.9"))
        assertEquals(IndicatorKind.CVE, IndicatorRisk.kindForValue("CVE-2025-1234"))
        assertEquals(IndicatorKind.HASH_SHA256, IndicatorRisk.kindForValue("a".repeat(64)))
        assertNull(IndicatorRisk.kindForValue("not a value"))
    }

    @Test
    fun testUrlHostExtractionRejectsSpoofedInput() {
        assertEquals("bad.example", ConnectorParsers.hostOf("https://bad.example/path?q=1"))
        assertNull(ConnectorParsers.normalizeUrl("javascript:alert(1)"))
        assertNull(ConnectorParsers.normalizeUrl("data:text/html,<script>"))
        assertTrue(ConnectorParsers.isDomain("example.com"))
        assertFalse(ConnectorParsers.isDomain("not_a_domain"))
        assertTrue(ConnectorParsers.isSha256("b".repeat(64)))
    }

    // ------------------------------------------------------------------ helpers

    private fun feed(handlerId: String): ConnectorSpec = ConnectorSpec(
        id = "test.$handlerId",
        name = "Test $handlerId",
        module = IntelligenceModule.CYBER_DEFENSE,
        provider = "test",
        endpoint = "https://example.com/feed",
        method = "GET",
        format = ConnectorFormat.JSON,
        transport = ConnectorTransport.HTTP,
        auth = ConnectorAuth.NONE,
        freeUse = "test",
        restrictions = "test",
        rateLimit = "test",
        cacheTtlMs = 6 * 60 * 60 * 1_000L,
        timeoutMs = 15_000,
        maxBytes = 4_000_000,
        defaultEnabled = false,
        implemented = true,
        handlerId = handlerId,
        verification = VerificationClass.IMPLEMENTED_AND_TESTED
    )

    private fun indicator(source: String, kind: IndicatorKind, value: String, confidence: Int): ThreatIndicator =
        ThreatIndicator(
            kind = kind,
            value = value,
            sourceId = source,
            module = IntelligenceModule.CYBER_DEFENSE,
            label = "test indicator",
            confidence = confidence,
            firstSeenEpochMs = now,
            expiresAtEpochMs = now + 3_600_000L,
            attribution = source
        )

    private class FakeTransport(private val result: TransportResult) : FeedTransport {
        override fun get(spec: ConnectorSpec, etag: String?, lastModified: String?): TransportResult = result
    }
}
