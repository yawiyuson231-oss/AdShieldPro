package com.adshield.pro

import com.adshield.pro.cybershield.AnomalyFinding
import com.adshield.pro.cybershield.BehavioralAnomalyDetector
import com.adshield.pro.cybershield.CloudIndicator
import com.adshield.pro.cybershield.CloudProviderStatus
import com.adshield.pro.cybershield.ComplianceEvaluator
import com.adshield.pro.cybershield.ComplianceReportJson
import com.adshield.pro.cybershield.ComplianceStatus
import com.adshield.pro.cybershield.CorrelationEngine
import com.adshield.pro.cybershield.CsEventAction
import com.adshield.pro.cybershield.CsSettingsSnapshot
import com.adshield.pro.cybershield.CsSeverity
import com.adshield.pro.cybershield.DeviceSecuritySnapshot
import com.adshield.pro.cybershield.DnsEventSnapshot
import com.adshield.pro.cybershield.FeodoParser
import com.adshield.pro.cybershield.GeoIndex
import com.adshield.pro.cybershield.IntelIndicator
import com.adshield.pro.cybershield.JsonLite
import com.adshield.pro.cybershield.JsonParseException
import com.adshield.pro.cybershield.JValue
import com.adshield.pro.cybershield.ShieldMode
import com.adshield.pro.cybershield.ShieldStateEvaluator
import com.adshield.pro.cybershield.StatuspageParser
import com.adshield.pro.cybershield.ThreatEventMapper
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * JVM unit tests for the CyberShield AI engines. All pure Kotlin — no Android
 * framework needed at runtime. Fixtures mimic the real published schemas;
 * no test asserts fabricated production data.
 */
class CyberShieldEngineTestSuite {

    private val now = 1_760_000_000_000L

    private fun dns(
        id: Long,
        domain: String,
        ts: Long = now - 60_000,
        blocked: Boolean = false,
        category: String? = null,
        source: String = "DoH upstream",
        protocol: String = "DoH",
        app: String? = null
    ) = DnsEventSnapshot(
        id = id, timestampEpochMs = ts, domain = domain, queryType = "A",
        isBlocked = blocked, category = category, matchedRule = if (blocked) "||$domain" else null,
        sourceList = source, latencyMs = 12, protocolUsed = protocol,
        appPackageName = app, appName = app
    )

    // ---- JsonLite ----------------------------------------------------------

    @Test
    fun jsonLiteParsesNestedStructuresAndEscapes() {
        val v = JsonLite.parse("""{"a":[1,2.5,-3e2,true,false,null],"b":{"c":"x\ny\u0041\"z"}}""")
        assertEquals(6, v.arr("a")!!.items.size)
        assertEquals(2.5, (v.arr("a")!!.items[1] as JValue.JNum).value, 0.0001)
        assertEquals(-300.0, (v.arr("a")!!.items[2] as JValue.JNum).value, 0.0001)
        assertEquals("x\nyA\"z", v.obj("b")!!.str("c"))
        assertNull(v.str("missing"))
    }

    @Test
    fun jsonLiteRejectsMalformedInput() {
        val bad = listOf(
            "{\"a\":1}trailing", "[1,]", "{unquoted:1}", "\"unterminated",
            "{\"a\":NaN}", "01", "\"bad\\xescape\"", "{\"a\":\"ctrl\u0001char\"}",
            "[".repeat(70) + "]".repeat(70)
        )
        for (input in bad) {
            var threw = false
            try { JsonLite.parse(input) } catch (e: JsonParseException) { threw = true }
            assertTrue("expected rejection of: ${input.take(30)}", threw)
        }
    }

    // ---- FeodoParser ---------------------------------------------------------

    private val feodoFixture = """
        [
          {"ip_address":"203.0.113.7","port":443,"status":"online","hostname":null,
           "as_number":64501,"as_name":"EXAMPLE-AS","country":"US",
           "first_seen_utc":"2026-10-01 10:00:00","last_online":"2026-11-01","malware":"QakBot"},
          {"ip_address":"198.51.100.9","port":8080,"status":"offline",
           "as_number":64502,"as_name":"OTHER-AS","country":"de",
           "first_seen_utc":"2026-09-01 00:00:00","last_online":null,"malware":"Emotet"},
          {"ip_address":"203.0.113.7","port":443,"status":"online","country":"US","malware":"QakBot"},
          {"ip_address":"999.1.1.1","port":443,"status":"online","country":"XX"},
          {"ip_address":"not-an-ip","port":443},
          {"ip_address":"192.0.2.55","port":443,"status":"online","country":null,"malware":null}
        ]
    """.trimIndent()

    @Test
    fun feodoParsesRealSchemaWithProvenance() {
        val snap = FeodoParser.parse(feodoFixture, now)
        // 6 rows: 1 duplicate + 2 invalid IPs removed, null-country row kept.
        assertEquals(3, snap.indicators.size)
        val first = snap.indicators[0]
        assertEquals("203.0.113.7", first.ip)
        assertEquals("US", first.countryCode)
        assertEquals("QakBot", first.malware)
        assertEquals("online", first.status)
        assertEquals(now, snap.fetchedAtEpochMs)
        assertEquals(FeodoParser.FEED_URL, snap.feedUrl)
        assertEquals("DE", snap.indicators[1].countryCode) // normalized uppercase
        assertNull(snap.indicators[1].lastOnline)          // null stays null, never invented
        assertNull(snap.indicators[2].countryCode)         // unknown location stays unknown
    }

    @Test
    fun feodoRejectsEmptyOrWrongShape() {
        var threw = 0
        try { FeodoParser.parse("{}", now) } catch (e: JsonParseException) { threw++ }
        try { FeodoParser.parse("[]", now) } catch (e: JsonParseException) { threw++ }
        try { FeodoParser.parse("[{\"ip_address\":\"bogus\"}]", now) } catch (e: JsonParseException) { threw++ }
        assertEquals(3, threw)
    }

    @Test
    fun ipv4ValidationIsStrict() {
        assertTrue(FeodoParser.isValidIpv4("1.2.3.4"))
        assertTrue(FeodoParser.isValidIpv4("255.255.255.255"))
        assertFalse(FeodoParser.isValidIpv4("256.1.1.1"))
        assertFalse(FeodoParser.isValidIpv4("01.2.3.4"))
        assertFalse(FeodoParser.isValidIpv4("1.2.3"))
        assertFalse(FeodoParser.isValidIpv4("::1"))
        assertFalse(FeodoParser.isValidIpv4("1.2.3.4.5"))
    }

    // ---- Statuspage ----------------------------------------------------------

    @Test
    fun statuspageMapsAllIndicatorsHonestly() {
        assertEquals(CloudIndicator.OPERATIONAL, StatuspageParser.parseIndicator("none"))
        assertEquals(CloudIndicator.DEGRADED, StatuspageParser.parseIndicator("minor"))
        assertEquals(CloudIndicator.PARTIAL_OUTAGE, StatuspageParser.parseIndicator("major"))
        assertEquals(CloudIndicator.MAJOR_OUTAGE, StatuspageParser.parseIndicator("critical"))
        assertEquals(CloudIndicator.MAINTENANCE, StatuspageParser.parseIndicator("maintenance"))
        assertEquals(CloudIndicator.UNKNOWN, StatuspageParser.parseIndicator(null))
        assertEquals(CloudIndicator.UNKNOWN, StatuspageParser.parseIndicator("weird"))
    }

    @Test
    fun statuspageParsesRealResponseShape() {
        val base = CloudProviderStatus("github", "GitHub", "https://www.githubstatus.com/api/v2/status.json")
        val body = """{"page":{"id":"kctbh9vrtdwd","name":"GitHub","updated_at":"2026-11-04T18:00:00Z"},
            "status":{"indicator":"minor","description":"Degraded Performance"}}"""
        val result = StatuspageParser.parseInto(base, body, now)
        assertEquals(CloudIndicator.DEGRADED, result.indicator)
        assertEquals("Degraded Performance", result.description)
        assertEquals("2026-11-04T18:00:00Z", result.providerUpdatedAt)
        assertEquals(now, result.fetchedAtEpochMs)
        assertNull(result.error)
    }

    @Test
    fun statuspageMissingStatusObjectThrows() {
        val base = CloudProviderStatus("x", "X", "https://x")
        var threw = false
        try { StatuspageParser.parseInto(base, "{\"page\":{}}", now) } catch (e: JsonParseException) { threw = true }
        assertTrue(threw)
    }

    // ---- ThreatEventMapper -----------------------------------------------------

    @Test
    fun severityClassificationMatchesRealBlockSources() {
        val confirmed = ThreatEventMapper.map(
            dns(1, "bad.example", blocked = true, category = "MALWARE",
                source = "AETHER AI: confirmed_malware (confirmed_intelligence)", protocol = "AETHER aether-android-1.0.0")
        )
        assertEquals(CsSeverity.CRITICAL, confirmed.severity)
        assertEquals(CsEventAction.BLOCKED, confirmed.action)

        val listMalware = ThreatEventMapper.map(dns(2, "bad2.example", blocked = true, category = "MALWARE", source = "URLHaus Malware & Phishing Filter"))
        assertEquals(CsSeverity.HIGH, listMalware.severity)

        val tracker = ThreatEventMapper.map(dns(3, "track.example", blocked = true, category = "TRACKERS"))
        assertEquals(CsSeverity.MEDIUM, tracker.severity)

        val ad = ThreatEventMapper.map(dns(4, "ads.example", blocked = true, category = "ADS"))
        assertEquals(CsSeverity.LOW, ad.severity)

        val allowed = ThreatEventMapper.map(dns(5, "good.example"))
        assertEquals(CsSeverity.INFO, allowed.severity)
        assertEquals(CsEventAction.ALLOWED, allowed.action)
        assertTrue(allowed.evidence.isNotEmpty())
    }

    @Test
    fun summarizeUsesOnlyRealEventsInWindow() {
        val empty = ThreatEventMapper.summarize(emptyList(), now)
        assertEquals(0L, empty.totalEvents)
        assertEquals(0, empty.activeThreatDomains)

        val events = ThreatEventMapper.mapAll(
            listOf(
                dns(1, "a.bad.example", blocked = true, category = "MALWARE"),
                dns(2, "b.bad.example", blocked = true, category = "MALWARE"),
                dns(3, "ads.example", blocked = true, category = "ADS"),
                dns(4, "ok.example"),
                dns(5, "old.bad.example", ts = now - 2 * 86_400_000L, blocked = true, category = "MALWARE")
            )
        )
        val stats = ThreatEventMapper.summarize(events, now)
        assertEquals(4L, stats.totalEvents)          // old event excluded
        assertEquals(3L, stats.blocked)
        assertEquals(1, stats.activeThreatDomains)   // a.bad + b.bad share registrable domain
        assertEquals(2L, stats.highCount)
    }

    @Test
    fun attackVectorSharesAndHourlyBuckets() {
        val events = ThreatEventMapper.mapAll(
            listOf(
                dns(1, "a.example", blocked = true, category = "MALWARE"),
                dns(2, "b.example", blocked = true, category = "ADS"),
                dns(3, "c.example", blocked = true, category = "ADS"),
                dns(4, "d.example")
            )
        )
        val vectors = ThreatEventMapper.attackVectors(events, now)
        assertEquals(2, vectors.size)
        assertEquals("ADS", vectors[0].category)
        assertEquals(1.0f, vectors.sumOf { it.share.toDouble() }.toFloat(), 0.001f)

        val buckets = ThreatEventMapper.hourlyBuckets(events, now)
        assertEquals(24, buckets.size)
        assertEquals(3L, buckets.sumOf { it.blocked })
        assertEquals(1L, buckets.sumOf { it.allowed })
        // Buckets are contiguous hours ending at the current hour.
        assertEquals(3_600_000L, buckets[1].hourStartEpochMs - buckets[0].hourStartEpochMs)
    }

    @Test
    fun protocolDistributionBucketsRealProtocols() {
        val snaps = listOf(
            dns(1, "a.example", protocol = "DoH"),
            dns(2, "b.example", protocol = "DoT"),
            dns(3, "c.example", blocked = true, protocol = "Sinkhole 0.0.0.0"),
            dns(4, "d.example", blocked = true, protocol = "AETHER aether-android-1.0.0"),
            dns(5, "e.example", protocol = "UDP")
        )
        val dist = ThreatEventMapper.protocolDistribution(snaps, now)
        assertEquals(5, dist.size)
        assertEquals(1.0f, dist.sumOf { it.share.toDouble() }.toFloat(), 0.001f)
        assertTrue(dist.any { it.protocol == "AI block" })
        assertTrue(dist.any { it.protocol == "Sinkhole" })
    }

    // ---- Correlation -----------------------------------------------------------

    @Test
    fun correlationGroupsByDomainAndRanksSeverity() {
        val events = ThreatEventMapper.mapAll(
            listOf(
                dns(1, "x.same.example", blocked = true, category = "TRACKERS", app = "AppA"),
                dns(2, "y.same.example", blocked = true, category = "MALWARE", app = "AppB"),
                dns(3, "solo.other.example", blocked = true, category = "ADS"),
                dns(4, "allowed.example"),
                dns(5, "ancient.example", ts = now - 3 * 86_400_000L, blocked = true, category = "MALWARE")
            )
        )
        val incidents = CorrelationEngine.correlate(events, now)
        assertEquals(2, incidents.size) // allowed + ancient excluded
        assertEquals("same.example", incidents[0].domain)
        assertEquals(CsSeverity.HIGH, incidents[0].severity)
        assertEquals(2, incidents[0].eventCount)
        assertEquals(listOf("AppA", "AppB"), incidents[0].apps.sorted())
    }

    // ---- Behavioral anomalies ----------------------------------------------------

    @Test
    fun sparseInputProducesNoAnomalies() {
        assertTrue(BehavioralAnomalyDetector.detect(emptyList(), now).isEmpty())
        assertTrue(BehavioralAnomalyDetector.detect(List(5) { dns(it.toLong(), "d$it.example") }, now).isEmpty())
    }

    @Test
    fun burstDetectionCarriesMeasuredEvidence() {
        val events = (0 until 40).map { dns(it.toLong(), "burst.example", ts = now - it * 5_000L) }
        val findings = BehavioralAnomalyDetector.detect(events, now)
        val burst = findings.firstOrNull { it.kind == "query_burst" }
        assertNotNull(burst)
        assertEquals("burst.example", burst!!.domain)
        assertTrue(burst.evidence.any { it.startsWith("count=") })
        assertEquals(CsSeverity.MEDIUM, burst.severity)
    }

    @Test
    fun beaconingDetectionOnRegularIntervals() {
        // 10 queries exactly 60 s apart — low variance, above the 5 s floor.
        val events = (0 until 10).map { dns(it.toLong(), "beacon.example", ts = now - it * 60_000L) }
        val findings = BehavioralAnomalyDetector.detect(events, now)
        assertTrue(findings.any { it.kind == "beaconing" })
    }

    @Test
    fun subdomainFloodDetection() {
        val events = (0 until 20).map { dns(it.toLong(), "host$it.tunnel.example", ts = now - it * 20_000L) }
        val findings = BehavioralAnomalyDetector.detect(events, now)
        val flood = findings.firstOrNull { it.kind == "subdomain_flood" }
        assertNotNull(flood)
        assertEquals("tunnel.example", flood!!.domain)
    }

    @Test
    fun dgaPatternIsFlaggedNeverBlocked() {
        val events = listOf(
            dns(1, "x7k9q2m4z8r1t6.evil.example"),
            dns(2, "google.com"),
            dns(3, "wikipedia.org")
        ) + (0 until 6).map { dns(10L + it, "filler$it.example", ts = now - it * 90_000L) }
        val findings = BehavioralAnomalyDetector.detect(events, now)
        val dga = findings.firstOrNull { it.kind == "dga_pattern" }
        assertNotNull(dga)
        assertEquals(CsSeverity.HIGH, dga!!.severity)
        assertTrue(dga.evidence.any { it.contains("not blocked") })
    }

    @Test
    fun normalTrafficProducesNoFindings() {
        val domains = listOf("google.com", "github.com", "wikipedia.org", "example.com", "mozilla.org", "android.com", "cloudflare.com", "amazon.com", "apple.com")
        val events = domains.mapIndexed { i, d -> dns(i.toLong(), d, ts = now - i * 7 * 60_000L) }
        assertTrue(BehavioralAnomalyDetector.detect(events, now).isEmpty())
    }

    // ---- Shield state ---------------------------------------------------------------

    @Test
    fun shieldNeverClaimsProtectionWhenInactive() {
        val off = ShieldStateEvaluator.evaluate("DISCONNECTED", null, true, 0, 1000)
        assertEquals(ShieldMode.OFF, off.mode)
        assertEquals("PROTECTION OFF", off.headline)
        assertFalse(off.headline.contains("PROTECTED"))

        val active = ShieldStateEvaluator.evaluate("CONNECTED", null, true, 3, 1000)
        assertEquals(ShieldMode.ACTIVE, active.mode)
        assertTrue(active.subtitle.contains("3 threats blocked"))

        val paused = ShieldStateEvaluator.evaluate("PAUSED", null, true, 0, 1000)
        assertEquals(ShieldMode.PAUSED, paused.mode)

        val error = ShieldStateEvaluator.evaluate("ERROR", "tunnel failed", true, 0, 0)
        assertEquals(ShieldMode.ERROR, error.mode)
        assertEquals("tunnel failed", error.error)

        val starting = ShieldStateEvaluator.evaluate("STARTING", null, true, 0, 0)
        assertEquals(ShieldMode.STARTING, starting.mode)

        val noAi = ShieldStateEvaluator.evaluate("CONNECTED", null, false, 0, 100)
        assertTrue(noAi.subtitle.contains("AETHER analysis disabled"))
    }

    // ---- Compliance ---------------------------------------------------------------

    private fun settings(vpn: String = "CONNECTED") = CsSettingsSnapshot(
        vpnStatus = vpn, protectionMode = "STANDARD", resolverProtocol = "DOH",
        aetherEnabled = true, aetherAutoBlock = true, autoUpdateFilters = true,
        detailedLogging = true, logRetentionDays = 7, loadedRuleCount = 5000
    )

    private fun secureDevice() = DeviceSecuritySnapshot(
        collectedAtEpochMs = now, deviceModel = "Test Device", androidVersion = "15", sdkInt = 35,
        securityPatch = "2026-10-05", patchAgeDays = 30,
        screenLockSecure = true, storageEncrypted = true, adbEnabled = false,
        developerOptionsEnabled = false, totalApps = 120, userApps = 40, sideloadedApps = 0,
        networkTransport = "Wi-Fi", networkValidated = true
    )

    @Test
    fun compliancePassesOnSecureDevice() {
        val report = ComplianceEvaluator.evaluate(secureDevice(), settings(), now)
        assertEquals(0, report.failed)
        assertTrue(report.score >= 90)
        assertEquals(report.checks.size, report.passed + report.warnings + report.failed + report.unavailable)
    }

    @Test
    fun complianceFlagsRealProblems() {
        val insecure = secureDevice().copy(
            screenLockSecure = false, adbEnabled = true, patchAgeDays = 400, sideloadedApps = 5
        )
        val report = ComplianceEvaluator.evaluate(insecure, settings(vpn = "DISCONNECTED"), now)
        assertTrue(report.failed >= 2)  // screen lock + DNS protection (+ patch)
        assertTrue(report.warnings >= 2) // adb + sideloaded
        assertTrue(report.score < 70)
        val lock = report.checks.first { it.id == "screen_lock" }
        assertEquals(ComplianceStatus.FAIL, lock.status)
        assertNotNull(lock.recommendation)
    }

    @Test
    fun complianceMarksUnknownSignalsUnavailable() {
        val unknown = DeviceSecuritySnapshot(collectedAtEpochMs = now)
        val report = ComplianceEvaluator.evaluate(unknown, settings(), now)
        assertTrue(report.unavailable >= 5)
        val lock = report.checks.first { it.id == "screen_lock" }
        assertEquals(ComplianceStatus.UNAVAILABLE, lock.status)
        // Unavailable checks never count as passes.
        assertTrue(report.passed <= 6)
    }

    @Test
    fun complianceReportJsonRoundTrips() {
        val report = ComplianceEvaluator.evaluate(secureDevice(), settings(), now)
        val json = ComplianceReportJson.render(report)
        val parsed = JsonLite.parse(json)
        assertEquals(report.score.toLong(), parsed.num("score")!!.toLong())
        assertEquals(report.checks.size, parsed.arr("checks")!!.items.size)
        assertEquals("screen_lock", (parsed.arr("checks")!!.items[4] as JValue.JObj).str("id"))
    }

    // ---- GeoIndex ---------------------------------------------------------------

    @Test
    fun projectionStaysInBounds() {
        assertEquals(0.5f, GeoIndex.projectX(0.0), 0.001f)
        assertEquals(0f, GeoIndex.projectX(-180.0), 0.001f)
        assertEquals(1f, GeoIndex.projectX(180.0), 0.001f)
        assertEquals(0f, GeoIndex.projectY(GeoIndex.LAT_TOP), 0.001f)
        assertEquals(1f, GeoIndex.projectY(GeoIndex.LAT_BOTTOM), 0.001f)
        // Out-of-viewport latitudes clamp instead of drawing off-canvas.
        assertEquals(1f, GeoIndex.projectY(-85.0), 0.001f)
    }

    private fun indicator(ip: String, country: String?, malware: String?, status: String) =
        IntelIndicator(ip, 443, status, country, "AS-TEST", 64500, malware, "2026-10-01", "2026-11-01")

    @Test
    fun clusteringGroupsByCountryAndCountsUnlocated() {
        val centroids = mapOf("US" to doubleArrayOf(39.0, -98.0), "DE" to doubleArrayOf(51.0, 10.0))
        val names = mapOf("US" to "United States", "DE" to "Germany")
        val result = GeoIndex.cluster(
            listOf(
                indicator("203.0.113.1", "US", "QakBot", "online"),
                indicator("203.0.113.2", "US", "QakBot", "offline"),
                indicator("203.0.113.3", "DE", "Emotet", "online"),
                indicator("203.0.113.4", null, "Emotet", "online"),
                indicator("203.0.113.5", "ZZ", null, "offline")
            ),
            centroids, names
        )
        assertEquals(2, result.clusters.size)
        assertEquals(2, result.unlocated) // null country + unknown centroid, never mapped
        assertEquals(5, result.total)
        val us = result.clusters.first { it.countryCode == "US" }
        assertEquals(2, us.count)
        assertEquals(1, us.onlineCount)
        assertEquals("United States", us.countryName)
    }

    @Test
    fun clusteringFiltersOnlineAndFamily() {
        val centroids = mapOf("US" to doubleArrayOf(39.0, -98.0))
        val inds = listOf(
            indicator("203.0.113.1", "US", "QakBot", "online"),
            indicator("203.0.113.2", "US", "Emotet", "offline")
        )
        val online = GeoIndex.cluster(inds, centroids, emptyMap(), onlineOnly = true)
        assertEquals(1, online.total)
        val family = GeoIndex.cluster(inds, centroids, emptyMap(), familyFilter = "emotet")
        assertEquals(1, family.total)
        assertEquals("Emotet", family.clusters[0].families[0].first)
    }

    @Test
    fun bundledWorldAssetsParseAndCoverMajorCountries() {
        // Gradle unit tests run with the module directory as working directory.
        val worldFile = File("src/main/assets/cybershield_world.json")
        val centroidFile = File("src/main/assets/cybershield_centroids.json")
        assertTrue("world asset missing at ${worldFile.absolutePath}", worldFile.exists())
        val world = GeoIndex.parseWorld(worldFile.readText())
        assertTrue(world.countries.size >= 150)
        val ids = world.countries.map { it.id }.toSet()
        assertTrue(ids.containsAll(listOf("US", "DE", "BR", "IN", "CN", "RU", "PH", "JP", "GB", "FR")))
        assertTrue(world.countries.all { it.rings.isNotEmpty() })
        val centroids = GeoIndex.parseCentroids(centroidFile.readText())
        assertTrue(centroids.size >= 150)
        // Every mapped country has a centroid so no indicator cluster is silently dropped.
        assertTrue(centroids.keys.containsAll(ids))
        val ph = centroids.getValue("PH")
        assertTrue(ph[0] in 4.0..22.0 && ph[1] in 116.0..127.0)
    }

    // ---- Demo data separation ------------------------------------------------------

    @Test
    fun demoIndicatorsUseDocumentationIpsOnly() {
        val demo = com.adshield.pro.cybershield.DemoIntel.indicators
        assertTrue(demo.isNotEmpty())
        // RFC 5737 TEST-NET-1 (192.0.2.0/24) — can never collide with real C2 infrastructure.
        assertTrue(demo.all { it.ip.startsWith("192.0.2.") })
        assertTrue(demo.all { it.asName?.contains("DEMO") == true })
    }
}
