package com.adshield.pro

import com.adshield.pro.engine.aether.AetherGodCore
import com.adshield.pro.engine.aether.AetherVerdict
import com.adshield.pro.engine.aether.DnsAnomalyAnalyzer
import com.adshield.pro.engine.aether.RuleDigitalTwin
import com.adshield.pro.engine.browser.BrowserContentBlocker
import com.adshield.pro.engine.dns.ResolverHealthMonitor
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.engine.zero.ZeroBreakageEngine
import com.adshield.pro.domain.model.RuleCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * OmniShield X — AETHER Infinity test suite (Parts 1, 4, 5, 6, 7).
 * Every component is tested against real engine behavior — no mocks, no fakes.
 */
class AetherInfinityTest {

    // --- DNS anomaly analysis (Parts 4/5/6) ---

    @Test
    fun dnsAnomaly_dgaDetection_highEntropyLabel() {
        assertTrue(DnsAnomalyAnalyzer.looksDgaGenerated("xkqjvbmzpqowierutasl.example.net"))
        // Ordinary words must NOT trip the detector
        assertFalse(DnsAnomalyAnalyzer.looksDgaGenerated("www.google.com"))
        assertFalse(DnsAnomalyAnalyzer.looksDgaGenerated("calendar-management-portal.example.org"))
    }

    @Test
    fun dnsAnomaly_tunnelingStructure_detectedButNotPunished() {
        // 8 labels
        assertTrue(DnsAnomalyAnalyzer.looksTunnelingPattern("a.b.c.d.e.f.g.h.example.net"))
        // oversized label
        assertTrue(DnsAnomalyAnalyzer.looksTunnelingPattern("${"a".repeat(55)}.example.net"))
        // ordinary CDN host with dashes/digits stays clean
        assertFalse(DnsAnomalyAnalyzer.looksTunnelingPattern("r1---sn-ab5l6ne7.googlevideo.com"))
    }

    /** Builds a minimal DNS response with one A answer using name compression. */
    private fun buildDnsResponse(domain: String, ip: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        fun u16(v: Int) { out.write((v shr 8) and 0xFF); out.write(v and 0xFF) }
        u16(0x1234); u16(0x8180); u16(1); u16(1); u16(0); u16(0) // header
        for (label in domain.split('.')) { out.write(label.length); out.write(label.toByteArray()); }
        out.write(0)
        u16(1); u16(1) // QTYPE=A, QCLASS=IN
        out.write(0xC0); out.write(0x0C) // pointer to QNAME (12)
        u16(1); u16(1); u16(60); u16(4) // A, IN, TTL, RDLENGTH
        out.write(ip)
        return out.toByteArray()
    }

    @Test
    fun rebindingGuard_extractsIpsAndBlocksPrivateAnswersForPublicDomains() {
        val response = buildDnsResponse("evil-example.com", byteArrayOf(10, 0, 0, 5))
        val ips = DnsAnomalyAnalyzer.extractAnswerIps(response)
        assertEquals(listOf("10.0.0.5"), ips)
        assertTrue(DnsAnomalyAnalyzer.isRebindingAttempt("evil-example.com", ips))

        // Loopback and IPv6 ULA also caught
        val loopback = DnsAnomalyAnalyzer.extractAnswerIps(buildDnsResponse("evil2.net", byteArrayOf(127, 0, 0, 1)))
        assertTrue(DnsAnomalyAnalyzer.isRebindingAttempt("evil2.net", loopback))

        // Internal namespaces legitimately answer private — never flagged
        assertFalse(DnsAnomalyAnalyzer.isRebindingAttempt("myrouter.local", listOf("192.168.1.1")))
        // Public IPs are fine
        val pub = DnsAnomalyAnalyzer.extractAnswerIps(buildDnsResponse("cloud.example.com", byteArrayOf(93, 184.toByte(), 216.toByte(), 34)))
        assertFalse(DnsAnomalyAnalyzer.isRebindingAttempt("cloud.example.com", pub))
        // Garbage bytes never crash
        assertEquals(emptyList<String>(), DnsAnomalyAnalyzer.extractAnswerIps(byteArrayOf(1, 2, 3)))
    }

    // --- GodCore orchestration (Part 1) ---

    private fun newCore(): AetherGodCore =
        AetherGodCore(FilterRuleEngine(), ZeroBreakageEngine(), ResolverHealthMonitor())

    @Test
    fun godcore_blockedAdQuery_producesEvidenceAndCounters() {
        val core = newCore()
        val decision = core.observeDnsQuery("ads.doubleclick.net", true, "||doubleclick.net^", "ADS")
        assertEquals(AetherVerdict.BLOCK_EVIDENCE, decision.finalVerdict)
        assertTrue(decision.findings.isNotEmpty())
        assertTrue(decision.findings.all { it.evidence.isNotEmpty() }) // every finding carries evidence

        val report = core.controlCenterReport(0)
        assertEquals(1L, report.dnsObserved)
        assertEquals(1L, report.blockedConfirmed)
        assertTrue(report.agentsOnline > 0)
        assertTrue(report.recentAudit.first().contains("ads.doubleclick.net"))
        // Agent health is real, not decorative
        val health = core.agentHealthSnapshot()
        assertTrue(health.any { it.evaluations > 0 && it.avgEvalMicros >= 0 })
    }

    @Test
    fun godcore_protectedDomainBlock_verificationOverrides_and_flags() {
        val core = newCore()
        // Engine mistakenly blocks a protected streaming domain → X-Verification + X-Video flag it
        val decision = core.observeDnsQuery("r2---sn-x.googlevideo.com", true, "||googlevideo.com^", "ADS")
        assertEquals(AetherVerdict.OVERRIDE_SAFE, decision.finalVerdict)
        val report = core.controlCenterReport(0)
        assertEquals(1L, report.verificationOverrides)
        assertEquals(1L, report.protectedOverrides)
    }

    @Test
    fun godcore_predictiveAgent_observesButNeverBlocks() {
        val core = newCore()
        val decision = core.observeDnsQuery("xkqjvbmzpqowierutasl.suspicious.example", false, null, null)
        assertEquals(AetherVerdict.OBSERVE, decision.finalVerdict)
        // Crucially: nothing was blocked — observation mode only
        assertFalse(decision.engineBlocked)
        assertEquals(1L, core.controlCenterReport(0).anomaliesObserved)
    }

    @Test
    fun godcore_rebinding_events_counted() {
        val core = newCore()
        core.recordRebindingBlocked("router-hijack.example", listOf("192.168.1.1"))
        val report = core.controlCenterReport(0)
        assertEquals(1L, report.rebindingBlocked)
    }

    // --- Digital Twin (Part 7) ---

    @Test
    fun digitalTwin_rejectsCandidateThatBreaksVideo_andAcceptsCleanCandidate() {
        val engine = FilterRuleEngine()
        val breaking = engine.parseFilterListContent("||googlevideo.com^\n||netflix.com^", RuleCategory.ADS, "Bad").getOrThrow()
        val badReport = RuleDigitalTwin.simulateCandidate(breaking.subdomainRules, breaking.exactRules, breaking.wildcardRules)
        assertFalse("Twin must catch playback-breaking candidates", badReport.passed)
        assertTrue(badReport.conflicts.any { it.contains("googlevideo.com") })

        val clean = engine.parseFilterListContent("||doubleclick.net^\n||adnxs.com^", RuleCategory.ADS, "Good").getOrThrow()
        val goodReport = RuleDigitalTwin.simulateCandidate(clean.subdomainRules, clean.exactRules, clean.wildcardRules)
        assertTrue(goodReport.passed)
        assertEquals(0, goodReport.conflicts.size)
    }

    // --- Resolver health (Parts 4/8) ---

    @Test
    fun resolverHealth_ranksBySuccessThenLatency() {
        val monitor = ResolverHealthMonitor()
        repeat(5) { monitor.record("CLOUDFLARE", 20, true) }
        repeat(5) { monitor.record("GOOGLE", 45, true) }
        repeat(4) { monitor.record("QUAD9", 30, true) }
        monitor.record("QUAD9", 30, false)

        val best = monitor.bestMeasuredResolver("__none__")
        assertNotNull(best)
        assertEquals("CLOUDFLARE", best!!.key) // 100% success + fastest

        val summary = monitor.summaryLine("QUAD9")
        assertTrue(summary.contains("80% success"))
    }

    // --- Video ad signals (Part 3) ---

    @Test
    fun videoAdEndpoints_blockedByPatternFilter() {
        val f = BrowserContentBlocker.Companion.UrlPatternFilter
        assertNotNull(f.match("https://pubads.g.doubleclick.net/ima/ads?cust=1", "pubads.g.doubleclick.net", true, "xmlhttprequest"))
        assertNotNull(f.match("https://media.vendor1.com/videoads/preroll.m3u8", "media.vendor1.com", true, "media"))
        // Playback must never be touched
        org.junit.Assert.assertNull(f.match("https://media.googlevideo.com/videoplayback?id=abc", "media.googlevideo.com", false, "media"))
    }
}
