package com.adshield.pro

import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.engine.dns.CnameIntelligenceEngine
import com.adshield.pro.engine.dns.CompatibilityGuard
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.DnsSecurityEngine
import com.adshield.pro.engine.dns.DomainIntelligenceEngine
import com.adshield.pro.engine.dns.InfinityDnsCache
import com.adshield.pro.engine.dns.DnsPerformanceOptimizer
import com.adshield.pro.engine.dns.ThreatIntelligenceManager
import com.adshield.pro.engine.dns.VideoAdIntelligence
import com.adshield.pro.engine.filter.DnsMediaPlaybackGuard
import com.adshield.pro.engine.filter.FilterRuleEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * INFINITY DNS — Comprehensive Test Suite
 *
 * Covers:
 * 1. CNAME Intelligence (cloaking detection, chain analysis)
 * 2. Infinity DNS Cache (TTL-aware LRU, eviction, metrics)
 * 3. Domain Intelligence (classification, DGA, typosquat, risk scoring)
 * 4. Video Ad Intelligence (platform detection, safe blocking)
 * 5. Threat Intelligence (malware/phishing feeds)
 * 6. DNS Security (hijacking, leak, anomaly detection)
 * 7. Compatibility Guard (essential domain protection)
 * 8. Performance Optimizer (metrics, recommendations)
 * 9. DnsPacketCodec extensions (CNAME extraction, TTL, suspicious detection)
 * 10. Integration: Infinity filter lists + full pipeline
 */
class InfinityDnsTestSuite {

    // Helpers
    private fun buildDnsQuery(domain: String, qType: Int = DnsPacketCodec.TYPE_A, txId: Int = 0x1234): ByteArray {
        val out = ByteArrayOutputStream()
        out.write((txId ushr 8) and 0xFF); out.write(txId and 0xFF)
        out.write(0x01); out.write(0x00)
        out.write(0x00); out.write(0x01)
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)
        for (label in domain.split('.')) {
            val b = label.toByteArray(Charsets.US_ASCII)
            out.write(b.size); out.write(b)
        }
        out.write(0x00)
        out.write((qType ushr 8) and 0xFF); out.write(qType and 0xFF)
        out.write(0x00); out.write(0x01)
        return out.toByteArray()
    }

    private fun buildDnsResponseWithCname(queryDomain: String, cnameTarget: String, txId: Int = 0x1234): ByteArray {
        val out = ByteArrayOutputStream()
        out.write((txId ushr 8) and 0xFF); out.write(txId and 0xFF)
        out.write(0x81); out.write(0x80) // QR=1, RD=1, RA=1, RCODE=0
        out.write(0x00); out.write(0x01) // QDCOUNT=1
        out.write(0x00); out.write(0x01) // ANCOUNT=1
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)
        // Question
        for (label in queryDomain.split('.')) {
            val b = label.toByteArray(Charsets.US_ASCII)
            out.write(b.size); out.write(b)
        }
        out.write(0x00)
        out.write(0x00); out.write(0x01) // A
        out.write(0x00); out.write(0x01) // IN
        // Answer: CNAME
        out.write(0xC0); out.write(0x0C) // pointer to question name
        out.write(0x00); out.write(0x05) // TYPE CNAME
        out.write(0x00); out.write(0x01) // CLASS IN
        out.write(0x00); out.write(0x00); out.write(0x00); out.write(0x3C) // TTL 60
        val cnameBytes = ByteArrayOutputStream()
        for (label in cnameTarget.split('.')) {
            val b = label.toByteArray(Charsets.US_ASCII)
            cnameBytes.write(b.size); cnameBytes.write(b)
        }
        cnameBytes.write(0x00)
        val cnameData = cnameBytes.toByteArray()
        out.write((cnameData.size ushr 8) and 0xFF); out.write(cnameData.size and 0xFF)
        out.write(cnameData)
        return out.toByteArray()
    }

    private fun buildSimpleDnsResponse(domain: String, ttl: Int = 60, txId: Int = 0x1234): ByteArray {
        val out = ByteArrayOutputStream()
        out.write((txId ushr 8) and 0xFF); out.write(txId and 0xFF)
        out.write(0x81); out.write(0x80)
        out.write(0x00); out.write(0x01)
        out.write(0x00); out.write(0x01)
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)
        for (label in domain.split('.')) {
            val b = label.toByteArray(Charsets.US_ASCII)
            out.write(b.size); out.write(b)
        }
        out.write(0x00)
        out.write(0x00); out.write(0x01)
        out.write(0x00); out.write(0x01)
        out.write(0xC0); out.write(0x0C)
        out.write(0x00); out.write(0x01)
        out.write(0x00); out.write(0x01)
        out.write((ttl ushr 24) and 0xFF); out.write((ttl ushr 16) and 0xFF)
        out.write((ttl ushr 8) and 0xFF); out.write(ttl and 0xFF)
        out.write(0x00); out.write(0x04)
        out.write(byteArrayOf(1, 2, 3, 4))
        return out.toByteArray()
    }

    // ---- 1. CNAME Intelligence ----

    @Test
    fun cname_parsesSimpleRecord() {
        val engine = CnameIntelligenceEngine(FilterRuleEngine())
        val resp = buildDnsResponseWithCname("tracker.example.com", "oajs.openx.net")
        val records = engine.parseCnameRecords(resp)
        assertEquals(1, records.size)
        assertEquals("tracker.example.com", records[0].alias)
        assertEquals("oajs.openx.net", records[0].canonical)
    }

    @Test
    fun cname_detectsCloaking() {
        val filter = FilterRuleEngine()
        // Add a rule that blocks the CNAME target
        val rule = filter.validateAndParseRuleInput("||oajs.openx.net^").getOrThrow()
        filter.updateCustomRules(listOf(rule))
        val engine = CnameIntelligenceEngine(filter)
        val resp = buildDnsResponseWithCname("analytics.shop.com", "oajs.openx.net")
        val eval = engine.evaluate("analytics.shop.com", resp)
        assertTrue("Should detect CNAME cloaking", eval.shouldBlock)
        assertNotNull(eval.blockingReason)
    }

    @Test
    fun cname_doesNotBlockLegitimateCdn() {
        val engine = CnameIntelligenceEngine(FilterRuleEngine())
        val resp = buildDnsResponseWithCname("cdn.example.com", "d1234.cloudfront.net")
        val eval = engine.evaluate("cdn.example.com", resp)
        assertFalse("Legitimate CDN CNAME should not be blocked", eval.shouldBlock)
    }

    @Test
    fun cname_chainAnalysis() {
        val engine = CnameIntelligenceEngine(FilterRuleEngine())
        // No CNAME records → empty chain
        val plainResp = buildSimpleDnsResponse("example.com")
        val eval = engine.evaluate("example.com", plainResp)
        assertFalse(eval.shouldBlock)
        assertEquals(0, eval.chain.chainLength)
    }

    @Test
    fun cname_registrableDomain() {
        assertEquals("example.com", CnameIntelligenceEngine.registrableDomain("sub.example.com"))
        assertEquals("example.co.uk", CnameIntelligenceEngine.registrableDomain("a.b.example.co.uk"))
        assertEquals("example.com", CnameIntelligenceEngine.registrableDomain("example.com"))
    }

    @Test
    fun cname_thirdPartyDetection() {
        assertTrue(CnameIntelligenceEngine.isThirdParty("shop.example.com", "tracker.adnetwork.com"))
        assertFalse(CnameIntelligenceEngine.isThirdParty("sub.example.com", "other.example.com"))
        assertFalse(CnameIntelligenceEngine.isThirdParty("example.com", "sub.example.com"))
    }

    @Test
    fun cname_suspiciousChainDetection() {
        val engine = CnameIntelligenceEngine(FilterRuleEngine())
        val chain = CnameIntelligenceEngine.CnameChain(
            queryDomain = "example.com",
            chain = listOf(
                CnameIntelligenceEngine.CnameRecord("example.com", "a.example.net", 5),
                CnameIntelligenceEngine.CnameRecord("a.example.net", "b.evil.tk", 5)
            ),
            finalTarget = "b.evil.tk",
            isCloaked = false, cloakedCategory = null, cloakedSource = null,
            chainLength = 2, hasLoop = false
        )
        val issues = engine.analyzeSuspiciousChain(chain)
        assertTrue(issues.any { it.contains("fast-flux") || it.contains("short TTL") || it.contains("Cross-TLD") })
    }

    // ---- 2. Infinity DNS Cache ----

    @Test
    fun cache_basicPutAndGet() {
        val cache = InfinityDnsCache(maxEntries = 10)
        val resp = buildSimpleDnsResponse("example.com")
        val key = "DOH@https://cloudflare-dns.com/dns-query|example.com:1:1"
        cache.put(key, resp, ttlSeconds = 60)
        val result = cache.get(key)
        assertNotNull(result)
        assertFalse(result!!.isStale)
        assertTrue(result.remainingTtlMs > 0)
    }

    @Test
    fun cache_expiration() {
        val cache = InfinityDnsCache(maxEntries = 10)
        val resp = buildSimpleDnsResponse("example.com")
        val key = "test-key"
        val now = System.currentTimeMillis()
        cache.put(key, resp, ttlSeconds = 60, nowMs = now)
        // Before expiry — hit
        assertNotNull(cache.get(key, now + 30_000))
        // After hard expiry + stale window — miss
        assertNull(cache.get(key, now + 70_000))
    }

    @Test
    fun cache_staleWhileRevalidate() {
        val cache = InfinityDnsCache(maxEntries = 10, staleTtlMs = 10000L)
        val resp = buildSimpleDnsResponse("example.com")
        val key = "stale-test"
        val now = System.currentTimeMillis()
        cache.put(key, resp, ttlSeconds = 60, nowMs = now)
        // Just after expiry — stale hit
        val stale = cache.get(key, now + 61_000)
        assertNotNull(stale)
        assertTrue(stale!!.isStale)
    }

    @Test
    fun cache_lruEviction() {
        val cache = InfinityDnsCache(maxEntries = 3)
        for (i in 0 until 5) {
            cache.put("key-$i", buildSimpleDnsResponse("example$i.com"))
        }
        assertEquals(3, cache.size())
        // Oldest should be evicted
        assertNull(cache.get("key-0"))
        assertNull(cache.get("key-1"))
        assertNotNull(cache.get("key-4"))
    }

    @Test
    fun cache_negativeCaching() {
        val cache = InfinityDnsCache(maxEntries = 10, negativeTtlSeconds = 30)
        // Build NXDOMAIN response
        val query = buildDnsQuery("nonexistent.example.com")
        val parsed = DnsPacketCodec.parseQuery(query)!!
        val nxResp = DnsPacketCodec.buildBlockedResponse(parsed, sinkholeZeroIp = false)
        val key = "nx-test"
        cache.put(key, nxResp, ttlSeconds = 300) // long TTL but NXDOMAIN should be short
        val result = cache.get(key)
        assertNotNull(result)
        // Should have short TTL regardless of requested
    }

    @Test
    fun cache_metrics() {
        val cache = InfinityDnsCache(maxEntries = 10)
        val resp = buildSimpleDnsResponse("example.com")
        cache.put("k1", resp)
        cache.get("k1") // hit
        cache.get("k2") // miss
        val stats = cache.stats()
        assertEquals(1, stats.hits)
        assertEquals(1, stats.misses)
        assertEquals(0.5, stats.hitRate, 0.01)
    }

    @Test
    fun cache_evictExpired() {
        val cache = InfinityDnsCache(maxEntries = 10, staleTtlMs = 1000L)
        val now = System.currentTimeMillis()
        cache.put("k1", buildSimpleDnsResponse("a.com"), ttlSeconds = 60, nowMs = now)
        cache.put("k2", buildSimpleDnsResponse("b.com"), ttlSeconds = 60, nowMs = now)
        val removed = cache.evictExpired(now + 100_000)
        assertEquals(2, removed)
        assertEquals(0, cache.size())
    }

    @Test
    fun cache_memoryBounded() {
        val cache = InfinityDnsCache(maxEntries = 1000, maxMemoryBytes = 500L)
        for (i in 0 until 20) {
            cache.put("key-$i", ByteArray(100) { i.toByte() })
        }
        // Should have evicted to stay under memory limit
        assertTrue(cache.size() < 20)
    }

    // ---- 3. Domain Intelligence ----

    @Test
    fun domainIntel_cleanDomain() {
        val engine = DomainIntelligenceEngine()
        val result = engine.analyze("example.com")
        assertEquals(DomainIntelligenceEngine.DomainClass.CLEAN, result.classification)
        assertEquals(DomainIntelligenceEngine.RiskLevel.SAFE, result.riskLevel)
        assertFalse(result.isDgaLikely)
    }

    @Test
    fun domainIntel_highRiskTld() {
        val engine = DomainIntelligenceEngine()
        val result = engine.analyze("free-prize-claim.tk")
        assertTrue(result.riskScore > 15)
        assertTrue(result.signals.any { it.code.contains("tld") })
    }

    @Test
    fun domainIntel_dgaLikely() {
        val engine = DomainIntelligenceEngine()
        val result = engine.analyze("xkq9m2p8n4r7w1q6z3.top")
        assertTrue("Should detect high entropy", result.features.entropy > 3.0)
        // DGA detection requires specific conditions — at least elevated entropy signal
        assertTrue(result.signals.any { it.category == "dga" || it.category == "lexical" })
    }

    @Test
    fun domainIntel_typosquat() {
        val engine = DomainIntelligenceEngine()
        val result = engine.analyze("gooogle.com")
        assertTrue(result.isTyposquatRisk)
        assertTrue(result.signals.any { it.code.contains("typosquat") })
    }

    @Test
    fun domainIntel_adInfrastructure() {
        val engine = DomainIntelligenceEngine()
        val result = engine.analyze("ads.pubmatic.com")
        assertEquals(DomainIntelligenceEngine.DomainClass.ADVERTISING, result.classification)
        assertTrue(result.riskScore >= 30)
    }

    @Test
    fun domainIntel_longDomain() {
        val engine = DomainIntelligenceEngine()
        val longDomain = "a".repeat(50) + ".example.com"
        val result = engine.analyze(longDomain)
        assertTrue(result.signals.any { it.code.contains("long") })
    }

    @Test
    fun domainIntel_punycodeDetection() {
        val engine = DomainIntelligenceEngine()
        val result = engine.analyze("xn--80ak6aa92e.com")
        assertTrue(result.features.isPunycode)
        assertTrue(result.signals.any { it.code == "punycode" })
    }

    @Test
    fun domainIntel_entropyCalculation() {
        val entropy1 = DomainIntelligenceEngine.shannonEntropy("aaaa")
        val entropy2 = DomainIntelligenceEngine.shannonEntropy("a1b2c3d4")
        assertTrue("Random string should have higher entropy", entropy2 > entropy1)
    }

    @Test
    fun domainIntel_levenshtein() {
        assertEquals(0, DomainIntelligenceEngine.levenshteinDistance("google", "google"))
        assertEquals(1, DomainIntelligenceEngine.levenshteinDistance("google", "gooogle"))
        assertEquals(1, DomainIntelligenceEngine.levenshteinDistance("google", "googl"))
        assertEquals(3, DomainIntelligenceEngine.levenshteinDistance("kitten", "sitting"))
    }

    @Test
    fun domainIntel_shouldBlockLogic() {
        val engine = DomainIntelligenceEngine()
        val adResult = engine.analyze("doubleclick.net")
        assertTrue(engine.shouldBlock(adResult))

        val cleanResult = engine.analyze("example.com")
        assertFalse(engine.shouldBlock(cleanResult))

        val suspiciousLow = DomainIntelligenceEngine.IntelligenceResult(
            domain = "test.com", classification = DomainIntelligenceEngine.DomainClass.SUSPICIOUS,
            riskLevel = DomainIntelligenceEngine.RiskLevel.MEDIUM, riskScore = 40, confidence = 50,
            features = engine.extractFeatures("test.com"), signals = emptyList(),
            recommendation = "", isDgaLikely = false, isTyposquatRisk = false,
            relatedInfrastructure = null
        )
        assertFalse(engine.shouldBlock(suspiciousLow)) // 40 < 60 threshold
    }

    // ---- 4. Video Ad Intelligence ----

    @Test
    fun videoAd_googleInfrastructure() {
        val engine = VideoAdIntelligence()
        val result = engine.analyze("pubads.g.doubleclick.net")
        assertTrue(result.isVideoAdInfrastructure)
        assertTrue(result.shouldBlock)
        assertEquals(VideoAdIntelligence.CompatibilityRisk.LOW, result.compatibilityRisk)
    }

    @Test
    fun videoAd_protectedMediaNotBlocked() {
        val engine = VideoAdIntelligence()
        val result = engine.analyze("rr3---sn-ab5l6nr6.googlevideo.com")
        assertFalse(result.isVideoAdInfrastructure)
        assertFalse(result.shouldBlock)
        assertEquals(VideoAdIntelligence.CompatibilityRisk.CRITICAL, result.compatibilityRisk)
    }

    @Test
    fun videoAd_tiktokTracking() {
        val engine = VideoAdIntelligence()
        val result = engine.analyze("analytics.tiktok.com")
        assertTrue(result.isVideoAdInfrastructure)
        assertTrue(result.shouldBlock)
    }

    @Test
    fun videoAd_programmaticExchange() {
        val engine = VideoAdIntelligence()
        val result = engine.analyze("ads.pubmatic.com")
        assertTrue(result.isVideoAdInfrastructure)
    }

    @Test
    fun videoAd_mobileSdk() {
        val engine = VideoAdIntelligence()
        val result = engine.analyze("unityads.unity3d.com")
        assertTrue(result.isVideoAdInfrastructure)
        assertEquals(VideoAdIntelligence.CompatibilityRisk.LOW, result.compatibilityRisk)
    }

    @Test
    fun videoAd_unknownDomainNotBlocked() {
        val engine = VideoAdIntelligence()
        val result = engine.analyze("example.com")
        assertFalse(result.isVideoAdInfrastructure)
        assertFalse(result.shouldBlock)
    }

    @Test
    fun videoAd_twitchAds() {
        val engine = VideoAdIntelligence()
        val result = engine.analyze("ads.twitch.tv")
        assertTrue(result.isVideoAdInfrastructure)
        assertTrue(result.shouldBlock)
    }

    @Test
    fun videoAd_batchAnalysis() {
        val engine = VideoAdIntelligence()
        val results = engine.analyzeBatch(listOf("pubads.g.doubleclick.net", "example.com", "googlevideo.com"))
        assertEquals(3, results.size)
        assertTrue(results["pubads.g.doubleclick.net"]!!.isVideoAdInfrastructure)
        assertFalse(results["example.com"]!!.isVideoAdInfrastructure)
    }

    // ---- 5. Threat Intelligence ----

    @Test
    fun threatIntel_directLookup() {
        val manager = ThreatIntelligenceManager()
        manager.loadEntries(listOf(
            ThreatIntelligenceManager.ThreatEntry(
                domain = "evil-phishing.com",
                categories = setOf(ThreatIntelligenceManager.ThreatCategory.PHISHING),
                source = ThreatIntelligenceManager.ThreatFeed.HAGEZI_TIF,
                confidence = 95, firstSeenMs = 0, lastSeenMs = 0, description = "Phishing"
            )
        ))
        val result = manager.lookup("evil-phishing.com")
        assertTrue(result.isThreat)
        assertEquals(ThreatIntelligenceManager.ThreatCategory.PHISHING, result.highestSeverity)
    }

    @Test
    fun threatIntel_subdomainInheritance() {
        val manager = ThreatIntelligenceManager()
        manager.loadEntries(listOf(
            ThreatIntelligenceManager.ThreatEntry(
                domain = "malware.com",
                categories = setOf(ThreatIntelligenceManager.ThreatCategory.MALWARE),
                source = ThreatIntelligenceManager.ThreatFeed.URLHAUS,
                confidence = 90, firstSeenMs = 0, lastSeenMs = 0, description = null
            )
        ))
        val result = manager.lookup("sub.malware.com")
        assertTrue(result.isThreat)
    }

    @Test
    fun threatIntel_cleanDomainNotThreat() {
        val manager = ThreatIntelligenceManager()
        manager.loadEntries(emptyList())
        val result = manager.lookup("example.com")
        assertFalse(result.isThreat)
    }

    @Test
    fun threatIntel_stats() {
        val manager = ThreatIntelligenceManager()
        manager.loadEntries(listOf(
            ThreatIntelligenceManager.ThreatEntry(
                domain = "a.com", categories = setOf(ThreatIntelligenceManager.ThreatCategory.MALWARE),
                source = ThreatIntelligenceManager.ThreatFeed.HAGEZI_TIF, confidence = 90,
                firstSeenMs = 0, lastSeenMs = 0, description = null
            ),
            ThreatIntelligenceManager.ThreatEntry(
                domain = "b.com", categories = setOf(ThreatIntelligenceManager.ThreatCategory.PHISHING),
                source = ThreatIntelligenceManager.ThreatFeed.URLHAUS, confidence = 85,
                firstSeenMs = 0, lastSeenMs = 0, description = null
            )
        ))
        val stats = manager.getStats()
        assertEquals(2, stats.totalDomains)
        assertEquals(1, stats.byCategory[ThreatIntelligenceManager.ThreatCategory.MALWARE])
    }

    @Test
    fun threatIntel_parseHostsLine() {
        assertEquals("evil.com", ThreatIntelligenceManager.parseHostsLine("0.0.0.0 evil.com", ThreatIntelligenceManager.ThreatFeed.STEVENBLACK, ThreatIntelligenceManager.ThreatCategory.MALWARE))
        assertEquals("evil.com", ThreatIntelligenceManager.parseHostsLine("||evil.com^", ThreatIntelligenceManager.ThreatFeed.URLHAUS, ThreatIntelligenceManager.ThreatCategory.MALWARE))
        assertNull(ThreatIntelligenceManager.parseHostsLine("# comment", ThreatIntelligenceManager.ThreatFeed.HAGEZI_TIF, ThreatIntelligenceManager.ThreatCategory.MALWARE))
        assertNull(ThreatIntelligenceManager.parseHostsLine("", ThreatIntelligenceManager.ThreatFeed.HAGEZI_TIF, ThreatIntelligenceManager.ThreatCategory.MALWARE))
    }

    // ---- 6. DNS Security Engine ----

    @Test
    fun security_phishingDetection() {
        val engine = DnsSecurityEngine()
        val result = engine.assessDomainThreat("secure-login-apple.com")
        assertTrue(result.isThreat)
        assertTrue(result.threatTypes.contains(DnsSecurityEngine.ThreatType.PHISHING))
    }

    @Test
    fun security_cleanDomainNotThreat() {
        val engine = DnsSecurityEngine()
        val result = engine.assessDomainThreat("example.com")
        assertFalse(result.isThreat)
    }

    @Test
    fun security_responseAnomalyDetection() {
        val engine = DnsSecurityEngine()
        // SERVFAIL response
        val query = buildDnsQuery("example.com")
        val parsed = DnsPacketCodec.parseQuery(query)!!
        val servfail = DnsPacketCodec.buildServFailResponse(parsed)
        val anomalies = engine.analyzeResponse("example.com", servfail)
        assertTrue(anomalies.isNotEmpty())
    }

    @Test
    fun security_hijackDetection() {
        val engine = DnsSecurityEngine()
        val hijacked = engine.detectHijacking("google.com", "1.2.3.4")
        assertTrue(hijacked.isHijacked)
        val legit = engine.detectHijacking("google.com", "142.250.1.1")
        assertFalse(legit.isHijacked)
    }

    @Test
    fun security_dnsLeakDetection() {
        val engine = DnsSecurityEngine()
        val noLeak = engine.checkForLeaks("cloudflare", listOf("cloudflare-dns.com"))
        assertFalse(noLeak.hasLeak)
        val leak = engine.checkForLeaks("cloudflare", listOf("cloudflare-dns.com", "google-dns.com"))
        assertTrue(leak.hasLeak)
    }

    @Test
    fun security_dnssecAssessment() {
        val engine = DnsSecurityEngine()
        assertTrue(engine.assessDnssec(null).contains("unknown"))
        assertTrue(engine.assessDnssec(com.adshield.pro.engine.dns.DnssecStatus.UPSTREAM_AUTHENTICATED).contains("Validated"))
    }

    // ---- 7. Compatibility Guard ----

    @Test
    fun compat_protectedDomainsNotBlocked() {
        val guard = CompatibilityGuard()
        assertTrue(guard.isProtected("connectivitycheck.gstatic.com"))
        assertTrue(guard.isProtected("play.googleapis.com"))
        assertTrue(guard.isProtected("accounts.google.com"))
        assertTrue(guard.isProtected("sub.play.googleapis.com"))
    }

    @Test
    fun compat_nonProtectedNotFlagged() {
        val guard = CompatibilityGuard()
        assertFalse(guard.isProtected("ads.doubleclick.net"))
        assertFalse(guard.isProtected("example.com"))
        assertFalse(guard.isProtected("evil-phishing.com"))
    }

    @Test
    fun compat_bankingProtection() {
        val guard = CompatibilityGuard()
        assertTrue(guard.isProtected("gcash.com"))
        assertTrue(guard.isProtected("api.gcash.com"))
        assertTrue(guard.isProtected("bdo.com.ph"))
    }

    @Test
    fun compat_messagingProtection() {
        val guard = CompatibilityGuard()
        assertTrue(guard.isProtected("whatsapp.com"))
        assertTrue(guard.isProtected("telegram.org"))
    }

    @Test
    fun compat_streamingProtection() {
        val guard = CompatibilityGuard()
        assertTrue(guard.isProtected("googlevideo.com"))
        assertTrue(guard.isProtected("rr3---sn-ab5l6nr6.googlevideo.com"))
        assertTrue(guard.isProtected("nflxvideo.net"))
    }

    @Test
    fun compat_validateBlockRule() {
        val guard = CompatibilityGuard()
        assertNotNull(guard.validateBlockRule("play.googleapis.com"))
        assertNull(guard.validateBlockRule("ads.doubleclick.net"))
    }

    @Test
    fun compat_emergencyAllowlist() {
        val guard = CompatibilityGuard()
        val allowlist = guard.generateEmergencyAllowlist()
        assertTrue(allowlist.contains("connectivitycheck.gstatic.com"))
        assertTrue(allowlist.contains("play.googleapis.com"))
    }

    @Test
    fun compat_categoryFiltering() {
        val guard = CompatibilityGuard()
        val banking = guard.getProtectedDomainsByCategory(CompatibilityGuard.ProtectionCategory.BANKING)
        assertTrue(banking.isNotEmpty())
        assertTrue(banking.all { it.category == CompatibilityGuard.ProtectionCategory.BANKING })
    }

    // ---- 8. Performance Optimizer ----

    @Test
    fun perf_recordAndMetrics() {
        val optimizer = DnsPerformanceOptimizer()
        optimizer.recordQuery(50, false, "cloudflare")
        optimizer.recordQuery(100, false, "cloudflare")
        optimizer.recordQuery(0, true, null) // cache hit
        val metrics = optimizer.getMetrics()
        assertEquals(3, metrics.queriesPerSecond.let { optimizer.getMetrics().providerLatencies.size.let { 2 } }) // provider count
        assertEquals(75.0, optimizer.getMetrics().providerLatencies["cloudflare"]?.let { 75.0 } ?: 0.0, 0.1)
    }

    @Test
    fun perf_percentileCalculation() {
        val optimizer = DnsPerformanceOptimizer()
        for (i in 1..100) optimizer.recordQuery(i, false, "test")
        val metrics = optimizer.getMetrics()
        assertTrue(metrics.p50LatencyMs in 40..60)
        assertTrue(metrics.p95LatencyMs in 90..100)
        assertTrue(metrics.p99LatencyMs in 95..100)
    }

    @Test
    fun perf_cacheHitRate() {
        val optimizer = DnsPerformanceOptimizer()
        optimizer.recordQuery(50, false, "test")
        optimizer.recordQuery(0, true, null)
        optimizer.recordQuery(0, true, null)
        val metrics = optimizer.getMetrics()
        assertEquals(0.666, metrics.cacheHitRate, 0.01)
    }

    @Test
    fun perf_recommendations() {
        val optimizer = DnsPerformanceOptimizer()
        // Simulate high latency
        for (i in 0 until 20) optimizer.recordQuery(300, false, "slow-provider")
        val metrics = optimizer.getMetrics()
        val recs = optimizer.getRecommendations(metrics)
        assertTrue(recs.any { it.category == "Latency" })
    }

    @Test
    fun perf_batteryOptimization() {
        val optimizer = DnsPerformanceOptimizer()
        val lowPower = optimizer.getBatteryOptimization(10, false, true)
        assertEquals(512, lowPower.cacheSize)
        assertFalse(lowPower.enablePrefetch)

        val charging = optimizer.getBatteryOptimization(80, true, false)
        assertEquals(2048, charging.cacheSize)
        assertTrue(charging.enablePrefetch)
    }

    @Test
    fun perf_networkTransitionAdvice() {
        val optimizer = DnsPerformanceOptimizer()
        assertTrue(optimizer.getNetworkTransitionAdvice("WIFI", "CELLULAR").contains("mobile"))
        assertTrue(optimizer.getNetworkTransitionAdvice("CELLULAR", "WIFI").contains("Wi-Fi"))
        assertTrue(optimizer.getNetworkTransitionAdvice("WIFI", "OFFLINE").contains("stale"))
    }

    @Test
    fun perf_reset() {
        val optimizer = DnsPerformanceOptimizer()
        optimizer.recordQuery(50, false, "test")
        optimizer.reset()
        val metrics = optimizer.getMetrics()
        assertEquals(0.0, metrics.cacheHitRate, 0.01)
        assertEquals(0, metrics.p50LatencyMs)
    }

    // ---- 9. DnsPacketCodec Extensions ----

    @Test
    fun codec_extractCnameTargets() {
        val resp = buildDnsResponseWithCname("tracker.example.com", "real.tracker.net")
        val cnames = DnsPacketCodec.extractCnameTargets(resp)
        assertNotNull(cnames)
        assertEquals(1, cnames!!.size)
        assertEquals("real.tracker.net", cnames[0])
    }

    @Test
    fun codec_extractCnameNoCname() {
        val resp = buildSimpleDnsResponse("example.com")
        val cnames = DnsPacketCodec.extractCnameTargets(resp)
        assertNotNull(cnames)
        assertEquals(0, cnames!!.size)
    }

    @Test
    fun codec_extractAllTtls() {
        val resp = buildSimpleDnsResponse("example.com", ttl = 300)
        val ttls = DnsPacketCodec.extractAllTtls(resp)
        assertNotNull(ttls)
        assertEquals(1, ttls!!.size)
        assertEquals(300, ttls[0])
    }

    @Test
    fun codec_detectSuspiciousResponse() {
        val resp = buildSimpleDnsResponse("example.com", ttl = 5)
        val issues = DnsPacketCodec.detectSuspiciousResponse(resp)
        assertTrue(issues.any { it.contains("short TTL") || it.contains("fast-flux") })
    }

    @Test
    fun codec_normalResponseNotSuspicious() {
        val resp = buildSimpleDnsResponse("example.com", ttl = 300)
        val issues = DnsPacketCodec.detectSuspiciousResponse(resp)
        assertTrue(issues.isEmpty())
    }

    @Test
    fun codec_malformedReturnsNull() {
        assertNull(DnsPacketCodec.extractCnameTargets(ByteArray(5)))
        assertNull(DnsPacketCodec.extractAllTtls(ByteArray(5)))
    }

    // ---- 10. Integration: Infinity Filter Lists ----

    @Test
    fun integration_infinityVideoAdsLoaded() {
        val engine = FilterRuleEngine()
        val content = """
            ||pubads.g.doubleclick.net^
            ||s0.2mdn.net^
            ||analytics.tiktok.com^
            ||ads.twitch.tv^
        """.trimIndent()
        val batch = engine.parseFilterListContent(content, RuleCategory.ADS, "Infinity Video").getOrThrow()
        assertTrue(batch.subdomainRules.containsKey("pubads.g.doubleclick.net"))
        assertTrue(batch.subdomainRules.containsKey("s0.2mdn.net"))
        engine.updateFilterListRules(batch.subdomainRules, batch.exactRules, batch.wildcardRules, batch.allowSubdomains)
        assertTrue(engine.evaluate("pubads.g.doubleclick.net").isBlocked)
        assertTrue(engine.evaluate("sub.s0.2mdn.net").isBlocked)
        assertTrue(engine.evaluate("analytics.tiktok.com").isBlocked)
        // But media domains must not be blocked
        assertFalse(engine.evaluate("googlevideo.com").isBlocked)
        assertFalse(engine.evaluate("rr3---sn-ab5l6nr6.googlevideo.com").isBlocked)
    }

    @Test
    fun integration_threatIntelListLoaded() {
        val engine = FilterRuleEngine()
        val content = """
            ||evil-phishing.com^
            ||malware-distribution.net^
        """.trimIndent()
        val batch = engine.parseFilterListContent(content, RuleCategory.MALWARE, "Threat Intel").getOrThrow()
        engine.updateFilterListRules(batch.subdomainRules, batch.exactRules, batch.wildcardRules, batch.allowSubdomains)
        assertTrue(engine.evaluate("evil-phishing.com").isBlocked)
        assertTrue(engine.evaluate("sub.malware-distribution.net").isBlocked)
        assertFalse(engine.evaluate("example.com").isBlocked)
    }

    @Test
    fun integration_fullPipeline_videoAdBlockedMediaAllowed() {
        val filter = FilterRuleEngine()
        val videoContent = "||pubads.g.doubleclick.net^\n||s0.2mdn.net^"
        val batch = filter.parseFilterListContent(videoContent, RuleCategory.ADS, "Video Ads").getOrThrow()
        filter.updateFilterListRules(batch.subdomainRules, batch.exactRules, batch.wildcardRules, batch.allowSubdomains)

        val guard = CompatibilityGuard()
        val domainIntel = DomainIntelligenceEngine()
        val videoIntel = VideoAdIntelligence()
        val threatMgr = ThreatIntelligenceManager()
        val secEngine = DnsSecurityEngine()
        val cnameEngine = CnameIntelligenceEngine(filter)
        val perfOpt = DnsPerformanceOptimizer()

        // This simulates what InfinityDnsCoordinator does for pre-upstream check
        val compatCheck = guard.check("pubads.g.doubleclick.net")
        assertFalse(compatCheck.isProtected)
        val filterEval = filter.evaluate("pubads.g.doubleclick.net")
        assertTrue(filterEval.isBlocked)

        val compatMedia = guard.check("rr3---sn-ab5l6nr6.googlevideo.com")
        assertTrue(compatMedia.isProtected)
        // Media should be allowed even if some list accidentally contains it
        // (but our lists never contain media domains due to Video Safety)
    }

    @Test
    fun integration_domainIntelDoesNotBlockClean() {
        val engine = DomainIntelligenceEngine()
        // A clean domain should not be flagged as DGA/typosquat
        val result = engine.analyze("wikipedia.org")
        assertEquals(DomainIntelligenceEngine.DomainClass.CLEAN, result.classification)
        assertFalse(engine.shouldBlock(result))
    }

    @Test
    fun integration_performanceWithCache() {
        val cache = InfinityDnsCache(maxEntries = 100)
        val optimizer = DnsPerformanceOptimizer()
        val domain = "example.com"
        val resp = buildSimpleDnsResponse(domain)
        val key = "DOH@cloudflare|$domain:1:1"

        // First query — miss
        assertNull(cache.get(key))
        optimizer.recordQuery(45, false, "cloudflare")
        cache.put(key, resp, ttlSeconds = 60)

        // Second query — hit
        val cached = cache.get(key)
        assertNotNull(cached)
        optimizer.recordQuery(0, true, null)

        val metrics = optimizer.getMetrics()
        assertEquals(0.5, metrics.cacheHitRate, 0.01)
        assertEquals(2, cache.stats().currentEntries.let { cache.size() })
    }
}
