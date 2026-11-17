package com.adshield.pro

import com.adshield.pro.domain.model.AppDnsActivity
import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.AppExclusionInfo
import com.adshield.pro.domain.model.CustomRule
import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.RuleMatchType
import com.adshield.pro.domain.model.RuleType
import com.adshield.pro.domain.model.TileVisualState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.browser.BrowserContentBlocker
import com.adshield.pro.engine.browser.LinkSanitizer
import com.adshield.pro.engine.dns.CnameCloakingInspector
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.DnsProviderHealthMonitor
import com.adshield.pro.engine.dns.DnsResolverBenchmark
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.engine.platform.ProtectionSnoozeEngine
import com.adshield.pro.engine.platform.ProtectionSnoozeEngine.AppFirewallFilter
import com.adshield.pro.engine.platform.ProtectionSnoozeEngine.StatusTone
import com.adshield.pro.engine.platform.ProtectionSnoozeEngine.WidgetAction
import com.adshield.pro.engine.security.UrlThreatScanner
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * End-to-end JVM verification suite for the AdShield Pro 2.11.0 feature expansion:
 * 1. CNAME-Cloaking Tracker Shield & DNS wire CNAME extraction
 * 2. Multi-provider DoH/DoT/UDP Resolver Speed Benchmark
 * 3. Per-App Firewall & Split-Tunnel filtering and summaries
 * 4. AdShield Shield Quick Settings Tile, Timed Auto-Resume Pause (Snooze) & Home Widget
 * 5. Android Share-Sheet & in-app Link Cleaner + Instant Threat Check
 */
class FeatureExpansion211TestSuite {

    private fun writeLabels(out: ByteArrayOutputStream, domain: String) {
        domain.trim('.').split('.').forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
    }

    private fun writeU16(out: ByteArrayOutputStream, v: Int) {
        out.write((v ushr 8) and 0xFF)
        out.write(v and 0xFF)
    }

    private fun writeU32(out: ByteArrayOutputStream, v: Long) {
        out.write(((v ushr 24) and 0xFF).toInt())
        out.write(((v ushr 16) and 0xFF).toInt())
        out.write(((v ushr 8) and 0xFF).toInt())
        out.write((v and 0xFF).toInt())
    }

    /** Builds a real RFC 1035 wire response containing a chain of CNAME records plus a final A RR. */
    private fun buildCnameChainResponse(
        txId: Int,
        question: String,
        cnameChain: List<String>,
        finalIpv4: ByteArray = byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34.toByte()),
        rcode: Int = 0
    ): ByteArray {
        val out = ByteArrayOutputStream()
        val anCount = cnameChain.size + 1
        writeU16(out, txId)
        writeU16(out, 0x8180 or (rcode and 0x0F)) // QR=1, RD=1, RA=1
        writeU16(out, 1) // QDCOUNT
        writeU16(out, anCount) // ANCOUNT
        writeU16(out, 0)
        writeU16(out, 0)

        writeLabels(out, question)
        writeU16(out, DnsPacketCodec.TYPE_A)
        writeU16(out, DnsPacketCodec.CLASS_IN)

        var owner = question
        for (target in cnameChain) {
            if (owner == question) {
                // Exercise RFC 1035 compression pointer to question name at offset 12.
                writeU16(out, 0xC00C)
            } else {
                writeLabels(out, owner)
            }
            writeU16(out, DnsPacketCodec.TYPE_CNAME)
            writeU16(out, DnsPacketCodec.CLASS_IN)
            writeU32(out, 120L)
            val rdata = ByteArrayOutputStream().also { writeLabels(it, target) }.toByteArray()
            writeU16(out, rdata.size)
            out.write(rdata)
            owner = target
        }

        writeLabels(out, owner)
        writeU16(out, DnsPacketCodec.TYPE_A)
        writeU16(out, DnsPacketCodec.CLASS_IN)
        writeU32(out, 60L)
        writeU16(out, 4)
        out.write(finalIpv4)
        return out.toByteArray()
    }

    @Test
    fun testCnameExtractionHandlesCompressedChainsAndRejectsMalformedWire() {
        val wire = buildCnameChainResponse(
            txId = 0x4242,
            question = "metrics.publisher.example",
            cnameChain = listOf("edge.publisher-cdn.example", "Collector.Eulerian.NET")
        )
        val targets = DnsPacketCodec.extractCnameTargets(wire)
        assertEquals(
            listOf("edge.publisher-cdn.example", "collector.eulerian.net"),
            targets
        )

        // Compressed target inside CNAME RDATA (sub.publisher.example using pointer to publisher.example)
        val compressedOut = ByteArrayOutputStream()
        writeU16(compressedOut, 0x1111)
        writeU16(compressedOut, 0x8180)
        writeU16(compressedOut, 1)
        writeU16(compressedOut, 1)
        writeU16(compressedOut, 0)
        writeU16(compressedOut, 0)
        // offset 12: "a.tracker.example" -> offset 14 is "tracker.example"
        writeLabels(compressedOut, "a.tracker.example")
        writeU16(compressedOut, DnsPacketCodec.TYPE_A)
        writeU16(compressedOut, DnsPacketCodec.CLASS_IN)
        writeU16(compressedOut, 0xC00C) // owner = a.tracker.example
        writeU16(compressedOut, DnsPacketCodec.TYPE_CNAME)
        writeU16(compressedOut, DnsPacketCodec.CLASS_IN)
        writeU32(compressedOut, 60L)
        val compressedRdata = ByteArrayOutputStream().apply {
            write(3)
            write("cdn".toByteArray(Charsets.US_ASCII))
            writeU16(this, 0xC000 or 14) // pointer to "tracker.example"
        }.toByteArray()
        writeU16(compressedOut, compressedRdata.size)
        compressedOut.write(compressedRdata)
        assertEquals(
            listOf("cdn.tracker.example"),
            DnsPacketCodec.extractCnameTargets(compressedOut.toByteArray())
        )

        // NXDOMAIN responses and queries (QR=0) must return no CNAME targets
        val nxWire = buildCnameChainResponse(0x2222, "a.example", listOf("b.example"), rcode = 3)
        assertTrue(DnsPacketCodec.extractCnameTargets(nxWire).isEmpty())

        val queryOnly = wire.copyOf().also { it[2] = (it[2].toInt() and 0x7F).toByte() }
        assertTrue(DnsPacketCodec.extractCnameTargets(queryOnly).isEmpty())

        // Trailing garbage inside CNAME RDLENGTH must be ignored safely
        val padded = ByteArrayOutputStream().apply {
            write(compressedOut.toByteArray().dropLast(compressedRdata.size + 2).toByteArray())
            writeU16(this, compressedRdata.size + 1)
            write(compressedRdata)
            write(0x00)
        }.toByteArray()
        assertTrue(DnsPacketCodec.extractCnameTargets(padded).isEmpty())
    }

    @Test
    fun testCnameCloakingBlocksTrackerAliasesWhileRespectingAllowlistAndMediaSafety() {
        val engine = FilterRuleEngine()
        engine.updateProtectionMode(ProtectionMode.STANDARD)
        val parsedList = engine.parseFilterListContent(
            """
            ||adtech-collector.example^
            ||pubads.g.doubleclick.net^
            """.trimIndent(),
            RuleCategory.TRACKERS,
            "Tracker Feed"
        ).getOrThrow()
        engine.updateFilterListRules(
            subdomainRules = parsedList.subdomainRules,
            exactRules = parsedList.exactRules,
            wildcardRules = parsedList.wildcardRules,
            allowSubdomains = parsedList.allowSubdomains
        )

        val cloakedWire = buildCnameChainResponse(
            txId = 0x3030,
            question = "stats.news-site.example",
            cnameChain = listOf("relay.news-site.example", "pixel.adtech-collector.example")
        )
        val qEval = engine.evaluate("stats.news-site.example")
        assertFalse(qEval.isBlocked)

        val blocked = CnameCloakingInspector.inspect(
            questionDomain = "stats.news-site.example",
            questionEvaluation = qEval,
            dnsResponse = cloakedWire,
            filterEngine = engine,
            enabled = true,
            bypassDomainFilters = false
        )
        assertTrue(blocked.shouldBlock)
        assertEquals("pixel.adtech-collector.example", blocked.cloakedTarget)
        assertEquals(RuleCategory.TRACKERS, blocked.matchedCategory)
        assertTrue(blocked.sourceName.startsWith("CNAME Uncloaking"))

        // Disabled toggle or per-app/network filter bypass allows the response untouched
        assertFalse(
            CnameCloakingInspector.inspect(
                "stats.news-site.example", qEval, cloakedWire, engine,
                enabled = false, bypassDomainFilters = false
            ).shouldBlock
        )
        assertFalse(
            CnameCloakingInspector.inspect(
                "stats.news-site.example", qEval, cloakedWire, engine,
                enabled = true, bypassDomainFilters = true
            ).shouldBlock
        )

        // Explicit user allow rule on the first-party host overrides CNAME blocking
        engine.updateCustomRules(
            listOf(
                CustomRule(
                    id = 1L,
                    pattern = "stats.news-site.example",
                    ruleType = RuleType.ALLOW,
                    matchType = RuleMatchType.EXACT
                )
            )
        )
        val allowEval = engine.evaluate("stats.news-site.example")
        assertFalse(
            CnameCloakingInspector.inspect(
                "stats.news-site.example", allowEval, cloakedWire, engine,
                enabled = true, bypassDomainFilters = false
            ).shouldBlock
        )

        // Streaming safety: CNAME onto a protected video CDN (googlevideo.com) is never broken
        val mediaWire = buildCnameChainResponse(
            txId = 0x4040,
            question = "stream.partner.example",
            cnameChain = listOf("rr2---sn-ab5l6nzl.googlevideo.com")
        )
        assertFalse(
            CnameCloakingInspector.inspect(
                "stream.partner.example",
                engine.evaluate("stream.partner.example"),
                mediaWire,
                engine,
                enabled = true,
                bypassDomainFilters = false
            ).shouldBlock
        )
    }

    @Test
    fun testDnsResolverBenchmarkRanksLiveProbesAndHandlesFailures() = runBlocking {
        val simulatedDelayByProvider = mapOf(
            "quad9" to 12L,
            "cloudflare" to 38L,
            "google" to 65L
        )
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor()).apply {
            providerTransport = UpstreamDnsResolver.ProviderTransport { query, _, endpoint ->
                val wait = simulatedDelayByProvider[endpoint.providerId]
                    ?: throw java.io.IOException("Simulated offline endpoint")
                Thread.sleep(wait)
                buildCnameChainResponse(
                    txId = query.transactionId,
                    question = query.questionDomain,
                    cnameChain = emptyList()
                )
            }
        }
        val config = DnsResolverConfig(
            preset = DnsProviderPreset.CLOUDFLARE,
            protocol = DnsProtocol.DOH
        )
        val report = DnsResolverBenchmark.run(resolver, config, "example.com", nowEpochMs = 1_700_000_000_000L)

        assertEquals("example.com", report.probeDomain)
        assertEquals(DnsProtocol.DOH, report.protocol)
        assertEquals(3, report.reachableCount)
        assertEquals(DnsProviderPreset.QUAD9, report.fastestReachable?.preset)
        // Reachable entries must sort strictly ascending by latency before unreachable ones
        val reachable = report.entries.filter { it.reachable }
        assertEquals(3, reachable.size)
        assertTrue(reachable[0].latencyMs!! <= reachable[1].latencyMs!!)
        assertTrue(reachable[1].latencyMs!! <= reachable[2].latencyMs!!)
        assertTrue(report.entries.drop(3).all { !it.reachable && it.latencyMs == null })
        // Benchmark must never pollute the live DNS cache
        assertEquals(0, resolver.getCacheSize())
    }

    @Test
    fun testAppFirewallSummaryAndFilteringModes() {
        val apps = listOf(
            AppExclusionInfo("com.bank.app", "City Bank", false, isExcludedFromVpn = true, AppDnsPolicy.DEFAULT, false, "Uses LAN mTLS"),
            AppExclusionInfo("com.offline.notes", "Offline Notes", false, isExcludedFromVpn = false, AppDnsPolicy.BLOCK_ALL, false, null),
            AppExclusionInfo("com.video.player", "StreamBox", false, isExcludedFromVpn = false, AppDnsPolicy.ALLOW_ALL, true, null),
            AppExclusionInfo("com.news.reader", "Daily News", false, isExcludedFromVpn = false, AppDnsPolicy.DEFAULT, false, null),
            AppExclusionInfo("com.android.systemui", "System UI", true, isExcludedFromVpn = false, AppDnsPolicy.DEFAULT, false, null),
            AppExclusionInfo("com.oem.telemetry", "OEM Telemetry", true, isExcludedFromVpn = false, AppDnsPolicy.BLOCK_ALL, false, null)
        )
        val activity = mapOf(
            "com.news.reader" to AppDnsActivity("com.news.reader", "Daily News", totalQueries = 42, blockedQueries = 11),
            "com.offline.notes" to AppDnsActivity("com.offline.notes", "Offline Notes", totalQueries = 7, blockedQueries = 7)
        )

        val summary = ProtectionSnoozeEngine.summarizeFirewall(apps, activity)
        assertEquals(6, summary.totalApps)
        assertEquals(1, summary.bypassedCount)
        assertEquals(2, summary.dnsBlockedCount)
        assertEquals(1, summary.dnsAllowAllCount)
        assertEquals(4, summary.customRuleCount)
        assertEquals(2, summary.activeTrafficCount)

        // Unconfigured system apps are hidden when includeSystemApps=false, but configured system apps remain visible!
        val defaultVisible = ProtectionSnoozeEngine.filterFirewallApps(
            apps, activity, "", AppFirewallFilter.ALL, includeSystemApps = false
        )
        assertEquals(5, defaultVisible.size)
        assertFalse(defaultVisible.any { it.packageName == "com.android.systemui" })
        assertTrue(defaultVisible.any { it.packageName == "com.oem.telemetry" })

        val dnsBlocked = ProtectionSnoozeEngine.filterFirewallApps(
            apps, activity, "", AppFirewallFilter.DNS_BLOCKED, includeSystemApps = false
        )
        assertEquals(setOf("com.offline.notes", "com.oem.telemetry"), dnsBlocked.map { it.packageName }.toSet())

        val bypassed = ProtectionSnoozeEngine.filterFirewallApps(
            apps, activity, "bank", AppFirewallFilter.BYPASSED, includeSystemApps = false
        )
        assertEquals(listOf("com.bank.app"), bypassed.map { it.packageName })

        val active = ProtectionSnoozeEngine.filterFirewallApps(
            apps, activity, "", AppFirewallFilter.ACTIVE_TRAFFIC, includeSystemApps = true
        )
        assertEquals(setOf("com.news.reader", "com.offline.notes"), active.map { it.packageName }.toSet())
    }

    @Test
    fun testProtectionSnoozeLifecycleAndTilePresentation() {
        val now = 1_700_000_000_000L
        assertEquals(1, ProtectionSnoozeEngine.clampMinutes(-5))
        assertEquals(15, ProtectionSnoozeEngine.clampMinutes(15))
        assertEquals(720, ProtectionSnoozeEngine.clampMinutes(9_999))

        val deadline = ProtectionSnoozeEngine.computeDeadline(now, 15)
        assertEquals(now + 15 * 60_000L, deadline)
        assertTrue(ProtectionSnoozeEngine.isSnoozeActive(deadline, now + 60_000L))
        assertFalse(ProtectionSnoozeEngine.isSnoozeDue(deadline, true, now + 60_000L))
        assertTrue(ProtectionSnoozeEngine.isSnoozeDue(deadline, true, deadline))
        assertFalse(ProtectionSnoozeEngine.isSnoozeDue(deadline, false, deadline + 5_000L))
        assertEquals("14m 0s left", ProtectionSnoozeEngine.formatRemaining(deadline, now + 60_000L))
        assertEquals("15m", ProtectionSnoozeEngine.formatRemainingCompact(deadline, now + 1_000L))

        val noConsent = ProtectionSnoozeEngine.presentShieldTile(
            VpnStatus.DISCONNECTED, false, 0L, 0L, hasVpnConsent = false, nowEpochMs = now
        )
        assertEquals(TileVisualState.INACTIVE, noConsent.state)
        assertEquals("Tap to allow VPN", noConsent.subtitle)

        val activeTile = ProtectionSnoozeEngine.presentShieldTile(
            VpnStatus.CONNECTED, true, 0L, 1_420L, hasVpnConsent = true, nowEpochMs = now
        )
        assertEquals(TileVisualState.ACTIVE, activeTile.state)
        assertEquals("Active · 1,420 blocked", activeTile.subtitle)

        val snoozedTile = ProtectionSnoozeEngine.presentShieldTile(
            VpnStatus.PAUSED, true, deadline, 1_420L, hasVpnConsent = true, nowEpochMs = now + 5 * 60_000L
        )
        assertEquals(TileVisualState.INACTIVE, snoozedTile.state)
        assertEquals("Paused · 10m", snoozedTile.subtitle)
    }

    @Test
    fun testHomeWidgetPresentationAcrossStates() {
        val now = 1_700_000_000_000L
        val connected = ProtectionSnoozeEngine.presentWidget(
            vpnStatus = VpnStatus.CONNECTED,
            vpnShouldRemainActive = true,
            snoozeUntilEpochMs = 0L,
            sessionBlocked = 250L,
            sessionTotal = 1_000L,
            allTimeBlocked = 12_500L,
            allTimeTotal = 50_000L,
            modeTitle = "Standard Mode",
            protocolName = "DOH",
            nowEpochMs = now
        )
        assertEquals("PROTECTED", connected.statusBadge)
        assertEquals(StatusTone.ACTIVE, connected.statusTone)
        assertEquals("Standard · DOH", connected.subtitle)
        assertEquals("250", connected.blockedCountLabel)
        assertEquals("25% of 1,000 session queries", connected.totalAndRateLabel)
        assertEquals(WidgetAction.STOP_VPN, connected.primaryAction)
        assertEquals(WidgetAction.SNOOZE_15M, connected.secondaryAction)

        val pausedSnooze = ProtectionSnoozeEngine.presentWidget(
            vpnStatus = VpnStatus.PAUSED,
            vpnShouldRemainActive = true,
            snoozeUntilEpochMs = now + 15 * 60_000L,
            sessionBlocked = 250L,
            sessionTotal = 1_000L,
            allTimeBlocked = 12_500L,
            allTimeTotal = 50_000L,
            modeTitle = "Strict Mode",
            protocolName = "DOT",
            nowEpochMs = now
        )
        assertEquals("PAUSED · 15m", pausedSnooze.statusBadge)
        assertEquals(StatusTone.PAUSED, pausedSnooze.statusTone)
        assertEquals(WidgetAction.RESUME_VPN, pausedSnooze.primaryAction)

        val off = ProtectionSnoozeEngine.presentWidget(
            vpnStatus = VpnStatus.DISCONNECTED,
            vpnShouldRemainActive = false,
            snoozeUntilEpochMs = 0L,
            sessionBlocked = 0L,
            sessionTotal = 0L,
            allTimeBlocked = 15_400L,
            allTimeTotal = 61_600L,
            modeTitle = "Standard Mode",
            protocolName = "DOH",
            nowEpochMs = now
        )
        assertEquals("OFF", off.statusBadge)
        assertEquals("15.4K", off.blockedCountLabel)
        assertEquals(WidgetAction.START_VPN, off.primaryAction)
        assertEquals(WidgetAction.OPEN_APP, off.secondaryAction)
    }

    @Test
    fun testLinkSanitizerStripsTrackersUnwrapsRedirectsAndPreservesFunctionalParams() {
        // 1. YouTube: strip `si` and `feature` while preserving `v`, `t` timestamp, and `list`!
        val yt = LinkSanitizer.sanitize("https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=43s&si=TrackToken99&list=PL123&feature=shared")
        assertEquals("https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=43s&list=PL123", yt.cleanedUrl)
        assertEquals(listOf("si", "feature"), yt.removedParams)
        assertTrue(yt.wasModified)

        // 2. Facebook outbound redirect wrapper + nested Instagram/UTM trackers
        val fbWrapped = "https://l.facebook.com/l.php?u=https%3A%2F%2Fshop.example.com%2Fitem%3Fsku%3DA%2BB%26utm_source%3Dig%26igshid%3Dxyz987%26fbclid%3DIwAR00&h=AT123"
        val unwrapped = LinkSanitizer.sanitize(fbWrapped, unwrapRedirects = true)
        assertEquals("https://shop.example.com/item?sku=A+B", unwrapped.cleanedUrl)
        assertEquals(listOf("l.facebook.com"), unwrapped.unwrappedFromHosts)
        assertEquals(listOf("utm_source", "igshid", "fbclid"), unwrapped.removedParams)

        // 3. Amazon product link: strip affiliate/search tracking while keeping `th=1&psc=1` variant selection
        val amz = LinkSanitizer.sanitize("https://www.amazon.com/dp/B08N5WRWNW?tag=aff-20&linkCode=ll1&pd_rd_i=B08N5WRWNW&qid=1700&sr=8-1&th=1&psc=1")
        assertEquals("https://www.amazon.com/dp/B08N5WRWNW?th=1&psc=1", amz.cleanedUrl)

        // 4. X / Twitter status strips `s` and `t`, while /search preserves `q` and `f`
        assertEquals(
            "https://x.com/example/status/1234567890",
            LinkSanitizer.sanitize("https://x.com/example/status/1234567890?s=46&t=SecretShareToken").cleanedUrl
        )
        assertEquals(
            "https://x.com/search?q=dnssec&f=live",
            LinkSanitizer.sanitize("https://x.com/search?q=dnssec&f=live&utm_medium=social").cleanedUrl
        )

        // 5. Privacy Browser integration increments stripped tracker counter accurately
        val blocker = BrowserContentBlocker(FilterRuleEngine())
        val cleaned = blocker.sanitizeTrackingParameters("https://youtu.be/dQw4w9WgXcQ?si=abc&t=12&gclid=999")
        assertEquals("https://youtu.be/dQw4w9WgXcQ?t=12", cleaned)
        assertEquals(2L, blocker.getStrippedTrackerParamCount())
    }

    @Test
    fun testSharedTextExtractionHandlesBalancedParensAndRejectsUnsafeRedirectSchemes() {
        // Balanced Wikipedia parentheses preserved; outer sentence parens & trailing period stripped
        val message = "Read this (https://en.wikipedia.org/wiki/DNS_(protocol)?utm_campaign=share&wprov=sfla1)."
        val result = LinkSanitizer.sanitizeSharedText(message)
        assertEquals(1, result.links.size)
        assertEquals(
            "Read this (https://en.wikipedia.org/wiki/DNS_(protocol)?wprov=sfla1).",
            result.cleanedText
        )
        assertEquals(listOf("utm_campaign"), result.primaryLink?.removedParams)

        // Evil javascript:/data: target inside a redirect wrapper must NEVER be unwrapped
        val evilRedirect = "https://www.google.com/url?q=javascript%3Aalert(1)&usg=AOvVaw"
        val safe = LinkSanitizer.sanitize(evilRedirect, unwrapRedirects = true)
        assertTrue(safe.unwrappedFromHosts.isEmpty())
        assertTrue(safe.cleanedUrl.startsWith("https://www.google.com/url"))

        // Cleaned phishing URL still triggers UrlThreatScanner detection
        val phishShare = "Urgent! https://l.facebook.com/l.php?u=http%3A%2F%2Fpaypa1.com%2Flogin%2Fverify%3Ffbclid%3D123"
        val cleanedPhish = LinkSanitizer.sanitizeSharedText(phishShare)
        assertEquals("http://paypa1.com/login/verify", cleanedPhish.primaryLink?.cleanedUrl)
        val verdict = UrlThreatScanner().scan(cleanedPhish.primaryLink!!.cleanedUrl)
        assertFalse(verdict.isSafe)
        assertTrue(verdict.riskScore > 0)
    }
}
