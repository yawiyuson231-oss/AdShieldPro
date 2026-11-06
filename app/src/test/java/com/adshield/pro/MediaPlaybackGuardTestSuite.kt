package com.adshield.pro

import com.adshield.pro.domain.model.CustomRule
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.RuleMatchType
import com.adshield.pro.domain.model.RuleType
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.engine.media.MediaPlaybackGuard
import com.adshield.pro.engine.platform.CapabilityRegistry
import com.adshield.pro.testing.BundledAsset
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AdShield Pro — video-ad blocking and the media playback guarantee (pure APK, DNS layer).
 *
 * Blocking happens in [FilterRuleEngine.evaluate], which is what
 * [com.adshield.pro.service.AdShieldVpnService] calls for every DNS question, so these tests measure
 * the real production path for every app on the device — not a browser shim.
 *
 * The product rule is one sentence: **video must not break.** These tests are what makes that a
 * guarantee instead of a hope:
 *
 *  1. every shipped list is checked against every protected playback host;
 *  2. the engine exempts those hosts above any filter list — proved with a hostile list that
 *     *tries* to block them;
 *  3. the curated video-ad layer actually blocks VAST/VPAID/SDK/SSAI ad hosts;
 *  4. our own list is checked to contain no playback host and no wildcard that could swallow one.
 */
class MediaPlaybackGuardTestSuite {

    private val protected = MediaPlaybackGuard.PROTECTED_DELIVERY_HOSTS

    // ---------------------------------------------------------------- the shipped lists

    @Test
    fun shippedListsNeverBlockAPlaybackHost() {
        BundledAsset.RULE_LISTS.forEach { name ->
            val rules = BundledAsset.parsedHosts(name)
            assertTrue("$name could not be parsed", rules.isNotEmpty())
            val offenders = MediaPlaybackGuard.blockedPlaybackHosts(rules)
            assertTrue("$name blocks playback hosts $offenders — video would break", offenders.isEmpty())
        }
    }

    @Test
    fun theShippedSourceRowReportsTheRealRuleCount() {
        val actual = BundledAsset.parsedHosts(BundledAsset.VIDEO_AD_NETWORK).size
        assertTrue("video_ad_network.txt must ship a meaningful rule set", actual >= 60)
        assertTrue(
            "the bundled source row must not understate its rules: declared 71, parsed $actual",
            actual >= 71
        )
    }

    @Test
    fun videoAdListNeverNamesAPlaybackHostAndHasNoDangerousWildcard() {
        val lines = BundledAsset.assetPath(BundledAsset.VIDEO_AD_NETWORK).toFile().readLines()
            .map { it.substringBefore(" #").trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") && !it.startsWith("!") }

        assertTrue("the video-ad list must ship rules", lines.size >= 60)

        val blockRules = lines.filter { it.startsWith("||") && !it.startsWith("@@") }
        val allowRules = lines.filter { it.startsWith("@@||") }
        assertTrue("the list must state its playback exemptions", allowRules.isNotEmpty())
        assertEquals(
            "every exemption must be a plain hostname",
            allowRules.size,
            allowRules.count { it.matches(Regex("^@@\\|\\|[a-z0-9.-]+\\^$")) }
        )
        assertEquals(
            "block rules must be plain hostnames — a wildcard could swallow a CDN",
            blockRules.size,
            blockRules.count { it.matches(Regex("^\\|\\|[a-z0-9.-]+\\^$")) }
        )

        protected.forEach { host ->
            assertFalse(
                "video_ad_network.txt blocks protected playback host $host",
                blockRules.any { it == "||$host^" }
            )
        }
        val blocked = blockRules.map { it.removePrefix("||").removeSuffix("^") }.toSet()
        val allowed = allowRules.map { it.removePrefix("@@||").removeSuffix("^") }.toSet()
        assertTrue(
            "a host is both allowed and blocked: ${blocked intersect allowed}",
            (blocked intersect allowed).isEmpty()
        )
    }

    @Test
    fun theGuaranteeDoesNotDependOnTheLegacySafetyAllowlist() {
        // Defence in depth, not entanglement: even with the built-in safety allowlist emptied out,
        // playback hosts must still be exempted. If this ever fails, the two layers got coupled.
        val engine = FilterRuleEngine()
        val hostile = buildString { protected.forEach { appendLine("||$it^") } }
        val parsed = engine.parseFilterListContent(hostile, RuleCategory.ADS, "hostile-feed").getOrThrow()
        engine.updateFilterListRules(
            subdomainRules = parsed.subdomainRules,
            exactRules = parsed.exactRules,
            wildcardRules = parsed.wildcardRules,
            allowSubdomains = parsed.allowSubdomains
        )
        // Empty the legacy allowlist AFTER loading lists — updateFilterListRules re-merges it.
        engine.restoreSnapshot(engine.getCurrentSnapshot().copy(builtInAllowSubdomains = emptySet()))
        engine.updateProtectionMode(ProtectionMode.STRICT)
        assertTrue(
            "precondition: the legacy allowlist really is empty",
            engine.getCurrentSnapshot().builtInAllowSubdomains.isEmpty()
        )

        protected.forEach { host ->
            val result = engine.evaluate(host)
            assertFalse("$host blocked without the safety allowlist", result.isBlocked)
            assertEquals("Media Playback Guard", result.sourceName)
        }
        // And the safety allowlist still works for its own hosts when it is present.
        assertFalse(FilterRuleEngine().evaluate("connectivitycheck.gstatic.com").isBlocked)
    }

    // ---------------------------------------------------------------- the DNS engine

    @Test
    fun hostileListCannotBlockAPlaybackHost() {
        val engine = FilterRuleEngine()
        // The most aggressive thing a synced third-party feed could do.
        val hostile = buildString {
            appendLine("!! hostile feed that tries to take video down")
            protected.forEach { appendLine("||$it^") }
            appendLine("||youtube.com^")
            appendLine("||googlevideo.com^")
            appendLine("||nflxvideo.net^")
            appendLine("||ttvnw.net^")
        }
        val parsed = engine.parseFilterListContent(hostile, RuleCategory.ADS, "hostile-feed").getOrThrow()
        assertTrue("the hostile list must actually contain rules", parsed.totalValidRules > 40)
        engine.updateFilterListRules(
            subdomainRules = parsed.subdomainRules,
            exactRules = parsed.exactRules,
            wildcardRules = parsed.wildcardRules,
            allowSubdomains = parsed.allowSubdomains
        )
        engine.updateProtectionMode(ProtectionMode.STRICT)

        protected.forEach { host ->
            val result = engine.evaluate(host)
            assertFalse("$host was blocked by ${result.sourceName}", result.isBlocked)
            assertEquals("Media Playback Guard", result.sourceName)
            assertEquals(79, result.priority)
        }
        // Real delivery subdomains must survive too.
        listOf(
            "r1---sn-ab5l6ne7.googlevideo.com",
            "rr1---sn-4g5e6nez.googlevideo.com",
            "manifest.googlevideo.com",
            "v16-webapp-prime.tiktok.com",
            "video-edge-abc.xyz.nflxvideo.net",
            "usher.ttvnw.net",
            "video.xx.fbcdn.net"
        ).forEach { host ->
            assertFalse("delivery subdomain $host must stay reachable", engine.evaluate(host).isBlocked)
        }
    }

    @Test
    fun theExemptionSurvivesEveryProtectionMode() {
        val engine = FilterRuleEngine()
        val hostile = buildString { protected.forEach { appendLine("||$it^") } }
        val parsed = engine.parseFilterListContent(hostile, RuleCategory.ADS, "hostile-feed").getOrThrow()
        engine.updateFilterListRules(
            subdomainRules = parsed.subdomainRules,
            exactRules = parsed.exactRules,
            wildcardRules = parsed.wildcardRules,
            allowSubdomains = parsed.allowSubdomains
        )
        ProtectionMode.entries.toList().forEach { mode ->
            engine.updateProtectionMode(mode)
            protected.forEach { host ->
                assertFalse("$host blocked in ${mode.name}", engine.evaluate(host).isBlocked)
            }
        }
    }

    @Test
    fun videoAdHostsAreBlockedWhilePlaybackPlays() {
        val engine = FilterRuleEngine()
        BundledAsset.loadInto(engine, BundledAsset.VIDEO_AD_NETWORK)

        // Ad plumbing: must be blocked.
        listOf(
            "pubads.g.doubleclick.net",
            "googleads.g.doubleclick.net",
            "securepubads.g.doubleclick.net",
            "static.doubleclick.net",
            "pagead2.googlesyndication.com",
            "imasdk.googleapis.com",
            "www.googletagservices.com",
            "ads.pubmatic.com",
            "ssp.inmobi.com",
            "cdn.adsafeprotected.com",
            "ssai.google.com",
            "api.ssai.yospace.com",
            "ssai.bcovlive.io",
            "pixel.adsafeprotected.com"
        ).forEach { host ->
            assertTrue("video-ad host $host must be blocked", engine.evaluate(host).isBlocked)
        }

        // Playback: must not be touched, on the same engine instance.
        listOf(
            "www.youtube.com",
            "m.youtube.com",
            "i.ytimg.com",
            "r1---sn-ab5l6ne7.googlevideo.com",
            "manifest.googlevideo.com",
            "occ-0-2851-3648.1.nflxso.net",
            "www.tiktok.com",
            "v16-webapp.tiktok.com",
            "www.facebook.com",
            "usher.ttvnw.net",
            "d1v7jayx2s9clc.cloudfront.net" // generic CDN: not exempted, and not in our list
        ).forEach { host ->
            assertFalse("playback host $host must not be blocked", engine.evaluate(host).isBlocked)
        }
    }

    @Test
    fun aUserCanStillBlockAPlaybackHostDeliberately() {
        // The guarantee is a system default, not a cage: an explicit user block still wins,
        // because the user's own decision outranks every built-in list.
        val engine = FilterRuleEngine()
        engine.updateCustomRules(
            listOf(
                CustomRule(
                    id = 1L,
                    rawPattern = "facebook.com",
                    normalizedPattern = "facebook.com",
                    ruleType = RuleType.BLOCK,
                    matchType = RuleMatchType.SUBDOMAIN,
                    category = RuleCategory.CUSTOM,
                    priority = 90,
                    isEnabled = true
                )
            )
        )
        assertTrue("a deliberate user block must still apply", engine.evaluate("www.facebook.com").isBlocked)
        assertFalse("everything else stays protected", engine.evaluate("www.youtube.com").isBlocked)
    }

    @Test
    fun guardRecognisesHostsAndTheirSubdomainsButNotLookalikes() {
        assertTrue(MediaPlaybackGuard.isProtectedDeliveryHost("googlevideo.com"))
        assertTrue(MediaPlaybackGuard.isProtectedDeliveryHost("r1---sn-abc.googlevideo.com"))
        assertTrue(MediaPlaybackGuard.isProtectedDeliveryHost("YOUTUBE.COM"))
        assertFalse(MediaPlaybackGuard.isProtectedDeliveryHost("notyoutube.com"))
        assertFalse(MediaPlaybackGuard.isProtectedDeliveryHost("youtube.com.evil.example"))
        assertFalse(MediaPlaybackGuard.isProtectedDeliveryHost("googlevideo.site"))
        assertFalse(MediaPlaybackGuard.isProtectedDeliveryHost(null))
        // Generic ad-carrying CDNs are deliberately NOT exempted: exempting them would gut blocking.
        assertFalse(MediaPlaybackGuard.isProtectedDeliveryHost("cloudfront.net"))
        assertFalse(MediaPlaybackGuard.isProtectedDeliveryHost("d123.cloudfront.net"))
        assertFalse(MediaPlaybackGuard.isProtectedDeliveryHost("fastly.net"))
        assertFalse(MediaPlaybackGuard.isProtectedDeliveryHost("akamaihd.net"))
    }

    @Test
    fun theUiStatementMatchesWhatTheEngineActuallyDoes() {
        // The claim rendered under Capabilities is not allowed to drift from measured behaviour.
        val capabilities = CapabilityRegistry.capabilities
        val guarantee = capabilities.first { it.id == "media-playback-guarantee" }
        val layer = capabilities.first { it.id == "media-video-ad-layer" }
        val stitched = capabilities.first { it.id == "media-firstparty-video-ads" }

        assertEquals("third-party video-ad blocking must be claimed as implemented", "IMPLEMENTED", guarantee.status.name)
        assertEquals("IMPLEMENTED", layer.status.name)
        assertEquals("stitched-in ads must be declared unavailable, not hand-waved", "UNAVAILABLE", stitched.status.name)
        assertTrue(
            "the unavailable row must say why (same stream, no separate request): " +
                "${stitched.dataSources} ${stitched.limitations}",
            (stitched.dataSources + stitched.limitations).any { it.contains("same stream") }
        )
        assertTrue(
            "the guarantee must name its own cost: ${guarantee.limitations}",
            guarantee.limitations.any { it.contains("telemetry") || it.contains("whole host family") }
        )
        assertTrue(
            "the shipped video-ad layer must be described as curated, not as an upstream feed: ${layer.limitations}",
            layer.limitations.any { it.contains("curated") || it.contains("stitched") }
        )
        // Every claim on that screen must be reproducible by a test in this class.
        listOf(guarantee, layer).forEach { capability ->
            assertTrue(
                "${capability.id} names a verification that is not a real test: ${capability.verification}",
                capability.verification.startsWith("MediaPlaybackGuardTestSuite.")
            )
        }
    }

    @Test
    fun syncedListConflictsAreReportableSoTheUiCanWarn() {
        assertNotNull(MediaPlaybackGuard.exemptionReason("youtube.com"))
        assertNull(MediaPlaybackGuard.exemptionReason("doubleclick.net"))
        assertEquals(
            listOf("googlevideo.com", "netflix.com"),
            MediaPlaybackGuard.blockedPlaybackHosts(setOf("googlevideo.com", "netflix.com"))
        )
        assertTrue(MediaPlaybackGuard.blockedPlaybackHosts(emptySet()).isEmpty())
        assertTrue(
            "the user-facing claim must name its own limit",
            MediaPlaybackGuard.HONEST_CAPABILITY_STATEMENT.contains("cannot be removed by DNS")
        )
    }
}
