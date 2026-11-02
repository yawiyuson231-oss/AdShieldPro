package com.adshield.pro

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.FilterEvaluationResult
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.engine.dns.DnsLeakDetector
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.engine.zero.ZeroBreakageEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * TitanShield Max — Module 11: Automated DNS-Firewall Compatibility & Quality suite.
 *
 * These tests load the REAL bundled production blocklists (HaGeZi Multi Pro ADS +
 * Threat Intelligence mini, 367k+ rules) into the real FilterRuleEngine and verify
 * that what users actually need — video playback, login/auth, payments, app stores,
 * game servers, messaging — is NEVER blocked, while ads/trackers/malware still are.
 *
 * This is the "run compatibility tests before enabling aggressive rules" gate:
 * if a future blocklist or engine change breaks any of these, CI fails before release.
 */
class DnsFirewallCompatibilityTest {

    companion object {
        /** Engine loaded once for the whole class against the real production rule set. */
        private val sharedEngine: FilterRuleEngine by lazy { buildRealEngine() }

        private fun readAsset(name: String): String {
            val candidates = listOf(File("src/main/assets/$name"), File("app/src/main/assets/$name"))
            val file = candidates.firstOrNull { it.isFile }
                ?: error("Bundled asset missing: $name (looked in ${candidates.map { it.path }})")
            return file.readText()
        }

        private fun buildRealEngine(): FilterRuleEngine {
            val engine = FilterRuleEngine()

            var subdomains = emptyMap<String, FilterRuleEngine.FilterListEntry>()
            var exact = emptyMap<String, FilterRuleEngine.FilterListEntry>()
            var wildcards = emptyList<FilterRuleEngine.WildcardEntry>()

            val lists = listOf(
                "core_max_ads.txt" to RuleCategory.ADS,
                "core_max_threats.txt" to RuleCategory.MALWARE
            )
            for ((assetName, category) in lists) {
                val parsed = engine.parseFilterListContent(readAsset(assetName), category, assetName.removeSuffix(".txt"))
                    .getOrThrow()
                subdomains = subdomains + parsed.subdomainRules
                exact = exact + parsed.exactRules
                wildcards = wildcards + parsed.wildcardRules
            }

            engine.updateFilterListRules(
                subdomainRules = subdomains,
                exactRules = exact,
                wildcardRules = wildcards
            )
            engine.updateProtectionMode(ProtectionMode.STANDARD)
            return engine
        }

        private fun expectAllowed(host: String) {
            val result = sharedEngine.evaluate(host)
            assertTrue(
                "COMPATIBILITY BREAK: '$host' must be allowed but was BLOCKED by '${result.sourceName}' (${result.matchedRule})",
                !result.isBlocked
            )
        }

        private fun expectBlocked(host: String) {
            val result = sharedEngine.evaluate(host)
            assertTrue(
                "PROTECTION REGRESSION: '$host' must be blocked but was ALLOWED via '${result.sourceName}'",
                result.isBlocked
            )
        }
    }

    // --- Module 5: Video playback compatibility (against the REAL lists) ---

    @Test
    fun compatibility_youtubePlaybackDomains_neverBlocked() {
        expectAllowed("r1---sn-ab5l6ne7.googlevideo.com")
        expectAllowed("rr3---sn-npoe7ney.googlevideo.com")
        expectAllowed("i.ytimg.com")
        expectAllowed("www.youtube.com")
        expectAllowed("m.youtube.com")
    }

    @Test
    fun compatibility_netflixPlaybackDomains_neverBlocked() {
        expectAllowed("www.netflix.com")
        expectAllowed("nflxvideo.net")
        expectAllowed("ipv4-c001-arn001-airbnb-isp.1.nflxso.net")
        expectAllowed("occ-0-2794-2795.1.nflxso.net")
    }

    @Test
    fun compatibility_tikTokPlaybackDomains_neverBlocked() {
        expectAllowed("www.tiktok.com")
        expectAllowed("v16-webapp.tiktok.com")
        expectAllowed("p16-sign.tiktokcdn.com")
        expectAllowed("v20.muscdn.com")
    }

    @Test
    fun compatibility_facebookInstagramCore_neverBlocked() {
        expectAllowed("www.facebook.com")
        expectAllowed("web.facebook.com")
        expectAllowed("www.instagram.com")
        expectAllowed("scontent.xx.fbcdn.net")
        expectAllowed("scontent.cdninstagram.com")
    }

    // --- Module 4: Auth, payments, stores, games, messaging ---

    @Test
    fun compatibility_authenticationDomains_neverBlocked() {
        expectAllowed("accounts.google.com")
        expectAllowed("myaccount.google.com")
        expectAllowed("oauthaccountmanager.googleapis.com")
        expectAllowed("login.microsoftonline.com")
        expectAllowed("appleid.apple.com")
        expectAllowed("api.twitter.com")
    }

    @Test
    fun compatibility_bankingPaymentDomains_neverBlocked() {
        expectAllowed("www.paypal.com")
        expectAllowed("js.stripe.com")
        expectAllowed("api.stripe.com")
        expectAllowed("www.gcash.com")
        expectAllowed("checkout.com")
    }

    @Test
    fun compatibility_playStoreAndUpdates_neverBlocked() {
        expectAllowed("play.google.com")
        expectAllowed("android.clients.google.com")
        expectAllowed("play.googleapis.com")
        expectAllowed("update.googleapis.com")
        expectAllowed("sdk.samsung.com")
    }

    @Test
    fun compatibility_gameServers_neverBlocked() {
        expectAllowed("aena.ms")
        expectAllowed("ylgdmirp.yleaflyrn.aena.ms") // MLBB-style deep server subdomain
        expectAllowed("mobile.yesware.garena.com")
        expectAllowed("clientsettings.roblox.com")
        expectAllowed("riotgames.com")
    }

    @Test
    fun compatibility_messagingDomains_neverBlocked() {
        expectAllowed("web.whatsapp.com")
        expectAllowed("api.telegram.org")
        expectAllowed("discord.com")
        expectAllowed("cdn.discordapp.com")
    }

    // --- Protection must still work (the whole point) ---

    @Test
    fun protection_adsTrackersMalware_stillBlocked() {
        expectBlocked("doubleclick.net")
        expectBlocked("www.googletagmanager.com")
        expectBlocked("google-analytics.com")
        expectBlocked("ads.adnxs.com")
        expectBlocked("scorecardresearch.com")
        expectBlocked("connect.facebook.net")
        expectBlocked("static.criteo.net")
    }

    // --- Critical Protection layer unit behavior ---

    @Test
    fun criticalProtection_beatsFilterLists_butNotUserRules() {
        val engine = FilterRuleEngine()
        val parsed = engine.parseFilterListContent("||googlevideo.com^\n||stripe.com^", RuleCategory.ADS, "Synthetic")
            .getOrThrow()
        engine.updateFilterListRules(parsed.subdomainRules, parsed.exactRules, parsed.wildcardRules)
        engine.updateProtectionMode(ProtectionMode.STANDARD)

        // Even though the list explicitly blocks these, Critical Protection wins.
        val video = engine.evaluate("rr2---sn-x.googlevideo.com")
        assertFalse(video.isBlocked)
        assertTrue(video.sourceName.contains("Critical Protection"))

        // A deliberate USER rule outranks the protection layer.
        engine.updateCustomRules(
            listOf(
                com.adshield.pro.domain.model.CustomRule(
                    rawPattern = "||googlevideo.com^",
                    normalizedPattern = "googlevideo.com",
                    ruleType = com.adshield.pro.domain.model.RuleType.BLOCK,
                    matchType = com.adshield.pro.domain.model.RuleMatchType.SUBDOMAIN,
                    comment = "user override test",
                    isEnabled = true
                )
            )
        )
        val userWin = engine.evaluate("rr2---sn-x.googlevideo.com")
        assertTrue("User explicit block must outrank Critical Protection", userWin.isBlocked)
        assertEquals("User Blocklist", userWin.sourceName)
    }

    // --- Module 7: Zero-Breakage watchdog logic ---

    @Test
    fun zeroBreakage_threeFailuresTriggerSafeMode_thenRecoveryRestores() {
        val zb = ZeroBreakageEngine()
        assertEquals(ZeroBreakageEngine.WatchdogAction.NONE, zb.onProbeResult(true))
        assertEquals(ZeroBreakageEngine.WatchdogAction.NONE, zb.onProbeResult(false))
        assertEquals(ZeroBreakageEngine.WatchdogAction.NONE, zb.onProbeResult(false))
        assertEquals(ZeroBreakageEngine.WatchdogAction.SAFE_MODE_FILTERING, zb.onProbeResult(false))
        assertTrue(zb.isSafeModeActive())

        // Still failing → stays in safe mode, no action flapping
        assertEquals(ZeroBreakageEngine.WatchdogAction.NONE, zb.onProbeResult(false))

        // Connectivity restored → restore full filtering exactly once
        assertEquals(ZeroBreakageEngine.WatchdogAction.RESTORE_FULL_FILTERING, zb.onProbeResult(true))
        assertFalse(zb.isSafeModeActive())
        assertEquals(ZeroBreakageEngine.WatchdogAction.NONE, zb.onProbeResult(true))
    }

    // --- Module 3/7: Shadow Mode semantics ---

    @Test
    fun shadowMode_reportsInsteadOfBlocking_andStaysHonestWhenOff() {
        val engine = FilterRuleEngine()
        val parsed = engine.parseFilterListContent("||tracker.example^", RuleCategory.ADS, "Synthetic").getOrThrow()
        engine.updateFilterListRules(parsed.subdomainRules, parsed.exactRules, parsed.wildcardRules)
        engine.updateProtectionMode(ProtectionMode.STANDARD)

        // Shadow OFF: real blocking
        assertTrue(engine.evaluate("ads.tracker.example").isBlocked)

        // Shadow ON: reported, allowed
        val captured = ArrayList<Pair<String, FilterEvaluationResult>>()
        engine.shadowDecisionListener = { domain, result -> captured.add(domain to result) }
        engine.setShadowModeEnabled(true)

        val shadowed = engine.evaluate("ads.tracker.example")
        assertFalse("Shadow mode must not enforce list blocks", shadowed.isBlocked)
        assertTrue(shadowed.sourceName.contains("Shadow Mode"))
        assertEquals(1, captured.size)
        assertEquals("ads.tracker.example", captured.first().first)

        // Shadow OFF again: full enforcement returns
        engine.setShadowModeEnabled(false)
        assertTrue(engine.evaluate("ads.tracker.example").isBlocked)
        assertEquals(1, captured.size)
    }

    // --- Module 1/6: DNS leak assessment ---

    @Test
    fun dnsLeakDetector_reportsEncryptionAndLimitationsHonesty() {
        val doh = DnsLeakDetector.assess(DnsResolverConfig(protocol = DnsProtocol.DOH), vpnActive = true)
        assertTrue(doh.upstreamEncrypted)
        assertTrue(doh.honestLimitations.any { it.contains("bypass") }) // hardcoded-resolver disclosure

        val plain = DnsLeakDetector.assess(DnsResolverConfig(protocol = DnsProtocol.UDP_TCP), vpnActive = true)
        assertFalse(plain.upstreamEncrypted)
        assertTrue(plain.protectionSummary.contains("visible"))

        val off = DnsLeakDetector.assess(DnsResolverConfig(protocol = DnsProtocol.DOH), vpnActive = false)
        assertFalse(off.upstreamEncrypted)
        assertTrue(off.protectionSummary.contains("VPN is off"))
    }
}
