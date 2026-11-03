package com.adshield.pro

import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.engine.adskip.AdSkipDecisionEngine
import com.adshield.pro.engine.aether.NewDomainAgeChecker
import com.adshield.pro.engine.aether.StrictHeuristicsShield
import com.adshield.pro.engine.filter.FilterRuleEngine
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * OmniShield X v4.5.0 — Platform-spec acceptance tests.
 *
 * Verifies against the REAL bundled production lists:
 *  - the 100 most-used app domains are never blocked (Balanced AND Strict),
 *  - lookalike/homoglyph brand impostors and random-looking (DGA) names are
 *    observed in Balanced and blocked in Strict,
 *  - new-domain age parsing (RDAP) is correct and unknown ages are never acted on,
 *  - the universal in-app ad-skip keeps its never-break guarantees in every mode.
 */
class PlatformSpecAcceptanceTest {

    companion object {
        private fun readAsset(name: String): String {
            val candidates = listOf(File("src/main/assets/$name"), File("app/src/main/assets/$name"))
            val file = candidates.firstOrNull { it.isFile }
                ?: error("Bundled asset missing: $name")
            return file.readText()
        }

        private fun buildRealEngine(mode: ProtectionMode): FilterRuleEngine {
            val engine = FilterRuleEngine()
            var subdomains = emptyMap<String, FilterRuleEngine.FilterListEntry>()
            var exact = emptyMap<String, FilterRuleEngine.FilterListEntry>()
            val lists = listOf(
                "core_max_ads.txt" to RuleCategory.ADS,
                "core_max_threats.txt" to RuleCategory.MALWARE
            )
            for ((assetName, category) in lists) {
                val parsed = engine.parseFilterListContent(readAsset(assetName), category, assetName.removeSuffix(".txt"))
                    .getOrThrow()
                subdomains = subdomains + parsed.subdomainRules
                exact = exact + parsed.exactRules
            }
            engine.updateFilterListRules(subdomainRules = subdomains, exactRules = exact, wildcardRules = emptyList())
            engine.updateProtectionMode(mode)
            return engine
        }

        /** The 100+ most-used app apex domains across categories (spec acceptance gate). */
        private val TOP_APP_DOMAINS: Set<String> = linkedSetOf(
            // Social & messaging
            "facebook.com", "instagram.com", "whatsapp.com", "tiktok.com", "x.com", "twitter.com",
            "reddit.com", "snapchat.com", "pinterest.com", "linkedin.com", "discord.com",
            "telegram.org", "signal.org", "threads.net", "twitch.tv",
            // Video & music
            "youtube.com", "netflix.com", "spotify.com", "primevideo.com", "disneyplus.com",
            "hulu.com", "max.com", "viu.com", "iflix.com",
            // Shopping
            "amazon.com", "shopee.ph", "lazada.com.ph", "temu.com", "aliexpress.com", "ebay.com",
            "etsy.com", "walmart.com", "shein.com", "zalora.com.ph",
            // Payments & banking (PH + global)
            "paypal.com", "gcash.com", "maya.ph", "bdo.com.ph", "bpi.com.ph", "unionbankph.com",
            "securitybank.com", "metrobank.com.ph", "citibank.com", "chase.com", "bankofamerica.com",
            "wellsfargo.com", "wise.com", "remitly.com", "xoom.com", "visa.com", "mastercard.com",
            // Rides, food, travel
            "uber.com", "grab.com", "lyft.com", "doordash.com", "foodpanda.com.ph", "mcdonalds.com",
            "jollibee.com.ph", "starbucks.com", "booking.com", "airbnb.com", "agoda.com",
            "traveloka.com", "cebupacificair.com", "philippineairlines.com", "qatarairways.com", "emirates.com",
            // Google / Microsoft / Apple ecosystems
            "google.com", "gmail.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
            "withgoogle.com", "android.com", "microsoft.com", "live.com", "outlook.com",
            "office.com", "skype.com", "xbox.com", "apple.com", "icloud.com",
            // Work & productivity
            "zoom.us", "slack.com", "notion.so", "trello.com", "asana.com", "canva.com",
            "dropbox.com", "wetransfer.com",
            // Games
            "roblox.com", "minecraft.net", "steamcommunity.com", "steampowered.com", "epicgames.com",
            "riotgames.com", "mobilelegends.com", "garena.com", "nintendo.com", "playstation.com",
            // Utilities, cloud, web
            "mega.nz", "mediafire.com", "speedtest.net", "fast.com", "wikipedia.org",
            "github.com", "gitlab.com", "stackoverflow.com", "weather.com",
            // News & PH institutions
            "inquirer.net", "philstar.com", "gmanetwork.com", "abs-cbn.com", "cnn.com", "bbc.com",
            "nytimes.com", "philhealth.gov.ph", "sss.gov.ph", "bir.gov.ph", "dfa.gov.ph"
        )
    }

    @Test
    fun top100MostUsedAppDomains_neverBlocked_balancedAndStrict() {
        assertTrue("Domain corpus must cover at least 100 distinct domains", TOP_APP_DOMAINS.size >= 100)
        for (mode in listOf(ProtectionMode.STANDARD, ProtectionMode.STRICT)) {
            val engine = buildRealEngine(mode)
            for (domain in TOP_APP_DOMAINS) {
                val verdict = engine.evaluate(domain)
                assertFalse(
                    "$domain must NEVER be blocked (mode=$mode) — got rule=${verdict.matchedRule} from ${verdict.sourceName}",
                    verdict.isBlocked
                )
            }
        }
    }

    @Test
    fun top100AppDomains_heuristicShieldFindsNoSignals() {
        for (domain in TOP_APP_DOMAINS) {
            val verdict = StrictHeuristicsShield.evaluate(
                domain = domain,
                strictMode = true,
                dgaLike = false,
                lookalikeBrand = null,
                newDomainAgeDays = null,
                checkNewDomains = false
            )
            assertFalse("Real app domain $domain must not trip the heuristic shield: ${verdict.detail}", verdict.block)
        }
    }

    @Test
    fun lookalikeImpostors_detected_firstPartyNeverFlagged() {
        val shield = StrictHeuristicsShield
        // Real brands and their subdomains: never impostors
        assertNull(shield.lookalikeBrandHit("google.com"))
        assertNull(shield.lookalikeBrandHit("mail.google.com"))
        assertNull(shield.lookalikeBrandHit("amazon.com"))
        assertNull(shield.lookalikeBrandHit("paypal.com"))
        // Distance-1 typosquats
        assertEquals("google", shield.lookalikeBrandHit("googl.com"))
        assertEquals("google", shield.lookalikeBrandHit("goog1e.com"))
        assertEquals("paypal", shield.lookalikeBrandHit("paypa1.com"))
        assertEquals("amazon", shield.lookalikeBrandHit("amaz0n.com"))
        assertEquals("facebook", shield.lookalikeBrandHit("facobook.com"))
        // Homoglyph impostor: Cyrillic о folds to the exact brand → must be caught
        assertEquals("google", shield.lookalikeBrandHit("gооgle.com"))
        // Separator tricks
        assertEquals("google", shield.lookalikeBrandHit("google-secure-login.com"))
        // Brand embedded in unrelated TLD label
        assertEquals("netflix", shield.lookalikeBrandHit("netflix-billing.top"))
    }

    @Test
    fun dgaAndLookalikeSignals_observedInBalanced_blockedInStrict() {
        val dgaDomain = "xkqjvbmzpqowierutasl.com"
        assertTrue(com.adshield.pro.engine.aether.DnsAnomalyAnalyzer.looksDgaGenerated(dgaDomain))

        val balanced = StrictHeuristicsShield.evaluate(
            domain = dgaDomain, strictMode = false, dgaLike = true,
            lookalikeBrand = null, newDomainAgeDays = 5, checkNewDomains = true
        )
        assertFalse("Balanced mode observes, never blocks", balanced.block)
        assertTrue(balanced.signal != null)

        val strict = StrictHeuristicsShield.evaluate(
            domain = dgaDomain, strictMode = true, dgaLike = true,
            lookalikeBrand = "netflix", newDomainAgeDays = 5, checkNewDomains = true
        )
        assertTrue("Strict mode blocks on heuristic signals", strict.block)
        assertTrue(strict.detail!!.contains("lookalike"))
        assertTrue(strict.detail!!.contains("random-looking"))
        assertTrue(strict.detail!!.contains("5 days"))
    }

    @Test
    fun newDomainAge_rdapParsing_exactAndUnknown() {
        val epoch = NewDomainAgeChecker.parseIso8601Utc("2026-10-11T00:00:00Z")
        assertEquals(0L, NewDomainAgeChecker.parseIso8601Utc("1970-01-01T00:00:00Z"))
        val json = """{"events":[{"eventAction":"registration","eventDate":"2026-10-01T00:00:00Z"}],"ldhName":"example.com"}"""
        assertEquals(10, NewDomainAgeChecker.parseAgeDaysFromRdap(json, epoch!!))
        assertEquals(null, NewDomainAgeChecker.parseAgeDaysFromRdap("""{"ldhName":"example.com"}""", epoch))

        NewDomainAgeChecker.clearCache()
        // ageDays() uses the real clock by design — build the event date relative to it
        val now = System.currentTimeMillis()
        val cal = java.util.Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC"))
        cal.timeInMillis = now - 10L * 86_400_000L
        val iso10d = String.format(
            "%04d-%02d-%02dT%02d:%02d:%02dZ",
            cal.get(java.util.Calendar.YEAR), cal.get(java.util.Calendar.MONTH) + 1,
            cal.get(java.util.Calendar.DAY_OF_MONTH), cal.get(java.util.Calendar.HOUR_OF_DAY),
            cal.get(java.util.Calendar.MINUTE), cal.get(java.util.Calendar.SECOND)
        )
        val freshJson = """{"events":[{"eventAction":"registration","eventDate":"$iso10d"}]}"""
        val age = runBlocking {
            NewDomainAgeChecker.ageDays("fresh-example.net") { freshJson }
        }
        assertEquals(10, age)
        // Unknown age must be reported as null (never blocked on unknown data)
        val unknown = runBlocking {
            NewDomainAgeChecker.ageDays("opaque-example.net") { """{"status":"client hold"}""" }
        }
        assertEquals(null, unknown)
    }

    @Test
    fun universalAdSkip_protectedSystemUisNeverTouched_evenInUniversalMode() {
        val adNode = AdSkipDecisionEngine.NodeInfo(
            viewIdResourceName = "com.youtube.player/skip_ad_button",
            text = null, contentDescription = null, isClickable = true, packageName = null
        )
        for (pkg in listOf(
            "com.android.systemui", "com.google.android.launcher", "com.android.settings",
            "com.android.dialer", "com.samsung.android.messaging", "com.google.android.inputmethod.latin"
        )) {
            val action = AdSkipDecisionEngine.decide(adNode, pkg, universalMode = true)
            assertEquals("Protected system UI $pkg must never be auto-tapped", AdSkipDecisionEngine.ActionType.NONE, action.type)
        }
    }

    @Test
    fun universalAdSkip_thirdPartyVideoApp_skipsAdWithEvidence_onlyInUniversalMode() {
        val adNode = AdSkipDecisionEngine.NodeInfo(
            viewIdResourceName = "com.thirdparty.player/ima_skip_button",
            text = null, contentDescription = null, isClickable = true, packageName = null
        )
        val universal = AdSkipDecisionEngine.decide(adNode, "com.some.videoapp", universalMode = true)
        assertEquals(AdSkipDecisionEngine.ActionType.CLICK_SKIP, universal.type)

        val restricted = AdSkipDecisionEngine.decide(adNode, "com.some.videoapp", universalMode = false)
        assertEquals(AdSkipDecisionEngine.ActionType.NONE, restricted.type)
    }

    @Test
    fun universalAdSkip_safetyRulesHoldInUniversalMode() {
        // Bare "Skip" (accessibility link) — never an ad
        val bareSkip = AdSkipDecisionEngine.NodeInfo(null, "Skip", null, true, null)
        assertEquals(
            AdSkipDecisionEngine.ActionType.NONE,
            AdSkipDecisionEngine.decide(bareSkip, "com.any.app", universalMode = true).type
        )
        // Bare "✕" (cart drawer close) — never an ad
        val bareClose = AdSkipDecisionEngine.NodeInfo(null, "✕", "Close", true, null)
        assertEquals(
            AdSkipDecisionEngine.ActionType.NONE,
            AdSkipDecisionEngine.decide(bareClose, "com.any.shop", universalMode = true).type
        )
        // Ad's own call-to-action — never tapped
        val cta = AdSkipDecisionEngine.NodeInfo(null, "Download", "Download now", true, null)
        assertEquals(
            AdSkipDecisionEngine.ActionType.NONE,
            AdSkipDecisionEngine.decide(cta, "com.any.app", universalMode = true).type
        )
        // Countdown skip ("Skip in 5") in a third-party player — skipped in universal mode
        val countdown = AdSkipDecisionEngine.NodeInfo(null, "Skip in 5s", null, true, null)
        assertEquals(
            AdSkipDecisionEngine.ActionType.CLICK_SKIP,
            AdSkipDecisionEngine.decide(countdown, "com.any.videoapp", universalMode = true).type
        )
        // Textual close-ad in universal mode still works (with ad evidence)
        val closeAd = AdSkipDecisionEngine.NodeInfo(null, "Close ad", null, true, null)
        assertEquals(
            AdSkipDecisionEngine.ActionType.CLICK_CLOSE,
            AdSkipDecisionEngine.decide(closeAd, "com.any.game", universalMode = true).type
        )
    }
}
