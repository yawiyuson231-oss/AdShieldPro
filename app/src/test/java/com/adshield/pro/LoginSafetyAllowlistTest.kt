package com.adshield.pro

import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.engine.filter.DnsMediaPlaybackGuard
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.engine.filter.LoginSafetyAllowlist
import com.adshield.pro.engine.filter.VideoAdNetworkCatalog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Blocking harder must never cost a login, a checkout or a captcha. These zones are exempted
 * inside the rule engine, before any feed rule is consulted.
 */
class LoginSafetyAllowlistTest {

    @Test
    fun testAggressiveRulesCannotBreakLoginsPaymentsOrCaptchas() {
        val engine = FilterRuleEngine()
        val batch = engine.parseFilterListContent(
            """
            ||accounts.google.com^
            ||login.microsoftonline.com^
            ||login.paypal.com^
            ||hcaptcha.com^
            ||doubleclick.net^
            """.trimIndent(),
            RuleCategory.ADS,
            "HostileList"
        ).getOrThrow()
        engine.updateFilterListRules(
            subdomainRules = batch.subdomainRules,
            exactRules = batch.exactRules,
            wildcardRules = batch.wildcardRules,
            allowSubdomains = batch.allowSubdomains
        )
        engine.updateProtectionMode(ProtectionMode.STRICT)

        listOf(
            "accounts.google.com",
            "login.microsoftonline.com",
            "login.paypal.com",
            "hcaptcha.com"
        ).forEach { host ->
            val result = engine.evaluate(host)
            assertFalse("$host must never be blocked", result.isBlocked)
            assertEquals("$host must be allowed by the safety allowlist", "System Safety Allowlist", result.sourceName)
        }

        assertTrue("ordinary ad infrastructure is still blocked", engine.evaluate("doubleclick.net").isBlocked)
    }

    @Test
    fun testLoginCriticalMatchingRespectsLabelBoundaries() {
        assertTrue(LoginSafetyAllowlist.isLoginCritical("accounts.google.com"))
        assertTrue(LoginSafetyAllowlist.isLoginCritical("HTTPS://Signin.PayPal.com:443/checkout"))
        assertTrue(LoginSafetyAllowlist.isLoginCritical("login.paypal.com"))
        assertFalse(LoginSafetyAllowlist.isLoginCritical("evil-paypal.com"))
        assertFalse(LoginSafetyAllowlist.isLoginCritical("paypal.com.secure-verify.tk"))
        assertFalse(LoginSafetyAllowlist.isLoginCritical(""))
    }

    @Test
    fun testSafetyZonesNeverOverlapTheAdOrCdnZones() {
        LoginSafetyAllowlist.ZONES.forEach { zone ->
            assertFalse(
                "$zone is also a video-ad zone",
                VideoAdNetworkCatalog.ENTRIES.any { it.suffix == zone }
            )
            assertFalse(
                "$zone is a shared CDN zone",
                DnsMediaPlaybackGuard.SHARED_CDN_ZONES.contains(zone)
            )
            assertTrue("$zone must be a real hostname", zone.contains('.'))
        }
        assertEquals(
            "safety zones must be unique",
            LoginSafetyAllowlist.ZONES.size,
            LoginSafetyAllowlist.ZONES.map { it.lowercase() }.distinct().size
        )
    }

    @Test
    fun testCaptivePortalChecksStayAllowed() {
        val engine = FilterRuleEngine()
        val batch = engine.parseFilterListContent(
            "||connectivitycheck.gstatic.com^\n||captive.apple.com^",
            RuleCategory.ADS,
            "HostileList"
        ).getOrThrow()
        engine.updateFilterListRules(
            subdomainRules = batch.subdomainRules,
            exactRules = batch.exactRules,
            wildcardRules = batch.wildcardRules,
            allowSubdomains = batch.allowSubdomains
        )
        engine.updateProtectionMode(ProtectionMode.STRICT)
        assertFalse(engine.evaluate("connectivitycheck.gstatic.com").isBlocked)
        assertFalse(engine.evaluate("captive.apple.com").isBlocked)
    }
}
