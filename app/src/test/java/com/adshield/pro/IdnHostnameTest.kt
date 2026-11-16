package com.adshield.pro

import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.engine.filter.DnsMediaPlaybackGuard
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.engine.filter.HostNameNormalizer
import com.adshield.pro.engine.filter.TemporaryAllowlist
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A Unicode hostname and its punycode form must be the same host to the filter, or a rule written
 * in one form misses queries sent in the other.
 */
class IdnHostnameTest {

    private fun engineWith(vararg lines: String): FilterRuleEngine {
        val engine = FilterRuleEngine()
        val parsed = engine.parseFilterListContent(lines.joinToString("\n"), RuleCategory.ADS, "idn-test")
            .getOrThrow()
        engine.updateFilterListRules(
            subdomainRules = parsed.subdomainRules,
            exactRules = parsed.exactRules,
            wildcardRules = parsed.wildcardRules,
            allowSubdomains = parsed.allowSubdomains
        )
        return engine
    }

    @Test
    fun testToAsciiConvertsOnlyTheLabelsThatNeedIt() {
        assertEquals("xn--mnchen-3ya.example", HostNameNormalizer.toAscii("münchen.example"))
        assertEquals("xn--mnchen-3ya.example", HostNameNormalizer.toAscii("xn--mnchen-3ya.example"))
        assertEquals("*.xn--mnchen-3ya.example", HostNameNormalizer.toAscii("*.münchen.example"))
        assertEquals("plain.example", HostNameNormalizer.toAscii("plain.example"))
        assertEquals("", HostNameNormalizer.toAscii(""))
        assertEquals("xn--bcher-kva.example", HostNameNormalizer.toAscii("bücher.example"))
        // Empty labels survive the conversion: the split/join never invents or drops a label.
        assertEquals("xn--mnchen-3ya..example", HostNameNormalizer.toAscii("münchen..example"))
    }

    @Test
    fun testAUnicodeRuleBlocksBothFormsOfTheQuery() {
        val engine = engineWith("||münchen-ads.de^")
        assertTrue("punycode query", engine.evaluate("xn--mnchen-ads-9db.de").isBlocked)
        assertTrue("unicode query", engine.evaluate("münchen-ads.de").isBlocked)
        assertTrue("mixed case and trailing dot", engine.evaluate("ADS.MÜNCHEN-ADS.DE.").isBlocked)
        assertTrue("subdomain", engine.evaluate("sub.xn--mnchen-ads-9db.de").isBlocked)
        assertFalse(engine.evaluate("example.de").isBlocked)
    }

    @Test
    fun testAPunycodeRuleBlocksTheUnicodeQuery() {
        val engine = engineWith("||xn--mnchen-ads-9db.de^")
        val evaluation = engine.evaluate("münchen-ads.de")
        assertTrue(evaluation.isBlocked)
        assertEquals("the log must name the normalized host", "xn--mnchen-ads-9db.de", evaluation.domain)
    }

    @Test
    fun testThePlaybackGuardSeesTheSameHostInBothForms() {
        assertEquals("xn--mnchen-3ya.example", DnsMediaPlaybackGuard.normalizeDomain("MÜNCHEN.example."))
        // A name that cannot be a hostname is refused rather than guessed at.
        assertEquals("", DnsMediaPlaybackGuard.normalizeDomain("münchen..example"))
        assertEquals("", DnsMediaPlaybackGuard.normalizeDomain("münchen example"))
    }

    @Test
    fun testATemporaryLeaseCoversBothForms() {
        val list = TemporaryAllowlist().apply { clock = { 1_000L } }
        assertNotNull(list.grant("münchen.example", durationMs = 600_000L))
        assertTrue(list.isAllowed("xn--mnchen-3ya.example"))
        assertTrue(list.isAllowed("münchen.example"))
        assertFalse(list.isAllowed("example"))
    }
}
