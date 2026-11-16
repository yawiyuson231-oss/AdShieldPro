package com.adshield.pro

import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.engine.filter.PlaybackSafetyAudit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PlaybackSafetyAuditTest {

    private fun engineWith(vararg lines: String): FilterRuleEngine {
        val engine = FilterRuleEngine()
        val parsed = engine.parseFilterListContent(lines.joinToString("\n"), RuleCategory.ADS, "audit-test")
            .getOrThrow()
        engine.updateFilterListRules(
            subdomainRules = parsed.subdomainRules,
            exactRules = parsed.exactRules,
            wildcardRules = parsed.wildcardRules,
            allowSubdomains = parsed.allowSubdomains
        )
        return engine
    }

    private fun blocked(engine: FilterRuleEngine): (String) -> Boolean = { host -> engine.evaluate(host).isBlocked }

    @Test
    fun testACleanConfigurationReportsClearPlaybackAndActiveBlocking() {
        val engine = engineWith("||doubleclick.net^")
        val findings = PlaybackSafetyAudit.audit(blocked(engine))
        assertTrue(findings.any { it.title == "Playback zones are clear" })
        assertTrue(findings.any { it.title == "Advert blocking is active" })
        assertFalse(findings.any { it.severity == PlaybackSafetyAudit.Severity.PROBLEM })
    }

    @Test
    fun testABlockedMediaZoneIsReportedAsAProblemNamingTheZone() {
        // The feed parser refuses playback-breaking lines, so this is what a user-written rule can
        // still do — and exactly what the audit must catch.
        val engine = engineWith("||googlevideo.com^")
        assertFalse("the parser must refuse this line", engine.evaluate("r1.googlevideo.com").isBlocked)

        val findings = PlaybackSafetyAudit.audit { host -> host == "googlevideo.com" }
        val problem = findings.first { it.severity == PlaybackSafetyAudit.Severity.PROBLEM }
        assertEquals("googlevideo.com is blocked", problem.title)
        assertTrue(problem.detail.contains("YouTube"))
        assertFalse("a broken media zone cannot be reported as clear", findings.any { it.title == "Playback zones are clear" })
    }

    @Test
    fun testNoCoverageAtAllIsAWarningNotASilentSuccess() {
        val findings = PlaybackSafetyAudit.audit { false }
        val warning = findings.first { it.severity == PlaybackSafetyAudit.Severity.WARNING }
        assertEquals("No advert zone is covered", warning.title)
        assertTrue(warning.detail.contains("baseline"))
        assertFalse("blocking nothing must not be called active", findings.any { it.title == "Advert blocking is active" })
    }

    @Test
    fun testEveryFindingCarriesTextThatCanBeShownToAUser() {
        PlaybackSafetyAudit.audit { host -> host == "doubleclick.net" }.forEach { finding ->
            assertTrue("a finding needs a title", finding.title.isNotBlank())
            assertTrue("a finding needs a detail", finding.detail.isNotBlank())
        }
    }

    @Test
    fun testTheProbesAreZonesNotIndividualApiHosts() {
        PlaybackSafetyAudit.MEDIA_PROBES.forEach { (host, carries) ->
            assertTrue("$host must be a registrable zone", host.count { it == '.' } >= 1)
            assertTrue("$host must say what it carries", carries.isNotBlank())
            assertFalse("a probe must not be a wildcard", host.contains('*'))
        }
    }
}
