package com.adshield.pro

import com.adshield.pro.engine.platform.DiagnosticBattery
import com.adshield.pro.engine.platform.DiagnosticFilterSource
import com.adshield.pro.engine.platform.DiagnosticReport
import com.adshield.pro.engine.platform.DiagnosticReportInput
import com.adshield.pro.engine.platform.DiagnosticScanTotals
import com.adshield.pro.engine.platform.DiagnosticScrubber
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The diagnostic report is the one artefact a user is expected to share, so these tests pin the two
 * properties that make it safe to share: it carries no identifiers, and it never dresses up missing
 * data as a clean result.
 */
class DiagnosticReportTest {

    private fun input(
        lastError: String? = null,
        sources: List<DiagnosticFilterSource> = emptyList(),
        totalQueries: Long = 1_200L,
        scans: DiagnosticScanTotals = DiagnosticScanTotals(
            total = 1,
            clean = 1,
            lastScanEpochMs = 1_700_000_000_000L
        ),
        battery: DiagnosticBattery? = DiagnosticBattery(
            levelPercent = 64,
            healthLabel = "Good",
            temperatureCelsius = 31.5f,
            isCharging = false
        ),
        vpnStatus: String = "CONNECTED"
    ) = DiagnosticReportInput(
        generatedAtEpochMs = 1_700_000_000_000L,
        appVersion = "2.0.0",
        androidApiLevel = 34,
        protectionMode = "STANDARD",
        vpnStatus = vpnStatus,
        resolverLabel = "Cloudflare",
        dnsProtocol = "DNS-over-HTTPS (DoH)",
        dnssecMode = "Report upstream DNSSEC status",
        failoverEnabled = true,
        loadedRuleCount = 120_000,
        totalQueries = totalQueries,
        blockedQueries = 300L,
        malwareBlocks = 2L,
        detailedLoggingEnabled = true,
        logRetentionDays = 7,
        filterSources = sources,
        customRuleCount = 12,
        lastFilterUpdateEpochMs = 1_690_000_000_000L,
        scans = scans,
        quarantinedCount = 0,
        excludedAppCount = 3,
        siteExceptionCount = 1,
        scheduledScanEnabled = true,
        scheduledScanIntervalHours = 24,
        battery = battery,
        lastError = lastError
    )

    @Test
    fun testReportCarriesNoIdentifiers() {
        val report = DiagnosticReport.build(
            input(
                lastError = "handshake to https://dns.example.com/q?token=abc failed for " +
                    "/data/user/0/com.adshield.pro/files/state.pem from alice@example.com via 192.168.1.44 " +
                    "while ads.tracker.example.net stayed unresolved",
                sources = listOf(
                    DiagnosticFilterSource(
                        name = "Owner alice@example.com list",
                        enabled = true,
                        ruleCount = 50_000,
                        statusMessage = "Downloaded from https://lists.example.org/a.txt"
                    ),
                    DiagnosticFilterSource(name = "AdGuard DNS filter", enabled = true, ruleCount = 60_000)
                )
            )
        )
        listOf(
            "example.com",
            "example.org",
            "alice@",
            "@",
            "/data/user",
            "192.168.1.44",
            "com.adshield.pro",
            "state.pem",
            "token=abc",
            "ads.tracker.example.net",
            "https://"
        ).forEach { leaked ->
            assertFalse("report must not contain '$leaked'", report.contains(leaked))
        }
        assertTrue(report.contains(DiagnosticScrubber.PLACEHOLDER_URL))
        assertTrue(report.contains(DiagnosticScrubber.PLACEHOLDER_HOST))
        // Non-identifying context still has to survive, otherwise the report is useless to support.
        assertTrue(report.contains("Cloudflare"))
        assertTrue(report.contains("AdGuard DNS filter"))
        assertTrue(report.contains("31.5 °C"))
    }

    @Test
    fun testScrubberRemovesUrlsEmailsPathsAddressesAndLongTokens() {
        val digest = "a".repeat(64)
        val scrubbed = DiagnosticScrubber.redact(
            "url https://tracker.example.net/p?u=abc email bob@example.org path /sdcard/Download/x.apk " +
                "gateway 10.1.2.3 token $digest host ads.example.com"
        )
        listOf("tracker.example.net", "bob@", "sdcard", "10.1.2.3", digest, "ads.example.com").forEach { leaked ->
            assertFalse("scrubber must remove '$leaked'", scrubbed.contains(leaked))
        }
        assertTrue(scrubbed.contains(DiagnosticScrubber.PLACEHOLDER_URL))
        assertTrue(scrubbed.contains(DiagnosticScrubber.PLACEHOLDER_PATH))
        assertTrue(scrubbed.contains(DiagnosticScrubber.PLACEHOLDER_EMAIL))
        assertTrue(scrubbed.contains(DiagnosticScrubber.PLACEHOLDER_TOKEN))
    }

    @Test
    fun testPunctuationWrappedPathsAndUrlCredentialsAreRemoved() {
        // A path in parentheses is not preceded by whitespace, so it must still be recognised.
        val parenthesised = DiagnosticScrubber.redact("Family (/storage/emulated/0/Download/tax_2026)")
        assertFalse(parenthesised.contains("storage"))
        assertFalse(parenthesised.contains("tax_2026"))
        assertTrue(parenthesised.contains(DiagnosticScrubber.PLACEHOLDER_PATH))

        // An e-mail inside a query string must not truncate the URL match and leak the rest.
        val credentialed = DiagnosticScrubber.redact(
            "List https://lists.example.org/download?owner=alice@example.com&key=shortSecret"
        )
        listOf("lists.example.org", "alice", "shortSecret", "owner=").forEach { leaked ->
            assertFalse("scrubber must remove '$leaked'", credentialed.contains(leaked))
        }

        // Base64-shaped secrets carry + / = and must not slip past the token rule.
        val base64 = "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345+/="
        assertFalse(DiagnosticScrubber.redact("token $base64").contains(base64))

        val report = DiagnosticReport.build(
            input(
                sources = listOf(
                    DiagnosticFilterSource(
                        name = "Family (/storage/emulated/0/Download/tax_2026)",
                        enabled = true,
                        ruleCount = 5
                    )
                )
            )
        )
        // "storage" alone is too broad a probe: the quarantine line legitimately says
        // "app-private storage". These fragments can only come from the leaked path.
        listOf("tax_2026", "/storage/emulated", "Download").forEach { leaked ->
            assertFalse("report must not contain '$leaked'", report.contains(leaked))
        }
        assertTrue(report.contains("Family ([path removed])"))
    }

    @Test
    fun testPublicResolverAddressesSurviveSoTheReportStaysUseful() {
        val scrubbed = DiagnosticScrubber.redact("resolver 1.1.1.1 and 2606:4700:4700::1111 answered")
        assertTrue(scrubbed.contains("1.1.1.1"))
        assertTrue(scrubbed.contains("2606:4700:4700::1111"))
    }

    @Test
    fun testEmptyStateIsReportedAsNotMeasured() {
        val empty = input(
            totalQueries = 0L,
            scans = DiagnosticScanTotals(),
            battery = null,
            vpnStatus = "DISCONNECTED"
        )
        val report = DiagnosticReport.build(empty)
        assertTrue(report.contains("NO DNS QUERIES ARE LOGGED YET"))
        assertTrue(report.contains("NO SCAN HAS BEEN PERFORMED YET"))
        assertTrue(report.contains("Battery telemetry was not available"))
        val checks = DiagnosticReport.suggestions(empty)
        assertTrue(checks.any { it.contains("no DNS filtering is active") })
        assertTrue(checks.any { it.contains("No filter list is enabled") })
        assertTrue(checks.any { it.contains("No security scan has run yet") })
    }

    @Test
    fun testReportIsDeterministicAndIndependentOfSourceOrder() {
        val alpha = DiagnosticFilterSource(name = "Alpha list", enabled = true, ruleCount = 10)
        val beta = DiagnosticFilterSource(name = "Beta list", enabled = true, ruleCount = 90)
        val first = DiagnosticReport.build(input(sources = listOf(alpha, beta)))
        val second = DiagnosticReport.build(input(sources = listOf(beta, alpha)))
        assertEquals(first, second)
        assertEquals(first, DiagnosticReport.build(input(sources = listOf(alpha, beta))))
        assertTrue(
            "heaviest list must be listed first",
            first.indexOf("Beta list") < first.indexOf("Alpha list")
        )
    }

    @Test
    fun testFreeTextIsBoundedAndSourceListIsCapped() {
        val verbose = List(200) { "detail" }.joinToString("\n")
        val scrubbed = DiagnosticScrubber.redactFreeText(verbose)
        assertTrue("free text must be bounded, was ${scrubbed.length}", scrubbed.length <= 240)
        assertFalse(scrubbed.contains("\n"))
        assertTrue(scrubbed.endsWith("…"))

        val many = (1..30).map { DiagnosticFilterSource(name = "List $it", enabled = true, ruleCount = it) }
        val report = DiagnosticReport.build(input(sources = many))
        assertTrue(report.contains("(+18 more enabled source(s) not listed)"))
        assertFalse(report.contains("List 1:"))
        assertTrue(report.contains("List 30:"))
    }

    @Test
    fun testHealthyInputStillDeniesBeingAnAudit() {
        val populated = input(
            sources = listOf(DiagnosticFilterSource(name = "AdGuard DNS filter", enabled = true, ruleCount = 60_000))
        )
        val report = DiagnosticReport.build(populated)
        assertTrue(report.contains("It is not a security audit"))
        assertTrue(report.contains("25.0%"))
        assertTrue(DiagnosticReport.suggestions(populated).none { it.contains("no DNS filtering is active") })
    }
}
