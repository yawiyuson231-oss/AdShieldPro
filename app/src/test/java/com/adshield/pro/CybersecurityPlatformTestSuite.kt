package com.adshield.pro

import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.DnsFirewallPolicy
import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.DnssecMode
import com.adshield.pro.domain.model.FilterEvaluationResult
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.engine.dns.DnsDiagnosticQueryFactory
import com.adshield.pro.engine.dns.DnsFirewallPolicyDecider
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.DnsProviderHealthMonitor
import com.adshield.pro.engine.dns.DnsProviderRegistry
import com.adshield.pro.engine.dns.DnsResponseValidationException
import com.adshield.pro.engine.dns.DnsResponseValidator
import com.adshield.pro.engine.dns.DnssecStatus
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import com.adshield.pro.engine.security.FileThreatScanner
import com.adshield.pro.engine.security.YaraLiteEngine
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.nio.file.Files

class CybersecurityPlatformTestSuite {
    private fun query(domain: String = "example.com"): DnsPacketCodec.ParsedDnsQuery =
        DnsPacketCodec.parseQuery(DnsDiagnosticQueryFactory.build(domain, transactionId = 0x1234))!!

    private fun allowed(source: String = "Allowed", blocked: Boolean = false) = FilterEvaluationResult(
        domain = "example.com", isBlocked = blocked, matchedRule = null, matchedCategory = null,
        matchType = null, sourceName = source, priority = 0
    )

    @Test
    fun providerPlanIsExplicitAndNeverCrossFailsPlaintextDns() {
        val config = DnsResolverConfig(
            preset = DnsProviderPreset.NEXTDNS,
            protocol = DnsProtocol.DOH,
            failoverEnabled = true,
            failoverProviderIds = setOf(DnsProviderPreset.CONTROL_D.id, DnsProviderPreset.QUAD9.id)
        )
        val plan = DnsProviderRegistry.queryPlan(config)
        assertEquals(listOf("nextdns", "controld", "quad9"), plan.map { it.providerId })
        assertEquals("https://dns.nextdns.io/dns-query", plan.first().dohUrl)
        assertEquals("p0.freedns.controld.com", plan[1].dotHostname)
        assertEquals(1, DnsProviderRegistry.queryPlan(config.copy(protocol = DnsProtocol.UDP_TCP)).size)
    }

    @Test
    fun healthCircuitOpensClosesAndUsesOnlyMeasuredLatency() {
        val health = DnsProviderHealthMonitor()
        repeat(3) { health.recordFailure("quad9", DnsProtocol.DOH, IOException("offline"), 1_000) }
        assertThrows(Exception::class.java) { health.checkAvailable("quad9", DnsProtocol.DOH, 2_000) }
        assertEquals(3, health.snapshot("quad9", DnsProtocol.DOH).failedQueries)
        health.checkAvailable("quad9", DnsProtocol.DOH, 32_000)
        health.recordSuccess("quad9", DnsProtocol.DOH, 42, 32_000)
        assertEquals(42L, health.snapshot("quad9", DnsProtocol.DOH).ewmaLatencyMs)
        assertEquals(0, health.snapshot("quad9", DnsProtocol.DOH).consecutiveFailures)
        health.recordSuccess("quad9", DnsProtocol.DOH, 22, 33_000)
        assertEquals(37L, health.snapshot("quad9", DnsProtocol.DOH).ewmaLatencyMs)
    }

    @Test
    fun validatorRejectsWrongQuestionTruncationServfailAndTrailingData() {
        val parsed = query()
        val valid = DnsPacketCodec.buildBlockedResponse(parsed, false)
        assertEquals(3, DnsResponseValidator.validate(parsed.rawPayload, valid).responseCode)

        val wrongQuestion = valid.copyOf()
        wrongQuestion[12] = 'z'.code.toByte()
        assertThrows(DnsResponseValidationException::class.java) {
            DnsResponseValidator.validate(parsed.rawPayload, wrongQuestion)
        }
        val truncated = valid.copyOf()
        truncated[2] = (truncated[2].toInt() or 0x02).toByte()
        assertThrows(DnsResponseValidationException::class.java) {
            DnsResponseValidator.validate(parsed.rawPayload, truncated)
        }
        assertThrows(DnsResponseValidationException::class.java) {
            DnsResponseValidator.validate(parsed.rawPayload, valid + byteArrayOf(0))
        }
        val servfail = DnsPacketCodec.buildServFailResponse(parsed)
        assertThrows(DnsResponseValidationException::class.java) {
            DnsResponseValidator.validate(parsed.rawPayload, servfail)
        }
    }

    @Test
    fun dnssecModeReportsUpstreamAdAndStrictModeRejectsUnsignedPositiveAnswers() {
        val parsed = query()
        val positive = DnsPacketCodec.buildBlockedResponse(parsed, true)
        assertThrows(DnsResponseValidationException::class.java) {
            DnsResponseValidator.validate(parsed.rawPayload, positive, DnssecMode.REQUIRE_AUTHENTICATED_ANSWERS)
        }
        positive[3] = (positive[3].toInt() or 0x20).toByte()
        val inspection = DnsResponseValidator.validate(
            parsed.rawPayload, positive, DnssecMode.REQUIRE_AUTHENTICATED_ANSWERS
        )
        assertTrue(inspection.authenticatedData)
        assertEquals(DnssecStatus.UPSTREAM_AUTHENTICATED, inspection.dnssecStatus)
    }

    @Test
    fun resolverFailsOverOnlyAfterValidationAndDoesNotDowngrade() = runBlocking {
        val health = DnsProviderHealthMonitor()
        val resolver = UpstreamDnsResolver(health)
        val calls = mutableListOf<String>()
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { parsed, _, endpoint ->
            calls += endpoint.providerId
            if (endpoint.providerId == "cloudflare") throw IOException("test outage")
            DnsPacketCodec.buildBlockedResponse(parsed, false)
        }
        val config = DnsResolverConfig(
            preset = DnsProviderPreset.CLOUDFLARE,
            protocol = DnsProtocol.DOH,
            failoverEnabled = true,
            failoverProviderIds = setOf(DnsProviderPreset.QUAD9.id)
        )
        val result = resolver.resolve(query("failover.example"), config)
        assertEquals(listOf("cloudflare", "quad9"), calls)
        assertEquals("quad9", result.providerId)
        assertTrue(result.protocolUsed.startsWith("DOH"))
        assertEquals(3, DnsResponseValidator.validate(query("failover.example").rawPayload, result.responseBytes).responseCode)
    }

    @Test
    fun resolverCircuitSkipsKnownOpenProviderWithoutExtendingIt() = runBlocking {
        val health = DnsProviderHealthMonitor()
        val resolver = UpstreamDnsResolver(health)
        var calls = 0
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { _, _, _ ->
            calls++
            throw IOException("offline")
        }
        val config = DnsResolverConfig(preset = DnsProviderPreset.QUAD9, protocol = DnsProtocol.DOT)
        repeat(3) { resolver.resolve(query("failure$it.example"), config) }
        assertEquals(3, calls)
        resolver.resolve(query("circuit-open.example"), config)
        assertEquals(3, calls)
        assertEquals(3, health.snapshot("quad9", DnsProtocol.DOT).failedQueries)
    }

    @Test
    fun appNetworkAndEmergencyPoliciesAreDeterministic() {
        val allTransports = NetworkTransportPolicy.entries.toSet()
        val appPolicies = DnsFirewallPolicy(
            appPolicies = mapOf("blocked.app" to AppDnsPolicy.BLOCK_ALL, "allowed.app" to AppDnsPolicy.ALLOW_ALL),
            protectedTransports = allTransports
        )
        assertTrue(DnsFirewallPolicyDecider.evaluate(allowed(), "blocked.app", NetworkTransportPolicy.WIFI, appPolicies).isBlocked)
        assertTrue(DnsFirewallPolicyDecider.evaluate(allowed(blocked = true), "allowed.app", NetworkTransportPolicy.WIFI, appPolicies).bypassDomainFilters)
        assertTrue(DnsFirewallPolicyDecider.evaluate(allowed(blocked = true), null, NetworkTransportPolicy.CELLULAR, appPolicies).isBlocked)

        val wifiOnly = appPolicies.copy(protectedTransports = setOf(NetworkTransportPolicy.WIFI))
        val bypass = DnsFirewallPolicyDecider.evaluate(allowed(blocked = true), null, NetworkTransportPolicy.CELLULAR, wifiOnly)
        assertFalse(bypass.isBlocked)
        assertTrue(bypass.bypassDomainFilters)

        val emergency = wifiOnly.copy(emergencyAllowlistOnly = true)
        assertTrue(DnsFirewallPolicyDecider.evaluate(allowed(), null, NetworkTransportPolicy.WIFI, emergency).isBlocked)
        assertFalse(DnsFirewallPolicyDecider.evaluate(allowed("User Allowlist"), null, NetworkTransportPolicy.WIFI, emergency).isBlocked)
    }

    fun yaraSubsetMatchesAsciiHexWideAndRejectsUnsupportedSyntax() {
        val rules = YaraLiteEngine.parse(
            """
            rule Hex_Test { strings: ${'$'}h = { 4D 5A ?? 7F } condition: any of them }
            rule Wide_Test { strings: ${'$'}w = "evil" wide nocase condition: any of them }
            """.trimIndent()
        )
        val engine = YaraLiteEngine(rules)
        assertEquals(listOf("Hex_Test"), engine.scan("xxMZ\u007f").map { it.ruleName })
        assertEquals(listOf("Wide_Test"), engine.scan("E\u0000V\u0000I\u0000L\u0000").map { it.ruleName })
        assertThrows(IllegalArgumentException::class.java) {
            YaraLiteEngine.parse("rule Bad { condition: true }")
        }
        // Braces inside quoted strings must not terminate the rule body (regression: the EICAR signature).
        val braceRule = YaraLiteEngine.parse(
            """
            rule Braced_String { strings: ${'$'}b = "a}b}c" condition: any of them }
            """.trimIndent()
        )
        assertEquals(listOf("Braced_String"), YaraLiteEngine(braceRule).scan("xxa}b}c").map { it.ruleName })
        assertTrue(YaraLiteEngine().scan("X5O!P%@AP[4\\PZX54(P^)7CC)7}\${'$'}EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\${'$'}H+H*").isNotEmpty())
    }

    @Test
    fun fileScannerUsesRealYaraRuleOutcomes() {
        val file = Files.createTempFile("adshield-yara", ".ps1").toFile()
        file.writeText("powershell.exe -WindowStyle hidden -enc SQBFAFgA")
        try {
            val verdict = FileThreatScanner().scanFile(file)
            assertEquals(FileThreatScanner.ThreatLevel.DANGEROUS, verdict.threatLevel)
            assertTrue(verdict.findings.any { it.contains("PowerShell_Encoded_Dropper") })
        } finally {
            file.delete()
        }
    }
}
