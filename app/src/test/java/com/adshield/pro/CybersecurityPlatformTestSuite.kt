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
    fun diagnosticQueryUsesEdns0AndNormalisesCase() {
        val wire = DnsDiagnosticQueryFactory.build("Example.COM.", transactionId = 0x2A2A)
        val parsed = DnsPacketCodec.parseQuery(wire)!!
        assertEquals("example.com", parsed.questionDomain)
        assertEquals(DnsPacketCodec.TYPE_A, parsed.qType)
        assertEquals(1, ((wire[10].toInt() and 0xFF) shl 8) or (wire[11].toInt() and 0xFF))
        // OPT TTL is 0x00008000: the DNSSEC OK bit is set so upstream AD/RRSIG evidence can be reported.
        assertEquals(0x80, wire[wire.size - 4].toInt() and 0xFF)
        assertThrows(IllegalArgumentException::class.java) { DnsDiagnosticQueryFactory.build("bad..name") }
    }

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

    @Test
    fun fileScannerFlagsEncodedPowerShellDropper() {
        val file = Files.createTempFile("adshield-dropper", ".ps1").toFile()
        file.writeText("powershell.exe -WindowStyle hidden -enc SQBFAFgA")
        try {
            val verdict = FileThreatScanner().scanFile(file)
            // The dropper heuristic is worth 60/100 on its own: high-risk, not auto-quarantine.
            assertEquals(FileThreatScanner.ThreatLevel.SUSPICIOUS, verdict.threatLevel)
            assertTrue(verdict.riskScore >= 60)
            assertTrue(verdict.findings.any { it.contains("Obfuscated PowerShell dropper command") })
            assertTrue(verdict.findings.none { it.contains("YARA") })
        } finally {
            file.delete()
        }
    }

    @Test
    fun resolverServesTtlCacheWithoutRequeryingUpstream() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        var calls = 0
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { parsed, _, _ ->
            calls++
            DnsPacketCodec.buildBlockedResponse(parsed, false)
        }
        val config = DnsResolverConfig(preset = DnsProviderPreset.CLOUDFLARE, protocol = DnsProtocol.DOH)
        val parsed = query("cache-hit.example")
        val first = resolver.resolve(parsed, config)
        assertFalse(first.fromCache)
        val second = resolver.resolve(parsed, config)
        assertTrue(second.fromCache)
        assertEquals(1, calls)
        assertEquals(parsed.transactionId, ((second.responseBytes[0].toInt() and 0xFF) shl 8) or (second.responseBytes[1].toInt() and 0xFF))
    }

    @Test
    fun strictDnssecFailsClosedWithServfailInsteadOfAnUnsignedAnswer() = runBlocking {
        val resolver = UpstreamDnsResolver(DnsProviderHealthMonitor())
        resolver.providerTransport = UpstreamDnsResolver.ProviderTransport { parsed, _, _ ->
            // A positive, unsigned answer: NOERROR with one A record and no AD bit.
            DnsPacketCodec.buildBlockedResponse(parsed, true)
        }
        val config = DnsResolverConfig(
            preset = DnsProviderPreset.QUAD9,
            protocol = DnsProtocol.DOT,
            dnssecMode = DnssecMode.REQUIRE_AUTHENTICATED_ANSWERS
        )
        val result = resolver.resolve(query("unsigned.example"), config)
        assertTrue(result.protocolUsed.startsWith("SERVFAIL"))
        val rcode = result.responseBytes[3].toInt() and 0x0F
        assertEquals(2, rcode)
    }

}
