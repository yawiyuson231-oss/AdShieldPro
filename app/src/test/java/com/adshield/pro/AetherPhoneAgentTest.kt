package com.adshield.pro

import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.aether.AetherPhoneAgent as Agent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AetherPhoneAgentTest {
    @Test
    fun unavailableReadingsAreNotReportedAsHealthy() {
        val report = Agent.review(snapshot(network = Agent.Network(Agent.Transport.UNKNOWN), dns = null))
        assertTrue(report.findings.isEmpty())
        assertTrue(report.hasUnavailableReadings)
        assertTrue(report.sections.flatMap { it.readings }.contains("Internet validation not available"))
        assertTrue(report.sections.flatMap { it.readings }.contains("Detailed DNS activity was not available."))
        assertTrue(report.sections.flatMap { it.readings }.contains("Scan history not available"))
        assertTrue(report.sections.flatMap { it.readings }.contains("Heat: Not reported"))
    }

    @Test
    fun identifiesReportedOpenWifiWeakSignalAndSignInAsSeparateIssues() {
        val report = Agent.review(snapshot(network = Agent.Network(
            transport = Agent.Transport.WIFI,
            internetValidated = false,
            captivePortal = true,
            wifiSecurity = Agent.WifiSecurity.OPEN,
            signalDbm = -86
        )))
        assertEquals(3, report.findings.size)
        assertEquals(2, report.findings.count { it.priority == Agent.Priority.ATTENTION })
        assertTrue(report.findings.all { it.nextTool == Agent.Tool.NETWORK_SETTINGS })
        assertTrue(report.findings.any { it.evidence.contains("-86 dBm") })
    }

    @Test
    fun doesNotInventWifiStatusWhenVpnMasksTheUnderlyingConnection() {
        val network = Agent.Network(Agent.Transport.VPN, wifiSecurity = Agent.WifiSecurity.OPEN, signalDbm = -110)
        val report = Agent.review(snapshot(network = network))
        assertTrue(report.findings.isEmpty())
        assertFalse(report.sections.flatMap { it.readings }.any { it.startsWith("Wi-Fi signal:") })
    }

    @Test
    fun recommendsOnlyBoundedToolsForProtectionSettings() {
        val initial = snapshot()
        val report = Agent.review(initial.copy(
            protection = initial.protection.copy(status = VpnStatus.PAUSED),
            settings = initial.settings.copy(protocol = DnsProtocol.UDP_TCP, aliasShieldOn = false, excludedApps = 2)
        ))
        assertEquals(Agent.Tool.PROTECTION, report.findings.first().nextTool)
        assertTrue(report.findings.any { it.nextTool == Agent.Tool.DNS_SETTINGS })
        assertTrue(report.findings.any { it.nextTool == Agent.Tool.ENABLE_ALIAS_SHIELD })
        assertTrue(report.findings.any { it.nextTool == Agent.Tool.APP_FIREWALL && it.evidence.contains("2 app exclusions") })
    }

    @Test
    fun benchmarksOnlyCredibleLatencyOrRecordedResolverFailures() {
        val recent = listOf(20, 30, 50, 55, 480).map { log(it) }
        val decoys = listOf(log(9_000, at = NOW - 3_600_001), log(6_000, blocked = true), log(0), log(8_000, at = NOW + 1))
        val report = Agent.review(snapshot(dns = recent + decoys))
        assertTrue(report.findings.any { it.nextTool == Agent.Tool.DNS_BENCHMARK && "480 ms p95" in it.evidence })
        assertFalse(Agent.review(snapshot(dns = recent.drop(4) + decoys)).findings.any { it.nextTool == Agent.Tool.DNS_BENCHMARK })
        val failed = log(0).copy(protocolUsed = "SERVFAIL (resolver did not answer)")
        assertTrue(Agent.review(snapshot(dns = List(3) { failed })).findings.any { it.nextTool == Agent.Tool.DNS_BENCHMARK })
    }

    @Test
    fun honoursLoggingOptOutAndDoesNotEchoRawActivity() {
        val blocked = log(0, blocked = true).copy(category = RuleCategory.MALWARE, sourceList = "HTTPS Uncloaking · List", matchedRule = "private.example")
        val initial = snapshot(dns = listOf(blocked) + List(5) { log(900) })
        val visible = Agent.review(initial)
        assertTrue(visible.sections.flatMap { it.readings }.any { it == "1 blocks tagged malware/phishing · 1 DNS Alias Shield blocks" })
        assertFalse(visible.toString().contains("private.example"))
        val hidden = Agent.review(initial.copy(settings = initial.settings.copy(dnsLoggingOn = false)))
        assertFalse(hidden.findings.any { it.nextTool == Agent.Tool.DNS_BENCHMARK })
        assertTrue(hidden.sections.flatMap { it.readings }.contains("Detailed DNS logging is off. Saved DNS rows were not used."))
    }

    @Test
    fun boundsSavedDnsWorkAndDoesNotTreatUnloggedLookupsAsZeroTraffic() {
        val bounded = Agent.review(snapshot(dns = List(250) { log(20) } + List(50) { log(5_000) }))
        assertFalse(bounded.findings.any { it.nextTool == Agent.Tool.DNS_BENCHMARK })
        assertTrue(bounded.sections.flatMap { it.readings }.any { "250 logged" in it })
        val noRows = Agent.review(snapshot(dns = emptyList()))
        assertTrue(noRows.sections.flatMap { it.readings }.any { "50 DNS requests" in it })
        assertTrue(noRows.sections.flatMap { it.readings }.any { "does not mean there was no traffic" in it })
    }

    @Test
    fun usesDevicePressureAndPastScansWithoutClaimingToFixOrDetectInfection() {
        val report = Agent.review(snapshot().copy(
            device = Agent.Device(true, 100_000_000L, Agent.Thermal.SEVERE),
            scanHistory = Agent.ScanHistory(retained = 4, flaggedTargets = 1, flaggedAppAudits = 1)
        ))
        assertEquals(Agent.Tool.BATTERY, report.findings.first().nextTool)
        assertEquals(2, report.findings.count { it.nextTool == Agent.Tool.OPTIMIZER })
        assertTrue(report.findings.any { it.nextTool == Agent.Tool.SCAN_HISTORY && "not proof" in it.evidence })
    }

    private fun snapshot(
        network: Agent.Network = Agent.Network(Agent.Transport.CELLULAR, internetValidated = true),
        dns: List<DnsActivityRecord>? = emptyList()
    ) = Agent.Snapshot(
        settings = Agent.Settings(
            vpnRequested = true, protocol = DnsProtocol.DOH, resolver = DnsProviderPreset.QUAD9,
            mode = ProtectionMode.STANDARD, allowlistOnly = false, aliasShieldOn = true, dnsLoggingOn = true,
            excludedApps = 0, allowDnsOverrides = 0, unfilteredNetworks = 0, blocksThirdPartyCookies = true,
            automaticFilterUpdates = true, scheduledScans = false
        ),
        protection = Agent.Protection(VpnStatus.CONNECTED, 100, 50, 2),
        network = network,
        device = Agent.Device(null, null, null),
        dnsRecords = dns,
        scanHistory = null,
        capturedAtMs = NOW
    )

    private fun log(latencyMs: Int, at: Long = NOW - 1, blocked: Boolean = false) = DnsActivityRecord(
        timestampEpochMs = at, domain = "private.example", queryType = "A", isBlocked = blocked,
        category = null, matchedRule = null, sourceList = "Allowed", latencyMs = latencyMs, protocolUsed = "DOH"
    )

    private companion object { const val NOW = 1_700_000_000_000L }
}
