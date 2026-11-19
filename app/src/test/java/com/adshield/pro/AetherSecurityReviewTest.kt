package com.adshield.pro

import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.DnsFirewallPolicy
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.domain.model.VpnTunnelReceipt
import com.adshield.pro.engine.aether.AetherAppReview
import com.adshield.pro.engine.aether.AetherDnsPolicyReview
import com.adshield.pro.engine.aether.AetherFileInput
import com.adshield.pro.engine.aether.AetherFilePickerApproval
import com.adshield.pro.engine.aether.AetherPhoneAgent
import com.adshield.pro.engine.aether.AetherSecurityReview as Review
import com.adshield.pro.engine.aether.AetherSecurityTask
import com.adshield.pro.engine.aether.AetherTaskApproval
import com.adshield.pro.engine.aether.AetherTaskProgress
import com.adshield.pro.engine.security.AppRiskAuditor
import com.adshield.pro.engine.security.FileThreatScanner
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.file.Files

class AetherSecurityReviewTest {
    private val phone = AetherPhoneAgent.Report(1L, emptyList(), listOf(AetherPhoneAgent.Section("Protection", listOf("Connected"))))
    private val auditor = AppRiskAuditor()
    private val profile = AppRiskAuditor.AppSecurityProfile(
        packageName = "com.example.fixture", appName = "Fixture", versionName = "1", targetSdkVersion = 35,
        requestedPermissions = emptyList(), installerPackageName = "com.android.vending", isSystemApp = false
    )
    private val fixtureHigh = auditor.audit(profile.copy(
        requestedPermissions = listOf("android.permission.RECEIVE_SMS"),
        declaredComponentPermissions = setOf("android.permission.BIND_ACCESSIBILITY_SERVICE")
    ))

    private fun savedDns(
        exclusions: Set<String> = emptySet(),
        policies: Map<String, AppDnsPolicy> = emptyMap(),
        allowlistOnly: Boolean = false
    ) = AetherDnsPolicyReview.inspect(
        config = DnsResolverConfig(),
        policy = DnsFirewallPolicy(appPolicies = policies, emergencyAllowlistOnly = allowlistOnly),
        excluded = exclusions,
        aliasShieldOn = true
    )

    @Test
    fun runsExactlyThreeReadOnlySpecialistsAndReportsSkippedApps() = runBlocking {
        val calls = mutableListOf<String>()
        val progress = mutableListOf<AetherTaskProgress>()
        val dns = savedDns()
        val fixtureClean = auditor.audit(profile.copy(packageName = "com.example.clean"))
        val audit = AppRiskAuditor.VisibleAudit(3, listOf(fixtureHigh, fixtureClean))
        val report = Review.run(
            readPhone = { calls += "phone"; phone },
            readDns = { calls += "dns"; dns },
            readApps = { calls += "apps"; audit },
            publish = { progress += it }, now = { 900L }
        )
        assertEquals(listOf("apps", "dns", "phone"), calls.sorted())
        assertEquals(listOf(AetherTaskProgress.ReviewingSecurity), progress)
        assertEquals(Review.Reading.Received(phone, 900L), report.phone)
        assertEquals(Review.Reading.Received(dns.summary, 900L), report.dns)
        assertEquals(Review.Reading.Received(AetherAppReview.from(audit), 900L), report.apps)
        assertEquals(900L, report.finishedAtMs)
        assertTrue(report.hasGaps)
        val apps = requireNotNull(report.apps.value)
        assertEquals(3, apps.visible)
        assertEquals(2, apps.inspected)
        assertEquals(1, apps.unavailable)
        assertEquals(listOf(fixtureHigh), apps.topFindings)
        assertEquals(0, report.appPolicyMatchCount)
    }

    @Test
    fun deadlineOrFailureLeavesOtherSpecialistsEvidenceIntact() = runBlocking {
        val apps = AppRiskAuditor.VisibleAudit(1, listOf(fixtureHigh))
        val dns = savedDns(exclusions = setOf(profile.packageName))
        val slowPhone = Review.run(readPhone = { awaitCancellation() }, readDns = { dns }, readApps = { apps },
            publish = {}, phoneTimeoutMs = 15L)
        assertEquals(Review.Reading.Missing(Review.MissingReason.TIMED_OUT), slowPhone.phone)
        assertEquals(dns.summary, slowPhone.dns.value)
        assertEquals(1, slowPhone.appPolicyMatchCount) // Phone evidence is not needed for the exact-ID join.
        assertTrue(slowPhone.hasGaps)

        val slowDns = Review.run(readPhone = { phone }, readDns = { awaitCancellation() }, readApps = { apps },
            publish = {}, dnsTimeoutMs = 15L)
        assertEquals(Review.Reading.Missing(Review.MissingReason.TIMED_OUT), slowDns.dns)
        assertEquals(phone, slowDns.phone.value)
        assertEquals(AetherAppReview.from(apps), slowDns.apps.value)
        assertNull(slowDns.appPolicyMatchCount)
        assertTrue(slowDns.hasGaps)

        val failedApps = Review.run(readPhone = { phone }, readDns = { dns }, readApps = { error("device fixture") }, publish = {})
        assertEquals(Review.Reading.Missing(Review.MissingReason.FAILED), failedApps.apps)
        assertEquals(phone, failedApps.phone.value)
        assertEquals(dns.summary, failedApps.dns.value)
        assertNull(failedApps.appPolicyMatchCount)
        assertTrue(failedApps.hasGaps)

        val slowApps = Review.run(readPhone = { phone }, readDns = { dns }, readApps = { awaitCancellation() },
            publish = {}, appsTimeoutMs = 15L)
        assertEquals(Review.Reading.Missing(Review.MissingReason.TIMED_OUT), slowApps.apps)
        assertEquals(phone, slowApps.phone.value)
        assertEquals(dns.summary, slowApps.dns.value)
    }

    @Test
    fun externalDeadlineCancelsTheReviewRatherThanReportingAMissingReading() = runBlocking {
        val report = withTimeoutOrNull(50L) {
            Review.run(readPhone = { awaitCancellation() }, readDns = { savedDns() },
                readApps = { AppRiskAuditor.VisibleAudit(0, emptyList()) }, publish = {})
        }
        assertNull(report)
    }

    @Test
    fun noInspectedAppsIsUnknownNotZeroMatches() = runBlocking {
        suspend fun review(audit: AppRiskAuditor.VisibleAudit, phoneReport: AetherPhoneAgent.Report = phone) =
            Review.run(readPhone = { phoneReport }, readDns = { savedDns() }, readApps = { audit }, publish = {})
        val noMetadata = review(AppRiskAuditor.VisibleAudit(1, emptyList()))
        assertTrue(noMetadata.hasGaps)
        assertEquals(0, noMetadata.apps.value?.inspected)
        assertNull(noMetadata.appPolicyMatchCount)
        val audit = AppRiskAuditor.VisibleAudit(1, listOf(fixtureHigh))
        val allRead = review(audit)
        assertFalse(allRead.hasGaps)
        assertEquals(0, allRead.appPolicyMatchCount)
        assertTrue(review(audit, phone.copy(hasUnavailableReadings = true)).hasGaps)
    }

    @Test
    fun runsIndependentSpecialistsAndCancelsAllWithoutAReport() = runBlocking {
        val live = mutableSetOf<String>()
        val stopped = mutableSetOf<String>()
        val allStarted = CompletableDeferred<Unit>()
        var returned = false
        suspend fun hold(reader: String): Nothing {
            live += reader
            if (live.size == 3) allStarted.complete(Unit)
            try {
                awaitCancellation()
            } finally {
                stopped += reader
            }
        }
        val job = launch {
            Review.run(readPhone = { hold("phone") }, readDns = { hold("dns") }, readApps = { hold("apps") }, publish = {})
            returned = true
        }
        withTimeout(2_000L) { allStarted.await() }
        job.cancelAndJoin()
        assertEquals(setOf("phone", "dns", "apps"), live)
        assertEquals(live, stopped)
        assertFalse(returned)
    }

    @Test
    fun joinsExactPackageIdsAcrossFullAuditBeforeDisplayLimits() = runBlocking {
        val topEight = (1..8).map { fixtureHigh.copy(profile = fixtureHigh.profile.copy(packageName = "com.example.high$it")) }
        val mediums = (1..5).reversed().map { index ->
            auditor.audit(profile.copy(packageName = "com.example.medium$index",
                declaredComponentPermissions = setOf("android.permission.BIND_ACCESSIBILITY_SERVICE")))
        }
        val sameLabel = auditor.audit(profile.copy(packageName = "com.example.unflagged", appName = mediums.first().profile.appName))
        val rows = mediums + listOf(sameLabel) + topEight
        val exclusions = rows.filter { it !in topEight }.map { it.profile.packageName }.toSet() +
            setOf("com.example.High1", "com.example.metadataunavailable")
        val report = Review.run(readPhone = { phone }, readDns = { savedDns(exclusions = exclusions) },
            readApps = { AppRiskAuditor.VisibleAudit(rows.size + 1, rows) }, publish = {})
        assertEquals(topEight, report.apps.value?.topFindings)
        assertTrue(report.hasGaps)
        assertEquals(5, report.appPolicyMatchCount)
        assertEquals((1..4).map { "com.example.medium$it" }, report.appPolicyMatches.map { it.packageName })
        assertTrue(report.appPolicyMatches.all { it.exception == AetherDnsPolicyReview.AppException.VPN_EXCLUDED })
        assertEquals(1, report.priorities.count { it.source == Review.Source.APP_POLICY })
    }

    @Test
    fun keepsAppAndPolicyOverlapAdvisoryWhenOtherRulesCanTakePrecedence() = runBlocking {
        val otherApp = fixtureHigh.copy(profile = fixtureHigh.profile.copy(packageName = "com.example.excluded"))
        val conflicting = "com.example.conflict"
        val dns = savedDns(
            exclusions = setOf(otherApp.profile.packageName, conflicting),
            policies = mapOf(profile.packageName to AppDnsPolicy.ALLOW_ALL,
                otherApp.profile.packageName to AppDnsPolicy.ALLOW_ALL, conflicting to AppDnsPolicy.BLOCK_ALL),
            allowlistOnly = true
        )
        val interrupted = phone.copy(findings = listOf(AetherPhoneAgent.Finding("DNS paused", AetherPhoneAgent.Priority.ATTENTION,
            "The tunnel reports paused.", AetherPhoneAgent.Tool.PROTECTION)))
        val report = Review.run(readPhone = { interrupted }, readDns = { dns },
            readApps = { AppRiskAuditor.VisibleAudit(2, listOf(fixtureHigh, otherApp)) }, publish = {})
        assertEquals(2, report.appPolicyMatchCount)
        assertEquals(mapOf(profile.packageName to AetherDnsPolicyReview.AppException.ALLOW_DNS,
            otherApp.profile.packageName to AetherDnsPolicyReview.AppException.VPN_EXCLUDED),
            report.appPolicyMatches.associate { it.packageName to it.exception })
        assertTrue(report.dns.value?.allowlistOnly == true)
        assertEquals(1, report.dns.value?.excludedAppsWithBlockRules)
        assertEquals(listOf(Review.Source.PROTECTION, Review.Source.DNS, Review.Source.APP_POLICY), report.priorities.map { it.source })
        assertEquals(listOf(AetherPhoneAgent.Tool.PROTECTION, AetherPhoneAgent.Tool.APP_FIREWALL, AetherPhoneAgent.Tool.APP_FIREWALL),
            report.priorities.map { it.nextTool })
    }

    @Test
    fun readsCurrentTunnelOnceAfterSpecialistsToAvoidReportingAnOlderGeneration() = runBlocking {
        val accepted = setOf(profile.packageName)
        val original = VpnTunnelReceipt(51, 1, false, accepted, emptySet())
        var runtime = VpnRuntimeState(status = VpnStatus.CONNECTED, tunnelReceipt = original)
        var runtimeReads = 0
        val report = Review.run(
            readPhone = { phone }, readDns = { savedDns(exclusions = accepted) },
            readApps = {
                runtime = VpnRuntimeState(status = VpnStatus.STARTING)
                AppRiskAuditor.VisibleAudit(1, listOf(fixtureHigh))
            },
            publish = {}, currentTunnel = { runtimeReads++; runtime }
        )
        assertEquals(1, runtimeReads)
        assertNull(report.dns.value?.tunnel)
        assertEquals(AetherDnsPolicyReview.ExclusionEvidence.UNKNOWN, report.appPolicyMatches.single().exclusionEvidence)
    }

    @Test
    fun declaredServiceBindingIsEvidenceButSpoofedPermissionSuffixesAreNot() {
        assertEquals(AppRiskAuditor.RiskLevel.HIGH, fixtureHigh.riskLevel)
        assertTrue(fixtureHigh.findings.any { "does not confirm" in it })
        val spoof = auditor.audit(profile.copy(
            requestedPermissions = listOf("com.example.android.permission.RECEIVE_SMS"),
            declaredComponentPermissions = setOf("com.example.android.permission.BIND_ACCESSIBILITY_SERVICE")
        ))
        assertEquals(AppRiskAuditor.RiskLevel.TRUSTED, spoof.riskLevel)
        assertTrue(spoof.findings.isEmpty())
        val requestedOnly = auditor.audit(profile.copy(requestedPermissions = listOf("android.permission.BIND_ACCESSIBILITY_SERVICE")))
        assertFalse(requestedOnly.findings.any { "binding" in it })
    }

    @Test
    fun staleOrRepeatedFilePickerCallbacksCannotAuthorizeAScan() {
        val approvals = AetherTaskApproval()
        val picker = AetherFilePickerApproval()
        val first = approvals.propose(AetherSecurityTask.SCAN_FILE, suggested = true)
        assertNull(picker.consume(first.id))
        picker.await(requireNotNull(approvals.approve(first.id)))
        picker.clear()
        assertNull(picker.consume(first.id))
        val second = approvals.propose(AetherSecurityTask.SCAN_FILE)
        picker.await(requireNotNull(approvals.approve(second.id)))
        assertNull(picker.consume(first.id))
        assertEquals(AetherSecurityTask.SCAN_FILE, picker.consume(second.id)?.task)
        assertNull(picker.consume(second.id))
    }

    @Test
    fun cancelDuringFileReadPreventsWritingTheNextChunk() {
        val output = ByteArrayOutputStream()
        var readCompleted = false
        runBlocking {
            val task = launch(start = CoroutineStart.LAZY) {
                val input = object : InputStream() {
                    override fun read(): Int = error("Expected a chunk read")
                    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                        bytes[offset] = 1
                        coroutineContext[kotlinx.coroutines.Job]?.cancel()
                        return 1
                    }
                }
                AetherFileInput.copy(input, output, maximum = 4L)
                readCompleted = true
            }
            task.join()
            assertTrue(task.isCancelled)
        }
        assertEquals(0, output.size())
        assertFalse(readCompleted)
    }

    @Test
    fun boundedFileReadRejectsOversizeAndStaticScannerChecksTheSelectedCopy() {
        val oversized = ByteArrayInputStream(ByteArray(20))
        val output = ByteArrayOutputStream()
        assertFalse(runBlocking { AetherFileInput.copy(oversized, output, maximum = 4L) })
        assertEquals(4, output.size())
        assertEquals(15, oversized.available()) // At most one extra byte was read to check the limit.
        val bytes = "A harmless test document".encodeToByteArray()
        val scratch = Files.createTempFile("aether-test-", ".pdf.exe").toFile()
        try {
            assertTrue(runBlocking { scratch.outputStream().use { AetherFileInput.copy(bytes.inputStream(), it, bytes.size.toLong()) } })
            assertEquals(bytes.size.toLong(), scratch.length())
            val result = FileThreatScanner().scanFile(scratch)
            assertTrue(result.findings.any { "Double-extension" in it })
            assertFalse(result.isClean)
        } finally {
            scratch.delete()
        }
    }
}
