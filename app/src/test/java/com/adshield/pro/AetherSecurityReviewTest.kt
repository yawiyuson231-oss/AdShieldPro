package com.adshield.pro

import com.adshield.pro.engine.aether.AetherAppReview
import com.adshield.pro.engine.aether.AetherFileInput
import com.adshield.pro.engine.aether.AetherFilePickerApproval
import com.adshield.pro.engine.aether.AetherPhoneAgent
import com.adshield.pro.engine.aether.AetherSecurityReview as Review
import com.adshield.pro.engine.aether.AetherSecurityTask
import com.adshield.pro.engine.aether.AetherTaskApproval
import com.adshield.pro.engine.aether.AetherTaskProgress
import com.adshield.pro.engine.aether.AetherTaskSource
import com.adshield.pro.engine.security.AppRiskAuditor
import com.adshield.pro.engine.security.FileThreatScanner
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
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

    @Test
    fun runsOnlyTheTwoReviewStepsAndReportsSkippedApps() {
        val progress = mutableListOf<AetherTaskProgress>()
        val report = runBlocking {
            Review.run(
                readPhone = { phone },
                readApps = { AetherAppReview.from(AppRiskAuditor.VisibleAudit(3, listOf(fixtureHigh, auditor.audit(profile)))) },
                publish = { progress += it }, now = { 900L }
            )
        }
        assertEquals(listOf(AetherTaskProgress.ReadingPhone, AetherTaskProgress.ReadingApps(0, 0)), progress)
        assertEquals(phone, report.phone.value)
        assertEquals(900L, report.finishedAtMs)
        assertTrue(report.hasGaps)
        val apps = requireNotNull(report.apps.value)
        assertEquals(3, apps.visible)
        assertEquals(2, apps.inspected)
        assertEquals(1, apps.unavailable)
        assertEquals(1, apps.highRisk)
        assertEquals(listOf(fixtureHigh), apps.topFindings)
    }

    @Test
    fun deadlineOrFailureLeavesTheOtherStepsEvidenceIntact() {
        val apps = AetherAppReview.from(AppRiskAuditor.VisibleAudit(1, listOf(auditor.audit(profile))))
        val timedOut = runBlocking {
            Review.run(readPhone = { awaitCancellation() }, readApps = { apps }, publish = {}, phoneTimeoutMs = 15L)
        }
        assertEquals(Review.Reading.Missing(Review.MissingReason.TIMED_OUT), timedOut.phone)
        assertEquals(apps, timedOut.apps.value)
        assertTrue(timedOut.hasGaps)
        val failed = runBlocking {
            Review.run(readPhone = { phone }, readApps = { error("device fixture") }, publish = {})
        }
        assertEquals(phone, failed.phone.value)
        assertEquals(Review.Reading.Missing(Review.MissingReason.FAILED), failed.apps)
        assertTrue(failed.hasGaps)
        val appsTimedOut = runBlocking {
            Review.run(readPhone = { phone }, readApps = { awaitCancellation() }, publish = {}, appsTimeoutMs = 15L)
        }
        assertEquals(phone, appsTimedOut.phone.value)
        assertEquals(Review.Reading.Missing(Review.MissingReason.TIMED_OUT), appsTimedOut.apps)
    }

    @Test
    fun externalDeadlineCancelsTheReviewRatherThanProducingAMissingStep() {
        var startedApps = false
        val report = runBlocking {
            withTimeoutOrNull(40) {
                Review.run(readPhone = { awaitCancellation() }, readApps = {
                    startedApps = true
                    error("Should have canceled both steps")
                }, publish = {})
            }
        }
        assertNull(report)
        assertFalse(startedApps)
    }

    @Test
    fun emptyMetadataIsAGapAndNotSuccessfulCoverage() {
        val apps = AetherAppReview.from(AppRiskAuditor.VisibleAudit(0, emptyList()))
        val noMetadata = runBlocking { Review.run(readPhone = { phone }, readApps = { apps }, publish = {}) }
        assertTrue(noMetadata.hasGaps)
        assertEquals(0, noMetadata.apps.value?.inspected)
        val observedApps = AetherAppReview.from(AppRiskAuditor.VisibleAudit(1, listOf(fixtureHigh)))
        val bothRead = runBlocking { Review.run(readPhone = { phone }, readApps = { observedApps }, publish = {}) }
        assertFalse(bothRead.hasGaps)
        val missingReadings = runBlocking {
            Review.run(readPhone = { phone.copy(hasUnavailableReadings = true) }, readApps = { observedApps }, publish = {})
        }
        assertTrue(missingReadings.hasGaps)
    }

    @Test
    fun cancelingTheReviewDoesNotStartTheNextStep() {
        var startedApps = false
        var publishedReport = false
        runBlocking {
            val job = launch(start = CoroutineStart.UNDISPATCHED) {
                Review.run(readPhone = { awaitCancellation() }, readApps = {
                    startedApps = true
                    error("This step must not run")
                }, publish = {})
                publishedReport = true
            }
            job.cancelAndJoin()
        }
        assertFalse(startedApps)
        assertFalse(publishedReport)
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
        val first = approvals.propose(AetherSecurityTask.SCAN_FILE, AetherTaskSource.ONLINE_API)
        assertNull(picker.consume(first.id))
        picker.await(requireNotNull(approvals.approve(first.id)))
        picker.clear()
        assertNull(picker.consume(first.id))
        val second = approvals.propose(AetherSecurityTask.SCAN_FILE, AetherTaskSource.MANUAL)
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
