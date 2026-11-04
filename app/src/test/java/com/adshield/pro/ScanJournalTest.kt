package com.adshield.pro

import com.adshield.pro.engine.security.QuarantineNaming
import com.adshield.pro.engine.security.QuarantinedItem
import com.adshield.pro.engine.security.ScanJournal
import com.adshield.pro.engine.security.ScanKind
import com.adshield.pro.engine.security.ScanProgress
import com.adshield.pro.engine.security.ScanSource
import com.adshield.pro.engine.security.SecurityLevel
import com.adshield.pro.engine.security.SecurityScanRecord
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Scan-journal contracts: unique ids (the history list keys on them), bounded retention,
 * persistence round-trips, and reports that never imply a scan happened when it did not.
 */
class ScanJournalTest {

    private fun record(
        id: Long,
        level: SecurityLevel = SecurityLevel.CLEAN,
        kind: ScanKind = ScanKind.FILE,
        ts: Long = 1_700_000_000_000L
    ) = SecurityScanRecord(
        id = id,
        kind = kind,
        target = "target-$id",
        threatLevel = level,
        riskScore = 10,
        threatName = null,
        findings = listOf("evidence"),
        recommendation = "review",
        timestampEpochMs = ts
    )

    @Test
    fun idsStayUniqueWhenManyScansFinishInTheSameMillisecond() {
        var history = emptyList<SecurityScanRecord>()
        val sameInstant = 1_700_000_000_000L
        repeat(100) {
            val id = ScanJournal.nextId(history, sameInstant)
            history = ScanJournal.append(history, record(id, ts = sameInstant))
        }
        assertEquals(100, history.size)
        assertEquals("duplicate ids would crash the keyed history list", 100, history.map { it.id }.distinct().size)
        assertEquals(history.map { it.id }.sortedDescending(), history.map { it.id })
    }

    @Test
    fun nextIdNeverGoesBackwardsEvenIfClockMovesBack() {
        val history = listOf(record(id = 5_000L))
        assertEquals(5_001L, ScanJournal.nextId(history, nowEpochMs = 1_000L))
    }

    @Test
    fun nextIdUsesWallClockWhenItIsAhead() {
        assertEquals(9_000L, ScanJournal.nextId(listOf(record(id = 10L)), nowEpochMs = 9_000L))
        assertEquals(1_700_000_000_000L, ScanJournal.nextId(emptyList(), 1_700_000_000_000L))
    }

    @Test
    fun historyIsBoundedAndNewestFirst() {
        var history = emptyList<SecurityScanRecord>()
        repeat(ScanJournal.MAX_RECORDS + 50) { i ->
            history = ScanJournal.append(history, record(id = i.toLong()))
        }
        assertEquals(ScanJournal.MAX_RECORDS, history.size)
        assertEquals((ScanJournal.MAX_RECORDS + 49).toLong(), history.first().id)
    }

    @Test
    fun batchAppendSortsNewestFirstAndRespectsTheCap() {
        val existing = listOf(record(id = 1L))
        val batch = listOf(record(id = 5L), record(id = 9L), record(id = 7L))
        val merged = ScanJournal.appendAll(existing, batch)
        assertEquals(listOf(9L, 7L, 5L, 1L), merged.map { it.id })
    }

    @Test
    fun emptyJournalIsNotEvidenceOfACleanDevice() {
        assertFalse(ScanJournal.hasScanned(emptyList()))
        assertTrue(ScanJournal.hasScanned(listOf(record(1L))))
        val report = ScanJournal.buildTextReport(emptyList(), "2.7.0", 123L)
        assertTrue(report.contains("NO SCAN HAS BEEN PERFORMED YET"))
        assertTrue(report.contains("not a statement that the device is clean"))
    }

    @Test
    fun summaryCountsEveryLevelAndKind() {
        val history = listOf(
            record(1, SecurityLevel.CLEAN, ScanKind.FILE),
            record(2, SecurityLevel.SUSPICIOUS, ScanKind.URL),
            record(3, SecurityLevel.DANGEROUS, ScanKind.APK),
            record(4, SecurityLevel.DANGEROUS, ScanKind.APP_AUDIT, ts = 1_700_000_000_999L)
        )
        val summary = ScanJournal.summarize(history)
        assertEquals(4, summary.total)
        assertEquals(1, summary.clean)
        assertEquals(1, summary.suspicious)
        assertEquals(2, summary.dangerous)
        // flagged = suspicious + dangerous = 1 + 2
        assertEquals(3, summary.flagged)
        assertEquals(2, summary.fileScans)
        assertEquals(1, summary.urlScans)
        assertEquals(1, summary.appAudits)
        assertEquals(1_700_000_000_999L, summary.lastScanEpochMs)
    }

    @Test
    fun emptySummaryHasNoLastScanTimestamp() {
        assertEquals(null, ScanJournal.summarize(emptyList()).lastScanEpochMs)
    }

    @Test
    fun reportIncludesRealFindingsAndStatesScannerLimits() {
        val history = listOf(
            record(1, SecurityLevel.DANGEROUS).copy(
                threatName = "Test.Dropper",
                findings = listOf("Exact match: EICAR antivirus test signature"),
                scanSource = ScanSource.SCHEDULED,
                durationMs = 42L
            )
        )
        val report = ScanJournal.buildTextReport(history, "2.7.0", 999L)
        assertTrue(report.contains("Test.Dropper"))
        assertTrue(report.contains("EICAR"))
        assertTrue(report.contains("Scheduled"))
        assertTrue(report.contains("42 ms"))
        assertTrue(report.contains("cannot guarantee"))
        assertTrue(report.contains("were not examined"))
        assertFalse("must never claim guaranteed detection", report.contains("100% detection"))
    }

    @Test
    fun scanRecordSurvivesPersistenceRoundTrip() {
        val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        val original = record(7L, SecurityLevel.SUSPICIOUS, ScanKind.URL)
            .copy(scanSource = ScanSource.SCHEDULED, durationMs = 123L, threatName = "Phishing host")
        val decoded = json.decodeFromString<List<SecurityScanRecord>>(
            json.encodeToString(listOf(original))
        )
        assertEquals(listOf(original), decoded)
    }

    @Test
    fun legacyRecordsWithoutNewFieldsStillDecode() {
        // Journals written before scanSource/durationMs existed must not be dropped.
        val legacy = """[{"id":1,"kind":"FILE","target":"a.apk","threatLevel":"CLEAN","riskScore":0,
            "threatName":null,"findings":[],"recommendation":"ok","timestampEpochMs":5}]"""
        val decoded = Json { ignoreUnknownKeys = true }.decodeFromString<List<SecurityScanRecord>>(legacy)
        assertEquals(1, decoded.size)
        assertEquals(ScanSource.MANUAL, decoded[0].scanSource)
        assertEquals(0L, decoded[0].durationMs)
    }

    @Test
    fun quarantineStoredNamesCannotEscapeTheDirectory() {
        val name = QuarantineNaming.storedFileName(42L)
        assertEquals("q_42.quarantined", name)
        assertFalse(name.contains("/"))
        assertFalse(name.contains(".."))
        assertTrue(QuarantineNaming.isStoredFileName(name))
    }

    @Test
    fun storedFileNameValidationRejectsForeignFiles() {
        assertFalse(QuarantineNaming.isStoredFileName("q_abc.quarantined"))
        assertFalse(QuarantineNaming.isStoredFileName("q_1.apk"))
        assertFalse(QuarantineNaming.isStoredFileName("evil_q_1.quarantined"))
        assertFalse(QuarantineNaming.isStoredFileName("q_1.quarantined.exe"))
    }

    @Test
    fun displayNamesAreStrippedOfTraversalAndControlCharacters() {
        assertEquals("evil.apk", QuarantineNaming.safeDisplayName("../../evil.apk"))
        assertEquals("evil.apk", QuarantineNaming.safeDisplayName("C:\\temp\\evil.apk"))
        assertFalse(QuarantineNaming.safeDisplayName("a\u0000b.apk").contains('\u0000'))
        assertEquals("unnamed file", QuarantineNaming.safeDisplayName("   "))
        assertEquals("unnamed file", QuarantineNaming.safeDisplayName("..."))
        assertTrue(QuarantineNaming.safeDisplayName("x".repeat(500)).length <= 80)
    }

    @Test
    fun quarantineIndexIsBoundedAndUsageIgnoresNegativeSizes() {
        var items = emptyList<QuarantinedItem>()
        repeat(QuarantineNaming.MAX_ITEMS + 10) { i ->
            items = QuarantineNaming.append(items, quarantined(i.toLong(), size = 10L))
        }
        assertEquals(QuarantineNaming.MAX_ITEMS, items.size)
        assertEquals(10L * QuarantineNaming.MAX_ITEMS, QuarantineNaming.totalBytes(items))
        assertEquals(0L, QuarantineNaming.totalBytes(listOf(quarantined(1L, size = -50L))))
    }

    @Test
    fun quarantineItemSurvivesPersistenceRoundTrip() {
        val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        val item = quarantined(3L, size = 2048L)
        assertEquals(item, json.decodeFromString<QuarantinedItem>(json.encodeToString(item)))
        assertNotEquals(item.sha256, "")
    }

    @Test
    fun progressIsIndeterminateUntilTheTotalIsKnown() {
        val unknown = ScanProgress("apps", completed = 0, total = 0)
        assertTrue(unknown.isIndeterminate)
        assertEquals(0f, unknown.fraction, 0.0001f)
        assertEquals("Scanning…", unknown.percentLabel)
    }

    @Test
    fun progressFractionIsClampedAndReportedHonestly() {
        assertEquals(0.5f, ScanProgress("f", 5, 10).fraction, 0.0001f)
        assertEquals("50%", ScanProgress("f", 5, 10).percentLabel)
        assertEquals(1f, ScanProgress("f", 99, 10).fraction, 0.0001f)
        assertEquals(0f, ScanProgress("f", -5, 10).fraction, 0.0001f)
        assertEquals("100%", ScanProgress("f", 10, 10).percentLabel)
    }

    private fun quarantined(id: Long, size: Long) = QuarantinedItem(
        id = id,
        displayName = "sample_$id.apk",
        originalLocation = "Download/sample_$id.apk",
        storedFileName = QuarantineNaming.storedFileName(id),
        sha256 = "a".repeat(64),
        sizeBytes = size,
        threatLevel = SecurityLevel.DANGEROUS,
        threatName = "Test.Threat",
        quarantinedAtEpochMs = 1_700_000_000_000L,
        originalRemoved = false
    )
}
