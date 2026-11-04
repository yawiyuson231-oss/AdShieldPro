package com.adshield.pro.engine.security

import kotlinx.serialization.Serializable

/** Where a scan record came from — reported honestly in history and exports. */
@Serializable
enum class ScanSource(val label: String) {
    MANUAL("Manual"),
    SCHEDULED("Scheduled")
}

/**
 * Pure scan-journal rules: identity, retention, aggregation and report rendering.
 *
 * Kept free of Android types so the guarantees that matter (unique ids, bounded history,
 * never claiming a scan that did not happen) are unit-testable on the JVM.
 */
object ScanJournal {

    /** Bounded so a long-lived install cannot grow the journal without limit. */
    const val MAX_RECORDS = 200

    /**
     * Scan ids must be strictly increasing.
     *
     * The UI keys its lazy history list on [SecurityScanRecord.id]; two scans completing in the
     * same millisecond used to produce duplicate keys, which crashes LazyColumn. Deriving the id
     * from `max(now, newest + 1)` keeps ids unique even under rapid or batched scanning.
     */
    fun nextId(existing: List<SecurityScanRecord>, nowEpochMs: Long): Long {
        val newest = existing.maxOfOrNull { it.id } ?: 0L
        return maxOf(nowEpochMs, newest + 1L)
    }

    /** Newest-first, capped at [MAX_RECORDS]. */
    fun append(existing: List<SecurityScanRecord>, record: SecurityScanRecord): List<SecurityScanRecord> =
        (listOf(record) + existing).take(MAX_RECORDS)

    /** Batch insert (scheduled runs, folder scans) preserving newest-first order. */
    fun appendAll(
        existing: List<SecurityScanRecord>,
        records: List<SecurityScanRecord>
    ): List<SecurityScanRecord> =
        (records.sortedByDescending { it.id } + existing).take(MAX_RECORDS)

    /** True only when a scan actually produced a record. Never inferred from a score. */
    fun hasScanned(history: List<SecurityScanRecord>): Boolean = history.isNotEmpty()

    fun summarize(history: List<SecurityScanRecord>): ScanJournalSummary = ScanJournalSummary(
        total = history.size,
        clean = history.count { it.threatLevel == SecurityLevel.CLEAN },
        suspicious = history.count { it.threatLevel == SecurityLevel.SUSPICIOUS },
        dangerous = history.count { it.threatLevel == SecurityLevel.DANGEROUS },
        lastScanEpochMs = history.maxOfOrNull { it.timestampEpochMs },
        fileScans = history.count { it.kind == ScanKind.FILE || it.kind == ScanKind.APK },
        urlScans = history.count { it.kind == ScanKind.URL },
        appAudits = history.count { it.kind == ScanKind.APP_AUDIT }
    )

    /**
     * Renders a plain-text threat report the user can export.
     *
     * The footer states the real limits of a local scanner instead of implying guaranteed
     * detection, and an empty journal produces an explicit "no scan performed" report rather
     * than a clean bill of health.
     */
    fun buildTextReport(
        history: List<SecurityScanRecord>,
        appVersion: String,
        generatedAtEpochMs: Long
    ): String = buildString {
        val summary = summarize(history)
        appendLine("AdShield Pro — Security Scan Report")
        appendLine("App version: $appVersion")
        appendLine("Generated (epoch ms): $generatedAtEpochMs")
        appendLine("=".repeat(52))
        appendLine()
        if (!hasScanned(history)) {
            appendLine("NO SCAN HAS BEEN PERFORMED YET.")
            appendLine("This report contains no findings because nothing has been scanned.")
            appendLine("It is not a statement that the device is clean.")
        } else {
            appendLine("Records retained: ${summary.total} (most recent $MAX_RECORDS kept)")
            appendLine("Last scan (epoch ms): ${summary.lastScanEpochMs}")
            appendLine("Clean: ${summary.clean}")
            appendLine("Suspicious: ${summary.suspicious}")
            appendLine("Dangerous: ${summary.dangerous}")
            appendLine("File/APK scans: ${summary.fileScans} · URL scans: ${summary.urlScans} · App audits: ${summary.appAudits}")
            appendLine()
            appendLine("FINDINGS")
            appendLine("-".repeat(52))
            history.forEach { record ->
                appendLine()
                appendLine("[${record.threatLevel.name}] ${record.kind.name} · ${record.target}")
                appendLine("  When (epoch ms): ${record.timestampEpochMs} · Source: ${record.scanSource.label}")
                appendLine("  Risk score: ${record.riskScore}/100")
                record.threatName?.let { appendLine("  Threat: $it") }
                if (record.durationMs > 0) appendLine("  Scan duration: ${record.durationMs} ms")
                if (record.findings.isEmpty()) {
                    appendLine("  Evidence: none recorded")
                } else {
                    record.findings.forEach { appendLine("  - $it") }
                }
                appendLine("  Recommendation: ${record.recommendation}")
            }
        }
        appendLine()
        appendLine("=".repeat(52))
        appendLine("LIMITS OF THIS REPORT")
        appendLine("- Scanning is local and signature/heuristic based. It cannot guarantee")
        appendLine("  detection of new, targeted or obfuscated malware. No product can.")
        appendLine("- Only files, apps and links that were actually scanned appear above.")
        appendLine("  Areas Android does not expose to this app were not examined.")
        appendLine("- Other applications' private data is not readable on non-root Android.")
        appendLine("- A CLEAN result means no known signature or structural indicator matched.")
    }
}

@Serializable
data class ScanJournalSummary(
    val total: Int = 0,
    val clean: Int = 0,
    val suspicious: Int = 0,
    val dangerous: Int = 0,
    val lastScanEpochMs: Long? = null,
    val fileScans: Int = 0,
    val urlScans: Int = 0,
    val appAudits: Int = 0
) {
    val flagged: Int get() = suspicious + dangerous
}

/**
 * A file isolated in app-private storage.
 *
 * [originalRemoved] is recorded rather than assumed: Android often does not let this app delete a
 * file it does not own, and the UI must not claim the original is gone when it is not.
 */
@Serializable
data class QuarantinedItem(
    val id: Long,
    val displayName: String,
    val originalLocation: String,
    val storedFileName: String,
    val sha256: String,
    val sizeBytes: Long,
    val threatLevel: SecurityLevel,
    val threatName: String? = null,
    val quarantinedAtEpochMs: Long,
    val originalRemoved: Boolean = false
)

/** Pure naming/sanitising rules for quarantine storage (no filesystem access). */
object QuarantineNaming {
    const val MAX_ITEMS = 100
    private const val SUFFIX = ".quarantined"

    /**
     * Stored names are derived from the record id, never from user input, so a hostile display
     * name like `../../evil.apk` can never escape the quarantine directory. The suffix also stops
     * Android from treating the isolated copy as an installable/openable file.
     */
    fun storedFileName(id: Long): String = "q_$id$SUFFIX"

    fun isStoredFileName(name: String): Boolean =
        name.startsWith("q_") && name.endsWith(SUFFIX) &&
            name.removePrefix("q_").removeSuffix(SUFFIX).all { it.isDigit() }

    /** Keeps a readable label for the UI without allowing path traversal or control characters. */
    fun safeDisplayName(raw: String): String {
        val base = raw.substringAfterLast('/').substringAfterLast('\\')
        val cleaned = base.map { if (it.isISOControl() || it == '/' || it == '\\') '_' else it }.joinToString("")
        return cleaned.trim().trimStart('.').take(80).ifBlank { "unnamed file" }
    }

    fun totalBytes(items: List<QuarantinedItem>): Long = items.sumOf { it.sizeBytes.coerceAtLeast(0L) }

    fun append(items: List<QuarantinedItem>, item: QuarantinedItem): List<QuarantinedItem> =
        (listOf(item) + items).take(MAX_ITEMS)
}

/**
 * Real scan progress. [total] of 0 means the target count is not yet known, which the UI must
 * render as an indeterminate indicator rather than a fabricated percentage.
 */
data class ScanProgress(
    val label: String,
    val completed: Int,
    val total: Int
) {
    val isIndeterminate: Boolean get() = total <= 0
    val fraction: Float
        get() = if (total <= 0) 0f else (completed.toFloat() / total.toFloat()).coerceIn(0f, 1f)
    val percentLabel: String
        get() = if (isIndeterminate) "Scanning…" else "${(fraction * 100).toInt()}%"
}
