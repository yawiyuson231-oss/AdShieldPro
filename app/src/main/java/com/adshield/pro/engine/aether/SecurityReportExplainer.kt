package com.adshield.pro.engine.aether

import com.adshield.pro.engine.security.ScanKind
import com.adshield.pro.engine.security.SecurityLevel
import com.adshield.pro.engine.security.SecurityScanRecord

/**
 * Deterministic, on-device report explanation. It summarizes recorded evidence only; it does not
 * pretend to be a generative model and cannot delete files or alter protection settings.
 */
object SecurityReportExplainer {
    data class Summary(
        val headline: String,
        val explanation: String,
        val recommendedActions: List<String>,
        val evidenceCount: Int
    )

    fun summarize(history: List<SecurityScanRecord>): Summary {
        if (history.isEmpty()) {
            return Summary(
                headline = "No scan evidence yet",
                explanation = "Choose a file, scan a link, or audit installed apps. AETHER will explain the resulting evidence here.",
                recommendedActions = listOf("Run a user-initiated scan before drawing security conclusions."),
                evidenceCount = 0
            )
        }
        val dangerous = history.filter { it.threatLevel == SecurityLevel.DANGEROUS }
        val suspicious = history.filter { it.threatLevel == SecurityLevel.SUSPICIOUS }
        val files = history.count { it.kind == ScanKind.FILE || it.kind == ScanKind.APK }
        val links = history.count { it.kind == ScanKind.URL }
        val headline = when {
            dangerous.isNotEmpty() -> "${dangerous.size} high-severity result${if (dangerous.size == 1) "" else "s"} need review"
            suspicious.isNotEmpty() -> "${suspicious.size} result${if (suspicious.size == 1) "" else "s"} contain risk indicators"
            else -> "No listed indicators in ${history.size} recorded scan${if (history.size == 1) "" else "s"}"
        }
        val explanation = buildString {
            append("Analyzed ${history.size} persisted reports: $files file/APK and $links link results. ")
            if (dangerous.isNotEmpty()) {
                append("The highest-scoring target is ${dangerous.maxBy { it.riskScore }.target}; its recorded evidence is ")
                append(dangerous.maxBy { it.riskScore }.findings.take(2).joinToString("; ").ifBlank { "a high-risk signature or structural indicator" })
                append(". ")
            }
            append("A clean result means only that the current local signatures and structural checks found nothing; it is not a guarantee of safety.")
        }
        val actions = buildList {
            if (dangerous.isNotEmpty()) add("Do not open or install high-severity targets. Review each finding, then delete or quarantine only with confirmation.")
            if (suspicious.isNotEmpty()) add("Verify suspicious targets with their publisher or source; heuristics can produce false positives.")
            if (dangerous.isEmpty() && suspicious.isEmpty()) add("Keep threat lists updated and rescan changed files; no destructive action is indicated by these reports.")
            add("Export or retain the underlying reports when seeking a second opinion; this assistant has no hidden evidence.")
        }
        return Summary(headline, explanation, actions, history.size)
    }
}
