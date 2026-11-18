package com.adshield.pro.data.repository

import com.adshield.pro.engine.aether.AetherAppReview
import com.adshield.pro.engine.aether.AetherGuidedPlan.Attempt
import com.adshield.pro.engine.aether.AetherPhoneAgent
import com.adshield.pro.engine.aether.AetherSecurityReview
import com.adshield.pro.engine.dns.DnsBenchmarkReport
import com.adshield.pro.engine.security.SecurityScanRecord
import com.adshield.pro.engine.security.UrlThreatScanner

internal sealed interface AetherTaskResult {
    data class Phone(val report: AetherPhoneAgent.Report) : AetherTaskResult
    data class Apps(val review: AetherAppReview) : AetherTaskResult
    data class Review(val report: AetherSecurityReview.Report) : AetherTaskResult
    data class Link(
        val host: String,
        val level: UrlThreatScanner.ThreatLevel,
        val findings: List<String>
    ) : AetherTaskResult
    data class ScannedFile(val record: SecurityScanRecord, val bytes: Long, val limitations: List<String>) : AetherTaskResult
    data object FileTooLarge : AetherTaskResult
    data object FileUnavailable : AetherTaskResult
    data class Dns(val report: DnsBenchmarkReport) : AetherTaskResult
    data object AliasShieldOn : AetherTaskResult
}

/** A receipt reports what was observed, not whether the device or object is safe. */
internal fun AetherTaskResult.planAttempt(): Attempt<AetherTaskResult> = when (this) {
    is AetherTaskResult.Phone -> Attempt.Completed(this, limited = report.hasUnavailableReadings)
    is AetherTaskResult.Apps -> if (review.inspected == 0) Attempt.Interrupted(this)
        else Attempt.Completed(this, limited = review.unavailable > 0)
    is AetherTaskResult.Review -> if (report.phone.value == null && (report.apps.value?.inspected ?: 0) == 0) {
        Attempt.Interrupted(this)
    } else Attempt.Completed(this, limited = report.hasGaps)
    is AetherTaskResult.Dns -> Attempt.Completed(this, limited = report.entries.isEmpty() || report.reachableCount < report.entries.size)
    is AetherTaskResult.ScannedFile -> Attempt.Completed(this, limited = limitations.isNotEmpty())
    AetherTaskResult.FileTooLarge, AetherTaskResult.FileUnavailable -> Attempt.Interrupted(this)
    is AetherTaskResult.Link, AetherTaskResult.AliasShieldOn -> Attempt.Completed(this)
}
