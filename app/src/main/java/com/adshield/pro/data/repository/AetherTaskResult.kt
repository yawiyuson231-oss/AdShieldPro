package com.adshield.pro.data.repository

import com.adshield.pro.engine.aether.AetherAppReview
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
