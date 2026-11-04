package com.adshield.pro.engine.security

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.ProtectionMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import java.io.File

/**
 * AdShield Pro — Complete Multi-Module System Scanner.
 *
 * Executes real, non-simulated scanning across all 6 supported device & application modules:
 * 1. Security & DNS Configuration (`SECURITY_CONFIG`)
 * 2. Installed Applications (`APPLICATIONS`)
 * 3. Downloads & Accessible Files (`DOWNLOADS_AND_FILES`)
 * 4. Storage & Junk Footprint (`STORAGE_AND_CACHE`)
 * 5. System & Battery/Thermal Components (`SYSTEM_COMPONENTS`)
 * 6. Filter Lists & Custom Rule Integrity (`FILTER_INTEGRITY`)
 *
 * Emits step-by-step live [SystemScanProgress] updates, captures real findings and I/O or
 * permission errors honestly, and generates a structured [SystemScanReport] that can be
 * persisted and exported as Markdown/text.
 */
class SystemScannerEngine(
    private val fileScanner: FileThreatScanner = FileThreatScanner(),
    private val apkAnalyzer: ApkAnalyzer = ApkAnalyzer()
) {

    @Serializable
    enum class SystemScanModule(val title: String) {
        SECURITY_CONFIG("Security & Network Configuration"),
        APPLICATIONS("Installed Applications"),
        DOWNLOADS_AND_FILES("Downloads & Accessible Files"),
        STORAGE_AND_CACHE("Storage & Cache Health"),
        SYSTEM_COMPONENTS("System, Battery & Thermal Health"),
        FILTER_INTEGRITY("Blocklists & Rule Integrity")
    }

    data class SystemScanProgress(
        val isRunning: Boolean,
        val currentModule: SystemScanModule?,
        val completedModules: Int,
        val totalModules: Int = SystemScanModule.entries.size,
        val percent: Int,
        val statusText: String,
        val itemsScannedSoFar: Int
    )

    @Serializable
    data class ModuleScanSummary(
        val module: SystemScanModule,
        val level: SecurityLevel,
        val itemsChecked: Int,
        val issuesFound: Int,
        val findings: List<String>,
        val errors: List<String>,
        val durationMs: Long
    )

    @Serializable
    data class SystemScanReport(
        val id: Long,
        val timestampEpochMs: Long,
        val overallLevel: SecurityLevel,
        val overallRiskScore: Int,
        val totalItemsScanned: Int,
        val totalFindings: Int,
        val totalErrors: Int,
        val durationMs: Long,
        val modules: List<ModuleScanSummary>,
        val summary: String
    ) {
        fun toDetailedReportText(): String = buildString {
            appendLine("# AdShield Pro — Complete System Scan Report")
            appendLine("Report ID: $id")
            appendLine("Timestamp (epoch ms): $timestampEpochMs")
            appendLine("Overall Verdict: ${overallLevel.name} (Risk Score: $overallRiskScore/100)")
            appendLine("Items Scanned: $totalItemsScanned | Findings: $totalFindings | Errors/Limitations: $totalErrors | Duration: ${durationMs}ms")
            appendLine("Summary: $summary")
            appendLine()
            for (mod in modules) {
                appendLine("## ${mod.module.title} [${mod.level.name}]")
                appendLine("- Checked: ${mod.itemsChecked} item(s) in ${mod.durationMs}ms")
                if (mod.findings.isEmpty()) {
                    appendLine("- Findings: None (clean)")
                } else {
                    mod.findings.forEach { appendLine("- Finding: $it") }
                }
                mod.errors.forEach { appendLine("- Notice/Error: $it") }
                appendLine()
            }
        }
    }

    /** Snapshot inputs supplied by the runtime so every module can be verified deterministically. */
    data class ScanInputs(
        val vpnConnected: Boolean,
        val protectionMode: ProtectionMode,
        val dnsProtocol: DnsProtocol,
        val threatSignatureCount: Int,
        val httpsUpgradeEnabled: Boolean,
        val blockThirdPartyCookies: Boolean,
        val auditAppsProvider: suspend () -> List<AppRiskAuditor.AppRiskAudit>,
        val scanDirectories: List<File>,
        val storageUsedPercent: Float,
        val storageAvailableBytes: Long,
        val recoverableJunkBytes: Long,
        val ramUsagePercent: Float,
        val isLowMemory: Boolean,
        val sdkInt: Int,
        val supportedPlatform: Boolean,
        val batteryTempCelsius: Float?,
        val batteryHealthGood: Boolean,
        val enabledFilterListCount: Int,
        val totalLoadedRules: Int,
        val ruleConflictCount: Int,
        val lastFilterSyncEpochMs: Long
    )

    suspend fun runCompleteScan(
        inputs: ScanInputs,
        onProgress: (SystemScanProgress) -> Unit = {}
    ): SystemScanReport = withContext(Dispatchers.IO) {
        val scanStartedMs = System.currentTimeMillis()
        val modules = ArrayList<ModuleScanSummary>(SystemScanModule.entries.size)
        val totalModules = SystemScanModule.entries.size
        var runningItemsCount = 0

        suspend fun runStep(
            index: Int,
            module: SystemScanModule,
            block: suspend () -> ModuleScanSummary
        ) {
            onProgress(
                SystemScanProgress(
                    isRunning = true,
                    currentModule = module,
                    completedModules = index,
                    totalModules = totalModules,
                    percent = ((index * 100) / totalModules).coerceIn(0, 99),
                    statusText = "Scanning ${module.title}…",
                    itemsScannedSoFar = runningItemsCount
                )
            )
            val modStart = System.currentTimeMillis()
            val summary = try {
                block()
            } catch (t: Throwable) {
                ModuleScanSummary(
                    module = module,
                    level = SecurityLevel.SUSPICIOUS,
                    itemsChecked = 0,
                    issuesFound = 0,
                    findings = emptyList(),
                    errors = listOf("Module failed: ${t.message ?: t::class.simpleName}"),
                    durationMs = (System.currentTimeMillis() - modStart).coerceAtLeast(1L)
                )
            }
            runningItemsCount += summary.itemsChecked
            modules.add(summary)
        }

        // 1. Security & Network Configuration
        runStep(0, SystemScanModule.SECURITY_CONFIG) {
            val t0 = System.currentTimeMillis()
            val findings = ArrayList<String>()
            if (!inputs.vpnConnected) {
                findings.add("Local DNS protection tunnel is currently disconnected — apps are not being filtered.")
            }
            if (inputs.dnsProtocol == DnsProtocol.UDP_TCP) {
                findings.add("Upstream DNS uses unencrypted UDP/TCP port 53 — switch to DoH or DoT for encrypted lookups.")
            }
            if (inputs.threatSignatureCount < 1_000) {
                findings.add("Low active malware/phishing signature count (${inputs.threatSignatureCount}); enable Threat Intelligence blocklist.")
            }
            if (!inputs.httpsUpgradeEnabled) {
                findings.add("Browser automatic HTTPS upgrade is disabled.")
            }
            if (!inputs.blockThirdPartyCookies) {
                findings.add("Browser third-party cookie blocking is disabled.")
            }
            val level = when {
                !inputs.vpnConnected || inputs.threatSignatureCount == 0 -> SecurityLevel.SUSPICIOUS
                findings.isNotEmpty() -> SecurityLevel.SUSPICIOUS
                else -> SecurityLevel.CLEAN
            }
            ModuleScanSummary(
                module = SystemScanModule.SECURITY_CONFIG,
                level = level,
                itemsChecked = 5,
                issuesFound = findings.size,
                findings = findings,
                errors = emptyList(),
                durationMs = (System.currentTimeMillis() - t0).coerceAtLeast(1L)
            )
        }

        // 2. Installed Applications Audit
        runStep(1, SystemScanModule.APPLICATIONS) {
            val t0 = System.currentTimeMillis()
            val errors = ArrayList<String>()
            val audits = try {
                inputs.auditAppsProvider()
            } catch (t: Throwable) {
                errors.add("Could not enumerate installed applications: ${t.message ?: "PackageManager error"}")
                emptyList()
            }
            val highRisk = audits.filter { it.riskLevel == AppRiskAuditor.RiskLevel.HIGH }
            val mediumRisk = audits.filter { it.riskLevel == AppRiskAuditor.RiskLevel.MEDIUM }
            val findings = buildList {
                highRisk.take(10).forEach { audit ->
                    add("HIGH RISK app '${audit.profile.appName}' (${audit.profile.packageName}): ${audit.findings.firstOrNull() ?: "high-risk permission stack"}")
                }
                if (mediumRisk.isNotEmpty()) {
                    add("${mediumRisk.size} installed app(s) have elevated permission combinations.")
                }
            }
            val level = when {
                highRisk.isNotEmpty() -> SecurityLevel.DANGEROUS
                mediumRisk.isNotEmpty() -> SecurityLevel.SUSPICIOUS
                else -> SecurityLevel.CLEAN
            }
            ModuleScanSummary(
                module = SystemScanModule.APPLICATIONS,
                level = level,
                itemsChecked = audits.size,
                issuesFound = highRisk.size + mediumRisk.size,
                findings = findings,
                errors = errors,
                durationMs = (System.currentTimeMillis() - t0).coerceAtLeast(1L)
            )
        }

        // 3. Downloads & Accessible Files
        runStep(2, SystemScanModule.DOWNLOADS_AND_FILES) {
            val t0 = System.currentTimeMillis()
            val findings = ArrayList<String>()
            val errors = ArrayList<String>()
            var checkedFiles = 0
            var dangerousCount = 0
            var suspiciousCount = 0

            for (dir in inputs.scanDirectories.distinctBy { it.absolutePath }) {
                if (!dir.exists()) continue
                if (!dir.canRead()) {
                    errors.add("Scoped storage restricts direct listing of '${dir.name}'; use Choose File to scan private external folders.")
                    continue
                }
                dir.walkTopDown()
                    .maxDepth(4)
                    .onFail { failedDir, ioEx ->
                        errors.add("Unreadable path '${failedDir.name}': ${ioEx.message ?: "access denied"}")
                    }
                    .take(MAX_FILES_PER_SYSTEM_SCAN)
                    .forEach { f ->
                        if (!f.isFile || !f.canRead() || f.length() <= 0L) return@forEach
                        // Skip AdShield's own encrypted vault ciphertext blobs
                        if (f.name.endsWith(".enc") && f.parentFile?.name == "blobs") return@forEach

                        checkedFiles++
                        val fVerdict = fileScanner.scanFile(f)
                        val isApk = f.name.endsWith(".apk", ignoreCase = true)
                        val apkVerdict = if (isApk) runCatching { apkAnalyzer.analyzeApk(f) }.getOrNull() else null

                        val dangerous = fVerdict.threatLevel == FileThreatScanner.ThreatLevel.DANGEROUS ||
                            apkVerdict?.threatLevel == ApkAnalyzer.ThreatLevel.DANGEROUS
                        val suspicious = !dangerous && (
                            fVerdict.threatLevel == FileThreatScanner.ThreatLevel.SUSPICIOUS ||
                                apkVerdict?.threatLevel == ApkAnalyzer.ThreatLevel.SUSPICIOUS
                            )

                        if (dangerous) {
                            dangerousCount++
                            val detail = fVerdict.threatName
                                ?: apkVerdict?.riskReasons?.firstOrNull()
                                ?: "dangerous signature"
                            findings.add("DANGEROUS file '${f.name}': $detail")
                        } else if (suspicious) {
                            suspiciousCount++
                            val detail = fVerdict.findings.firstOrNull()
                                ?: apkVerdict?.riskReasons?.firstOrNull()
                                ?: "structural risk indicator"
                            findings.add("Suspicious file '${f.name}': $detail")
                        }
                    }
            }

            val level = when {
                dangerousCount > 0 -> SecurityLevel.DANGEROUS
                suspiciousCount > 0 -> SecurityLevel.SUSPICIOUS
                else -> SecurityLevel.CLEAN
            }
            ModuleScanSummary(
                module = SystemScanModule.DOWNLOADS_AND_FILES,
                level = level,
                itemsChecked = checkedFiles,
                issuesFound = dangerousCount + suspiciousCount,
                findings = findings.take(15),
                errors = errors.distinct().take(8),
                durationMs = (System.currentTimeMillis() - t0).coerceAtLeast(1L)
            )
        }

        // 4. Storage & Cache Health
        runStep(3, SystemScanModule.STORAGE_AND_CACHE) {
            val t0 = System.currentTimeMillis()
            val findings = ArrayList<String>()
            if (inputs.storageUsedPercent >= 92f) {
                findings.add("Critical storage pressure: ${"%.1f".format(java.util.Locale.US, inputs.storageUsedPercent)}% full (${inputs.storageAvailableBytes / (1024 * 1024)} MB free).")
            }
            if (inputs.recoverableJunkBytes >= 25L * 1024L * 1024L) {
                findings.add("${inputs.recoverableJunkBytes / (1024 * 1024)} MB of temporary cache/junk files can be reclaimed in Optimizer.")
            }
            if (inputs.isLowMemory || inputs.ramUsagePercent >= 92f) {
                findings.add("High system memory pressure (${"%.0f".format(java.util.Locale.US, inputs.ramUsagePercent)}% RAM used).")
            }
            val level = if (findings.isNotEmpty()) SecurityLevel.SUSPICIOUS else SecurityLevel.CLEAN
            ModuleScanSummary(
                module = SystemScanModule.STORAGE_AND_CACHE,
                level = level,
                itemsChecked = 3,
                issuesFound = findings.size,
                findings = findings,
                errors = emptyList(),
                durationMs = (System.currentTimeMillis() - t0).coerceAtLeast(1L)
            )
        }

        // 5. System, Battery & Thermal Components
        runStep(4, SystemScanModule.SYSTEM_COMPONENTS) {
            val t0 = System.currentTimeMillis()
            val findings = ArrayList<String>()
            if (!inputs.supportedPlatform) {
                findings.add("Running on Android API ${inputs.sdkInt}, outside the primary validated API range.")
            }
            val temp = inputs.batteryTempCelsius
            if (temp != null && temp >= 43f) {
                findings.add("Elevated battery temperature (${"%.1f".format(java.util.Locale.US, temp)}°C) — unplug charger or reduce workload.")
            }
            if (!inputs.batteryHealthGood) {
                findings.add("Android BatteryManager reports degraded battery health status.")
            }
            val level = when {
                temp != null && temp >= 46f -> SecurityLevel.DANGEROUS
                findings.isNotEmpty() -> SecurityLevel.SUSPICIOUS
                else -> SecurityLevel.CLEAN
            }
            ModuleScanSummary(
                module = SystemScanModule.SYSTEM_COMPONENTS,
                level = level,
                itemsChecked = 3,
                issuesFound = findings.size,
                findings = findings,
                errors = emptyList(),
                durationMs = (System.currentTimeMillis() - t0).coerceAtLeast(1L)
            )
        }

        // 6. Filter Lists & Rule Integrity
        runStep(5, SystemScanModule.FILTER_INTEGRITY) {
            val t0 = System.currentTimeMillis()
            val findings = ArrayList<String>()
            if (inputs.enabledFilterListCount == 0 || inputs.totalLoadedRules == 0) {
                findings.add("Zero active filter rules are loaded — enable at least one blocklist in Ad Blocker.")
            }
            if (inputs.ruleConflictCount > 0) {
                findings.add("${inputs.ruleConflictCount} custom rule conflict(s) or shadow rule(s) detected.")
            }
            val ageDays = if (inputs.lastFilterSyncEpochMs > 0L) {
                (System.currentTimeMillis() - inputs.lastFilterSyncEpochMs) / 86_400_000L
            } else -1L
            if (ageDays > 14L) {
                findings.add("Remote filter lists have not been synced in $ageDays days.")
            }
            val level = when {
                inputs.totalLoadedRules == 0 -> SecurityLevel.DANGEROUS
                findings.isNotEmpty() -> SecurityLevel.SUSPICIOUS
                else -> SecurityLevel.CLEAN
            }
            ModuleScanSummary(
                module = SystemScanModule.FILTER_INTEGRITY,
                level = level,
                itemsChecked = 3 + inputs.enabledFilterListCount,
                issuesFound = findings.size,
                findings = findings,
                errors = emptyList(),
                durationMs = (System.currentTimeMillis() - t0).coerceAtLeast(1L)
            )
        }

        val totalFindings = modules.sumOf { it.issuesFound }
        val totalErrors = modules.sumOf { it.errors.size }
        val hasDangerous = modules.any { it.level == SecurityLevel.DANGEROUS }
        val hasSuspicious = modules.any { it.level == SecurityLevel.SUSPICIOUS }
        val overallLevel = when {
            hasDangerous -> SecurityLevel.DANGEROUS
            hasSuspicious -> SecurityLevel.SUSPICIOUS
            else -> SecurityLevel.CLEAN
        }

        var riskScore = 0
        modules.forEach { mod ->
            riskScore += when (mod.level) {
                SecurityLevel.DANGEROUS -> 45 + (mod.issuesFound * 8)
                SecurityLevel.SUSPICIOUS -> 12 + (mod.issuesFound * 5)
                SecurityLevel.CLEAN -> 0
            }
        }
        val clampedRisk = riskScore.coerceIn(0, 100)
        val elapsedMs = (System.currentTimeMillis() - scanStartedMs).coerceAtLeast(1L)

        val summaryText = when (overallLevel) {
            SecurityLevel.DANGEROUS -> "Critical threat(s) detected across $totalFindings finding(s) (${runningItemsCount} items checked in ${elapsedMs}ms)."
            SecurityLevel.SUSPICIOUS -> "Completed with $totalFindings advisory finding(s) across ${modules.size} modules (${runningItemsCount} items checked)."
            SecurityLevel.CLEAN -> "All ${modules.size} system modules passed ($runningItemsCount items verified clean in ${elapsedMs}ms)."
        }

        onProgress(
            SystemScanProgress(
                isRunning = false,
                currentModule = null,
                completedModules = totalModules,
                totalModules = totalModules,
                percent = 100,
                statusText = summaryText,
                itemsScannedSoFar = runningItemsCount
            )
        )

        SystemScanReport(
            id = System.currentTimeMillis(),
            timestampEpochMs = System.currentTimeMillis(),
            overallLevel = overallLevel,
            overallRiskScore = clampedRisk,
            totalItemsScanned = runningItemsCount,
            totalFindings = totalFindings,
            totalErrors = totalErrors,
            durationMs = elapsedMs,
            modules = modules,
            summary = summaryText
        )
    }

    companion object {
        private const val MAX_FILES_PER_SYSTEM_SCAN = 400
    }
}
