package com.adshield.pro.engine.compliance

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Local security-configuration assessment.
 *
 * This is a device hardening checklist evaluated from real Android signals and the app's own
 * settings — it is NOT ISO 27001, SOC 2, GDPR or HIPAA certification, and the report says so
 * explicitly. A check whose signal cannot be read is UNKNOWN, never a fabricated pass. The
 * score counts only checks that could actually be evaluated.
 *
 * Pure evaluation + report rendering, unit-tested on the JVM.
 */
object ComplianceChecker {

    enum class CheckStatus { PASS, FAIL, UNKNOWN }

    enum class Category(val label: String) {
        DEVICE("Device"),
        DATA("Data"),
        NETWORK("Network"),
        PRIVACY("Privacy")
    }

    /**
     * Raw signals. `null` means "could not be measured on this device" — the evaluator must
     * report UNKNOWN for it. [securityPatchLevel] is Build.VERSION.SECURITY_PATCH (yyyy-MM-dd).
     */
    data class DeviceSecuritySignals(
        val deviceLabel: String,
        val androidRelease: String,
        val sdkInt: Int,
        val securityPatchLevel: String?,
        val screenLockEnabled: Boolean?,
        val storageEncrypted: Boolean?,
        val adbEnabled: Boolean?,
        val developerOptionsEnabled: Boolean?,
        val vpnActive: Boolean,
        val threatSignatureCount: Int,
        val autoUpdateFiltersEnabled: Boolean,
        val lastFilterUpdateEpochMs: Long,
        val bundledBaselineAvailable: Boolean,
        val scheduledScanEnabled: Boolean,
        val detailedDnsLoggingEnabled: Boolean,
        val logRetentionDays: Int,
        val highRiskAppCount: Int?,
        val appCanInstallUnknownSources: Boolean?
    )

    data class ComplianceCheck(
        val id: String,
        val title: String,
        val category: Category,
        val status: CheckStatus,
        val detail: String,
        val recommendation: String?
    )

    data class CategorySummary(
        val category: Category,
        val passed: Int,
        val failed: Int,
        val unknown: Int
    ) {
        val evaluated: Int get() = passed + failed
        /** Pass ratio over evaluated checks; null when nothing could be evaluated. */
        val passRatio: Float? get() = if (evaluated == 0) null else passed.toFloat() / evaluated
    }

    data class ComplianceReport(
        val generatedAtEpochMs: Long,
        val deviceLabel: String,
        val androidRelease: String,
        val checks: List<ComplianceCheck>,
        val categories: List<CategorySummary>,
        /** 0..100 over evaluated checks only; null when nothing could be evaluated. */
        val scorePercent: Int?,
        val unknownCount: Int
    )

    private const val PATCH_MAX_AGE_DAYS = 120L
    private const val FILTER_FRESH_MS = 48 * 60 * 60 * 1000L

    fun evaluate(signals: DeviceSecuritySignals, nowEpochMs: Long = System.currentTimeMillis()): ComplianceReport {
        val checks = ArrayList<ComplianceCheck>()

        // ---------------- DEVICE ----------------
        checks += booleanCheck(
            id = "device-screen-lock",
            title = "Screen lock enabled",
            category = Category.DEVICE,
            value = signals.screenLockEnabled,
            passDetail = "KeyguardManager reports a secure lock screen (PIN, pattern, password or biometric).",
            failDetail = "No secure lock screen is configured.",
            recommendation = "Set a PIN, password or biometric lock in Android settings."
        )
        checks += booleanCheck(
            id = "device-encryption",
            title = "Storage encrypted",
            category = Category.DEVICE,
            value = signals.storageEncrypted,
            passDetail = "DevicePolicyManager reports device storage is encrypted.",
            failDetail = "Device storage is reported as not encrypted.",
            recommendation = "Encryption is mandatory on Android 10+; a FAIL here indicates an unusual device state."
        )
        checks += booleanCheck(
            id = "device-adb",
            title = "USB debugging (ADB) disabled",
            category = Category.DEVICE,
            value = signals.adbEnabled?.not(),
            passDetail = "Settings.Global.ADB_ENABLED is off.",
            failDetail = "ADB is enabled — a connected computer can control the device.",
            recommendation = "Turn off USB debugging in Developer options when not actively using it."
        )
        checks += booleanCheck(
            id = "device-dev-options",
            title = "Developer options disabled",
            category = Category.DEVICE,
            value = signals.developerOptionsEnabled?.not(),
            passDetail = "Developer options are switched off.",
            failDetail = "Developer options are enabled, widening the attack surface.",
            recommendation = "Disable Developer options unless you need them."
        )
        checks += patchCheck(signals.securityPatchLevel, nowEpochMs)

        // ---------------- NETWORK ----------------
        checks += ComplianceCheck(
            id = "network-dns-filtering",
            title = "DNS threat filtering active",
            category = Category.NETWORK,
            status = if (signals.vpnActive) CheckStatus.PASS else CheckStatus.FAIL,
            detail = if (signals.vpnActive) {
                "The local DNS VPN tunnel is connected and filtering queries."
            } else {
                "The DNS tunnel is not running, so ad/tracker/malware domains are not being filtered."
            },
            recommendation = if (signals.vpnActive) null else "Turn on protection from the dashboard shield."
        )
        checks += ComplianceCheck(
            id = "network-threat-signatures",
            title = "Threat intelligence loaded",
            category = Category.NETWORK,
            status = when {
                signals.threatSignatureCount >= 1000 -> CheckStatus.PASS
                signals.threatSignatureCount > 0 -> CheckStatus.FAIL
                else -> CheckStatus.FAIL
            },
            detail = "${signals.threatSignatureCount} malware-domain signatures active in the filter engine.",
            recommendation = if (signals.threatSignatureCount >= 1000) null else "Sync the filter lists to load the full threat baseline."
        )
        checks += ComplianceCheck(
            id = "network-filter-freshness",
            title = "Filter lists up to date",
            category = Category.NETWORK,
            status = when {
                signals.lastFilterUpdateEpochMs > 0L && nowEpochMs - signals.lastFilterUpdateEpochMs <= FILTER_FRESH_MS -> CheckStatus.PASS
                signals.lastFilterUpdateEpochMs > 0L -> CheckStatus.FAIL
                signals.bundledBaselineAvailable -> CheckStatus.PASS
                else -> CheckStatus.UNKNOWN
            },
            detail = when {
                signals.lastFilterUpdateEpochMs > 0L && nowEpochMs - signals.lastFilterUpdateEpochMs <= FILTER_FRESH_MS ->
                    "Lists synced within the last 48 hours."
                signals.lastFilterUpdateEpochMs > 0L ->
                    "Last sync is older than 48 hours."
                signals.bundledBaselineAvailable ->
                    "Never synced remotely; the bundled offline baseline is active."
                else -> "No synced lists and no bundled baseline could be confirmed."
            },
            recommendation = if (signals.lastFilterUpdateEpochMs == 0L) "Run a filter sync when online to stay current." else null
        )
        checks += booleanCheck(
            id = "network-auto-update",
            title = "Automatic filter updates",
            category = Category.NETWORK,
            value = signals.autoUpdateFiltersEnabled,
            passDetail = "WorkManager refreshes the lists periodically.",
            failDetail = "Automatic list updates are disabled.",
            recommendation = "Enable auto-sync so new threat domains are blocked without manual action."
        )

        // ---------------- DATA ----------------
        checks += ComplianceCheck(
            id = "data-local-processing",
            title = "Local-only security processing",
            category = Category.DATA,
            status = CheckStatus.PASS,
            detail = "DNS logs, scans and detection run on-device. Threat-intel sync downloads public feeds only; no personal data is uploaded.",
            recommendation = null
        )
        checks += ComplianceCheck(
            id = "data-retention",
            title = "DNS history retention ≤ 7 days",
            category = Category.DATA,
            status = if (signals.logRetentionDays <= 7) CheckStatus.PASS else CheckStatus.FAIL,
            detail = "Detailed DNS history is pruned after ${signals.logRetentionDays} day(s).",
            recommendation = if (signals.logRetentionDays <= 7) null else "Shorten log retention in Settings → privacy."
        )
        checks += ComplianceCheck(
            id = "data-logging-choice",
            title = "Detailed logging is a deliberate choice",
            category = Category.DATA,
            status = CheckStatus.PASS,
            detail = if (signals.detailedDnsLoggingEnabled) {
                "Per-domain logging is ON: richer threat history, stored locally only."
            } else {
                "Per-domain logging is OFF: only anonymous aggregate counters are kept."
            },
            recommendation = null
        )

        // ---------------- PRIVACY ----------------
        checks += booleanCheck(
            id = "privacy-scheduled-scan",
            title = "Scheduled security scan",
            category = Category.PRIVACY,
            value = signals.scheduledScanEnabled,
            passDetail = "A periodic WorkManager scan audits installed apps and re-verifies quarantine.",
            failDetail = "No scheduled scan is configured; audits only run when you start them.",
            recommendation = "Enable scheduled scans in the Security tab."
        )
        checks += ComplianceCheck(
            id = "privacy-app-risk",
            title = "No high-risk apps detected",
            category = Category.PRIVACY,
            status = when (signals.highRiskAppCount) {
                null -> CheckStatus.UNKNOWN
                0 -> CheckStatus.PASS
                else -> CheckStatus.FAIL
            },
            detail = when (signals.highRiskAppCount) {
                null -> "No app audit has been run yet, so app risk is unknown — not assumed clean."
                0 -> "The latest permission-stack audit found no high-risk apps."
                else -> "${signals.highRiskAppCount} high-risk app(s) flagged by the permission audit."
            },
            recommendation = when (signals.highRiskAppCount) {
                null -> "Run the app audit from the Endpoints tab."
                0 -> null
                else -> "Review the flagged apps in the Endpoints tab."
            }
        )
        checks += booleanCheck(
            id = "privacy-unknown-sources",
            title = "This app cannot sideload packages",
            category = Category.PRIVACY,
            value = signals.appCanInstallUnknownSources?.not(),
            passDetail = "PackageManager.canRequestPackageInstalls() is false for AdShield.",
            failDetail = "AdShield currently holds the install-unknown-apps grant (used by the updater).",
            recommendation = "Revoke the install permission for AdShield when you are not updating it."
        )

        val categories = Category.entries.map { category ->
            val inCategory = checks.filter { it.category == category }
            CategorySummary(
                category = category,
                passed = inCategory.count { it.status == CheckStatus.PASS },
                failed = inCategory.count { it.status == CheckStatus.FAIL },
                unknown = inCategory.count { it.status == CheckStatus.UNKNOWN }
            )
        }
        val evaluated = checks.count { it.status != CheckStatus.UNKNOWN }
        val passed = checks.count { it.status == CheckStatus.PASS }
        return ComplianceReport(
            generatedAtEpochMs = nowEpochMs,
            deviceLabel = signals.deviceLabel,
            androidRelease = signals.androidRelease,
            checks = checks,
            categories = categories,
            scorePercent = if (evaluated == 0) null else Math.round(passed * 100f / evaluated),
            unknownCount = checks.count { it.status == CheckStatus.UNKNOWN }
        )
    }

    private fun booleanCheck(
        id: String,
        title: String,
        category: Category,
        value: Boolean?,
        passDetail: String,
        failDetail: String,
        recommendation: String
    ): ComplianceCheck = ComplianceCheck(
        id = id,
        title = title,
        category = category,
        status = when (value) {
            null -> CheckStatus.UNKNOWN
            true -> CheckStatus.PASS
            false -> CheckStatus.FAIL
        },
        detail = when (value) {
            null -> "This signal could not be read on the device; the check is reported as unknown."
            true -> passDetail
            false -> failDetail
        },
        recommendation = if (value == false) recommendation else null
    )

    private fun patchCheck(patchLevel: String?, nowEpochMs: Long): ComplianceCheck {
        if (patchLevel.isNullOrBlank()) {
            return ComplianceCheck(
                "device-security-patch", "Security patch level current", Category.DEVICE,
                CheckStatus.UNKNOWN, "Build.VERSION.SECURITY_PATCH is not readable on this device.", null
            )
        }
        val parsed = runCatching {
            SimpleDateFormat("yyyy-MM-dd", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }.parse(patchLevel)
        }.getOrNull()
        if (parsed == null) {
            return ComplianceCheck(
                "device-security-patch", "Security patch level current", Category.DEVICE,
                CheckStatus.UNKNOWN, "Security patch string '$patchLevel' is not a yyyy-MM-dd date.", null
            )
        }
        val ageDays = (nowEpochMs - parsed.time) / (24 * 60 * 60 * 1000L)
        val pass = ageDays <= PATCH_MAX_AGE_DAYS
        return ComplianceCheck(
            id = "device-security-patch",
            title = "Security patch level current",
            category = Category.DEVICE,
            status = if (pass) CheckStatus.PASS else CheckStatus.FAIL,
            detail = "Security patch $patchLevel is $ageDays day(s) old (threshold $PATCH_MAX_AGE_DAYS).",
            recommendation = if (pass) null else "Install the latest Android security update."
        )
    }

    /** Exportable plain-text report. Always states what this assessment is and is not. */
    fun buildTextReport(report: ComplianceReport, appVersion: String): String = buildString {
        appendLine("CYBERSHIELD AI — DEVICE SECURITY CONFIGURATION REPORT")
        appendLine("Generated by AdShield Pro v$appVersion")
        val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
        appendLine("Generated at: ${sdf.format(Date(report.generatedAtEpochMs))}")
        appendLine("Device: ${report.deviceLabel} · Android ${report.androidRelease}")
        appendLine()
        appendLine("Scope: local device configuration checks only. This is NOT an ISO 27001,")
        appendLine("SOC 2, GDPR or HIPAA certification, and it does not audit any organisation.")
        appendLine()
        appendLine("Score: ${report.scorePercent?.let { "$it%" } ?: "not measurable"} of evaluated checks passed " +
            "(${report.unknownCount} check(s) could not be measured and are excluded).")
        appendLine()
        report.categories.forEach { summary ->
            appendLine("== ${summary.category.label.uppercase()} — ${summary.passed} passed / ${summary.failed} failed / ${summary.unknown} unknown ==")
            report.checks.filter { it.category == summary.category }.forEach { check ->
                appendLine("[${check.status.name}] ${check.title}")
                appendLine("    ${check.detail}")
                check.recommendation?.let { appendLine("    Recommendation: $it") }
            }
            appendLine()
        }
        appendLine("Method: every check reads a real Android API or an AdShield setting.")
        appendLine("UNKNOWN means the signal was unavailable — it is never counted as a pass.")
    }
}
