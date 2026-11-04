package com.adshield.pro.engine.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.RuleType
import com.adshield.pro.engine.filter.FilterRuleEngine
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AdShield Pro — Security Center orchestrator.
 *
 * Anti-virus + anti-phishing + multi-module system scanning:
 * - WEB/LINK PROTECTION: live threat-intelligence hosts from the on-device filter engine
 *   (honouring user allowlists, exact-only rules, subdomain suffix rules, and wildcards)
 *   plus deep URL static analysis (typosquatting, punycode, credential patterns, dropper structures).
 * - FILE PROTECTION: signature + structural scanning of any accessible file — polyglot
 *   executables, script droppers, macro documents, zip-slip archives, EICAR test standard.
 * - APP PROTECTION: static APK analysis with a real binary-manifest parser plus whole-device
 *   and post-install installed-app audits using permission-stack triage.
 * - COMPLETE SYSTEM SCANNING: 6-module real progress & report engine persisted in [historyStore].
 *
 * 100% on-device. Files and links never leave the phone.
 */
@Singleton
class SecurityEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val filterRuleEngine: FilterRuleEngine
) {

    val urlScanner: UrlThreatScanner = UrlThreatScanner(
        object : UrlThreatScanner.KnownThreatHostLookup {
            override fun isKnownThreatHost(host: String): Boolean = isHostOnActiveThreatBlocklist(host)
            override fun evaluateFullHost(host: String): Boolean = isHostOnActiveThreatBlocklist(host)
        }
    )

    val systemScanner = SystemScannerEngine()

    val historyStore: SecurityScanHistoryStore by lazy {
        SecurityScanHistoryStore(File(context.filesDir, "security_scan_history.json"))
    }

    private val fileScanner = FileThreatScanner()
    private val apkAnalyzer = ApkAnalyzer()
    private val appAuditor = AppRiskAuditor()

    // --- Web / link protection -------------------------------------------------

    /**
     * True when [host] is blocked by an active MALWARE-category rule (exact, subdomain, or wildcard)
     * and NOT exempted by a user allow rule or the built-in safety allowlist.
     */
    fun isHostOnActiveThreatBlocklist(host: String): Boolean {
        return evaluateThreatBlocklistSnapshot(host, filterRuleEngine.getCurrentSnapshot())
    }

    fun scanUrl(rawUrl: String): UrlThreatScanner.UrlVerdict = urlScanner.scan(rawUrl)

    // --- File protection -------------------------------------------------------

    suspend fun scanFile(file: File): SecurityScanRecord = withContext(Dispatchers.IO) {
        val fileVerdict = fileScanner.scanFile(file)
        val apkReport = if (file.name.lowercase().let { it.endsWith(".apk") || it.endsWith(".apks") || it.endsWith(".xapk") }) {
            runCatching { apkAnalyzer.analyzeApk(file) }.getOrNull()
        } else null

        val combinedScore = maxOf(fileVerdict.riskScore, apkReport?.riskScore ?: 0)
        val combinedFindings = (fileVerdict.findings + (apkReport?.riskReasons ?: emptyList())).distinct()
        val threatName = apkReport?.let { r ->
            if (r.threatLevel == ApkAnalyzer.ThreatLevel.DANGEROUS || r.threatLevel == ApkAnalyzer.ThreatLevel.SUSPICIOUS) {
                "Risky APK: ${r.packageName ?: file.name} (score ${r.riskScore})"
            } else fileVerdict.threatName
        } ?: fileVerdict.threatName

        val level = when {
            fileVerdict.threatLevel == FileThreatScanner.ThreatLevel.DANGEROUS ||
                apkReport?.threatLevel == ApkAnalyzer.ThreatLevel.DANGEROUS -> SecurityLevel.DANGEROUS
            fileVerdict.threatLevel == FileThreatScanner.ThreatLevel.SUSPICIOUS ||
                apkReport?.threatLevel == ApkAnalyzer.ThreatLevel.SUSPICIOUS -> SecurityLevel.SUSPICIOUS
            else -> SecurityLevel.CLEAN
        }

        SecurityScanRecord(
            id = System.currentTimeMillis(),
            kind = if (apkReport != null) ScanKind.APK else ScanKind.FILE,
            target = file.absolutePath,
            threatLevel = level,
            riskScore = combinedScore,
            threatName = threatName,
            findings = combinedFindings,
            recommendation = if (apkReport != null && level != SecurityLevel.CLEAN) {
                "Do not install this APK. ${apkReport.riskReasons.firstOrNull() ?: "Risk indicators found."}"
            } else fileVerdict.recommendation,
            timestampEpochMs = System.currentTimeMillis()
        )
    }

    suspend fun scanUriContent(uri: Uri, displayName: String): SecurityScanRecord? = withContext(Dispatchers.IO) {
        val temp = File(context.cacheDir, "sec_scan_${System.currentTimeMillis()}_${displayName.take(60).replace(Regex("[^A-Za-z0-9._-]"), "_")}")
        try {
            val stream = context.contentResolver.openInputStream(uri)
            if (stream == null) {
                temp.delete()
                return@withContext null
            }
            stream.use { input ->
                temp.outputStream().use { output -> input.copyTo(output, 1 shl 16) }
            }
        } catch (t: Throwable) {
            temp.delete()
            return@withContext null
        }
        try {
            val record = scanFile(temp)
            record.copy(target = displayName)
        } finally {
            temp.delete()
        }
    }

    // --- Installed app protection ---------------------------------------------

    suspend fun auditInstalledApps(): List<AppRiskAuditor.AppRiskAudit> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val apps = runCatching { pm.getInstalledApplications(PackageManager.GET_PERMISSIONS) }
            .getOrDefault(emptyList())

        apps.mapNotNull { appInfo ->
            buildAppProfile(pm, appInfo)?.let { appAuditor.audit(it) }
        }.sortedWith(
            compareByDescending<AppRiskAuditor.AppRiskAudit> { it.riskScore }
                .thenBy { it.profile.appName.lowercase() }
        )
    }

    suspend fun auditSinglePackage(packageName: String): AppRiskAuditor.AppRiskAudit? = withContext(Dispatchers.IO) {
        if (packageName.isBlank() || packageName == context.packageName) return@withContext null
        val pm = context.packageManager
        val appInfo = runCatching { pm.getApplicationInfo(packageName, PackageManager.GET_PERMISSIONS) }.getOrNull()
            ?: return@withContext null
        val profile = buildAppProfile(pm, appInfo) ?: return@withContext null
        appAuditor.audit(profile)
    }

    private fun buildAppProfile(pm: PackageManager, appInfo: ApplicationInfo): AppRiskAuditor.AppSecurityProfile? {
        val requested: List<String> = runCatching {
            pm.getPackageInfo(appInfo.packageName, PackageManager.GET_PERMISSIONS)
                .requestedPermissions?.toList()
        }.getOrNull() ?: emptyList()
        val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            runCatching {
                pm.getInstallSourceInfo(appInfo.packageName).installingPackageName
            }.getOrNull()
        } else {
            @Suppress("DEPRECATION")
            runCatching { pm.getInstallerPackageName(appInfo.packageName) }.getOrNull()
        }
        val label = runCatching { pm.getApplicationLabel(appInfo).toString() }.getOrDefault(appInfo.packageName)
        val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val isUpdated = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

        return AppRiskAuditor.AppSecurityProfile(
            packageName = appInfo.packageName,
            appName = label,
            versionName = runCatching { pm.getPackageInfo(appInfo.packageName, 0).versionName }.getOrNull(),
            targetSdkVersion = appInfo.targetSdkVersion,
            requestedPermissions = requested,
            installerPackageName = installer,
            isSystemApp = isSystem,
            isUpdatedSystemApp = isUpdated,
            firstInstallTimeEpochMs = runCatching {
                pm.getPackageInfo(appInfo.packageName, 0).firstInstallTime
            }.getOrDefault(0L)
        )
    }

    // --- Security posture summary ----------------------------------------------

    fun activeThreatSignatureCount(): Int =
        countMalwareSignatures(filterRuleEngine.getCurrentSnapshot())

    companion object {
        fun evaluateThreatBlocklistSnapshot(
            rawHost: String,
            snap: FilterRuleEngine.FilterSnapshot
        ): Boolean {
            val normalized = rawHost.trim().lowercase().trimEnd('.')
            if (normalized.isEmpty()) return false

            // 1. User custom exact allow
            if (snap.customAllowExact.containsKey(normalized)) return false

            // Build suffix chain once
            val suffixes = ArrayList<String>(6)
            var cursor: String? = normalized
            while (cursor != null) {
                suffixes.add(cursor)
                cursor = if (cursor.contains('.')) cursor.substringAfter('.') else null
            }

            // 2. User custom subdomain allow
            if (suffixes.any { snap.customAllowSubdomain.containsKey(it) }) return false

            // 3. User custom wildcards (Allow wins before Block)
            for (wc in snap.customWildcards) {
                if (wc.regex.matches(normalized)) {
                    if (wc.ruleType == RuleType.ALLOW) return false
                    if (wc.ruleType == RuleType.BLOCK && wc.category == RuleCategory.MALWARE) return true
                }
            }

            // 4. Built-in safety allowlist
            if (suffixes.any { snap.builtInAllowSubdomains.contains(it) }) return false

            if (!snap.protectionMode.activeCategories.contains(RuleCategory.MALWARE)) {
                return false
            }

            // 5. Filter-list exact match (exact normalized host ONLY, never parent suffixes)
            if (snap.filterListExact[normalized]?.category == RuleCategory.MALWARE) {
                return true
            }

            // 6. Filter-list subdomain suffix walk
            for (suffix in suffixes) {
                if (snap.filterListSubdomains[suffix]?.category == RuleCategory.MALWARE) {
                    return true
                }
            }

            // 7. Filter-list wildcard match
            for (wc in snap.filterListWildcards) {
                if (wc.category == RuleCategory.MALWARE && wc.regex.matches(normalized)) {
                    return true
                }
            }

            return false
        }

        fun countMalwareSignatures(snap: FilterRuleEngine.FilterSnapshot): Int {
            val subCount = snap.filterListSubdomains.values.count { it.category == RuleCategory.MALWARE }
            val exactCount = snap.filterListExact.values.count { it.category == RuleCategory.MALWARE }
            val wildcardCount = snap.filterListWildcards.count { it.category == RuleCategory.MALWARE }
            return subCount + exactCount + wildcardCount
        }

        fun buildSecurityPosture(
            highRiskApps: Int,
            threatSignatures: Int,
            vpnActive: Boolean
        ): SecurityPosture {
            var score = 100
            if (!vpnActive) score -= 40
            score -= (highRiskApps * 12).coerceAtMost(36)
            if (threatSignatures < 1000) score -= 15
            return SecurityPosture(
                protectionScore = score.coerceIn(0, 100),
                highRiskApps = highRiskApps,
                threatSignatures = threatSignatures,
                webProtectionActive = vpnActive && threatSignatures > 0
            )
        }
    }
}

@Serializable
enum class SecurityLevel { CLEAN, SUSPICIOUS, DANGEROUS }

@Serializable
enum class ScanKind { FILE, URL, APK, APP_AUDIT, SYSTEM }

@Serializable
data class SecurityScanRecord(
    val id: Long,
    val kind: ScanKind,
    val target: String,
    val threatLevel: SecurityLevel,
    val riskScore: Int,
    val threatName: String?,
    val findings: List<String>,
    val recommendation: String,
    val timestampEpochMs: Long
)

data class SecurityPosture(
    val protectionScore: Int,
    val highRiskApps: Int,
    val threatSignatures: Int,
    val webProtectionActive: Boolean
)
