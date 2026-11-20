package com.adshield.pro.engine.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.data.repository.IntelligenceRecorder
import com.adshield.pro.engine.intelligence.IntelligenceEventFactory
import com.adshield.pro.engine.filter.FilterRuleEngine
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.delay
import kotlinx.coroutines.yield
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AdShield Pro — Security Center orchestrator.
 *
 * Local static security checks over user-selected files, links and Android-visible app metadata:
 * - WEB/LINK PROTECTION: live threat-intelligence hosts from the on-device filter engine
 *   (both the DNS VPN and this scanner read the same updated malware lists) plus deep URL
 *   static analysis (typosquatting, punycode, credential patterns, dropper structures).
 * - FILE PROTECTION: signature + structural scanning of any accessible file — polyglot
 *   executables, script droppers, macro documents, zip-slip archives, EICAR test standard.
 * - APP PROTECTION: static APK analysis with a real binary-manifest parser plus a whole-device
 *   installed-app audit using permission-stack indicators.
 *
 * 100% on-device. Files and links never leave the phone.
 */
@Singleton
class SecurityEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val filterRuleEngine: FilterRuleEngine,
    private val intelligenceRecorder: IntelligenceRecorder
) {

    val urlScanner: UrlThreatScanner = UrlThreatScanner(
        object : UrlThreatScanner.KnownThreatHostLookup {
            override fun isKnownThreatHost(host: String): Boolean = isHostOnActiveThreatBlocklist(host)
        }
    )

    private val fileScanner = FileThreatScanner()
    private val apkAnalyzer = ApkAnalyzer()
    private val appAuditor = AppRiskAuditor()
    private val metadataAuditCache = BoundedAuditCache<AppRiskAuditor.AppSecurityProfile, AppRiskAuditor.AppRiskAudit>()
    private val permissionHistory = PermissionObservationHistory()

    // --- Web / link protection -------------------------------------------------

    /** True when the host (exact or parent) is on any active MALWARE-category list. */
    fun isHostOnActiveThreatBlocklist(host: String): Boolean {
        val snap = filterRuleEngine.getCurrentSnapshot()
        if (snap.protectionMode.activeCategories.contains(RuleCategory.MALWARE)) {
            var suffix: String? = host.lowercase().trimEnd('.')
            while (suffix != null) {
                val entry = snap.filterListSubdomains[suffix] ?: snap.filterListExact[suffix]
                if (entry != null && entry.category == RuleCategory.MALWARE) {
                    return true
                }
                suffix = if (suffix.contains('.')) suffix.substringAfter('.') else null
            }
        }
        return false
    }

    fun scanUrl(rawUrl: String): UrlThreatScanner.UrlVerdict = urlScanner.scan(rawUrl)

    // --- File protection -------------------------------------------------------

    internal data class FileInspection(val record: SecurityScanRecord, val bytes: Long, val limitations: List<String>)

    suspend fun scanFile(file: File): SecurityScanRecord = inspectFile(file).let {
        it.record.copy(findings = it.record.findings + it.limitations)
    }

    internal suspend fun inspectFile(file: File): FileInspection = withContext(Dispatchers.IO) {
        val startedAt = System.currentTimeMillis()
        val checkpoint: () -> Unit = { ensureActive() }
        val fileVerdict = fileScanner.scanFile(file, checkpoint)
        val extension = file.extension.lowercase()
        val apkReport = if (extension == "apk") apkAnalyzer.analyzeApk(file, checkpoint) else null
        val publisherAdvisory = com.adshield.pro.engine.evolution.EvolutionAdvisoryText.evaluate(
            enabled = extension == "apk" && com.adshield.pro.engine.evolution.EvolutionPublisherConfiguration.enabled(context),
            sha256 = fileVerdict.sha256
        ) { hash ->
            val stager = requireNotNull(com.adshield.pro.engine.evolution.EvolutionPublisherConfiguration.createStager(context))
            stager.lookupSha256(hash)
        }
        val limitations = buildList {
            publisherAdvisory.limitation?.let { add(it) }
            addAll(fileVerdict.limitations)
            if (apkReport != null) {
                addAll(apkReport.limitations)
                add("APK signatures were not cryptographically verified.")
            } else if (extension == "apks" || extension == "xapk") {
                add("Checked outer archive metadata only. Split APK contents were not inspected.")
            }
        }

        val combinedScore = maxOf(fileVerdict.riskScore, apkReport?.riskScore ?: 0)
        val combinedFindings = fileVerdict.findings + (apkReport?.riskReasons ?: emptyList()) +
            listOfNotNull(publisherAdvisory.finding)
        val threatName = apkReport?.let { r ->
            if (r.threatLevel == ApkAnalyzer.ThreatLevel.DANGEROUS || r.threatLevel == ApkAnalyzer.ThreatLevel.SUSPICIOUS) {
                "APK risk indicators (score ${r.riskScore})"
            } else fileVerdict.threatName
        } ?: fileVerdict.threatName

        val level = when {
            fileVerdict.threatLevel == FileThreatScanner.ThreatLevel.DANGEROUS ||
                apkReport?.threatLevel == ApkAnalyzer.ThreatLevel.DANGEROUS -> SecurityLevel.DANGEROUS
            fileVerdict.threatLevel == FileThreatScanner.ThreatLevel.SUSPICIOUS ||
                apkReport?.threatLevel == ApkAnalyzer.ThreatLevel.SUSPICIOUS -> SecurityLevel.SUSPICIOUS
            else -> SecurityLevel.CLEAN
        }

        ensureActive()
        val finishedAt = System.currentTimeMillis()
        val record = SecurityScanRecord(
            id = finishedAt,
            kind = ScanKind.FILE,
            target = file.absolutePath,
            threatLevel = level,
            riskScore = combinedScore,
            threatName = threatName,
            findings = combinedFindings,
            recommendation = when {
                apkReport != null && level != SecurityLevel.CLEAN -> "Do not install this APK based on this check. Verify the source and review the indicators."
                level == SecurityLevel.CLEAN && limitations.isNotEmpty() -> "This scan had limits. It cannot confirm that the file is safe."
                else -> fileVerdict.recommendation
            },
            timestampEpochMs = finishedAt,
            durationMs = (finishedAt - startedAt).coerceAtLeast(0L)
        )
        FileInspection(record, fileVerdict.sizeBytes, limitations)
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

    suspend fun auditInstalledApps(
        onProgress: (completed: Int, total: Int, currentTarget: String) -> Unit = { _, _, _ -> }
    ): List<AppRiskAuditor.AppRiskAudit> = auditVisibleApps(onProgress).inspected

    /** Report unavailable metadata separately from inspected apps, including uninstall races. */
    @Suppress("DEPRECATION") // The int flags also work on the minSdk path.
    suspend fun auditVisibleApps(
        onProgress: (processed: Int, total: Int, currentTarget: String) -> Unit = { _, _, _ -> }
    ): AppRiskAuditor.VisibleAudit = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val apps = runCatching { pm.getInstalledApplications(0) }.getOrElse {
            return@withContext AppRiskAuditor.VisibleAudit(0, emptyList())
        }
        val inspected = ArrayList<AppRiskAuditor.AppRiskAudit>(apps.size)
        val resources = AuditResourceSampler(context)
        var pacing = EvolutionWorkPolicy.plan(resources.sample())
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or
            PackageManager.MATCH_DISABLED_COMPONENTS
        apps.forEachIndexed { index, appInfo ->
            ensureActive()
            val packageName = appInfo.packageName
            val info = runCatching { pm.getPackageInfo(packageName, flags) }.getOrNull()
            var label = packageName
            if (info != null) {
                val installer = runCatching {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        pm.getInstallSourceInfo(packageName).installingPackageName
                    } else {
                        pm.getInstallerPackageName(packageName)
                    }
                }.getOrNull()
                label = runCatching { pm.getApplicationLabel(appInfo).toString() }.getOrDefault(packageName)
                val bindings = buildSet {
                    info.services.orEmpty().mapNotNullTo(this) { service ->
                        service.permission?.takeIf { it == "android.permission.BIND_ACCESSIBILITY_SERVICE" ||
                            it == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" }
                    }
                    info.receivers.orEmpty().mapNotNullTo(this) { receiver ->
                        receiver.permission?.takeIf { it == "android.permission.BIND_DEVICE_ADMIN" }
                    }
                }
                val profile = AppRiskAuditor.AppSecurityProfile(
                    packageName = packageName,
                    appName = label,
                    versionName = info.versionName,
                    targetSdkVersion = appInfo.targetSdkVersion,
                    requestedPermissions = info.requestedPermissions?.toList().orEmpty(),
                    installerPackageName = installer,
                    isSystemApp = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                    isUpdatedSystemApp = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0,
                    firstInstallTimeEpochMs = info.firstInstallTime,
                    declaredComponentPermissions = bindings
                )
                // Re-read every permission/binding/source before using the complete profile as
                // an in-memory key. No timestamp-only shortcut can hide permission changes.
                inspected += metadataAuditCache.getOrCompute(profile, pacing.cacheEntries) { appAuditor.audit(profile) }
            }
            ensureActive()
            onProgress(index + 1, apps.size, label)
            if ((index + 1) % pacing.batchSize == 0) {
                yield()
                if (pacing.yieldMillis > 0L) delay(pacing.yieldMillis)
                pacing = EvolutionWorkPolicy.plan(resources.sample())
            }
        }
        ensureActive()
        val permissionChanges = permissionHistory.observe(inspected.map { it.profile })
        if (permissionChanges > 0) {
            intelligenceRecorder.record(IntelligenceEventFactory.privacySettingChanged(
                title = "Declared app permissions changed",
                detail = "$permissionChanges inspected app(s) changed requested permissions or component bindings since an earlier completed audit in this process. Actual permission grants and behavior were not checked.",
                timestampEpochMs = System.currentTimeMillis()
            ))
        }
        val ordered = inspected.sortedWith(compareByDescending<AppRiskAuditor.AppRiskAudit> { it.riskScore }
            .thenBy { it.profile.appName.lowercase() })
        AppRiskAuditor.VisibleAudit(apps.size, ordered)
    }

    // --- Security posture summary ----------------------------------------------

    fun activeThreatSignatureCount(): Int {
        val snap = filterRuleEngine.getCurrentSnapshot()
        return snap.filterListSubdomains.values.count {
            it.category == RuleCategory.MALWARE
        }
    }

    companion object {
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
enum class ScanKind { FILE, URL, APK, APP_AUDIT }

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
    val timestampEpochMs: Long,
    val scanSource: ScanSource = ScanSource.MANUAL,
    val durationMs: Long = 0L,
    /** A user-granted SAF URI, when deletion/quarantine can be offered without broad storage access. */
    val sourceUri: String? = null
)

data class SecurityPosture(
    val protectionScore: Int,
    val highRiskApps: Int,
    val threatSignatures: Int,
    val webProtectionActive: Boolean
)
