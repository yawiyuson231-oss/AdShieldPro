package com.adshield.pro.worker

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.hilt.work.HiltWorker
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.adshield.pro.MainActivity
import com.adshield.pro.R
import com.adshield.pro.data.local.preferences.ScanJournalStore
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.engine.security.AppRiskAuditor
import com.adshield.pro.engine.security.QuarantineManager
import com.adshield.pro.engine.security.ScanKind
import com.adshield.pro.engine.security.ScanSource
import com.adshield.pro.engine.security.SecurityEngine
import com.adshield.pro.engine.security.SecurityLevel
import com.adshield.pro.engine.security.SecurityScanRecord
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit

/**
 * Periodic on-device security scan.
 *
 * What it actually does, and nothing more:
 *  1. Audits every installed application's permission stack and installer provenance.
 *  2. Re-verifies the SHA-256 of anything already in quarantine (tamper detection).
 *  3. Persists real records to the scan journal and notifies only when something was flagged.
 *
 * What it deliberately does not do: it cannot read other apps' private files or scan shared
 * storage the user has not granted. Those areas are reported as not examined rather than
 * silently counted as clean.
 */
@HiltWorker
class ScheduledScanWorker @AssistedInject constructor(
    @Assisted private val appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val securityEngine: SecurityEngine,
    private val journalStore: ScanJournalStore,
    private val quarantineManager: QuarantineManager,
    private val preferencesRepository: UserPreferencesRepository
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val settings = preferencesRepository.getSettingsSnapshot()
        if (!settings.scheduledScanEnabled) return Result.success()

        return try {
            val startedAt = System.currentTimeMillis()
            val records = mutableListOf<SecurityScanRecord>()

            // 1. Installed-application audit (real PackageManager evidence).
            val audits = securityEngine.auditInstalledApps()
            val flagged = audits.filter {
                it.riskLevel == AppRiskAuditor.RiskLevel.HIGH || it.riskLevel == AppRiskAuditor.RiskLevel.MEDIUM
            }
            val finishedAt = System.currentTimeMillis()

            flagged.forEach { audit ->
                records += SecurityScanRecord(
                    id = 0L, // assigned by the journal so ids stay unique
                    kind = ScanKind.APP_AUDIT,
                    target = "${audit.profile.appName} (${audit.profile.packageName})",
                    threatLevel = if (audit.riskLevel == AppRiskAuditor.RiskLevel.HIGH) {
                        SecurityLevel.DANGEROUS
                    } else {
                        SecurityLevel.SUSPICIOUS
                    },
                    riskScore = audit.riskScore,
                    threatName = audit.findings.firstOrNull(),
                    findings = audit.findings,
                    recommendation = "Review this app's permissions and installer source in Security → Apps.",
                    timestampEpochMs = finishedAt,
                    scanSource = ScanSource.SCHEDULED,
                    durationMs = (finishedAt - startedAt).coerceAtLeast(0L)
                )
            }

            // A scan that found nothing still produces a record, so history proves it ran.
            records += SecurityScanRecord(
                id = 0L,
                kind = ScanKind.APP_AUDIT,
                target = "Scheduled device audit — ${audits.size} installed app(s) examined",
                threatLevel = if (flagged.isEmpty()) SecurityLevel.CLEAN else SecurityLevel.SUSPICIOUS,
                riskScore = flagged.maxOfOrNull { it.riskScore } ?: 0,
                threatName = null,
                findings = buildList {
                    add("${audits.size} installed application(s) audited on this device.")
                    add("${flagged.size} app(s) matched elevated permission or provenance indicators.")
                    add("Shared storage and other apps' private files were not examined: Android does not grant this app access.")
                },
                recommendation = if (flagged.isEmpty()) {
                    "No elevated-risk application indicators matched. This is not a guarantee that the device is malware-free."
                } else {
                    "Open Security → Apps to review the flagged applications."
                },
                timestampEpochMs = finishedAt,
                scanSource = ScanSource.SCHEDULED,
                durationMs = (finishedAt - startedAt).coerceAtLeast(0L)
            )

            // 2. Quarantine integrity re-check.
            val quarantined = journalStore.quarantineSnapshot()
            quarantined.forEach { item ->
                val intact = quarantineManager.verifyIntegrity(item)
                if (!intact) {
                    records += SecurityScanRecord(
                        id = 0L,
                        kind = ScanKind.FILE,
                        target = "Quarantine: ${item.displayName}",
                        threatLevel = SecurityLevel.SUSPICIOUS,
                        riskScore = 40,
                        threatName = "Quarantined file failed integrity verification",
                        findings = listOf(
                            "Stored SHA-256 no longer matches the recorded digest, or the isolated copy is missing."
                        ),
                        recommendation = "Delete and re-quarantine this item; do not restore it.",
                        timestampEpochMs = System.currentTimeMillis(),
                        scanSource = ScanSource.SCHEDULED
                    )
                }
            }

            journalStore.recordAll(records)

            val dangerousCount = records.count { it.threatLevel == SecurityLevel.DANGEROUS }
            val suspiciousCount = records.count { it.threatLevel == SecurityLevel.SUSPICIOUS }
            if (dangerousCount > 0 || suspiciousCount > 0) {
                postFindingsNotification(dangerousCount, suspiciousCount)
            }
            Result.success()
        } catch (t: Throwable) {
            // Retry on transient failures (PackageManager pressure, IO), never crash the process.
            if (runAttemptCount < 3) Result.retry() else Result.failure()
        }
    }

    private fun postFindingsNotification(dangerous: Int, suspicious: Int) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                appContext,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) return
        }

        val nm = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                SCAN_CHANNEL_ID,
                "Scheduled security scans",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply { description = "Reports findings from the periodic on-device security scan" }
            nm.createNotificationChannel(channel)
        }

        val pendingIntent = PendingIntent.getActivity(
            appContext,
            203,
            Intent(appContext, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val message = buildString {
            append("Scheduled scan finished: ")
            append("$dangerous dangerous, $suspicious suspicious finding(s).")
            append(" Open Security to review.")
        }

        val notification = NotificationCompat.Builder(appContext, SCAN_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification_shield)
            .setContentTitle("AdShield scheduled scan")
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        nm.notify(SCAN_NOTIFICATION_ID, notification)
    }

    companion object {
        private const val WORK_NAME = "adshield_scheduled_security_scan"
        private const val SCAN_CHANNEL_ID = "adshield_scheduled_scan_channel"
        private const val SCAN_NOTIFICATION_ID = 4203

        /** Minimum period WorkManager supports is 15 minutes; the product floor is 12 hours. */
        fun scheduleOrCancel(context: Context, enabled: Boolean, intervalHours: Int) {
            val workManager = WorkManager.getInstance(context)
            if (!enabled) {
                workManager.cancelUniqueWork(WORK_NAME)
                return
            }
            val constraints = Constraints.Builder()
                .setRequiresBatteryNotLow(true)
                .build()
            val request = PeriodicWorkRequestBuilder<ScheduledScanWorker>(
                repeatInterval = intervalHours.coerceIn(12, 168).toLong(),
                repeatIntervalTimeUnit = TimeUnit.HOURS
            ).setConstraints(constraints).build()

            workManager.enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.UPDATE,
                request
            )
        }
    }
}
