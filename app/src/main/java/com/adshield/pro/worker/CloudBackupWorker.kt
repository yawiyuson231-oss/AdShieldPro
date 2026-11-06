package com.adshield.pro.worker

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.adshield.pro.data.repository.CloudRepository
import com.adshield.pro.data.repository.IntelligenceRecorder
import com.adshield.pro.engine.intelligence.IntelligenceEventFactory
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit

/**
 * Automatic daily backup of the DNS configuration when the user has enabled it.
 *
 * It only runs when the account is configured and signed in; otherwise it exits without doing
 * anything, so enabling the toggle never produces fake backup entries.
 */
@HiltWorker
class CloudBackupWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val repository: CloudRepository,
    private val intelligenceRecorder: IntelligenceRecorder
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        if (!repository.isConfigured()) return Result.success()
        if (repository.session.value == null) return Result.success()
        if (!repository.autoBackupEnabled()) return Result.success()
        val startedAt = System.currentTimeMillis()
        return try {
            repository.uploadBackup(repository.captureBackup(), LABEL)
            intelligenceRecorder.emit(
                IntelligenceEventFactory.automationJob(
                    jobLabel = "Cloud configuration backup",
                    success = true,
                    detail = "Encrypted configuration backup uploaded",
                    durationMs = System.currentTimeMillis() - startedAt,
                    timestampEpochMs = System.currentTimeMillis()
                )
            )
            Result.success()
        } catch (e: Exception) {
            intelligenceRecorder.emit(
                IntelligenceEventFactory.automationJob(
                    jobLabel = "Cloud configuration backup",
                    success = false,
                    detail = e.message ?: "upload failed",
                    durationMs = System.currentTimeMillis() - startedAt,
                    timestampEpochMs = System.currentTimeMillis()
                )
            )
            if (runAttemptCount >= MAX_ATTEMPTS) Result.failure() else Result.retry()
        }
    }

    companion object {
        private const val UNIQUE_WORK_NAME = "adshield_cloud_auto_backup"
        private const val LABEL = "Automatic backup"
        private const val MAX_ATTEMPTS = 3

        fun scheduleOrCancel(context: Context, enabled: Boolean) {
            val workManager = WorkManager.getInstance(context)
            if (!enabled) {
                workManager.cancelUniqueWork(UNIQUE_WORK_NAME)
                return
            }
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.UNMETERED)
                .setRequiresBatteryNotLow(true)
                .build()
            val request = PeriodicWorkRequestBuilder<CloudBackupWorker>(1, TimeUnit.DAYS)
                .setConstraints(constraints)
                .build()
            workManager.enqueueUniquePeriodicWork(
                UNIQUE_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }
}
