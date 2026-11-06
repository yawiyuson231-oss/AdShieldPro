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
import com.adshield.pro.data.repository.AdShieldRepository
import com.adshield.pro.data.repository.IntelligenceRecorder
import com.adshield.pro.engine.intelligence.IntelligenceEventFactory
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit

/**
 * Background WorkManager task that periodically updates enabled filter lists
 * and prunes expired local DNS logs according to the user's retention policy.
 */
@HiltWorker
class FilterUpdateWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val repository: AdShieldRepository,
    private val intelligenceRecorder: IntelligenceRecorder
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val startedAt = System.currentTimeMillis()
        repository.enforceLogRetentionPolicy()
        val updateResult = repository.updateAllEnabledFilterLists()
        val duration = System.currentTimeMillis() - startedAt
        return if (updateResult.isSuccess) {
            intelligenceRecorder.emit(
                IntelligenceEventFactory.automationJob(
                    jobLabel = "Filter list sync",
                    success = true,
                    detail = "${updateResult.getOrNull() ?: 0} rule(s) loaded from enabled sources",
                    durationMs = duration,
                    timestampEpochMs = System.currentTimeMillis()
                )
            )
            Result.success()
        } else {
            intelligenceRecorder.emit(
                IntelligenceEventFactory.automationJob(
                    jobLabel = "Filter list sync",
                    success = false,
                    detail = updateResult.exceptionOrNull()?.message ?: "list download failed",
                    durationMs = duration,
                    timestampEpochMs = System.currentTimeMillis()
                )
            )
            Result.retry()
        }
    }

    companion object {
        private const val UNIQUE_WORK_NAME = "adshield_pro_periodic_filter_sync"

        fun scheduleOrCancelPeriodicUpdates(
            context: Context,
            enabled: Boolean,
            intervalHours: Int
        ) {
            val workManager = WorkManager.getInstance(context)
            if (!enabled) {
                workManager.cancelUniqueWork(UNIQUE_WORK_NAME)
                return
            }

            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true)
                .build()

            val request = PeriodicWorkRequestBuilder<FilterUpdateWorker>(
                intervalHours.coerceIn(6, 168).toLong(),
                TimeUnit.HOURS
            )
                .setConstraints(constraints)
                .build()

            workManager.enqueueUniquePeriodicWork(
                UNIQUE_WORK_NAME,
                ExistingPeriodicWorkPolicy.UPDATE,
                request
            )
        }
    }
}
