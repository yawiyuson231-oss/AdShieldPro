package com.adshield.pro.worker

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.adshield.pro.data.repository.ConnectorRepository
import com.adshield.pro.data.repository.IntelligenceRecorder
import com.adshield.pro.engine.intelligence.IntelligenceEventFactory
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit

/**
 * Background synchronization for the default-enabled public feeds.
 *
 * Constraints are deliberately conservative for ordinary phones: network required, battery not
 * low, WorkManager-owned timing (no wake locks, no exact alarms, no foreground service). The job
 * records its real outcome so the Automation node reflects what actually happened, and a failure
 * is retried with exponential backoff by WorkManager itself.
 */
@HiltWorker
class ConnectorSyncWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val repository: ConnectorRepository,
    private val recorder: IntelligenceRecorder
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val startedAt = System.currentTimeMillis()
        return try {
            val synced = repository.syncDueFeeds()
            val pruned = repository.prune()
            val stored = repository.totalIndicators()
            recorder.emit(
                IntelligenceEventFactory.automationJob(
                    jobLabel = "Feed sync",
                    success = true,
                    detail = "$synced feed(s) refreshed · $stored indicator(s) cached · $pruned expired row(s) pruned",
                    durationMs = System.currentTimeMillis() - startedAt,
                    timestampEpochMs = System.currentTimeMillis()
                )
            )
            Result.success()
        } catch (t: Throwable) {
            runCatching {
                recorder.emit(
                    IntelligenceEventFactory.automationJob(
                        jobLabel = "Feed sync",
                        success = false,
                        detail = t.message ?: t::class.java.simpleName,
                        durationMs = System.currentTimeMillis() - startedAt,
                        timestampEpochMs = System.currentTimeMillis()
                    )
                )
            }
            if (runAttemptCount < MAX_ATTEMPTS) Result.retry() else Result.failure()
        }
    }

    companion object {
        const val UNIQUE_WORK_NAME = "connector-sync"
        private const val MAX_ATTEMPTS = 3

        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true)
                .build()
            val request = PeriodicWorkRequestBuilder<ConnectorSyncWorker>(6, TimeUnit.HOURS)
                .setConstraints(constraints)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 10, TimeUnit.MINUTES)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }
}

/** Daily indicator-cache retention so the local index cannot grow without bound. */
@HiltWorker
class ConnectorRetentionWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val repository: ConnectorRepository
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result = try {
        repository.prune()
        Result.success()
    } catch (t: Throwable) {
        if (runAttemptCount < 2) Result.retry() else Result.failure()
    }

    companion object {
        private const val UNIQUE_WORK_NAME = "connector-retention"

        fun schedule(context: Context) {
            val constraints = Constraints.Builder().setRequiresBatteryNotLow(true).build()
            val request = PeriodicWorkRequestBuilder<ConnectorRetentionWorker>(1, TimeUnit.DAYS)
                .setConstraints(constraints)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }
}
