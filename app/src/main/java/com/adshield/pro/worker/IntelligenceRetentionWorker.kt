package com.adshield.pro.worker

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.adshield.pro.data.repository.IntelligenceLimits
import com.adshield.pro.data.repository.IntelligenceRecorder
import com.adshield.pro.data.repository.IntelligenceRepository
import com.adshield.pro.engine.intelligence.IntelligenceEventFactory
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit

/**
 * Keeps the intelligence event store bounded even when the app is never opened.
 *
 * WorkManager is the correct owner for this job: it is deferrable, needs no network, respects
 * Doze, and Android can throttle it without affecting DNS protection (which runs in the VPN
 * service). The job records its own real outcome once, so the Automation Core node shows that
 * retention really ran instead of pretending automation is active.
 */
@HiltWorker
class IntelligenceRetentionWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val repository: IntelligenceRepository,
    private val recorder: IntelligenceRecorder
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val startedAt = System.currentTimeMillis()
        return try {
            val removed = repository.prune(startedAt)
            recorder.emit(
                IntelligenceEventFactory.automationJob(
                    jobLabel = "Event retention",
                    success = true,
                    detail = "$removed expired event(s) removed · cap ${IntelligenceLimits.MAX_STORED_EVENTS} rows / " +
                        "${IntelligenceLimits.RETENTION_DAYS} days",
                    durationMs = System.currentTimeMillis() - startedAt,
                    timestampEpochMs = System.currentTimeMillis()
                )
            )
            Result.success()
        } catch (t: Throwable) {
            recoreFailure(startedAt, t)
            if (runAttemptCount < MAX_ATTEMPTS) Result.retry() else Result.failure()
        }
    }

    private suspend fun recoreFailure(startedAt: Long, throwable: Throwable) {
        runCatching {
            recorder.emit(
                IntelligenceEventFactory.automationJob(
                    jobLabel = "Event retention",
                    success = false,
                    detail = throwable.message ?: throwable::class.java.simpleName,
                    durationMs = System.currentTimeMillis() - startedAt,
                    timestampEpochMs = System.currentTimeMillis()
                )
            )
        }
    }

    companion object {
        private const val UNIQUE_WORK_NAME = "adshield_intelligence_retention"
        private const val MAX_ATTEMPTS = 3

        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiresBatteryNotLow(true)
                .build()
            val request = PeriodicWorkRequestBuilder<IntelligenceRetentionWorker>(1, TimeUnit.DAYS)
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
