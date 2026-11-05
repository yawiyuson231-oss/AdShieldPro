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
import com.adshield.pro.cybershield.data.ThreatIntelRepository
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit

/**
 * Periodic background refresh of the verified external threat-intel cache
 * (Feodo Tracker). Network-constrained, battery-friendly, cancellable from the
 * dashboard. No foreground service is added for this.
 */
@HiltWorker
class ThreatIntelRefreshWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val threatIntelRepository: ThreatIntelRepository
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val ok = threatIntelRepository.refreshAwait(force = true)
        return if (ok) Result.success() else Result.retry()
    }

    companion object {
        private const val UNIQUE_WORK_NAME = "cybershield_threat_intel_refresh"

        fun scheduleOrCancel(context: Context, enabled: Boolean) {
            val workManager = WorkManager.getInstance(context)
            if (!enabled) {
                workManager.cancelUniqueWork(UNIQUE_WORK_NAME)
                return
            }
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true)
                .build()
            val request = PeriodicWorkRequestBuilder<ThreatIntelRefreshWorker>(6, TimeUnit.HOURS)
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
