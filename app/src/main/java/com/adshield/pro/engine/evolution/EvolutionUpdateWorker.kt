package com.adshield.pro.engine.evolution

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.adshield.pro.engine.security.AuditResourceSampler
import com.adshield.pro.engine.security.EvolutionWorkPolicy
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/** Optional data staging only. Does not alter detectors or disable essential protection. */
class EvolutionUpdateWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        if (!EvolutionPublisherConfiguration.enabled(applicationContext)) return@withContext Result.success()
        val stager = EvolutionPublisherConfiguration.createStager(applicationContext)
            ?: return@withContext Result.failure()
        try {
            val sampler = AuditResourceSampler(applicationContext)
            sampler.sample()
            delay(200)
            val manager = applicationContext.getSystemService(ConnectivityManager::class.java)
            val capabilities = manager?.getNetworkCapabilities(manager.activeNetwork)
            val conditions = sampler.sample().copy(
                networkValidated = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                networkMetered = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)?.not()
            )
            if (!EvolutionWorkPolicy.plan(conditions).optionalResearchSyncAllowed) {
                return@withContext if (runAttemptCount < 3) Result.retry() else Result.failure()
            }
            try {
                stager.fetchAndStage {
                    !isStopped && EvolutionPublisherConfiguration.enabled(applicationContext)
                }
            } catch (_: EvolutionUpdateStager.AlreadyCurrent) { /* Valid unchanged package. */ }
            if (isStopped || !EvolutionPublisherConfiguration.enabled(applicationContext)) return@withContext Result.success()
            stager.activateLatest()
            EvolutionPublisherConfiguration.recordStatus(applicationContext, "Verified data checked; advisory lookup ready if unexpired")
            Result.success()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: IOException) {
            EvolutionPublisherConfiguration.recordStatus(applicationContext, "Update unavailable; prior data retained subject to expiry")
            if (runAttemptCount < 3) Result.retry() else Result.failure()
        } catch (_: Exception) {
            EvolutionPublisherConfiguration.recordStatus(applicationContext, "Update rejected or invalid; prior data retained subject to expiry")
            Result.failure()
        }
    }

    companion object {
        private const val NAME = "adshield_reviewed_evolution_staging"
        fun checkNow(context: Context) {
            if (!EvolutionPublisherConfiguration.enabled(context) ||
                EvolutionPublisherConfiguration.createStager(context) == null) return
            val constraints = Constraints.Builder().setRequiredNetworkType(NetworkType.UNMETERED)
                .setRequiresBatteryNotLow(true).setRequiresStorageNotLow(true).build()
            val request = androidx.work.OneTimeWorkRequestBuilder<EvolutionUpdateWorker>()
                .setConstraints(constraints)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES).build()
            WorkManager.getInstance(context).enqueueUniqueWork("$NAME-now", androidx.work.ExistingWorkPolicy.KEEP, request)
        }

        fun reconcile(context: Context) {
            val manager = WorkManager.getInstance(context)
            if (!EvolutionPublisherConfiguration.enabled(context) ||
                EvolutionPublisherConfiguration.createStager(context) == null) {
                manager.cancelUniqueWork(NAME)
                manager.cancelUniqueWork("$NAME-now")
                return
            }
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.UNMETERED)
                .setRequiresBatteryNotLow(true)
                .setRequiresStorageNotLow(true)
                .build()
            val request = PeriodicWorkRequestBuilder<EvolutionUpdateWorker>(24, TimeUnit.HOURS)
                .setConstraints(constraints)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
                .build()
            manager.enqueueUniquePeriodicWork(NAME, ExistingPeriodicWorkPolicy.KEEP, request)
        }
    }
}
