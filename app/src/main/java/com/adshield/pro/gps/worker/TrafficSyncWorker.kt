package com.adshield.pro.gps.worker

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.adshield.pro.gps.data.GpsDao
import com.adshield.pro.gps.data.GpsPreferences
import com.adshield.pro.gps.data.TrafficApiClient
import com.adshield.pro.gps.traffic.SpeedObservation
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit

/**
 * AdShield Pro — traffic synchronisation worker.
 *
 * Two jobs, both optional and both no-ops when the user has not opted in:
 *
 *  1. **Upload** the locally queued anonymous speed samples and any pending incident reports.
 *     Runs only on an unmetered-by-choice connection, with exponential backoff, so a flaky network
 *     does not burn battery. Samples are deleted only after the server acknowledges them.
 *  2. **Sync** the community aggregate for the area the user is looking at, so the traffic overlay
 *     can colour roads the device has not driven itself.
 *
 * If no backend is configured, the worker returns success immediately and does nothing at all —
 * this is what guarantees the app never silently depends on a paid traffic API.
 */
@HiltWorker
class TrafficSyncWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val dao: GpsDao,
    private val preferences: GpsPreferences,
    private val client: TrafficApiClient
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val policy = preferences.currentPolicy()
        val enabled = client.isEnabled()
        val backend = client.backendUrl()

        // Nothing to do without a backend: this is the honest default state.
        if (!enabled || backend.isNullOrBlank()) {
            return Result.success()
        }

        return try {
            val token = preferences.reporterToken()
            var uploaded = 0

            if (policy.contributeTraffic) {
                val queued = dao.queuedObservations(limit = 200)
                if (queued.isNotEmpty()) {
                    val observations = queued.map { row ->
                        SpeedObservation(
                            segmentId = row.segmentId,
                            speedKmh = row.speedKmh,
                            timestampMs = row.capturedAtMs,
                            accuracyMeters = row.accuracyMeters,
                            headingDegrees = row.headingDegrees,
                            reporterToken = token,
                            sampleCount = row.sampleCount
                        )
                    }
                    val accepted = client.uploadObservations(token, observations)
                    if (accepted > 0) {
                        // Delete only what the server confirmed; the rest stays queued for the next run.
                        val confirmedIds = queued.take(accepted).map { it.id }
                        dao.markUploaded(confirmedIds)
                        uploaded = accepted
                    } else {
                        dao.bumpAttempts(queued.map { it.id })
                        if (queued.any { it.uploadAttempts >= 5 }) {
                            // Drop samples the backend keeps rejecting rather than retrying forever.
                            val stale = queued.filter { it.uploadAttempts >= 5 }.map { it.id }
                            dao.markUploaded(stale)
                        }
                        return if (runAttemptCount < 3) Result.retry() else Result.success()
                    }
                }
            }

            if (policy.allowIncidentReporting) {
                dao.pendingIncidents().take(10).forEach { incident ->
                    val kind = runCatching {
                        com.adshield.pro.gps.traffic.IncidentKind.valueOf(incident.kind)
                    }.getOrNull() ?: return@forEach
                    val ok = client.submitIncident(
                        token = token,
                        kind = kind,
                        segmentId = incident.segmentId,
                        position = com.adshield.pro.gps.geo.GeoPoint(incident.latitude, incident.longitude),
                        notes = incident.notes
                    )
                    if (ok) dao.setIncidentSyncState(incident.id, "SYNCED")
                }
            }

            dao.deleteObservationsOlderThan(System.currentTimeMillis() - MAX_SAMPLE_AGE_MS)
            dao.purgeExpiredIncidents(System.currentTimeMillis())
            Result.success()
        } catch (t: Throwable) {
            if (runAttemptCount < 3) Result.retry() else Result.failure()
        }
    }

    companion object {
        private const val UPLOAD_WORK = "adshield_traffic_upload"
        private const val MAX_SAMPLE_AGE_MS = 48L * 3600_000L

        /** Enqueued when a new sample is recorded; coalesced by the unique-work name. */
        fun enqueueUpload(context: Context) {
            val request = OneTimeWorkRequestBuilder<TrafficSyncWorker>()
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .setRequiresBatteryNotLow(true)
                        .build()
                )
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(context)
                .enqueueUniqueWork(UPLOAD_WORK, ExistingWorkPolicy.KEEP, request)
        }
    }
}

/**
 * Periodic housekeeping: retention sweep for trip history, expired incidents, stale traffic cache.
 * WorkManager's minimum period is 15 minutes; this runs once a day, which is plenty.
 */
@HiltWorker
class GpsMaintenanceWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val dao: GpsDao,
    private val preferences: GpsPreferences,
    private val tripRecorder: com.adshield.pro.gps.nav.TripRecorder
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val policy = preferences.currentPolicy()
        return try {
            tripRecorder.purgeExpired(policy)
            val now = System.currentTimeMillis()
            dao.purgeExpiredIncidents(now)
            // Segment traffic older than an hour is not shown as a live claim any more.
            dao.deleteStaleSegmentTraffic(now - 3600_000L)
            dao.deleteObservationsOlderThan(now - 48L * 3600_000L)
            dao.deleteHistoryOlderThan(now - 30L * 24L * 3600_000L)
            Result.success()
        } catch (t: Throwable) {
            Result.retry()
        }
    }

    companion object {
        private const val WORK_NAME = "adshield_gps_maintenance"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<GpsMaintenanceWorker>(1, TimeUnit.DAYS)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiresBatteryNotLow(true)
                        .build()
                )
                .build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, request)
        }
    }
}
