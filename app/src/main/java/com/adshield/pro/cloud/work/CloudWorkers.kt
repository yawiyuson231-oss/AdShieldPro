package com.adshield.pro.cloud.work

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.hilt.work.HiltWorker
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.ForegroundInfo
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import com.adshield.pro.R
import com.adshield.pro.cloud.backup.DnsBackupManager
import com.adshield.pro.cloud.data.CloudBackupEntity
import com.adshield.pro.cloud.data.CloudDao
import com.adshield.pro.cloud.data.CloudResult
import com.adshield.pro.cloud.data.CloudTransferEntity
import com.adshield.pro.cloud.engine.CloudDownloadEngine
import com.adshield.pro.cloud.engine.CloudUploadEngine
import com.adshield.pro.cloud.engine.TransferControl
import com.adshield.pro.cloud.engine.TransferInterruptedException
import com.adshield.pro.cloud.engine.TransferProgress
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject

/** Live transfer controls, so the UI can pause/cancel a running worker instantly. */
object TransferRegistry {
    private val controls = java.util.concurrent.ConcurrentHashMap<String, TransferControl>()

    fun controlFor(transferId: String): TransferControl =
        controls.getOrPut(transferId) { TransferControl() }

    fun peek(transferId: String): TransferControl? = controls[transferId]

    fun forget(transferId: String) {
        controls.remove(transferId)
    }

    fun reset() {
        controls.values.forEach { it.resume() }
    }
}

private const val CHANNEL_ID = "adshield_cloud_transfers"
private const val NOTIFICATION_ID = 7421

private fun ensureChannel(context: Context) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
    val manager = context.getSystemService(NotificationManager::class.java) ?: return
    if (manager.getNotificationChannel(CHANNEL_ID) != null) return
    val channel = NotificationChannel(
        CHANNEL_ID,
        "Cloud transfers",
        NotificationManager.IMPORTANCE_LOW
    ).apply {
        description = "Background uploads and downloads for CyberShield Cloud"
        setShowBadge(false)
    }
    manager.createNotificationChannel(channel)
}

private fun foregroundInfo(context: Context, title: String, progress: Int, indeterminate: Boolean): ForegroundInfo {
    ensureChannel(context)
    val notification = NotificationCompat.Builder(context, CHANNEL_ID)
        .setContentTitle(title)
        .setSmallIcon(R.drawable.ic_adshield_mark)
        .setOngoing(true)
        .setOnlyAlertOnce(true)
        .setProgress(100, progress.coerceIn(0, 100), indeterminate)
        .build()
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        ForegroundInfo(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
    } else {
        ForegroundInfo(NOTIFICATION_ID, notification)
    }
}

/**
 * Background upload worker.
 *
 * Uses WorkManager (with backoff + network constraints) so uploads survive screen-off and
 * process death. Progress is persisted in Room after every ~1% so the dashboard always shows
 * real numbers, and pause/resume is driven by [TransferRegistry] + the server's part ledger.
 */
@HiltWorker
class CloudUploadWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val dao: CloudDao,
    private val uploadEngine: CloudUploadEngine
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val transferId = inputData.getString(KEY_TRANSFER_ID) ?: return Result.failure()
        val transfer = dao.transfer(transferId) ?: return Result.failure()
        val uri = transfer.localUri?.let(Uri::parse) ?: return Result.failure()
        val control = TransferRegistry.controlFor(transferId)
        val startedAt = System.currentTimeMillis()

        dao.updateTransferStatus(transferId, "running", null, startedAt)
        setForeground(foregroundInfo(applicationContext, "Uploading ${transfer.fileName}", 0, true))

        var lastPersisted = -1L
        return try {
            val result = uploadEngine.upload(
                uri = uri,
                name = transfer.fileName,
                mime = transfer.mime,
                parentId = transfer.parentId,
                encrypted = transfer.encrypted,
                control = control,
                onSession = { session ->
                    // Persist the server session so a restart can resume the same upload.
                    kotlinx.coroutines.runBlocking {
                        dao.saveUploadSession(
                            transferId,
                            session.uploadId,
                            session.partsTotal,
                            session.partSize,
                            System.currentTimeMillis()
                        )
                    }
                },
                onProgress = { progress ->
                    if (progress.bytesTransferred - lastPersisted >= maxOf(progress.totalBytes / 100, 128 * 1024)) {
                        lastPersisted = progress.bytesTransferred
                        kotlinx.coroutines.runBlocking {
                            dao.updateTransferProgress(
                                transferId,
                                progress.bytesTransferred,
                                "running",
                                null,
                                System.currentTimeMillis()
                            )
                        }
                        runCatching {
                            setProgress(workDataOf("progress" to progress.fraction))
                            setForeground(
                                foregroundInfo(
                                    applicationContext,
                                    "Uploading ${transfer.fileName}",
                                    (progress.fraction * 100).toInt(),
                                    false
                                )
                            )
                        }
                    }
                }
            )
            when (result) {
                is CloudResult.Success -> {
                    dao.markCompleted(
                        transferId,
                        result.value.nodeId ?: result.value.backupId,
                        result.value.sha256,
                        System.currentTimeMillis()
                    )
                    TransferRegistry.forget(transferId)
                    Result.success(workDataOf("nodeId" to (result.value.nodeId ?: "")))
                }
                is CloudResult.Failure -> {
                    dao.updateTransferStatus(transferId, "failed", result.message, System.currentTimeMillis())
                    TransferRegistry.forget(transferId)
                    if (result.retryable && runAttemptCount < 5) Result.retry() else Result.failure()
                }
                else -> {
                    dao.updateTransferStatus(
                        transferId,
                        "failed",
                        "Cloud account is not available",
                        System.currentTimeMillis()
                    )
                    Result.failure()
                }
            }
        } catch (interrupted: TransferInterruptedException) {
            dao.updateTransferStatus(
                transferId,
                if (control.cancelled) "cancelled" else "paused",
                interrupted.message,
                System.currentTimeMillis()
            )
            Result.success()
        } catch (error: Throwable) {
            dao.updateTransferStatus(transferId, "failed", error.message, System.currentTimeMillis())
            if (runAttemptCount < 5) Result.retry() else Result.failure()
        }
    }

    companion object {
        const val KEY_TRANSFER_ID = "transfer_id"
        private const val UNIQUE_PREFIX = "adshield_cloud_upload_"

        fun enqueue(
            context: Context,
            transferId: String,
            wifiOnly: Boolean,
            replace: Boolean = false
        ) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(if (wifiOnly) NetworkType.UNMETERED else NetworkType.CONNECTED)
                .build()
            val request = OneTimeWorkRequestBuilder<CloudUploadWorker>()
                .setInputData(Data.Builder().putString(KEY_TRANSFER_ID, transferId).build())
                .setConstraints(constraints)
                .setBackoffCriteria(androidx.work.BackoffPolicy.EXPONENTIAL, 30, java.util.concurrent.TimeUnit.SECONDS)
                .addTag(UNIQUE_PREFIX + transferId)
                .build()
            WorkManager.getInstance(context).enqueueUniqueWork(
                UNIQUE_PREFIX + transferId,
                if (replace) ExistingWorkPolicy.REPLACE else ExistingWorkPolicy.KEEP,
                request
            )
        }

        fun cancel(context: Context, transferId: String) {
            WorkManager.getInstance(context).cancelUniqueWork(UNIQUE_PREFIX + transferId)
        }
    }
}

/** Background download worker (progress + integrity verification). */
@HiltWorker
class CloudDownloadWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val dao: CloudDao,
    private val downloadEngine: CloudDownloadEngine
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val transferId = inputData.getString(CloudUploadWorker.KEY_TRANSFER_ID) ?: return Result.failure()
        val transfer = dao.transfer(transferId) ?: return Result.failure()
        val ticketUrl = inputData.getString(KEY_TICKET_URL) ?: return Result.failure()
        val control = TransferRegistry.controlFor(transferId)
        dao.updateTransferStatus(transferId, "running", null, System.currentTimeMillis())
        setForeground(foregroundInfo(applicationContext, "Downloading ${transfer.fileName}", 0, true))

        var lastPersisted = -1L
        return try {
            val result = downloadEngine.download(
                ticketUrl = ticketUrl,
                fileName = transfer.fileName,
                expectedSize = transfer.size,
                expectedSha256 = transfer.sha256,
                control = control,
                onProgress = { progress: TransferProgress ->
                    if (progress.bytesTransferred - lastPersisted >= maxOf(progress.totalBytes / 100, 128 * 1024)) {
                        lastPersisted = progress.bytesTransferred
                        kotlinx.coroutines.runBlocking {
                            dao.updateTransferProgress(
                                transferId,
                                progress.bytesTransferred,
                                "running",
                                null,
                                System.currentTimeMillis()
                            )
                        }
                        runCatching {
                            setForeground(
                                foregroundInfo(
                                    applicationContext,
                                    "Downloading ${transfer.fileName}",
                                    (progress.fraction * 100).toInt(),
                                    false
                                )
                            )
                        }
                    }
                }
            )
            when (result) {
                is CloudResult.Success -> {
                    dao.saveDownloadedPath(transferId, result.value.absolutePath, System.currentTimeMillis())
                    TransferRegistry.forget(transferId)
                    Result.success(workDataOf("path" to result.value.absolutePath))
                }
                is CloudResult.Failure -> {
                    dao.updateTransferStatus(transferId, "failed", result.message, System.currentTimeMillis())
                    if (result.retryable && runAttemptCount < 3) Result.retry() else Result.failure()
                }
                else -> {
                    dao.updateTransferStatus(transferId, "failed", "Cloud unavailable", System.currentTimeMillis())
                    Result.failure()
                }
            }
        } catch (interrupted: TransferInterruptedException) {
            dao.updateTransferStatus(
                transferId,
                if (control.cancelled) "cancelled" else "paused",
                interrupted.message,
                System.currentTimeMillis()
            )
            Result.success()
        } catch (error: Throwable) {
            dao.updateTransferStatus(transferId, "failed", error.message, System.currentTimeMillis())
            Result.retry()
        }
    }

    companion object {
        const val KEY_TICKET_URL = "ticket_url"
        private const val UNIQUE_PREFIX = "adshield_cloud_download_"

        fun enqueue(context: Context, transferId: String, ticketUrl: String) {
            val request = OneTimeWorkRequestBuilder<CloudDownloadWorker>()
                .setInputData(
                    Data.Builder()
                        .putString(CloudUploadWorker.KEY_TRANSFER_ID, transferId)
                        .putString(KEY_TICKET_URL, ticketUrl)
                        .build()
                )
                .setConstraints(
                    Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
                )
                .addTag(UNIQUE_PREFIX + transferId)
                .build()
            WorkManager.getInstance(context).enqueueUniqueWork(
                UNIQUE_PREFIX + transferId,
                ExistingWorkPolicy.REPLACE,
                request
            )
        }
    }
}

/** Nightly/periodic encrypted DNS + configuration backup. */
@HiltWorker
class CloudAutoBackupWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val dao: CloudDao,
    private val backupManager: DnsBackupManager
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val kind = inputData.getString(KEY_KIND) ?: "full"
        val label = inputData.getString(KEY_LABEL) ?: "Automatic backup"
        val control = TransferRegistry.controlFor("backup-$kind")
        return try {
            when (val result = backupManager.uploadBackup(kind, label, null, control) { }) {
                is CloudResult.Success -> {
                    dao.upsertBackups(
                        listOf(
                            CloudBackupEntity(
                                id = result.value.id,
                                kind = result.value.kind,
                                label = result.value.label,
                                size = result.value.size,
                                sha256 = result.value.sha256,
                                encrypted = true,
                                integrityOk = true,
                                createdAt = result.value.createdAt,
                                verifiedAt = null,
                                restoredAt = null,
                                syncedAt = System.currentTimeMillis()
                            )
                        )
                    )
                    Result.success()
                }
                is CloudResult.Failure -> if (result.retryable) Result.retry() else Result.failure()
                else -> Result.failure()
            }
        } catch (error: Throwable) {
            if (runAttemptCount < 3) Result.retry() else Result.failure()
        } finally {
            TransferRegistry.forget("backup-$kind")
        }
    }

    companion object {
        const val KEY_KIND = "backup_kind"
        const val KEY_LABEL = "backup_label"

        fun enqueuePeriodic(context: Context, intervalHours: Int, kinds: Set<String>) {
            val request = androidx.work.PeriodicWorkRequestBuilder<CloudAutoBackupWorker>(
                intervalHours.toLong().coerceIn(1, 168),
                java.util.concurrent.TimeUnit.HOURS
            )
                .setInputData(
                    Data.Builder()
                        .putString(KEY_KIND, kinds.firstOrNull() ?: "full")
                        .putString(KEY_LABEL, "Scheduled CyberShield backup")
                        .build()
                )
                .setConstraints(
                    Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
                )
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                "adshield_cloud_auto_backup",
                androidx.work.ExistingPeriodicWorkPolicy.UPDATE,
                request
            )
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork("adshield_cloud_auto_backup")
        }
    }
}

/** Helper for enqueueing a one-off manual backup with its own unique name. */
fun enqueueManualBackup(context: Context, kind: String, label: String) {
    val request = OneTimeWorkRequestBuilder<CloudAutoBackupWorker>()
        .setInputData(
            Data.Builder()
                .putString(CloudAutoBackupWorker.KEY_KIND, kind)
                .putString(CloudAutoBackupWorker.KEY_LABEL, label)
                .build()
        )
        .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
        .build()
    WorkManager.getInstance(context).enqueue(request)
}
