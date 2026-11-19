package com.adshield.pro.worker

import android.content.Context
import android.provider.DocumentsContract
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.adshield.pro.data.local.preferences.ScanJournalStore
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.data.repository.SafFileRepository
import com.adshield.pro.engine.security.ScanSource
import com.adshield.pro.engine.security.SecurityLevel
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit

/**
 * Periodic Background SAF Folder Scanner (`Downloads` / User-Granted Trees).
 *
 * Scans only document trees for which the user explicitly granted a persistent `UriPermission`
 * (`contentResolver.persistedUriPermissions`), persisting flagged records to [ScanJournalStore].
 * Never requests `MANAGE_EXTERNAL_STORAGE` or claims coverage outside granted trees.
 */
@HiltWorker
class SafFolderScanWorker @AssistedInject constructor(
    @Assisted private val appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val safFileRepository: SafFileRepository,
    private val journalStore: ScanJournalStore,
    private val preferencesRepository: UserPreferencesRepository
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val settings = preferencesRepository.getSettingsSnapshot()
        if (!settings.scheduledSafScanEnabled) return Result.success()

        val persistedTrees = appContext.contentResolver.persistedUriPermissions
            .filter { it.isReadPermission && DocumentsContract.isTreeUri(it.uri) }
            .take(4)

        if (persistedTrees.isEmpty()) return Result.success()

        for (perm in persistedTrees) {
            runCatching {
                val rootId = DocumentsContract.getTreeDocumentId(perm.uri)
                val batch = safFileRepository.scanTree(perm.uri, rootId) {}
                val flagged = batch.records.filter {
                    it.threatLevel == SecurityLevel.DANGEROUS || it.threatLevel == SecurityLevel.SUSPICIOUS
                }.map { it.copy(id = 0L, scanSource = ScanSource.SCHEDULED) }
                if (flagged.isNotEmpty()) {
                    journalStore.recordAll(flagged)
                }
            }
        }
        return Result.success()
    }

    companion object {
        const val WORK_NAME = "adshield_scheduled_saf_folder_scan"

        fun applySchedule(context: Context, enabled: Boolean, intervalHours: Int = 12) {
            val wm = WorkManager.getInstance(context)
            if (!enabled) {
                wm.cancelUniqueWork(WORK_NAME)
                return
            }
            val hours = intervalHours.coerceIn(6, 168).toLong()
            val req = PeriodicWorkRequestBuilder<SafFolderScanWorker>(hours, TimeUnit.HOURS).build()
            wm.enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.UPDATE, req)
        }
    }
}
