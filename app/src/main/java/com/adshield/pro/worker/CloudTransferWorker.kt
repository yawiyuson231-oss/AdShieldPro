package com.adshield.pro.worker

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.adshield.pro.cloud.CloudTransferEngine
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject

/**
 * Background executor for queued cloud uploads/downloads. Runs with network required, retries
 * on transient failure, and never touches the DNS path — the blocker works fully offline.
 */
@HiltWorker
class CloudTransferWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val engine: CloudTransferEngine
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val transferId = inputData.getString(KEY_TRANSFER_ID) ?: return Result.failure()
        return when (engine.runTransfer(transferId)) {
            is Result.Success -> Result.success()
            else -> Result.retry()
        }
    }

    companion object {
        const val KEY_TRANSFER_ID = "transfer_id"
    }
}
