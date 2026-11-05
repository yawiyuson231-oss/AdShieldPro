package com.adshield.pro.worker

import android.content.Context
import android.net.Uri
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import com.adshield.pro.data.cloud.CloudUploadEngine
import com.adshield.pro.data.cloud.UploadRequest
import com.adshield.pro.data.cloud.UploadState
import com.adshield.pro.data.cloud.UriUploadSource
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject

/**
 * Keeps an upload alive after the screen is closed.
 *
 * The worker does no uploading logic of its own: it re-opens the file, re-attaches it to the
 * persisted job and lets the engine resume from the parts the API says are already stored.
 */
@HiltWorker
class CloudUploadWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val engine: CloudUploadEngine
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        engine.restore()
        val jobId = inputData.getString(KEY_JOB_ID) ?: return Result.failure()
        val uriString = inputData.getString(KEY_URI) ?: return Result.failure()
        val name = inputData.getString(KEY_NAME) ?: return Result.failure()
        val mime = inputData.getString(KEY_MIME) ?: "application/octet-stream"
        val size = inputData.getLong(KEY_SIZE, -1L)
        val parent = inputData.getString(KEY_PARENT)
        if (size <= 0L) return Result.failure()

        val source = UriUploadSource(applicationContext.contentResolver, Uri.parse(uriString), size)
        val existing = engine.snapshot(jobId)
        val request = UploadRequest(
            id = jobId,
            source = source,
            name = existing?.name ?: name,
            contentType = existing?.contentType ?: mime,
            parentId = existing?.parentId ?: parent
        )
        val result = engine.run(request)
        return when (result.state) {
            UploadState.COMPLETED -> Result.success(workDataOf(KEY_JOB_ID to jobId))
            UploadState.PAUSED, UploadState.CANCELLED -> Result.success()
            UploadState.FAILED -> if (runAttemptCount >= MAX_ATTEMPTS) Result.failure() else Result.retry()
            else -> Result.retry()
        }
    }

    companion object {
        const val KEY_JOB_ID = "job_id"
        const val KEY_URI = "uri"
        const val KEY_NAME = "name"
        const val KEY_MIME = "mime"
        const val KEY_SIZE = "size"
        const val KEY_PARENT = "parent_id"
        private const val MAX_ATTEMPTS = 3
    }
}
