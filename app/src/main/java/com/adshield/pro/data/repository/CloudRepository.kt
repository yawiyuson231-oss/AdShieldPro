package com.adshield.pro.data.repository

import android.content.Context
import android.net.Uri
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.workDataOf
import com.adshield.pro.data.cloud.AccountResponseDto
import com.adshield.pro.data.cloud.AuditEntryDto
import com.adshield.pro.data.cloud.CloudAccountManager
import com.adshield.pro.data.cloud.CloudApi
import com.adshield.pro.data.cloud.CloudBackupManager
import com.adshield.pro.data.cloud.CloudBackupPayload
import com.adshield.pro.data.cloud.CloudEndpoints
import com.adshield.pro.data.cloud.CloudNodeDto
import com.adshield.pro.data.cloud.CloudSession
import com.adshield.pro.data.cloud.CloudSessionStore
import com.adshield.pro.data.cloud.CloudShareDto
import com.adshield.pro.data.cloud.CloudUploadEngine
import com.adshield.pro.data.cloud.CloudVault
import com.adshield.pro.data.cloud.DownloadResponseDto
import com.adshield.pro.data.cloud.DuplicateGroupDto
import com.adshield.pro.data.cloud.HealthDto
import com.adshield.pro.data.cloud.KindCountsDto
import com.adshield.pro.data.cloud.NodeActionResponseDto
import com.adshield.pro.data.cloud.NodeVersionDto
import com.adshield.pro.data.cloud.PublicShareDto
import com.adshield.pro.data.cloud.ReconcileResponseDto
import com.adshield.pro.data.cloud.ShareRowDto
import com.adshield.pro.data.cloud.UploadRequest
import com.adshield.pro.data.cloud.UploadSource
import com.adshield.pro.data.cloud.UriUploadSource
import com.adshield.pro.data.cloud.UploadJob
import com.adshield.pro.data.cloud.UploadState
import com.adshield.pro.engine.security.FileThreatScanner
import com.adshield.pro.worker.CloudUploadWorker
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

data class QuarantineEntry(
    val name: String,
    val threatName: String?,
    val riskScore: Int,
    val findings: List<String>,
    val atEpochMs: Long
)

/**
 * Single entry point for the Cloud UI.
 *
 * Everything here talks to the real API or the real upload engine: there is no local mock path,
 * so a screen cannot show capacity or progress that the backend did not report.
 */
@Singleton
class CloudRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val api: CloudApi,
    private val engine: CloudUploadEngine,
    private val accounts: CloudAccountManager,
    private val backups: CloudBackupManager,
    private val store: CloudSessionStore,
    private val vault: CloudVault
) {
    private val scanner = FileThreatScanner()
    private val mutableQuarantine = MutableStateFlow<List<QuarantineEntry>>(emptyList())

    val session: StateFlow<CloudSession?> = accounts.session
    val jobs: StateFlow<List<UploadJob>> = engine.jobsFlow
    val progress = engine.progressFlow
    val quarantine: StateFlow<List<QuarantineEntry>> = mutableQuarantine.asStateFlow()

    // ------------------------------------------------------------ configuration

    fun endpoints(): CloudEndpoints = store.endpoints()

    fun saveEndpoints(endpoints: CloudEndpoints) = accounts.saveEndpoints(endpoints)

    suspend fun health(): HealthDto = api.health()

    fun isConfigured(): Boolean = store.endpoints().isConfigured

    // ------------------------------------------------------------ account

    suspend fun signUp(email: String, password: String, turnstileToken: String? = null): CloudSession =
        accounts.signUp(email, password, turnstileToken)

    suspend fun signIn(email: String, password: String, turnstileToken: String? = null): CloudSession =
        accounts.signIn(email, password, turnstileToken)

    suspend fun signOut() = accounts.signOut()

    suspend fun resetPassword(email: String) = accounts.resetPassword(email)

    suspend fun verifySession(): Boolean = accounts.verifySession()

    suspend fun account(): AccountResponseDto = api.account()

    suspend fun reconcile(): ReconcileResponseDto = api.reconcile()

    suspend fun audit(): List<AuditEntryDto> = api.audit()

    // ------------------------------------------------------------ files

    suspend fun nodes(
        parentId: String? = null,
        kind: String? = null,
        search: String? = null,
        trashed: Boolean = false
    ): List<CloudNodeDto> = api.nodes(parentId, kind, search, trashed)

    suspend fun kinds(): KindCountsDto = api.kinds()

    suspend fun createFolder(name: String, parentId: String?): CloudNodeDto = api.createFolder(name, parentId)

    suspend fun rename(nodeId: String, name: String): NodeActionResponseDto = api.rename(nodeId, name)

    suspend fun move(nodeId: String, parentId: String?): NodeActionResponseDto = api.move(nodeId, parentId)

    suspend fun copy(nodeId: String): NodeActionResponseDto = api.copy(nodeId)

    suspend fun trash(nodeId: String): NodeActionResponseDto = api.trash(nodeId)

    suspend fun restore(nodeId: String): NodeActionResponseDto = api.restore(nodeId)

    suspend fun purge(nodeId: String): NodeActionResponseDto = api.purge(nodeId)

    suspend fun versions(nodeId: String): List<NodeVersionDto> = api.versions(nodeId)

    suspend fun downloadUrl(nodeId: String): DownloadResponseDto = api.downloadUrl(nodeId)

    suspend fun duplicates(): List<DuplicateGroupDto> = api.duplicates()

    // ------------------------------------------------------------ sharing

    suspend fun createShare(nodeId: String, expiresInSeconds: Long): CloudShareDto =
        api.createShare(nodeId, expiresInSeconds)

    suspend fun shares(): List<ShareRowDto> = api.shares()

    suspend fun revokeShare(shareId: String): Boolean = api.revokeShare(shareId)

    suspend fun shareUrl(token: String): String = "${store.endpoints().apiBaseUrl.trimEnd('/')}/v1/share/$token"

    suspend fun openShare(token: String): PublicShareDto = api.openShare(token)

    // ------------------------------------------------------------ uploads

    suspend fun restoreJobs() = engine.restore()

    fun jobsSnapshot(): List<UploadJob> = engine.jobs()

    /**
     * Scans the file, then hands it to the resumable upload engine.
     *
     * A file the scanner rates DANGEROUS is quarantined locally instead of being uploaded: the
     * entry is kept so the user can see exactly what was refused and why.
     */
    suspend fun enqueueUpload(
        uri: Uri,
        name: String,
        mimeType: String?,
        parentId: String?,
        background: Boolean = false
    ): UploadRequest? {
        val source: UploadSource = UriUploadSource.of(context.contentResolver, uri) ?: return null
        val verdict = scan(uri, name)
        if (verdict.threatLevel == FileThreatScanner.ThreatLevel.DANGEROUS) {
            mutableQuarantine.value = mutableQuarantine.value + QuarantineEntry(
                name = name,
                threatName = verdict.threatName,
                riskScore = verdict.riskScore,
                findings = verdict.findings,
                atEpochMs = System.currentTimeMillis()
            )
            return null
        }
        val request = UploadRequest(
            source = source,
            name = name,
            contentType = mimeType ?: guessMimeType(name),
            parentId = parentId
        )
        if (background) {
            enqueueBackground(request, uri, source.sizeBytes)
        } else {
            engine.launch(request)
        }
        return request
    }

    private fun enqueueBackground(request: UploadRequest, uri: Uri, sizeBytes: Long) {
        val data = workDataOf(
            CloudUploadWorker.KEY_JOB_ID to request.id,
            CloudUploadWorker.KEY_URI to uri.toString(),
            CloudUploadWorker.KEY_NAME to request.name,
            CloudUploadWorker.KEY_MIME to request.contentType,
            CloudUploadWorker.KEY_SIZE to sizeBytes,
            CloudUploadWorker.KEY_PARENT to request.parentId
        )
        val work = OneTimeWorkRequestBuilder<CloudUploadWorker>()
            .setInputData(data)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .setRequiresBatteryNotLow(true)
                    .build()
            )
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(context).enqueue(work)
    }

    fun pauseUpload(jobId: String) = engine.pause(jobId)

    fun resumeUpload(jobId: String) = engine.resume(jobId)

    fun cancelUpload(jobId: String) = engine.cancel(jobId)

    suspend fun forgetUpload(jobId: String) = engine.forget(jobId)

    fun uploadStateOf(jobId: String): UploadState = engine.snapshot(jobId)?.state ?: UploadState.QUEUED

    private suspend fun scan(uri: Uri, name: String): FileThreatScanner.FileVerdict = withContext(Dispatchers.IO) {
        val temp = File(context.cacheDir, "cloud-scan-${System.currentTimeMillis()}-$name")
        try {
            context.contentResolver.openInputStream(uri)?.use { input ->
                temp.outputStream().use { output ->
                    val buffer = ByteArray(256 * 1024)
                    var total = 0L
                    while (total < SCAN_LIMIT_BYTES) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        output.write(buffer, 0, read)
                        total += read
                    }
                }
            }
            scanner.scanFile(temp)
        } finally {
            temp.delete()
        }
    }

    private fun guessMimeType(name: String): String {
        val ext = name.substringAfterLast('.', "").lowercase()
        return MIME_BY_EXTENSION[ext] ?: "application/octet-stream"
    }

    // ------------------------------------------------------------ backups

    suspend fun captureBackup(): CloudBackupPayload = backups.capture()

    suspend fun uploadBackup(payload: CloudBackupPayload, label: String) = backups.upload(payload, label)

    suspend fun listBackups() = api.backups()

    suspend fun verifyBackup(backupId: String): Boolean = backups.verifyStored(backupId)

    suspend fun restoreBackup(backupId: String): CloudBackupManager.RestoreReport {
        val (_, payload) = backups.downloadAndVerify(backupId)
        return backups.apply(payload)
    }

    suspend fun deleteBackup(backupId: String): Boolean = api.deleteBackup(backupId)

    fun autoBackupEnabled(): Boolean = store.autoBackupEnabled()

    fun setAutoBackupEnabled(enabled: Boolean) = store.setAutoBackupEnabled(enabled)

    fun lastAutoBackupEpochMs(): Long = store.lastAutoBackupEpochMs()

    // ------------------------------------------------------------ vault

    fun vaultConfigured(): Boolean = vault.isConfigured()

    fun vaultUnlocked(): Boolean = vault.isUnlocked()

    fun setupVault(passphrase: CharArray): Boolean = vault.setup(passphrase)

    fun unlockVault(passphrase: CharArray): Boolean = vault.unlock(passphrase)

    fun lockVault() = vault.lock()

    companion object {
        private const val SCAN_LIMIT_BYTES = 8L * 1024 * 1024
        private val MIME_BY_EXTENSION = mapOf(
            "jpg" to "image/jpeg", "jpeg" to "image/jpeg", "png" to "image/png", "gif" to "image/gif",
            "webp" to "image/webp", "heic" to "image/heic", "bmp" to "image/bmp",
            "mp4" to "video/mp4", "mkv" to "video/x-matroska", "webm" to "video/webm",
            "mov" to "video/quicktime", "avi" to "video/x-msvideo", "m4v" to "video/mp4",
            "mp3" to "audio/mpeg", "flac" to "audio/flac", "wav" to "audio/wav",
            "ogg" to "audio/ogg", "m4a" to "audio/mp4", "aac" to "audio/aac",
            "pdf" to "application/pdf", "txt" to "text/plain", "md" to "text/markdown",
            "csv" to "text/csv", "json" to "application/json", "xml" to "application/xml",
            "doc" to "application/msword",
            "docx" to "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xls" to "application/vnd.ms-excel",
            "xlsx" to "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "zip" to "application/zip", "apk" to "application/vnd.android.package-archive"
        )
    }
}
