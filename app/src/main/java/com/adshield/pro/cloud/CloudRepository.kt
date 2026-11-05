package com.adshield.pro.cloud

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.adshield.pro.data.local.db.CloudDao
import com.adshield.pro.data.local.db.CloudFileEntity
import com.adshield.pro.data.repository.AdShieldRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Orchestrates cloud operations: auth, metadata, quota, DNS config backup/restore and the
 * resumable transfer queue. All network work happens on Dispatchers.IO; the DNS blocker never
 * touches this class, so protection keeps working fully offline.
 */
@Singleton
class CloudRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val api: CloudApiClient,
    private val authStore: CloudAuthStore,
    private val cloudDao: CloudDao,
    private val adShieldRepository: AdShieldRepository,
    private val transferEngine: CloudTransferEngine
) {

    val sessionFlow: Flow<AuthSession?> = authStore.sessionFlow
    val apiBaseUrlFlow = authStore.apiBaseUrlFlow

    fun filesFlow(folder: String = "/"): Flow<List<CloudFileEntity>> = cloudDao.observeFiles(folder)
    fun trashFlow(): Flow<List<CloudFileEntity>> = cloudDao.observeTrash()
    val transfers: Flow<List<com.adshield.pro.data.local.db.CloudTransferEntity>> = cloudDao.observeTransfers()
    val dnsBackups: Flow<List<com.adshield.pro.data.local.db.CloudDnsBackupEntity>> = cloudDao.observeDnsBackups()

    private suspend fun baseUrl(): String = authStore.currentApiBaseUrl()
    private suspend fun token(): String {
        val session = authStore.currentSession()
        require(CloudConfig.isValidApiBaseUrl(baseUrl())) { "Cloud backend is not configured yet." }
        require(authStore.isSessionUsable(session, System.currentTimeMillis())) { "Sign in to AdShield Cloud first." }
        return session!!.accessToken
    }

    // --- Auth ---
    suspend fun signUp(email: String, password: String): Result<AuthSession> = withContext(Dispatchers.IO) {
        runCatching {
            val session = api.signUp(baseUrl(), email, password)
            authStore.saveSession(session)
            session
        }
    }

    suspend fun signIn(email: String, password: String): Result<AuthSession> = withContext(Dispatchers.IO) {
        runCatching {
            val session = api.signIn(baseUrl(), email, password)
            authStore.saveSession(session)
            session
        }
    }

    suspend fun signOut() = authStore.clearSession()

    suspend fun setApiBaseUrl(url: String): Result<Unit> = runCatching {
        require(CloudConfig.isValidApiBaseUrl(url)) { "Enter a valid https:// Worker URL (no trailing slash)." }
        authStore.saveApiBaseUrl(url)
    }

    // --- Quota / overview ---
    suspend fun quota(): Result<QuotaInfo> = withContext(Dispatchers.IO) {
        runCatching { api.quota(baseUrl(), token()) }
    }

    // --- Files ---
    suspend fun refreshFiles(folder: String = "/"): Result<List<CloudFile>> = withContext(Dispatchers.IO) {
        runCatching {
            val files = api.listFiles(baseUrl(), token(), folder, null)
            cloudDao.upsertCloudFiles(files.map { it.toEntity() })
            files
        }
    }

    suspend fun createFolder(path: String): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching { api.createFolder(baseUrl(), token(), path) }
    }

    suspend fun renameFile(id: String, newName: String) = withContext(Dispatchers.IO) {
        runCatching { api.renameFile(baseUrl(), token(), id, newName) }
    }

    suspend fun moveFile(id: String, folderPath: String) = withContext(Dispatchers.IO) {
        runCatching { api.moveFile(baseUrl(), token(), id, folderPath) }
    }

    suspend fun copyFile(id: String, folderPath: String) = withContext(Dispatchers.IO) {
        runCatching { api.copyFile(baseUrl(), token(), id, folderPath) }
    }

    suspend fun deleteFile(id: String, permanent: Boolean) = withContext(Dispatchers.IO) {
        runCatching { api.deleteFile(baseUrl(), token(), id, permanent) }
    }

    suspend fun restoreFile(id: String) = withContext(Dispatchers.IO) {
        runCatching { api.restoreFile(baseUrl(), token(), id) }
    }

    suspend fun versions(id: String) = withContext(Dispatchers.IO) {
        runCatching { api.versions(baseUrl(), token(), id) }
    }

    suspend fun shareFile(id: String, ttlHours: Int, maxDownloads: Int) = withContext(Dispatchers.IO) {
        runCatching { api.share(baseUrl(), token(), id, ttlHours.coerceIn(1, 168), maxDownloads.coerceIn(1, 1000)) }
    }

    suspend fun listShares() = withContext(Dispatchers.IO) {
        runCatching { api.listShares(baseUrl(), token()) }
    }

    // --- Transfers ---
    suspend fun enqueueUpload(uri: Uri, displayName: String, folderPath: String): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val (size, mime) = probe(uri)
            val sha = sha256Of(uri)
            val dedupe = CloudWire.dedupeKey(sha, size)
            cloudDao.findDuplicate(sha, size)?.let { existing ->
                return@runCatching "duplicate:${existing.id}:$dedupe"
            }
            require(CloudWire.isAllowedFileType(displayName, mime)) { "File type not allowed (executable/web content is blocked)." }
            QuotaManager.canUpload(size, quota().getOrNull()?.usedBytes ?: 0L, quota().getOrNull()?.quotaBytes ?: 0L).getOrThrow()
            transferEngine.enqueueUpload(uri, displayName, folderPath, size, mime, sha)
        }
    }

    suspend fun enqueueDownload(fileId: String, displayName: String, destUri: Uri): Result<String> =
        transferEngine.enqueueDownload(fileId, displayName, destUri)

    suspend fun pauseTransfer(id: String) = transferEngine.pause(id)
    suspend fun resumeTransfer(id: String) = transferEngine.resume(id)
    suspend fun cancelTransfer(id: String) = transferEngine.cancel(id)

    // --- DNS security cloud backup ---
    suspend fun backupDnsConfig(label: String): Result<com.adshield.pro.data.local.db.CloudDnsBackupEntity> =
        withContext(Dispatchers.IO) {
            runCatching {
                val payload = DnsBackupSerializer.buildBackupPayload(
                    adShieldRepository,
                    appVersion = context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "unknown",
                    nowEpochMs = System.currentTimeMillis()
                )
                val sha = DnsBackupSerializer.sha256Hex(payload)
                val bytes = payload.toByteArray(Charsets.UTF_8)
                val fileName = "dns-backup-${System.currentTimeMillis()}.adshield-backup"
                val record = api.createFileRecord(
                    baseUrl(), token(), fileName, "/backups", bytes.size.toLong(),
                    "application/x-adshield-backup", sha, multipart = false
                )
                val signed = api.signedUploadUrl(baseUrl(), token(), record.id, bytes.size.toLong(), sha)
                require(CloudWire.isSignedUrlValid(signed.url, System.currentTimeMillis())) { "Server issued an invalid signed URL." }
                transferEngine.putBytes(signed, bytes)
                val backup = com.adshield.pro.data.local.db.CloudDnsBackupEntity(
                    id = record.id, label = label.ifBlank { fileName }, cloudFileId = record.id,
                    sha256 = sha, createdAtEpochMs = System.currentTimeMillis()
                )
                cloudDao.upsertDnsBackup(backup)
                backup
            }
        }

    suspend fun restoreDnsBackup(backupId: String): Result<Int> = withContext(Dispatchers.IO) {
        runCatching {
            val backup = cloudDao.observeDnsBackups().first().first { it.id == backupId }
            val signed = api.signedDownloadUrl(baseUrl(), token(), backup.cloudFileId)
            require(CloudWire.isSignedUrlValid(signed.url, System.currentTimeMillis())) { "Signed URL expired; retry the restore." }
            val raw = transferEngine.getString(signed)
            require(DnsBackupSerializer.sha256Hex(raw) == backup.sha256) { "Integrity check failed: backup hash mismatch." }
            val payload = DnsBackupSerializer.parseBackup(raw)
                ?: throw IllegalStateException("Downloaded file is not a valid AdShield DNS backup.")
            val ruleCount = adShieldRepository.restoreConfigurationFromJson(payload).getOrThrow()
            cloudDao.markBackupRestored(backupId, System.currentTimeMillis())
            ruleCount
        }
    }

    // --- helpers ---
    private fun probe(uri: Uri): Pair<Long, String> {
        var size = -1L
        var mime = "application/octet-stream"
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
            val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (cursor.moveToFirst()) {
                if (sizeIndex >= 0) size = cursor.getLong(sizeIndex)
                if (nameIndex >= 0) {
                    val name = cursor.getString(nameIndex) ?: ""
                    mime = context.contentResolver.getType(uri) ?: "application/octet-stream"
                    if (name.endsWith(".json", true)) mime = "application/json"
                }
            }
        }
        if (size < 0) size = contentLength(uri)
        return size to mime
    }

    private fun contentLength(uri: Uri): Long {
        context.contentResolver.openFileDescriptor(uri, "r")?.use { pfd ->
            return pfd.statSize
        }
        return 0L
    }

    private fun sha256Of(uri: Uri): String {
        val digest = MessageDigest.getInstance("SHA-256")
        openStream(uri).use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun openStream(uri: Uri): InputStream =
        context.contentResolver.openInputStream(uri) ?: throw IllegalStateException("Cannot open $uri")

    private fun CloudFile.toEntity() = CloudFileEntity(
        id = id, name = name, folderPath = folderPath, sizeBytes = sizeBytes,
        mimeType = mimeType, sha256 = sha256, isDeleted = isDeleted,
        version = version, updatedAtEpochMs = updatedAtEpochMs
    )
}
