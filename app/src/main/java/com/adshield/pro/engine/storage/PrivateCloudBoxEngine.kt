package com.adshield.pro.engine.storage

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Credentials
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.asRequestBody
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.crypto.SecretKey

/**
 * AdShield Pro — Private Cloud Storage Box Engine.
 *
 * Provides:
 * 1. AES-256-GCM encrypted local vault storage (`filesDir/private_cloud_box/`) for documents,
 *    photos, videos, audio, archives, APKs, and arbitrary files.
 * 2. Folder organization (`Documents`, `Photos`, `Videos`, `Audio`, `Other`, plus custom folders),
 *    category filtering, search, safe text/image/file preview extraction, export/download, and deletion.
 * 3. Privacy controls: PBKDF2-HMAC-SHA256 PIN lock, encrypted metadata/credentials at rest, and
 *    storage quota / per-category breakdown.
 * 4. Standards-based HTTPS WebDAV Private Cloud Sync (`PUT`, `GET`, `DELETE`, `MKCOL`) compatible
 *    with Nextcloud, ownCloud, Koofr, Fastmail, Box WebDAV, or any user-owned WebDAV server.
 */
class PrivateCloudBoxEngine(
    private val rootDir: File,
    private val secretKeyProvider: () -> SecretKey = {
        VaultCrypto.getOrCreateVaultSecretKey(File(rootDir, ".vault_master.key"))
    },
    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build(),
    private val allowLoopbackHttpForTesting: Boolean = false
) {

    @Serializable
    enum class VaultCategory(val displayName: String, val defaultFolder: String) {
        DOCUMENTS("Documents", "Documents"),
        PHOTOS("Photos", "Photos"),
        VIDEOS("Videos", "Videos"),
        AUDIO("Audio", "Audio"),
        ARCHIVES("Archives", "Archives"),
        APPLICATIONS("Apps (APK)", "Applications"),
        OTHER("Other Files", "Other")
    }

    @Serializable
    data class VaultItem(
        val id: String,
        val displayName: String,
        val folder: String,
        val mimeType: String,
        val category: VaultCategory,
        val originalSizeBytes: Long,
        val storedSizeBytes: Long,
        val sha256: String,
        val encryptedAtRest: Boolean,
        val createdAtEpochMs: Long,
        val cloudSyncedAtEpochMs: Long? = null,
        val remoteUrl: String? = null
    )

    @Serializable
    data class CloudEndpointConfig(
        val serverBaseUrl: String = "",
        val username: String = "",
        val passwordOrToken: String = "",
        val uploadEncryptedEnvelope: Boolean = true,
        val autoSyncOnUpload: Boolean = false
    ) {
        val isConfigured: Boolean
            get() = serverBaseUrl.isNotBlank()
    }

    @Serializable
    private data class PersistedVaultIndex(
        val folders: List<String> = DEFAULT_FOLDERS,
        val items: List<VaultItem> = emptyList(),
        val quotaBytes: Long = DEFAULT_QUOTA_BYTES,
        val pinSaltBase64: String? = null,
        val pinHashBase64: String? = null,
        val pinIterations: Int = 120_000,
        val cloudConfig: CloudEndpointConfig = CloudEndpointConfig()
    )

    data class VaultStorageSummary(
        val usedBytes: Long,
        val originalBytes: Long,
        val quotaBytes: Long,
        val deviceFreeBytes: Long,
        val itemCount: Int,
        val syncedCount: Int,
        val folderNames: List<String>,
        val bytesByCategory: Map<VaultCategory, Long>,
        val isPinConfigured: Boolean,
        val isLocked: Boolean,
        val cloudConfigured: Boolean,
        val cloudEndpointLabel: String?
    )

    sealed class VaultPreview {
        data class TextPreview(val title: String, val text: String, val truncated: Boolean) : VaultPreview()
        data class ImagePreview(val title: String, val decryptedTempFile: File, val sizeBytes: Long) : VaultPreview()
        data class MediaOrBinaryPreview(
            val title: String,
            val mimeType: String,
            val category: VaultCategory,
            val sizeBytes: Long,
            val sha256: String,
            val decryptedTempFile: File
        ) : VaultPreview()
    }

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private val blobsDir = File(rootDir, "blobs").apply { mkdirs() }
    private val previewCacheDir = File(rootDir, "preview_tmp").apply { mkdirs() }
    private val indexFile = File(rootDir, "vault_index.enc")
    private val lock = Any()

    @Volatile
    private var unlockedSession: Boolean = true

    private var state: PersistedVaultIndex = loadIndex()

    init {
        if (state.pinSaltBase64 != null && state.pinHashBase64 != null) {
            unlockedSession = false
        }
    }

    fun isPinConfigured(): Boolean = synchronized(lock) {
        state.pinSaltBase64 != null && state.pinHashBase64 != null
    }

    fun isUnlocked(): Boolean = unlockedSession

    fun lockVault() {
        synchronized(lock) {
            if (isPinConfigured()) {
                unlockedSession = false
                clearPreviewTempFiles()
            }
        }
    }

    fun unlockVault(pin: String): Boolean = synchronized(lock) {
        val salt = state.pinSaltBase64 ?: return@synchronized true.also { unlockedSession = true }
        val hash = state.pinHashBase64 ?: return@synchronized true.also { unlockedSession = true }
        val ok = VaultCrypto.verifyPin(pin, VaultCrypto.PinVerifier(salt, hash, state.pinIterations))
        if (ok) unlockedSession = true
        ok
    }

    fun setOrUpdatePin(newPin: String): Result<Unit> = runCatching {
        val verifier = VaultCrypto.createPinVerifier(newPin)
        synchronized(lock) {
            state = state.copy(
                pinSaltBase64 = verifier.saltBase64,
                pinHashBase64 = verifier.hashBase64,
                pinIterations = verifier.iterations
            )
            unlockedSession = true
            saveIndexLocked()
        }
    }

    fun clearPin(currentPin: String): Result<Unit> = runCatching {
        synchronized(lock) {
            if (isPinConfigured() && !unlockVault(currentPin)) {
                throw SecurityException("Incorrect current vault PIN.")
            }
            state = state.copy(pinSaltBase64 = null, pinHashBase64 = null)
            unlockedSession = true
            saveIndexLocked()
        }
    }

    fun listItems(
        folder: String? = null,
        category: VaultCategory? = null,
        searchQuery: String = ""
    ): List<VaultItem> = synchronized(lock) {
        if (!unlockedSession) return emptyList()
        val q = searchQuery.trim().lowercase()
        state.items.filter { item ->
            (folder.isNullOrBlank() || item.folder.equals(folder, ignoreCase = true)) &&
                (category == null || item.category == category) &&
                (q.isEmpty() || item.displayName.lowercase().contains(q) || item.folder.lowercase().contains(q))
        }.sortedByDescending { it.createdAtEpochMs }
    }

    fun listFolders(): List<String> = synchronized(lock) {
        state.folders.distinct()
    }

    fun createFolder(rawName: String): Result<String> = runCatching {
        requireUnlocked()
        val cleaned = sanitizeFolderName(rawName)
        require(cleaned.isNotEmpty()) { "Folder name cannot be empty." }
        synchronized(lock) {
            if (state.folders.none { it.equals(cleaned, ignoreCase = true) }) {
                state = state.copy(folders = state.folders + cleaned)
                saveIndexLocked()
            }
        }
        cleaned
    }

    fun moveItemToFolder(itemId: String, targetFolder: String): Result<VaultItem> = runCatching {
        requireUnlocked()
        val cleanedFolder = sanitizeFolderName(targetFolder)
        require(cleanedFolder.isNotEmpty()) { "Destination folder name cannot be empty." }
        synchronized(lock) {
            val existing = state.items.firstOrNull { it.id == itemId }
                ?: throw IllegalArgumentException("Vault item not found.")
            val updated = existing.copy(folder = cleanedFolder)
            val updatedFolders = if (state.folders.any { it.equals(cleanedFolder, ignoreCase = true) }) {
                state.folders
            } else {
                state.folders + cleanedFolder
            }
            state = state.copy(
                folders = updatedFolders,
                items = state.items.map { if (it.id == itemId) updated else it }
            )
            saveIndexLocked()
            updated
        }
    }

    fun updateQuotaBytes(quotaBytes: Long) {
        synchronized(lock) {
            state = state.copy(quotaBytes = quotaBytes.coerceIn(64L * 1024 * 1024, 64L * 1024 * 1024 * 1024))
            saveIndexLocked()
        }
    }

    fun getCloudEndpointConfig(): CloudEndpointConfig = synchronized(lock) { state.cloudConfig }

    fun configureCloudEndpoint(config: CloudEndpointConfig): Result<CloudEndpointConfig> = runCatching {
        requireUnlocked()
        val trimmedUrl = config.serverBaseUrl.trim().trimEnd('/')
        if (trimmedUrl.isNotEmpty()) {
            validateCloudEndpointUrl(trimmedUrl)
        }
        val cleaned = config.copy(
            serverBaseUrl = trimmedUrl,
            username = config.username.trim()
        )
        synchronized(lock) {
            state = state.copy(cloudConfig = cleaned)
            saveIndexLocked()
        }
        cleaned
    }

    fun storageSummary(): VaultStorageSummary = synchronized(lock) {
        val used = state.items.sumOf { it.storedSizeBytes }
        val original = state.items.sumOf { it.originalSizeBytes }
        val byCat = VaultCategory.entries.associateWith { cat ->
            state.items.filter { it.category == cat }.sumOf { it.originalSizeBytes }
        }.filterValues { it > 0L }
        val endpointLabel = state.cloudConfig.serverBaseUrl.takeIf { it.isNotBlank() }?.let {
            runCatching { URI(it).host ?: it }.getOrDefault(it)
        }
        VaultStorageSummary(
            usedBytes = used,
            originalBytes = original,
            quotaBytes = state.quotaBytes,
            deviceFreeBytes = rootDir.usableSpace,
            itemCount = state.items.size,
            syncedCount = state.items.count { it.cloudSyncedAtEpochMs != null },
            folderNames = state.folders,
            bytesByCategory = byCat,
            isPinConfigured = isPinConfigured(),
            isLocked = !unlockedSession,
            cloudConfigured = state.cloudConfig.isConfigured,
            cloudEndpointLabel = endpointLabel
        )
    }

    /**
     * Imports a file stream into the encrypted Private Cloud Storage Box and optionally syncs it
     * to the user's configured HTTPS WebDAV endpoint.
     */
    suspend fun uploadStream(
        inputStream: InputStream,
        displayName: String,
        mimeType: String?,
        targetFolder: String? = null
    ): Result<VaultItem> = withContext(Dispatchers.IO) {
        runCatching {
            requireUnlocked()
            val safeName = sanitizeFileName(displayName)
            val stagingFile = File(previewCacheDir, "upload_${UUID.randomUUID()}.tmp")
            try {
                var totalRead = 0L
                val headBuffer = ByteArray(32)
                var headLen = 0
                val currentUsed = synchronized(lock) { state.items.sumOf { it.storedSizeBytes } }
                val quota = synchronized(lock) { state.quotaBytes }

                stagingFile.outputStream().use { out ->
                    val buf = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        val r = inputStream.read(buf)
                        if (r < 0) break
                        if (r > 0) {
                            if (headLen < headBuffer.size) {
                                val copyCount = minOf(r, headBuffer.size - headLen)
                                System.arraycopy(buf, 0, headBuffer, headLen, copyCount)
                                headLen += copyCount
                            }
                            totalRead += r
                            if (currentUsed + totalRead > quota) {
                                throw IllegalStateException("Vault storage quota exceeded (${quota / (1024 * 1024)} MB limit).")
                            }
                            out.write(buf, 0, r)
                        }
                    }
                }

                val resolvedMime = UniversalFileManager.resolveMimeType(
                    fileName = safeName,
                    declaredMime = mimeType,
                    headerBytes = headBuffer.copyOf(headLen)
                )
                val category = classifyVaultCategory(safeName, resolvedMime)
                val folder = targetFolder?.let { sanitizeFolderName(it) }?.takeIf { it.isNotEmpty() }
                    ?: category.defaultFolder

                val itemId = UUID.randomUUID().toString()
                val blobFile = File(blobsDir, "$itemId.enc")
                val sha256 = VaultCrypto.encryptFile(stagingFile, blobFile, secretKeyProvider())

                var item = VaultItem(
                    id = itemId,
                    displayName = safeName,
                    folder = folder,
                    mimeType = resolvedMime,
                    category = category,
                    originalSizeBytes = stagingFile.length(),
                    storedSizeBytes = blobFile.length(),
                    sha256 = sha256,
                    encryptedAtRest = true,
                    createdAtEpochMs = System.currentTimeMillis()
                )

                val autoSync = synchronized(lock) {
                    val folders = if (state.folders.any { it.equals(folder, ignoreCase = true) }) {
                        state.folders
                    } else {
                        state.folders + folder
                    }
                    state = state.copy(folders = folders, items = listOf(item) + state.items)
                    saveIndexLocked()
                    state.cloudConfig.isConfigured && state.cloudConfig.autoSyncOnUpload
                }

                if (autoSync) {
                    syncItemToCloud(item.id).getOrNull()?.let { synced -> item = synced }
                }

                item
            } finally {
                stagingFile.delete()
            }
        }
    }

    suspend fun uploadFile(
        sourceFile: File,
        mimeType: String? = null,
        targetFolder: String? = null
    ): Result<VaultItem> = withContext(Dispatchers.IO) {
        if (!sourceFile.exists() || !sourceFile.isFile) {
            return@withContext Result.failure(IllegalArgumentException("Source file does not exist."))
        }
        sourceFile.inputStream().use { stream ->
            uploadStream(stream, sourceFile.name, mimeType, targetFolder)
        }
    }

    /**
     * Decrypts a vault item and writes its verified plaintext bytes to [outputStream].
     * If the local encrypted blob is missing (e.g. cloud-only restore), fetches it from WebDAV first.
     */
    suspend fun downloadToStream(itemId: String, outputStream: OutputStream): Result<VaultItem> =
        withContext(Dispatchers.IO) {
            runCatching {
                requireUnlocked()
                val item = synchronized(lock) {
                    state.items.firstOrNull { it.id == itemId }
                } ?: throw IllegalArgumentException("Vault item not found.")

                val blobFile = ensureLocalBlobPresent(item)
                val tempPlain = File(previewCacheDir, "export_${UUID.randomUUID()}.tmp")
                try {
                    VaultCrypto.decryptFile(blobFile, tempPlain, secretKeyProvider())
                    val actualSha = sha256Hex(tempPlain)
                    if (!actualSha.equals(item.sha256, ignoreCase = true)) {
                        throw SecurityException("Vault integrity check failed: SHA-256 mismatch.")
                    }
                    tempPlain.inputStream().use { input -> input.copyTo(outputStream) }
                    item
                } finally {
                    tempPlain.delete()
                }
            }
        }

    /**
     * Decrypts a vault item to a temporary preview file inside app-private cache (`preview_tmp`)
     * and returns structured preview data (text snippet, image file, or media/document descriptor).
     */
    suspend fun buildPreview(itemId: String, maxTextChars: Int = 8_192): Result<VaultPreview> =
        withContext(Dispatchers.IO) {
            runCatching {
                requireUnlocked()
                val item = synchronized(lock) {
                    state.items.firstOrNull { it.id == itemId }
                } ?: throw IllegalArgumentException("Vault item not found.")

                val blobFile = ensureLocalBlobPresent(item)
                clearPreviewTempFiles()
                val ext = item.displayName.substringAfterLast('.', "bin").take(10)
                val previewFile = File(previewCacheDir, "preview_${item.id.take(8)}.$ext")
                VaultCrypto.decryptFile(blobFile, previewFile, secretKeyProvider())

                when {
                    isTextPreviewable(item.displayName, item.mimeType) -> {
                        val rawBytes = previewFile.inputStream().use { stream ->
                            val cap = ByteArray((maxTextChars * 2).coerceAtMost(65_536))
                            val n = stream.read(cap)
                            if (n <= 0) ByteArray(0) else cap.copyOf(n)
                        }
                        previewFile.delete()
                        val fullText = String(rawBytes, StandardCharsets.UTF_8)
                        val truncated = item.originalSizeBytes > rawBytes.size || fullText.length > maxTextChars
                        VaultPreview.TextPreview(
                            title = item.displayName,
                            text = fullText.take(maxTextChars),
                            truncated = truncated
                        )
                    }
                    item.category == VaultCategory.PHOTOS -> {
                        VaultPreview.ImagePreview(
                            title = item.displayName,
                            decryptedTempFile = previewFile,
                            sizeBytes = item.originalSizeBytes
                        )
                    }
                    else -> {
                        VaultPreview.MediaOrBinaryPreview(
                            title = item.displayName,
                            mimeType = item.mimeType,
                            category = item.category,
                            sizeBytes = item.originalSizeBytes,
                            sha256 = item.sha256,
                            decryptedTempFile = previewFile
                        )
                    }
                }
            }
        }

    fun clearPreviewTempFiles() {
        previewCacheDir.listFiles()?.forEach { runCatching { it.delete() } }
    }

    /**
     * Deletes a vault item locally and (if `deleteRemoteToo = true` and synced) from the WebDAV server.
     */
    suspend fun deleteItem(itemId: String, deleteRemoteToo: Boolean = false): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                requireUnlocked()
                val (removed, cloudCfg) = synchronized(lock) {
                    val found = state.items.firstOrNull { it.id == itemId }
                    state = state.copy(items = state.items.filterNot { it.id == itemId })
                    saveIndexLocked()
                    found to state.cloudConfig
                }
                File(blobsDir, "$itemId.enc").delete()
                if (deleteRemoteToo && removed?.remoteUrl != null && cloudCfg.isConfigured) {
                    val reqBuilder = Request.Builder().url(removed.remoteUrl).delete()
                    applyCloudAuth(reqBuilder, cloudCfg)
                    httpClient.newCall(reqBuilder.build()).execute().close()
                }
            }
        }

    /**
     * Uploads [itemId] to the configured HTTPS WebDAV private cloud server (`PUT`).
     * When `uploadEncryptedEnvelope = true` (default), only the AES-256-GCM `.enc` ciphertext
     * leaves the device so the cloud provider never sees plaintext bytes.
     */
    suspend fun syncItemToCloud(itemId: String): Result<VaultItem> = withContext(Dispatchers.IO) {
        runCatching {
            requireUnlocked()
            val (item, cfg) = synchronized(lock) {
                val found = state.items.firstOrNull { it.id == itemId }
                    ?: throw IllegalArgumentException("Vault item not found.")
                found to state.cloudConfig
            }
            if (!cfg.isConfigured) {
                throw IllegalStateException("Configure an HTTPS WebDAV server URL before syncing to cloud.")
            }
            validateCloudEndpointUrl(cfg.serverBaseUrl)

            val blobFile = File(blobsDir, "${item.id}.enc")
            if (!blobFile.exists()) {
                throw IllegalStateException("Local encrypted file missing for '${item.displayName}'.")
            }

            // Best-effort MKCOL for the folder collection on WebDAV servers
            val encodedFolder = encodePathSegment(item.folder)
            val folderUrl = "${cfg.serverBaseUrl}/$encodedFolder/"
            runCatching {
                val mkcolReq = Request.Builder().url(folderUrl).method("MKCOL", null)
                applyCloudAuth(mkcolReq, cfg)
                httpClient.newCall(mkcolReq.build()).execute().close()
            }

            val remoteFileName = if (cfg.uploadEncryptedEnvelope) {
                "${item.id}_${item.displayName}.enc"
            } else {
                "${item.id}_${item.displayName}"
            }
            val targetUrl = "$folderUrl${encodePathSegment(remoteFileName)}"

            val tempPlainForUpload = if (!cfg.uploadEncryptedEnvelope) {
                File(previewCacheDir, "dav_up_${UUID.randomUUID()}.tmp").also {
                    VaultCrypto.decryptFile(blobFile, it, secretKeyProvider())
                }
            } else null

            try {
                val fileToSend = tempPlainForUpload ?: blobFile
                val mediaType = (if (cfg.uploadEncryptedEnvelope) "application/octet-stream" else item.mimeType)
                    .toMediaType()
                val putReq = Request.Builder()
                    .url(targetUrl)
                    .put(fileToSend.asRequestBody(mediaType))
                applyCloudAuth(putReq, cfg)

                httpClient.newCall(putReq.build()).execute().use { resp ->
                    if (!resp.isSuccessful && resp.code !in listOf(200, 201, 204)) {
                        throw IllegalStateException("Cloud upload failed (HTTP ${resp.code}).")
                    }
                }
            } finally {
                tempPlainForUpload?.delete()
            }

            val syncedItem = item.copy(
                cloudSyncedAtEpochMs = System.currentTimeMillis(),
                remoteUrl = targetUrl
            )
            synchronized(lock) {
                state = state.copy(items = state.items.map { if (it.id == item.id) syncedItem else it })
                saveIndexLocked()
            }
            syncedItem
        }
    }

    suspend fun syncAllUnsyncedToCloud(): Result<Int> = withContext(Dispatchers.IO) {
        runCatching {
            requireUnlocked()
            val unsynced = synchronized(lock) {
                state.items.filter { it.cloudSyncedAtEpochMs == null }.map { it.id }
            }
            var count = 0
            for (id in unsynced) {
                if (syncItemToCloud(id).isSuccess) count++
            }
            count
        }
    }

    private fun ensureLocalBlobPresent(item: VaultItem): File {
        val blobFile = File(blobsDir, "${item.id}.enc")
        if (blobFile.exists()) return blobFile

        val remoteUrl = item.remoteUrl
            ?: throw IllegalStateException("Encrypted file is missing and has no cloud backup URL.")
        val cfg = synchronized(lock) { state.cloudConfig }
        validateCloudEndpointUrl(remoteUrl)

        val getReq = Request.Builder().url(remoteUrl).get()
        applyCloudAuth(getReq, cfg)
        httpClient.newCall(getReq.build()).execute().use { resp ->
            if (!resp.isSuccessful) {
                throw IllegalStateException("Cloud download failed (HTTP ${resp.code}).")
            }
            val body = resp.body ?: throw IllegalStateException("Empty cloud response.")
            val downloadedTmp = File(previewCacheDir, "dav_dl_${UUID.randomUUID()}.tmp")
            try {
                body.byteStream().use { input ->
                    downloadedTmp.outputStream().use { out -> input.copyTo(out) }
                }
                val head = downloadedTmp.inputStream().use { s ->
                    val b = ByteArray(32)
                    val n = s.read(b)
                    if (n <= 0) ByteArray(0) else b.copyOf(n)
                }
                if (VaultCrypto.isEncryptedEnvelope(head)) {
                    downloadedTmp.copyTo(blobFile, overwrite = true)
                } else {
                    VaultCrypto.encryptFile(downloadedTmp, blobFile, secretKeyProvider())
                }
            } finally {
                downloadedTmp.delete()
            }
        }
        return blobFile
    }

    private fun validateCloudEndpointUrl(url: String) {
        val parsed = runCatching { URI(url) }.getOrNull()
            ?: throw IllegalArgumentException("Malformed cloud server URL.")
        val scheme = parsed.scheme?.lowercase() ?: ""
        val host = parsed.host?.lowercase() ?: throw IllegalArgumentException("Cloud server URL is missing a hostname.")
        if (scheme == "https") return
        if (allowLoopbackHttpForTesting && scheme == "http" && (host == "127.0.0.1" || host == "localhost")) {
            return
        }
        throw SecurityException("Private Cloud Sync requires an encrypted https:// endpoint.")
    }

    private fun applyCloudAuth(builder: Request.Builder, cfg: CloudEndpointConfig) {
        if (cfg.username.isNotBlank() && cfg.passwordOrToken.isNotBlank()) {
            builder.header("Authorization", Credentials.basic(cfg.username, cfg.passwordOrToken, StandardCharsets.UTF_8))
        } else if (cfg.passwordOrToken.isNotBlank()) {
            builder.header("Authorization", "Bearer ${cfg.passwordOrToken.trim()}")
        }
    }

    private fun requireUnlocked() {
        if (!unlockedSession) {
            throw SecurityException("Private Cloud Storage Box is locked. Enter your PIN to access files.")
        }
    }

    private fun loadIndex(): PersistedVaultIndex {
        if (!indexFile.exists()) return PersistedVaultIndex()
        return runCatching {
            val raw = indexFile.readBytes()
            val plain = if (VaultCrypto.isEncryptedEnvelope(raw)) {
                VaultCrypto.decryptBytes(raw, secretKeyProvider())
            } else {
                raw
            }
            json.decodeFromString<PersistedVaultIndex>(String(plain, StandardCharsets.UTF_8))
        }.getOrDefault(PersistedVaultIndex())
    }

    private fun saveIndexLocked() {
        rootDir.mkdirs()
        val encoded = json.encodeToString(state).toByteArray(StandardCharsets.UTF_8)
        val encrypted = VaultCrypto.encryptBytes(encoded, secretKeyProvider())
        val tmp = File(rootDir, "vault_index.tmp")
        tmp.writeBytes(encrypted)
        if (!tmp.renameTo(indexFile)) {
            tmp.copyTo(indexFile, overwrite = true)
            tmp.delete()
        }
    }

    companion object {
        val DEFAULT_FOLDERS = listOf("Documents", "Photos", "Videos", "Audio", "Archives", "Applications", "Other")
        const val DEFAULT_QUOTA_BYTES = 2L * 1024L * 1024L * 1024L // 2 GB default local vault ceiling

        fun classifyVaultCategory(fileName: String, mimeType: String): VaultCategory {
            val lowerMime = mimeType.lowercase()
            val ext = fileName.substringAfterLast('.', "").lowercase()
            return when {
                ext in setOf("apk", "apks", "xapk", "aab") || lowerMime == "application/vnd.android.package-archive" ->
                    VaultCategory.APPLICATIONS
                lowerMime.startsWith("image/") || ext in setOf("jpg", "jpeg", "png", "webp", "gif", "bmp", "heic", "svg") ->
                    VaultCategory.PHOTOS
                lowerMime.startsWith("video/") || ext in setOf("mp4", "mkv", "webm", "mov", "avi", "m4v", "3gp") ->
                    VaultCategory.VIDEOS
                lowerMime.startsWith("audio/") || ext in setOf("mp3", "m4a", "wav", "ogg", "opus", "flac", "aac") ->
                    VaultCategory.AUDIO
                ext in setOf("zip", "rar", "7z", "tar", "gz", "bz2", "xz") ||
                    lowerMime in setOf("application/zip", "application/gzip", "application/x-7z-compressed") ->
                    VaultCategory.ARCHIVES
                lowerMime.startsWith("text/") ||
                    lowerMime in setOf(
                        "application/pdf", "application/json", "application/xml",
                        "application/msword",
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                    ) ||
                    ext in setOf("pdf", "txt", "md", "csv", "json", "xml", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "log") ->
                    VaultCategory.DOCUMENTS
                else -> VaultCategory.OTHER
            }
        }

        private fun isTextPreviewable(fileName: String, mimeType: String): Boolean {
            val lowerMime = mimeType.lowercase()
            val ext = fileName.substringAfterLast('.', "").lowercase()
            return lowerMime.startsWith("text/") ||
                lowerMime == "application/json" ||
                lowerMime == "application/xml" ||
                ext in setOf("txt", "md", "csv", "json", "xml", "log", "yaml", "yml", "ini", "conf", "html")
        }

        private fun sanitizeFolderName(raw: String): String =
            raw.trim().replace(Regex("""[\\/:*?"<>|\u0000-\u001F]"""), "_").take(48)

        private fun sanitizeFileName(raw: String): String {
            val cleaned = raw.trim().substringAfterLast('/').substringAfterLast('\\')
                .replace(Regex("""[\u0000-\u001F<>:"|?*]"""), "_")
                .take(120)
            return cleaned.ifBlank { "file_${System.currentTimeMillis()}" }
        }

        private fun encodePathSegment(raw: String): String =
            URLEncoder.encode(raw, StandardCharsets.UTF_8.name()).replace("+", "%20")

        private fun sha256Hex(file: File): String {
            val md = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buf = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val r = input.read(buf)
                    if (r < 0) break
                    if (r > 0) md.update(buf, 0, r)
                }
            }
            return md.digest().joinToString("") { "%02x".format(it) }
        }
    }
}
