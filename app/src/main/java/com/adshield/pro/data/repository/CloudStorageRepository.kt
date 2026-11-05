package com.adshield.pro.data.repository

import android.content.Context
import android.net.Uri
import android.webkit.MimeTypeMap
import androidx.core.content.FileProvider
import com.adshield.pro.data.local.db.AdShieldDao
import com.adshield.pro.data.local.db.StorageProviderEntity
import com.adshield.pro.domain.model.CloudObject
import com.adshield.pro.domain.model.CloudPreview
import com.adshield.pro.domain.model.StorageProvider
import com.adshield.pro.domain.model.StorageProviderHealth
import com.adshield.pro.domain.model.StorageProviderKind
import com.adshield.pro.engine.storage.WebDavClient
import com.adshield.pro.engine.storage.WebDavDownloadResult
import com.adshield.pro.engine.storage.WebDavListing
import com.adshield.pro.engine.storage.WebDavPath
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import java.io.File
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class CloudStorageRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val dao: AdShieldDao,
    private val credentials: ProviderCredentialStore
) {
    val providers: Flow<List<StorageProvider>> = dao.observeStorageProviders().map { rows ->
        rows.map(::toDomain)
    }

    suspend fun registerProvider(
        name: String,
        kind: StorageProviderKind,
        baseUrl: String,
        username: String,
        password: String
    ): StorageProvider = withContext(Dispatchers.IO) {
        val endpoint = WebDavClient.endpoint(baseUrl)
        require(name.isNotBlank()) { "Give this authorized server a recognizable name" }
        val now = System.currentTimeMillis()
        val provider = StorageProviderEntity(
            id = UUID.randomUUID().toString(),
            name = name.trim().take(100),
            kind = kind.name,
            baseUrl = endpoint.toString(),
            username = username.trim(),
            health = StorageProviderHealth.CHECKING.name,
            lastCheckedEpochMs = now,
            lastError = null,
            totalBytes = null,
            availableBytes = null,
            usedBytes = null
        )
        dao.upsertStorageProvider(provider)
        credentials.put(provider.id, password)
        checkProvider(provider.id)
        requireNotNull(dao.getStorageProvider(provider.id)).let(::toDomain)
    }

    suspend fun removeProvider(id: String) = withContext(Dispatchers.IO) {
        dao.deleteStorageProvider(id)
        credentials.remove(id)
    }

    suspend fun checkProvider(id: String): StorageProvider = withContext(Dispatchers.IO) {
        val original = requireNotNull(dao.getStorageProvider(id)) { "Storage provider no longer exists" }
        dao.upsertStorageProvider(
            original.copy(
                health = StorageProviderHealth.CHECKING.name,
                lastCheckedEpochMs = System.currentTimeMillis(),
                lastError = null
            )
        )
        val checked = runCatching { clientFor(original).list("") }
        checked.fold(
            onSuccess = { listing ->
                val online = original.copy(
                    health = StorageProviderHealth.ONLINE.name,
                    lastCheckedEpochMs = System.currentTimeMillis(),
                    lastError = null,
                    totalBytes = listing.quota.totalBytes,
                    availableBytes = listing.quota.availableBytes,
                    usedBytes = listing.quota.usedBytes
                )
                dao.upsertStorageProvider(online)
                toDomain(online)
            },
            onFailure = { failure ->
                val offline = original.copy(
                    health = StorageProviderHealth.OFFLINE.name,
                    lastCheckedEpochMs = System.currentTimeMillis(),
                    lastError = failure.message ?: "Connection failed"
                )
                dao.upsertStorageProvider(offline)
                toDomain(offline)
            }
        )
    }

    suspend fun list(providerId: String, path: String): WebDavListing = withContext(Dispatchers.IO) {
        val provider = requireNotNull(dao.getStorageProvider(providerId))
        runCatching { clientFor(provider).list(path) }.fold(
            onSuccess = { listing ->
                dao.upsertStorageProvider(
                    provider.copy(
                        health = StorageProviderHealth.ONLINE.name,
                        lastCheckedEpochMs = System.currentTimeMillis(),
                        lastError = null,
                        totalBytes = listing.quota.totalBytes,
                        availableBytes = listing.quota.availableBytes,
                        usedBytes = listing.quota.usedBytes
                    )
                )
                listing
            },
            onFailure = { failure ->
                dao.upsertStorageProvider(
                    provider.copy(
                        health = StorageProviderHealth.OFFLINE.name,
                        lastCheckedEpochMs = System.currentTimeMillis(),
                        lastError = failure.message ?: "Connection failed"
                    )
                )
                throw failure
            }
        )
    }

    suspend fun createFolder(providerId: String, parentPath: String, name: String) = withContext(Dispatchers.IO) {
        clientForId(providerId).createFolder(parentPath, name)
    }

    suspend fun delete(providerId: String, path: String, isDirectory: Boolean) = withContext(Dispatchers.IO) {
        clientForId(providerId).delete(path, isDirectory)
    }

    suspend fun rename(providerId: String, path: String, isDirectory: Boolean, newName: String) = withContext(Dispatchers.IO) {
        clientForId(providerId).rename(path, isDirectory, newName)
    }

    suspend fun createPublicShare(providerId: String, path: String): String = withContext(Dispatchers.IO) {
        clientForId(providerId).createNextcloudPublicLink(path)
    }

    suspend fun upload(
        providerId: String,
        parentPath: String,
        name: String,
        mimeType: String,
        source: Uri,
        sizeBytes: Long,
        onProgress: (Long) -> Unit
    ): String? = withContext(Dispatchers.IO) {
        val input = context.contentResolver.openInputStream(source) ?: error("Cannot read the selected source document")
        clientForId(providerId).upload(
            parentPath = parentPath,
            name = WebDavPath.normalize(name).also { require(!it.contains('/')) },
            mimeType = mimeType.ifBlank { "application/octet-stream" },
            contentLength = sizeBytes,
            input = input,
            onProgress = onProgress
        )
    }

    suspend fun download(
        providerId: String,
        path: String,
        destination: Uri,
        onProgress: (Long) -> Unit
    ): WebDavDownloadResult = withContext(Dispatchers.IO) {
        val output = context.contentResolver.openOutputStream(destination, "wt")
            ?: error("Cannot write to the selected destination")
        clientForId(providerId).download(path, output, onProgress)
    }

    suspend fun preview(
        providerId: String,
        item: CloudObject,
        onProgress: (Long) -> Unit
    ): CloudPreview = withContext(Dispatchers.IO) {
        require(!item.isDirectory) { "Folders cannot be previewed as files" }
        require(item.sizeBytes <= MAX_PREVIEW_BYTES) { "Preview is limited to files up to 256 MiB; use Download instead" }
        val directory = File(context.cacheDir, "cloud_previews").apply { mkdirs() }
        directory.listFiles()?.filter { it.lastModified() < System.currentTimeMillis() - PREVIEW_RETENTION_MS }
            ?.forEach { it.delete() }
        val safeName = item.name.replace(Regex("[^A-Za-z0-9._-]"), "_").take(100)
        val target = File(directory, "${UUID.randomUUID()}-$safeName")
        val result = target.outputStream().use { output ->
            clientForId(providerId).download(item.path, output, onProgress)
        }
        val extension = item.name.substringAfterLast('.', "")
        val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension.lowercase())
            ?: "application/octet-stream"
        val uri = FileProvider.getUriForFile(context, context.packageName + ".fileprovider", target)
        CloudPreview(uri.toString(), item.name, mime, result.sha256)
    }

    private suspend fun clientForId(id: String): WebDavClient =
        clientFor(requireNotNull(dao.getStorageProvider(id)) { "Storage provider no longer exists" })

    private fun clientFor(provider: StorageProviderEntity): WebDavClient {
        val password = credentials.get(provider.id)
            ?: error("Credentials are unavailable. Remove and reconnect this provider.")
        return WebDavClient(
            providerId = provider.id,
            baseUrl = WebDavClient.endpoint(provider.baseUrl),
            username = provider.username,
            password = password,
            isNextcloud = provider.kind == StorageProviderKind.NEXTCLOUD.name
        )
    }

    private fun toDomain(row: StorageProviderEntity) = StorageProvider(

        id = row.id,
        name = row.name,
        kind = runCatching { StorageProviderKind.valueOf(row.kind) }.getOrDefault(StorageProviderKind.WEBDAV),
        baseUrl = row.baseUrl,
        username = row.username,
        health = runCatching { StorageProviderHealth.valueOf(row.health) }.getOrDefault(StorageProviderHealth.UNCHECKED),
        lastCheckedEpochMs = row.lastCheckedEpochMs,
        lastError = row.lastError,
        totalBytes = row.totalBytes,
        availableBytes = row.availableBytes,
        usedBytes = row.usedBytes
    )

    private companion object {
        const val MAX_PREVIEW_BYTES = 256L * 1024L * 1024L
        const val PREVIEW_RETENTION_MS = 24L * 60L * 60L * 1000L
    }
}
