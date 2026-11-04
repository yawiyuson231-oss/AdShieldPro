package com.adshield.pro.domain.model

import kotlinx.serialization.Serializable

/** Search providers receive queries and network metadata; private mode does not change that fact. */
@Serializable
enum class SearchProvider(val label: String, val searchBaseUrl: String) {
    DUCKDUCKGO("DuckDuckGo", "https://duckduckgo.com/?q="),
    GOOGLE("Google", "https://www.google.com/search?q=")
}

@Serializable
data class SearchHistoryEntry(
    val query: String,
    val provider: SearchProvider,
    val timestampEpochMs: Long
)

enum class StorageProviderKind(val label: String) {
    NEXTCLOUD("Nextcloud Community"),
    WEBDAV("Generic WebDAV")
}

enum class StorageProviderHealth { UNCHECKED, CHECKING, ONLINE, OFFLINE }

/** A registered endpoint. Secrets are deliberately absent and live in Android Keystore storage. */
data class StorageProvider(
    val id: String,
    val name: String,
    val kind: StorageProviderKind,
    val baseUrl: String,
    val username: String,
    val health: StorageProviderHealth,
    val lastCheckedEpochMs: Long,
    val lastError: String?,
    val totalBytes: Long?,
    val availableBytes: Long?,
    val usedBytes: Long?
)

data class VerifiedStorageCapacity(
    val provisionedBytes: Long,
    val availableBytes: Long,
    val usedBytes: Long,
    val verifiedProviders: Int,
    val unavailableProviders: Int,
    val unreportedProviders: Int
)

/**
 * Counts only providers that just passed a health check and reported non-negative DAV quota values.
 * Last-known values from an offline provider are never counted as usable capacity.
 */
object InfinityCapacityCalculator {
    fun aggregate(providers: List<StorageProvider>): VerifiedStorageCapacity {
        val online = providers.filter { it.health == StorageProviderHealth.ONLINE }
        val verified = online.filter {
            it.totalBytes != null && it.totalBytes >= 0L &&
                it.availableBytes != null && it.availableBytes >= 0L
        }
        return VerifiedStorageCapacity(
            provisionedBytes = verified.sumOf { it.totalBytes!! },
            availableBytes = verified.sumOf { it.availableBytes!! },
            usedBytes = verified.sumOf { (it.totalBytes!! - it.availableBytes!!).coerceAtLeast(0L) },
            verifiedProviders = verified.size,
            unavailableProviders = providers.count { it.health != StorageProviderHealth.ONLINE },
            unreportedProviders = online.count { provider -> verified.none { it.id == provider.id } }
        )
    }
}

data class CloudObject(
    val providerId: String,
    val path: String,
    val name: String,
    val isDirectory: Boolean,
    val sizeBytes: Long,
    val lastModifiedEpochMs: Long?,
    val etag: String?
)

data class CloudPreview(
    val contentUri: String,
    val fileName: String,
    val mimeType: String,
    val sha256: String
)

data class CloudOperationState(
    val running: Boolean = false,
    val indeterminate: Boolean = false,
    val completedBytes: Long = 0L,
    val totalBytes: Long? = null,
    val label: String? = null,
    val error: String? = null
)

data class ManagedFile(
    val uri: String,
    val documentId: String,
    val name: String,
    val mimeType: String,
    val sizeBytes: Long,
    val lastModifiedEpochMs: Long,
    val isDirectory: Boolean
)

data class FileScanProgress(
    val running: Boolean = false,
    val current: Int = 0,
    val total: Int = 0,
    val currentName: String? = null,
    val scanned: Int = 0,
    val skipped: Int = 0,
    val errors: Int = 0
)

data class DuplicateFileGroup(
    val sha256: String,
    val sizeBytes: Long,
    val files: List<ManagedFile>
)

data class ManagedFileListing(
    val treeUri: String,
    val documentId: String,
    val files: List<ManagedFile>
)

enum class DirectDownloadStatus {
    INSPECTING, READY, QUEUED, RUNNING, PAUSED_BY_SYSTEM, COMPLETED, FAILED, CANCELLED
}

data class DirectDownload(
    val id: String,
    val systemDownloadId: Long?,
    val sourceUrl: String,
    val fileName: String,
    val mimeType: String,
    val destinationUri: String?,
    val status: DirectDownloadStatus,
    val downloadedBytes: Long,
    val totalBytes: Long?,
    val createdAtEpochMs: Long,
    val updatedAtEpochMs: Long,
    val error: String?,
    val integrityStatus: String?
)

data class InspectedMedia(
    val url: String,
    val finalUrl: String,
    val fileName: String,
    val mimeType: String,
    val sizeBytes: Long?
)
