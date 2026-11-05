package com.adshield.pro.domain.model

import kotlinx.serialization.Serializable

/**
 * Search providers receive queries and network metadata; private mode does not change that fact.
 *
 * Honesty note: choosing Google still sends the query to Google, and Google may log it. The
 * provider label says so rather than implying the app makes Google anonymous.
 */
@Serializable
enum class SearchProvider(
    val label: String,
    val homeUrl: String,
    val privacyNote: String
) {
    DUCKDUCKGO(
        label = "DuckDuckGo",
        homeUrl = "https://duckduckgo.com/",
        privacyNote = "Default. Does not build a search history profile tied to you."
    ),
    GOOGLE(
        label = "Google",
        homeUrl = "https://www.google.com/",
        privacyNote = "Google receives and may log your query. Tracking-parameter stripping and " +
            "cookie blocking still apply, but the query itself is not anonymous."
    );

    /** Query prefix used by [com.adshield.pro.engine.browser.PrivateSearch.navigationTarget]. */
    val searchBaseUrl: String
        get() = when (this) {
            DUCKDUCKGO -> "https://duckduckgo.com/?q="
            GOOGLE -> "https://www.google.com/search?q="
        }

    /** Builds the provider's query URL with the term percent-encoded exactly once. */
    fun searchUrl(query: String): String = searchBaseUrl + percentEncodeQueryComponent(query.trim())

    companion object {
        /** Unknown / legacy / corrupt preference values fall back to the privacy default. */
        fun fromName(raw: String?): SearchProvider =
            entries.firstOrNull { it.name.equals(raw?.trim(), ignoreCase = true) } ?: DUCKDUCKGO
    }
}

private const val HEX_DIGITS = "0123456789ABCDEF"

/**
 * RFC 3986 percent-encoding of a query component. Spaces become `%20`, UTF-8 multibyte characters
 * are encoded per byte, and reserved characters such as `&`, `=` and `+` are escaped so a search
 * term can never inject extra query parameters.
 */
internal fun percentEncodeQueryComponent(value: String): String {
    val bytes = value.toByteArray(Charsets.UTF_8)
    val out = StringBuilder(bytes.size)
    for (byte in bytes) {
        val code = byte.toInt() and 0xFF
        val char = code.toChar()
        val unreserved = char in 'A'..'Z' || char in 'a'..'z' || char in '0'..'9' ||
            char == '-' || char == '_' || char == '.' || char == '~'
        if (unreserved) {
            out.append(char)
        } else {
            out.append('%').append(HEX_DIGITS[code shr 4]).append(HEX_DIGITS[code and 0x0F])
        }
    }
    return out.toString()
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
    val errors: Int = 0,
    val limitReached: Boolean = false
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
