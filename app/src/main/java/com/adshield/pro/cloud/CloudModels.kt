package com.adshield.pro.cloud

import kotlinx.serialization.Serializable

/**
 * Wire models for the AdShield cloud backend (see cloud-worker/src/index.js).
 * All JSON is produced/consumed only over HTTPS against the user-configured Worker.
 */

@Serializable
data class AuthSession(
    val accessToken: String,
    val refreshToken: String = "",
    val userId: String,
    val email: String,
    val expiresAtEpochSec: Long
)

@Serializable
data class QuotaInfo(
    val quotaBytes: Long,
    val usedBytes: Long,
    val fileCount: Long,
    val uploadCountAllTime: Long = 0L,
    val downloadCountAllTime: Long = 0L
) {
    val remainingBytes: Long get() = (quotaBytes - usedBytes).coerceAtLeast(0L)
}

@Serializable
data class CloudFile(
    val id: String,
    val name: String,
    val folderPath: String,
    val sizeBytes: Long,
    val mimeType: String,
    val sha256: String,
    val isDeleted: Boolean = false,
    val createdAtEpochMs: Long,
    val updatedAtEpochMs: Long,
    val version: Int = 1
) {
    val kind: CloudFileKind get() = CloudFileKind.fromMime(mimeType)
}

enum class CloudFileKind(val label: String) {
    PHOTO("Photos"), VIDEO("Videos"), DOCUMENT("Documents"), MUSIC("Music"), BACKUP("Backup"), OTHER("Other");

    companion object {
        fun fromMime(mime: String): CloudFileKind = when {
            mime.startsWith("image/") -> PHOTO
            mime.startsWith("video/") -> VIDEO
            mime.startsWith("audio/") -> MUSIC
            mime in DOCUMENT_MIMES || mime.startsWith("text/") || mime.endsWith("pdf") ||
                mime.endsWith("json") || mime.endsWith("xml") -> DOCUMENT
            mime.endsWith("adshield-backup") || mime == "application/x-adshield-backup" -> BACKUP
            else -> OTHER
        }

        private val DOCUMENT_MIMES = setOf(
            "application/pdf",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.ms-excel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.ms-powerpoint",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/zip",
            "application/json"
        )
    }
}

@Serializable
data class CloudFileVersion(
    val version: Int,
    val sizeBytes: Long,
    val sha256: String,
    val createdAtEpochMs: Long
)

@Serializable
data class ShareLink(
    val id: String,
    val fileId: String,
    val fileName: String,
    val expiresAtEpochMs: Long,
    val maxDownloads: Int,
    val downloadCount: Int,
    val createdAtEpochMs: Long
) {
    fun isExpired(nowEpochMs: Long): Boolean = expiresAtEpochMs <= nowEpochMs
}

@Serializable
data class SignedUrlResponse(
    val url: String,
    val method: String,
    val expiresAtEpochMs: Long,
    val headers: Map<String, String> = emptyMap()
)

@Serializable
data class DnsBackupRecord(
    val id: String,
    val label: String,
    val sha256: String,
    val sizeBytes: Long,
    val createdAtEpochMs: Long,
    val restoredAtEpochMs: Long? = null
)

@Serializable
data class ApiErrorBody(val error: String)

/**
 * Pure helpers — kept free of Android/OkHttp types so the JVM suite can cover them.
 */
object CloudWire {

    /**
     * Extracts the `exp` query parameter (epoch seconds) from a signed URL. Returns null when
     * the URL carries no expiry — such a URL must be rejected by the caller, never trusted.
     */
    fun signedUrlExpiryEpochSec(url: String): Long? {
        val queryStart = url.indexOf('?')
        if (queryStart < 0) return null
        return url.substring(queryStart + 1)
            .split('&')
            .firstOrNull { it.startsWith("exp=") }
            ?.substringAfter('=')
            ?.toLongOrNull()
    }

    /** True when [url] is a signed URL whose expiry is still in the future. */
    fun isSignedUrlValid(url: String, nowEpochMs: Long, maxTtlSeconds: Long = CloudConfig.MAX_SIGNED_URL_TTL_SECONDS): Boolean {
        val expSec = signedUrlExpiryEpochSec(url) ?: return false
        val nowSec = nowEpochMs / 1000L
        if (expSec <= nowSec) return false
        return expSec - nowSec <= maxTtlSeconds
    }

    /**
     * Duplicate-detection key: content hash + size. Two files with the same key are byte-identical
     * (SHA-256 collision aside) and the server stores the object once.
     */
    fun dedupeKey(sha256: String, sizeBytes: Long): String = "$sha256:$sizeBytes"

    /** File-type validation against the extension/mime allowlist the Worker also enforces. */
    fun isAllowedFileType(fileName: String, mimeType: String): Boolean {
        val blockedExtensions = setOf("apk", "exe", "scr", "bat", "cmd", "msi", "js", "html", "htm", "svg")
        val ext = fileName.substringAfterLast('.', "").lowercase()
        if (ext in blockedExtensions) return false
        val blockedMimes = setOf("text/html", "image/svg+xml", "application/x-msdownload", "application/javascript")
        return mimeType.lowercase() !in blockedMimes
    }
}
