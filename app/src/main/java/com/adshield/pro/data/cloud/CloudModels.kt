package com.adshield.pro.data.cloud

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Wire models for the AdShield Cloud API (see `cloud/src/index.js`).
 *
 * Every field has a default and unknown keys are ignored, so a newer backend can never crash an
 * older app. Nullability mirrors the database: folders have no size, trashed nodes have a
 * `deletedAt`, and aggregate counts are null when the user owns nothing yet.
 */

// ------------------------------------------------------------------ account

@Serializable
data class CloudAccountDto(
    val id: String = "",
    val email: String = "",
    val createdAt: Long = 0L,
    val quotaBytes: Long = 0L,
    val usedBytes: Long = 0L,
    val retentionDays: Int = 30
)

@Serializable
data class CloudUsageDto(
    val quotaBytes: Long = 0L,
    val usedBytes: Long = 0L,
    val remainingBytes: Long = 0L,
    val percentUsed: Double = 0.0,
    val trashedFiles: Int = 0,
    val trashedBytes: Long = 0L
)

@Serializable
data class CloudQuotaWarningDto(
    val level: String = "ok",
    val message: String = ""
)

@Serializable
data class CloudLimitsDto(
    val hourlyRequests: Long = 0L,
    val note: String = ""
)

@Serializable
data class AccountResponseDto(
    val account: CloudAccountDto = CloudAccountDto(),
    val usage: CloudUsageDto = CloudUsageDto(),
    val warning: CloudQuotaWarningDto = CloudQuotaWarningDto(),
    val apiRequestsLast24h: Long = 0L,
    val limits: CloudLimitsDto = CloudLimitsDto()
)

@Serializable
data class FreeTierDto(
    val storageBytes: Long = 0L,
    val note: String = ""
)

@Serializable
data class HealthDto(
    val ok: Boolean = false,
    val provider: String = "",
    val mode: String = "",
    val freeTier: FreeTierDto = FreeTierDto()
)

@Serializable
data class ReconcileResponseDto(
    val b2Bytes: Long = 0L,
    val b2Objects: Int = 0,
    val databaseBytes: Long = 0L,
    val driftBytes: Long = 0L
)

@Serializable
data class AuditEntryDto(
    val action: String = "",
    val detail: String? = null,
    val ip: String? = null,
    @SerialName("created_at") val createdAt: Long = 0L
)

@Serializable
data class AuditResponseDto(
    val entries: List<AuditEntryDto> = emptyList()
)

// ------------------------------------------------------------------ browsing

@Serializable
data class CloudNodeDto(
    val id: String = "",
    val parentId: String? = null,
    val kind: String = "file",
    val name: String = "",
    val sizeBytes: Long? = null,
    val contentType: String? = null,
    val sha1: String? = null,
    val createdAt: Long = 0L,
    val updatedAt: Long = 0L,
    val deletedAt: Long? = null,
    val purgeAt: Long? = null
) {
    val isFolder: Boolean get() = kind == "folder"
    val size: Long get() = sizeBytes ?: 0L
}

@Serializable
data class NodesResponseDto(
    val nodes: List<CloudNodeDto> = emptyList()
)

@Serializable
data class KindCountsDto(
    val photos: Long? = null,
    val videos: Long? = null,
    val audio: Long? = null,
    val documents: Long? = null,
    val total: Long? = null
) {
    fun photosOrZero(): Long = photos ?: 0L
    fun videosOrZero(): Long = videos ?: 0L
    fun audioOrZero(): Long = audio ?: 0L
    fun documentsOrZero(): Long = documents ?: 0L
    fun totalOrZero(): Long = total ?: 0L
}

@Serializable
data class KindCountsResponseDto(
    val counts: KindCountsDto = KindCountsDto()
)

@Serializable
data class FolderResponseDto(
    val node: CloudNodeDto = CloudNodeDto()
)

/** rename / move / copy / delete / restore / purge all answer with this shape. */
@Serializable
data class NodeActionResponseDto(
    val node: CloudNodeDto? = null,
    val trashed: Boolean = false,
    val restored: Boolean = false,
    val purged: Boolean = false,
    val purgeAt: Long? = null,
    val error: String? = null
)

@Serializable
data class NodeVersionDto(
    val version: Int = 0,
    @SerialName("size_bytes") val sizeBytes: Long = 0L,
    val sha1: String? = null,
    @SerialName("created_at") val createdAt: Long = 0L
)

@Serializable
data class VersionsResponseDto(
    val versions: List<NodeVersionDto> = emptyList()
)

@Serializable
data class DownloadResponseDto(
    val url: String = "",
    val expiresInSeconds: Long = 0L,
    val sizeBytes: Long? = null,
    val sha1: String? = null
)

@Serializable
data class DuplicateGroupDto(
    val sha1: String = "",
    val copies: Int = 0,
    val bytes: Long = 0L,
    val names: List<String> = emptyList()
)

@Serializable
data class DuplicatesResponseDto(
    val groups: List<DuplicateGroupDto> = emptyList()
)

// ------------------------------------------------------------------ uploads

@Serializable
data class UploadPartTicketDto(
    val partNumber: Int = 0,
    val uploadUrl: String = "",
    val token: String = ""
)

@Serializable
data class UploadInitResponseDto(
    val sessionId: String = "",
    val nodeId: String = "",
    val key: String = "",
    val partSize: Long = 0L,
    val totalParts: Int = 1,
    val multipart: Boolean = false,
    val parts: List<UploadPartTicketDto> = emptyList()
)

@Serializable
data class UploadSessionDto(
    val id: String = "",
    val name: String = "",
    val status: String = "open",
    val declaredSize: Long = 0L,
    val partSize: Long = 0L,
    val totalParts: Int = 0,
    val uploadedParts: List<Int> = emptyList(),
    val uploadedBytes: Long = 0L
)

@Serializable
data class UploadStatusResponseDto(
    val session: UploadSessionDto = UploadSessionDto(),
    val partUrls: List<UploadPartTicketDto> = emptyList()
)

@Serializable
data class UploadPartResponseDto(
    val partNumber: Int = 0,
    val uploadedBytes: Long = 0L
)

@Serializable
data class UploadCompleteResponseDto(
    val node: CloudNodeDto = CloudNodeDto(),
    val replaced: Boolean = false
)

@Serializable
data class UploadCancelResponseDto(
    val cancelled: Boolean = false
)

// ------------------------------------------------------------------ sharing

@Serializable
data class CloudShareDto(
    val id: String = "",
    val token: String = "",
    val url: String = "",
    val expiresAt: Long? = null,
    val permission: String = "read"
)

@Serializable
data class ShareCreateResponseDto(
    val share: CloudShareDto = CloudShareDto()
)

@Serializable
data class ShareRowDto(
    val id: String = "",
    val token: String = "",
    @SerialName("node_id") val nodeId: String = "",
    @SerialName("expires_at") val expiresAt: Long? = null,
    @SerialName("created_at") val createdAt: Long = 0L,
    val downloads: Long = 0L,
    val name: String = "",
    @SerialName("size_bytes") val sizeBytes: Long? = null
)

@Serializable
data class ShareListResponseDto(
    val shares: List<ShareRowDto> = emptyList()
)

@Serializable
data class PublicShareDto(
    val name: String = "",
    val sizeBytes: Long = 0L,
    val contentType: String = "",
    val url: String = "",
    val expiresInSeconds: Long = 0L
)

// ------------------------------------------------------------------ backups

@Serializable
data class BackupInitResponseDto(
    val backupId: String = "",
    val key: String = "",
    val uploadUrl: String = "",
    val token: String = ""
)

@Serializable
data class BackupCommitResponseDto(
    val backupId: String = "",
    val sizeBytes: Long = 0L,
    val sha256: String = "",
    val verified: Boolean = false
)

@Serializable
data class BackupRowDto(
    val id: String = "",
    val kind: String = "full_config",
    val label: String = "",
    @SerialName("size_bytes") val sizeBytes: Long = 0L,
    val sha256: String = "",
    @SerialName("created_at") val createdAt: Long = 0L,
    @SerialName("restored_at") val restoredAt: Long? = null
)

@Serializable
data class BackupListResponseDto(
    val backups: List<BackupRowDto> = emptyList()
)

@Serializable
data class BackupDetailResponseDto(
    val backup: BackupRowDto = BackupRowDto(),
    val url: String = ""
)

@Serializable
data class BackupRestoreResponseDto(
    val backupId: String = "",
    val sha256: String = "",
    val sizeBytes: Long = 0L,
    val url: String = ""
)

// ------------------------------------------------------------------ UI helpers

enum class CloudFileKind(val label: String) {
    PHOTO("Photo"),
    VIDEO("Video"),
    AUDIO("Audio"),
    DOCUMENT("Document"),
    ARCHIVE("Archive"),
    OTHER("File")
}

/** Classifies a node by its real MIME type, never by a hard-coded extension guess alone. */
fun CloudNodeDto.fileKind(): CloudFileKind {
    if (isFolder) return CloudFileKind.OTHER
    val type = contentType?.substringBefore(';')?.trim()?.lowercase().orEmpty()
    return when {
        type.startsWith("image/") -> CloudFileKind.PHOTO
        type.startsWith("video/") -> CloudFileKind.VIDEO
        type.startsWith("audio/") -> CloudFileKind.AUDIO
        type == "application/pdf" || type.startsWith("text/") -> CloudFileKind.DOCUMENT
        type in DOCUMENT_MIME_TYPES -> CloudFileKind.DOCUMENT
        type in ARCHIVE_MIME_TYPES -> CloudFileKind.ARCHIVE
        else -> extensionKind(name)
    }
}

private fun extensionKind(name: String): CloudFileKind {
    val ext = name.substringAfterLast('.', "").lowercase()
    return when (ext) {
        "jpg", "jpeg", "png", "gif", "webp", "heic", "avif", "bmp" -> CloudFileKind.PHOTO
        "mp4", "mkv", "webm", "mov", "avi", "m4v", "3gp" -> CloudFileKind.VIDEO
        "mp3", "flac", "wav", "ogg", "m4a", "aac", "opus" -> CloudFileKind.AUDIO
        "pdf", "txt", "md", "csv", "json", "xml", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "odt", "ods", "rtf", "epub" -> CloudFileKind.DOCUMENT
        "zip", "rar", "7z", "tar", "gz", "bz2", "xz" -> CloudFileKind.ARCHIVE
        else -> CloudFileKind.OTHER
    }
}

private val DOCUMENT_MIME_TYPES = setOf(
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.oasis.opendocument.text",
    "application/json",
    "application/xml"
)

private val ARCHIVE_MIME_TYPES = setOf(
    "application/zip",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/gzip",
    "application/x-tar"
)

/** Human-readable size that never invents precision: 1 048 576 B stays "1.0 MB", not "1 MB". */
fun formatCloudBytes(bytes: Long): String {
    if (bytes < 0) return "0 B"
    if (bytes < 1024) return "$bytes B"
    val units = arrayOf("KB", "MB", "GB", "TB")
    var value = bytes / 1024.0
    var unit = 0
    while (value >= 1024 && unit < units.lastIndex) {
        value /= 1024
        unit += 1
    }
    val decimals = if (value < 10) 1 else 0
    return "${"%.${decimals}f".format(java.util.Locale.US, value)} ${units[unit]}"
}
