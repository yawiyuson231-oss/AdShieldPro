package com.adshield.pro.cloud.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Wire models for the CyberShield Cloud API (see cloud/worker).
 * All responses are decoded with `ignoreUnknownKeys = true`, so the server can evolve
 * additively without breaking installed clients.
 */

@Serializable
data class CloudErrorDto(val error: CloudErrorBody? = null)

@Serializable
data class CloudErrorBody(
    val code: String = "unknown",
    val message: String = "Unknown error",
    val details: Map<String, String>? = null,
    val requestId: String? = null
)

@Serializable
data class CloudMetaDto(
    val service: String = "",
    val apiVersion: Int = 0,
    val storageProvider: String = "",
    val defaultQuotaBytes: Long = 0,
    val globalSafetyCapBytes: Long = 0,
    val maxSingleUploadBytes: Long = 0,
    val partSizeBytes: Long = 0,
    val signedUrlTtlSeconds: Int = 0,
    val trashRetentionDays: Int = 0,
    val dailyRequestBudget: Int = 0,
    val turnstileSiteKey: String? = null,
    val botProtection: Boolean = false,
    val encryptionAtRest: String = "",
    val clientSideEncryption: String = "",
    val paidFeaturesEnabled: Boolean = true
)

@Serializable
data class CloudHealthDto(
    val status: String = "unknown",
    val service: String = "",
    val version: String = "",
    val environment: String = "",
    val storageProvider: String = "",
    val database: String = "",
    val storage: String = "",
    val configurationProblems: List<String> = emptyList()
)

@Serializable
data class CloudUserDto(
    val id: String = "",
    val email: String? = null,
    val displayName: String? = null,
    val tier: String = "free",
    val status: String = "active",
    val createdAt: Long = 0,
    val clientEncryption: Boolean = false
)

@Serializable
data class CloudQuotaDto(
    val quotaBytes: Long = 0,
    val usedBytes: Long = 0,
    val remainingBytes: Long = 0,
    val percentUsed: Double = 0.0,
    val globalCapBytes: Long = 0,
    val globalUsedBytes: Long = 0,
    val globalRemainingBytes: Long = 0,
    val providerFreeBytes: Long = 0,
    val tier: String = "free",
    val canUpload: Boolean = false
)

@Serializable
data class CloudFileStatsDto(
    val files: Int = 0,
    val folders: Int = 0,
    val bytes: Long = 0
)

@Serializable
data class CloudBackupStatsDto(val count: Int = 0, val bytes: Long = 0)

@Serializable
data class CloudDailyUsageDto(
    val day: String = "",
    val requests: Int = 0,
    val requestBudget: Int = 0,
    val percentOfBudget: Double = 0.0,
    val bytesUp: Long = 0,
    val bytesDown: Long = 0,
    val remainingRequests: Int = 0
)

@Serializable
data class CloudProviderDto(
    val name: String = "",
    val maxSingleUploadBytes: Long = 0,
    val partSizeBytes: Long = 0,
    val freeTierBytes: Long = 0
)

@Serializable
data class CloudAccountDto(
    val user: CloudUserDto = CloudUserDto(),
    val quota: CloudQuotaDto = CloudQuotaDto(),
    val files: CloudFileStatsDto = CloudFileStatsDto(),
    val backups: CloudBackupStatsDto = CloudBackupStatsDto(),
    val dailyUsage: CloudDailyUsageDto = CloudDailyUsageDto(),
    val provider: CloudProviderDto = CloudProviderDto()
)

@Serializable
data class CloudNodeDto(
    val id: String = "",
    val parentId: String? = null,
    val name: String = "",
    val kind: String = "file",
    val mime: String? = null,
    val size: Long = 0,
    val sha256: String? = null,
    val provider: String = "",
    val version: Int = 0,
    val status: String = "active",
    val encrypted: Boolean = false,
    val scanStatus: String = "not_scanned",
    val scanDetail: String? = null,
    val downloadCount: Long = 0,
    val createdAt: Long = 0,
    val updatedAt: Long = 0,
    val trashedAt: Long? = null,
    val extension: String = ""
) {
    val isFolder: Boolean get() = kind == "folder"
    val isImage: Boolean get() = mime?.startsWith("image/") == true
    val isVideo: Boolean get() = mime?.startsWith("video/") == true
    val isAudio: Boolean get() = mime?.startsWith("audio/") == true
    val isQuarantined: Boolean get() = status == "quarantined"
}

@Serializable
data class CloudPageDto(
    val items: List<CloudNodeDto> = emptyList(),
    val nextCursor: String? = null,
    val totalSize: Long = 0
)

@Serializable
data class CloudNodeDetailDto(
    val node: CloudNodeDto = CloudNodeDto(),
    val versions: List<CloudVersionDto> = emptyList(),
    val folderStats: CloudFolderStatsDto? = null
)

@Serializable
data class CloudFolderStatsDto(val count: Int = 0, val bytes: Long = 0)

@Serializable
data class CloudVersionDto(
    val id: String = "",
    val version: Int = 0,
    val size: Long = 0,
    val sha256: String? = null,
    val provider: String = "",
    val createdAt: Long = 0
)

@Serializable
data class CloudVersionsDto(val currentVersion: Int = 0, val versions: List<CloudVersionDto> = emptyList())

@Serializable
data class CloudDuplicateDto(
    val nodeId: String = "",
    val name: String = "",
    val size: Long = 0,
    val referenceCreated: Boolean = false
)

@Serializable
data class CloudPartRefDto(val partNumber: Int = 0, val size: Long = 0)

@Serializable
data class CloudInitUploadDto(
    val uploadId: String = "",
    val mode: String = "single",
    val partSize: Long = 0,
    val partsTotal: Int = 0,
    val expiresAt: Long = 0,
    val nodeId: String? = null,
    val duplicate: CloudDuplicateDto? = null,
    val maxSingleUploadBytes: Long = 0,
    val uploadToken: String? = null,
    val uploadTokenExpiresAt: Long = 0,
    val uploadUrls: Map<String, String>? = null
)

@Serializable
data class CloudUploadStateDto(
    val id: String = "",
    val name: String = "",
    val size: Long = 0,
    val uploadType: String = "single",
    val partSize: Long = 0,
    val partsTotal: Int = 0,
    val status: String = "pending",
    val bytesReceived: Long = 0,
    val acceptedParts: List<CloudPartRefDto> = emptyList(),
    val missingParts: List<Int> = emptyList(),
    val uploadToken: String? = null,
    val expiresAt: Long = 0
)

@Serializable
data class CloudScanDto(
    val verdict: String = "clean",
    val findings: Int = 0,
    val engine: String = ""
)

@Serializable
data class CloudCompleteUploadDto(
    val status: String = "",
    val nodeId: String? = null,
    val backupId: String? = null,
    val size: Long = 0,
    val sha256: String? = null,
    val sha256Verified: Boolean = false,
    val scan: CloudScanDto? = null,
    val warning: String? = null
)

@Serializable
data class CloudPartResultDto(
    val uploadId: String = "",
    val partNumber: Int = 0,
    val etag: String = "",
    val size: Long = 0,
    val partsDone: Int = 0,
    val partsTotal: Int = 0
)

@Serializable
data class CloudDownloadTicketDto(
    val url: String = "",
    val expiresAt: Long = 0,
    val fileName: String = "",
    val size: Long = 0,
    val mime: String? = null,
    val sha256: String? = null,
    val encrypted: Boolean = false
)

@Serializable
data class CloudVerifyDto(
    val matches: Boolean = false,
    val computedSha256: String = "",
    val recordedSha256: String? = null,
    val size: Long = 0
)

@Serializable
data class CloudShareDto(
    val id: String = "",
    val nodeId: String = "",
    val fileName: String = "",
    val expiresAt: Long = 0,
    val maxDownloads: Int = 0,
    val downloadCount: Int = 0,
    val passwordProtected: Boolean = false,
    val allowPreview: Boolean = true,
    val revoked: Boolean = false,
    val createdAt: Long = 0,
    val lastAccessAt: Long? = null
) {
    val isExpired: Boolean get() = expiresAt in 1 until System.currentTimeMillis()
}

@Serializable
data class CloudShareListDto(val shares: List<CloudShareDto> = emptyList())

@Serializable
data class CloudCreatedShareDto(
    val share: CloudShareDto = CloudShareDto(),
    val token: String = "",
    val shareUrl: String = "",
    val note: String = ""
)

@Serializable
data class CloudBackupDto(
    val id: String = "",
    val kind: String = "",
    val label: String = "",
    val schemaVersion: Int = 1,
    val size: Long = 0,
    val sha256: String = "",
    val encrypted: Boolean = true,
    val appVersion: String? = null,
    val deviceLabel: String? = null,
    val ruleCount: Int = 0,
    val integrityOk: Boolean = true,
    val verifiedAt: Long? = null,
    val restoredAt: Long? = null,
    val createdAt: Long = 0
)

@Serializable
data class CloudBackupListDto(
    val backups: List<CloudBackupDto> = emptyList(),
    val totalBytes: Long = 0,
    val kinds: List<String> = emptyList()
)

@Serializable
data class CloudBackupInitDto(
    val uploadId: String = "",
    val mode: String = "single",
    val partSize: Long = 0,
    val partsTotal: Int = 0,
    val uploadToken: String? = null,
    val uploadUrl: String? = null,
    val kind: String = "",
    val label: String = "",
    val encryptionNote: String? = null,
    val expiresAt: Long = 0
)

@Serializable
data class CloudBackupVerifyDto(
    val matches: Boolean = false,
    val computedSha256: String = "",
    val backup: CloudBackupDto = CloudBackupDto()
)

@Serializable
data class CloudBackupRestoreDto(
    val url: String = "",
    val expiresAt: Long = 0,
    val sha256: String = "",
    val size: Long = 0,
    val kind: String = "",
    val schemaVersion: Int = 1
)

@Serializable
data class CloudAuditEntryDto(
    val id: String = "",
    val action: String = "",
    val targetType: String? = null,
    val targetId: String? = null,
    val success: Boolean = true,
    val ipHash: String? = null,
    val detail: String? = null,
    val createdAt: Long = 0
)

@Serializable
data class CloudAuditListDto(val entries: List<CloudAuditEntryDto> = emptyList())

@Serializable
data class CloudQuarantineItemDto(
    val id: String = "",
    val name: String = "",
    val size: Long = 0,
    val scanStatus: String = "",
    val detail: String? = null,
    val updatedAt: Long = 0
)

@Serializable
data class CloudScanCountsDto(
    val engine: String = "",
    val counts: Map<String, Int> = emptyMap(),
    val quarantined: List<CloudQuarantineItemDto> = emptyList()
)

@Serializable
data class CloudEncryptionDto(
    val inTransit: String = "",
    val atRest: String = "",
    val clientSide: String = "",
    val signedUrlTtlSeconds: Int = 0
)

@Serializable
data class CloudShareSummaryDto(
    val active: Int = 0,
    val total: Int = 0,
    val passwordProtected: Int = 0
)

@Serializable
data class CloudRecentEventDto(
    val action: String = "",
    val success: Boolean = true,
    val createdAt: Long = 0
)

@Serializable
data class CloudSecurityDto(
    val encryption: CloudEncryptionDto = CloudEncryptionDto(),
    val scanning: CloudScanCountsDto = CloudScanCountsDto(),
    val shares: CloudShareSummaryDto = CloudShareSummaryDto(),
    val recentEvents: List<CloudRecentEventDto> = emptyList()
)

/** Supabase GoTrue session payload. */
@Serializable
data class CloudAuthSessionDto(
    @SerialName("access_token") val accessToken: String = "",
    @SerialName("refresh_token") val refreshToken: String = "",
    @SerialName("expires_in") val expiresIn: Long = 3600,
    @SerialName("token_type") val tokenType: String = "bearer",
    val user: CloudAuthUserDto? = null
)

@Serializable
data class CloudAuthUserDto(
    val id: String = "",
    val email: String? = null,
    @SerialName("email_confirmed_at") val emailConfirmedAt: String? = null
)

@Serializable
data class CloudStatsDto(
    val usage: CloudFolderStatsDto = CloudFolderStatsDto(),
    val byCategory: Map<String, Long> = emptyMap(),
    val recentUploads: List<CloudNodeDto> = emptyList(),
    val recentDownloads: List<CloudNodeDto> = emptyList()
)

@Serializable
data class CloudUploadListDto(val uploads: List<CloudUploadStateDto> = emptyList())
