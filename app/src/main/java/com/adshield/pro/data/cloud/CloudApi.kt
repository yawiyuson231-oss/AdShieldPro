package com.adshield.pro.data.cloud

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/** Supplies the Supabase access token for the signed-in user, or null when signed out. */
fun interface CloudTokenProvider {
    suspend fun accessToken(): String?
}

class CloudException(
    val status: Int,
    val code: String,
    val detail: String? = null
) : Exception("cloud api error $status: $code")

/**
 * Typed client for the AdShield Cloud API.
 *
 * The client only ever handles signed-in-user endpoints and short-lived storage URLs: no bucket
 * credentials exist anywhere in the app, so none can be extracted from the APK.
 */
interface CloudApi {

    suspend fun health(): HealthDto

    // account
    suspend fun register(turnstileToken: String): AccountResponseDto
    suspend fun account(): AccountResponseDto
    suspend fun reconcile(): ReconcileResponseDto
    suspend fun audit(): List<AuditEntryDto>

    // browsing
    suspend fun nodes(
        parentId: String? = null,
        kind: String? = null,
        search: String? = null,
        trashed: Boolean = false,
        recursive: Boolean = false
    ): List<CloudNodeDto>

    suspend fun kinds(): KindCountsDto
    suspend fun createFolder(name: String, parentId: String?): CloudNodeDto
    suspend fun rename(nodeId: String, name: String): NodeActionResponseDto
    suspend fun move(nodeId: String, parentId: String?): NodeActionResponseDto
    suspend fun copy(nodeId: String): NodeActionResponseDto
    suspend fun trash(nodeId: String): NodeActionResponseDto
    suspend fun restore(nodeId: String): NodeActionResponseDto
    suspend fun purge(nodeId: String): NodeActionResponseDto
    suspend fun versions(nodeId: String): List<NodeVersionDto>
    suspend fun downloadUrl(nodeId: String): DownloadResponseDto
    suspend fun duplicates(): List<DuplicateGroupDto>

    // uploads
    suspend fun initUpload(
        name: String,
        size: Long,
        parentId: String? = null,
        contentType: String? = null
    ): UploadInitResponseDto

    suspend fun uploadStatus(sessionId: String): UploadStatusResponseDto
    suspend fun recordPart(
        sessionId: String,
        partNumber: Int,
        size: Long,
        sha1: String
    ): UploadPartResponseDto

    suspend fun completeUpload(sessionId: String): UploadCompleteResponseDto
    suspend fun cancelUpload(sessionId: String): Boolean

    // sharing
    suspend fun createShare(nodeId: String, expiresInSeconds: Long): CloudShareDto
    suspend fun shares(): List<ShareRowDto>
    suspend fun revokeShare(shareId: String): Boolean
    suspend fun openShare(token: String): PublicShareDto

    // backups
    suspend fun initBackup(kind: String, label: String, size: Long): BackupInitResponseDto
    suspend fun commitBackup(backupId: String, size: Long, sha256: String): BackupCommitResponseDto
    suspend fun backups(): List<BackupRowDto>
    suspend fun backupDetail(backupId: String): BackupDetailResponseDto
    suspend fun restoreBackup(backupId: String): BackupRestoreResponseDto
    suspend fun deleteBackup(backupId: String): Boolean
}

class CloudApiClient internal constructor(
    private val http: OkHttpClient,
    private val baseUrl: () -> String,
    private val tokenProvider: CloudTokenProvider,
    private val json: Json = defaultCloudJson()
) : CloudApi {

    /** Exposed so the upload engine can stream bytes straight to the storage provider. */
    val httpClient: OkHttpClient get() = http

    constructor(http: OkHttpClient, baseUrl: String, tokenProvider: CloudTokenProvider) :
        this(http, { baseUrl }, tokenProvider, defaultCloudJson())

    // ---------------------------------------------------------------- plumbing

    private fun url(path: String, block: (okhttp3.HttpUrl.Builder) -> Unit = {}): okhttp3.HttpUrl {
        val configured = baseUrl().trim().ifBlank { "https://unconfigured.invalid/" }
        val base = (if (configured.endsWith('/')) configured else "$configured/").toHttpUrl()
        return base.newBuilder().addPathSegments(path.trimStart('/')).apply(block).build()
    }

    private suspend fun call(request: Request): String = withContext(Dispatchers.IO) {
        http.newCall(request).execute().use { response ->
            val body = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw parseError(response.code, body)
            }
            body
        }
    }

    private suspend fun get(path: String, block: (okhttp3.HttpUrl.Builder) -> Unit = {}): String =
        call(authorized(url(path, block)).get().build())

    private suspend fun post(path: String, body: String = "{}"): String =
        call(authorized(url(path)).post(body.toRequestBody(JSON_MEDIA_TYPE)).build())

    private suspend fun delete(path: String): String =
        call(authorized(url(path)).delete().build())

    /**
     * `detail` is documented as free-form JSON and the server sends an object for quota errors
     * (`{"requestedBytes":…,"remainingBytes":…}`). Typing it as a String made the whole body fail
     * to decode, which threw away the server's real error code and message.
     */
    @kotlinx.serialization.Serializable
    private class ErrorBodyDto(val error: String? = null, val detail: JsonElement? = null)

    private fun parseError(status: Int, body: String): CloudException {
        val parsed = runCatching { json.decodeFromString<ErrorBodyDto>(body) }.getOrNull()
        return CloudException(status, parsed?.error ?: "http $status", parsed?.detail?.toString())
    }

    private suspend fun authorized(target: okhttp3.HttpUrl): Request.Builder {
        val builder = Request.Builder().url(target)
        val token = tokenProvider.accessToken()
        if (!token.isNullOrBlank()) builder.addHeader("Authorization", "Bearer $token")
        return builder
    }

    private inline fun <reified T> decode(raw: String): T = json.decodeFromString(raw)

    // ---------------------------------------------------------------- endpoints

    override suspend fun health(): HealthDto = decode(get("/v1/health"))

    override suspend fun register(turnstileToken: String): AccountResponseDto =
        decode(post("/v1/account/register", json.encodeToString(mapOf("turnstileToken" to turnstileToken))))

    override suspend fun account(): AccountResponseDto = decode(get("/v1/account"))

    override suspend fun reconcile(): ReconcileResponseDto = decode(post("/v1/account/reconcile"))

    override suspend fun audit(): List<AuditEntryDto> = decode<AuditResponseDto>(get("/v1/audit")).entries

    override suspend fun nodes(
        parentId: String?,
        kind: String?,
        search: String?,
        trashed: Boolean,
        recursive: Boolean
    ): List<CloudNodeDto> = decode<NodesResponseDto>(
        get("/v1/nodes") {
            if (trashed) it.addQueryParameter("trashed", "1")
            else if (recursive) it.addQueryParameter("recursive", "1")
            else if (parentId != null) it.addQueryParameter("parentId", parentId)
            if (!kind.isNullOrBlank() && kind != "all") it.addQueryParameter("kind", kind)
            if (!search.isNullOrBlank()) it.addQueryParameter("search", search)
        }
    ).nodes

    override suspend fun kinds(): KindCountsDto = decode<KindCountsResponseDto>(get("/v1/nodes/kinds")).counts

    override suspend fun createFolder(name: String, parentId: String?): CloudNodeDto =
        decode<FolderResponseDto>(post("/v1/folders", json.encodeToString(FolderRequest(name, parentId)))).node

    override suspend fun rename(nodeId: String, name: String): NodeActionResponseDto =
        decode(post("/v1/nodes/$nodeId/rename", json.encodeToString(mapOf("name" to name))))

    override suspend fun move(nodeId: String, parentId: String?): NodeActionResponseDto =
        decode(post("/v1/nodes/$nodeId/move", json.encodeToString(mapOf("parentId" to parentId))))

    override suspend fun copy(nodeId: String): NodeActionResponseDto =
        decode(post("/v1/nodes/$nodeId/copy"))

    override suspend fun trash(nodeId: String): NodeActionResponseDto =
        decode(post("/v1/nodes/$nodeId/delete"))

    override suspend fun restore(nodeId: String): NodeActionResponseDto =
        decode(post("/v1/nodes/$nodeId/restore"))

    override suspend fun purge(nodeId: String): NodeActionResponseDto =
        decode(delete("/v1/nodes/$nodeId"))

    override suspend fun versions(nodeId: String): List<NodeVersionDto> =
        decode<VersionsResponseDto>(get("/v1/nodes/$nodeId/versions")).versions

    override suspend fun downloadUrl(nodeId: String): DownloadResponseDto =
        decode(get("/v1/nodes/$nodeId/download"))

    override suspend fun duplicates(): List<DuplicateGroupDto> =
        decode<DuplicatesResponseDto>(get("/v1/duplicates")).groups

    override suspend fun initUpload(
        name: String,
        size: Long,
        parentId: String?,
        contentType: String?
    ): UploadInitResponseDto = decode(
        post(
            "/v1/uploads/init",
            json.encodeToString(UploadInitRequest(name, size, parentId, contentType))
        )
    )

    override suspend fun uploadStatus(sessionId: String): UploadStatusResponseDto =
        decode(get("/v1/uploads/$sessionId"))

    override suspend fun recordPart(
        sessionId: String,
        partNumber: Int,
        size: Long,
        sha1: String
    ): UploadPartResponseDto = decode(
        post("/v1/uploads/$sessionId/part/$partNumber", json.encodeToString(UploadPartRequest(size, sha1)))
    )

    override suspend fun completeUpload(sessionId: String): UploadCompleteResponseDto =
        decode(post("/v1/uploads/$sessionId/complete"))

    override suspend fun cancelUpload(sessionId: String): Boolean =
        decode<UploadCancelResponseDto>(post("/v1/uploads/$sessionId/cancel")).cancelled

    override suspend fun createShare(nodeId: String, expiresInSeconds: Long): CloudShareDto =
        decode<ShareCreateResponseDto>(
            post("/v1/shares", json.encodeToString(ShareRequest(nodeId, expiresInSeconds)))
        ).share

    override suspend fun shares(): List<ShareRowDto> =
        decode<ShareListResponseDto>(get("/v1/shares")).shares

    override suspend fun revokeShare(shareId: String): Boolean {
        delete("/v1/shares/$shareId")
        return true
    }

    override suspend fun openShare(token: String): PublicShareDto = decode(get("/v1/share/$token"))

    override suspend fun initBackup(kind: String, label: String, size: Long): BackupInitResponseDto =
        decode(post("/v1/backups/init", json.encodeToString(BackupInitRequest(kind, label, size))))

    override suspend fun commitBackup(
        backupId: String,
        size: Long,
        sha256: String
    ): BackupCommitResponseDto = decode(
        post("/v1/backups/$backupId/commit", json.encodeToString(BackupCommitRequest(size, sha256)))
    )

    override suspend fun backups(): List<BackupRowDto> =
        decode<BackupListResponseDto>(get("/v1/backups")).backups

    override suspend fun backupDetail(backupId: String): BackupDetailResponseDto =
        decode(get("/v1/backups/$backupId"))

    override suspend fun restoreBackup(backupId: String): BackupRestoreResponseDto =
        decode(post("/v1/backups/$backupId/restore"))

    override suspend fun deleteBackup(backupId: String): Boolean {
        delete("/v1/backups/$backupId")
        return true
    }

    // ---------------------------------------------------------------- request bodies

    @kotlinx.serialization.Serializable
    private class FolderRequest(val name: String, val parentId: String?)

    @kotlinx.serialization.Serializable
    private class UploadInitRequest(
        val name: String,
        val size: Long,
        val parentId: String? = null,
        val contentType: String? = null
    )

    @kotlinx.serialization.Serializable
    private class UploadPartRequest(val size: Long, val sha1: String)

    @kotlinx.serialization.Serializable
    private class ShareRequest(val nodeId: String, val expiresInSeconds: Long)

    @kotlinx.serialization.Serializable
    private class BackupInitRequest(val kind: String, val label: String, val size: Long)

    @kotlinx.serialization.Serializable
    private class BackupCommitRequest(val size: Long, val sha256: String)

    private companion object {
        val JSON_MEDIA_TYPE = "application/json".toMediaType()
    }
}

fun defaultCloudJson(): Json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
    explicitNulls = false
}
