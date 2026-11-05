package com.adshield.pro.cloud.data

import com.adshield.pro.cloud.util.ByteFormat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/** Result wrapper for every cloud call — typed failures instead of exceptions in the UI. */
sealed class CloudResult<out T> {
    data class Success<T>(val value: T) : CloudResult<T>()

    data class Failure(
        val code: String,
        val message: String,
        val httpStatus: Int = 0,
        val retryable: Boolean = false
    ) : CloudResult<Nothing>()

    data object NotConfigured : CloudResult<Nothing>()
    data object NotAuthenticated : CloudResult<Nothing>()
}

inline fun <T, R> CloudResult<T>.map(transform: (T) -> R): CloudResult<R> = when (this) {
    is CloudResult.Success -> CloudResult.Success(transform(value))
    is CloudResult.Failure -> this
    CloudResult.NotConfigured -> CloudResult.NotConfigured
    CloudResult.NotAuthenticated -> CloudResult.NotAuthenticated
}

/**
 * REST client for the CyberShield Cloud Worker.
 *
 * Security properties:
 *  • HTTPS only — a cleartext base URL is refused outright.
 *  • Bearer tokens come from [CloudSessionStore] and are refreshed transparently once.
 *  • No cloud provider credential exists in the APK; object bytes are uploaded to signed
 *    Worker endpoints that carry only short-lived HMAC tokens.
 */
@Singleton
class CloudApiClient @Inject constructor(
    private val httpClient: OkHttpClient,
    private val configRepository: CloudConfigRepository,
    private val sessionStore: CloudSessionStore,
    private val json: Json
) {
    private val refreshMutex = Mutex()

    // ---------------------------------------------------------------- plumbing
    private suspend fun baseUrl(): String? {
        val config = configRepository.snapshot()
        val base = config.apiBaseUrl.trim()
        if (base.isEmpty()) return null
        return if (base.startsWith("http://10.0.2.2") || base.startsWith("http://localhost") || base.startsWith("http://127.0.0.1")) {
            // Emulator-only development loopback stays allowed; every other host must be HTTPS.
            base.trimEnd('/')
        } else if (base.startsWith("https://")) {
            base.trimEnd('/')
        } else {
            null
        }
    }

    private fun errorFrom(response: Response, bodyText: String): CloudResult.Failure {
        val parsed = runCatching { json.decodeFromString(CloudErrorDto.serializer(), bodyText) }.getOrNull()
        val code = parsed?.error?.code ?: "http_${response.code}"
        val message = parsed?.error?.message ?: "Request failed with HTTP ${response.code}"
        val retryable = response.code == 429 || response.code >= 500
        return CloudResult.Failure(code, message, response.code, retryable)
    }

    private fun transportFailure(error: Throwable): CloudResult.Failure {
        val message = when (error) {
            is IOException -> "Network unavailable: ${error.message ?: "connection failed"}"
            else -> error.message ?: "Unexpected cloud error"
        }
        return CloudResult.Failure("network_error", message, 0, retryable = true)
    }

    private suspend fun <T> decoded(
        method: String,
        path: String,
        body: JsonElement? = null,
        authenticated: Boolean = true,
        decoder: (JsonElement) -> T
    ): CloudResult<T> = withContext(Dispatchers.IO) {
        val base = baseUrl() ?: return@withContext CloudResult.NotConfigured
        if (authenticated && sessionStore.current() == null) return@withContext CloudResult.NotAuthenticated

        suspend fun attempt(isRetry: Boolean): CloudResult<T> {
            val session = if (authenticated) ensureSession() else null
            if (authenticated && session == null) return CloudResult.NotAuthenticated

            val builder = Request.Builder().url("$base$path").method(
                method,
                when {
                    body != null -> body.toString().toRequestBody(JSON_MEDIA)
                    method == "POST" || method == "PUT" || method == "PATCH" -> "{}".toRequestBody(JSON_MEDIA)
                    else -> null
                }
            )
            if (session != null) builder.header("Authorization", "Bearer ${session.accessToken}")
            builder.header("X-Client-Version", com.adshield.pro.BuildConfig.VERSION_NAME)

            return try {
                httpClient.newCall(builder.build()).execute().use { response ->
                    val text = response.body?.string().orEmpty()
                    if (response.code == 401 && authenticated && !isRetry) {
                        // One transparent refresh attempt, then give up.
                        if (refreshSession()) return attempt(true)
                        sessionStore.clear()
                        return CloudResult.NotAuthenticated
                    }
                    if (!response.isSuccessful) return errorFrom(response, text)
                    val element = runCatching { json.parseToJsonElement(text) }
                        .getOrElse { return CloudResult.Failure("malformed_response", "Server returned invalid JSON", response.code) }
                    runCatching { CloudResult.Success(decoder(element)) }
                        .getOrElse { CloudResult.Failure("decode_error", it.message ?: "Could not parse response", response.code) }
                }
            } catch (error: Throwable) {
                transportFailure(error)
            }
        }
        attempt(false)
    }

    private suspend fun ensureSession(): CloudSession? {
        val session = sessionStore.current() ?: return null
        if (!session.needsRefresh) return session
        return if (refreshSession()) sessionStore.current() else session
    }

    private suspend fun refreshSession(): Boolean = refreshMutex.withLock {
        val session = sessionStore.current() ?: return false
        if (session.refreshToken.isBlank()) return false
        val config = configRepository.snapshot()
        val url = "${config.supabaseUrl}/auth/v1/token?grant_type=refresh_token"
        return withContext(Dispatchers.IO) {
            try {
                val requestBody = buildJsonObject { put("refresh_token", session.refreshToken) }
                    .toString().toRequestBody(JSON_MEDIA)
                val request = Request.Builder()
                    .url(url)
                    .post(requestBody)
                    .header("apikey", config.supabaseAnonKey)
                    .header("Content-Type", "application/json")
                    .build()
                httpClient.newCall(request).execute().use { response ->
                    val text = response.body?.string().orEmpty()
                    if (!response.isSuccessful) {
                        sessionStore.clear()
                        return@withContext false
                    }
                    val dto = json.decodeFromString(CloudAuthSessionDto.serializer(), text)
                    if (dto.accessToken.isBlank()) {
                        sessionStore.clear()
                        return@withContext false
                    }
                    sessionStore.save(
                        CloudSession(
                            accessToken = dto.accessToken,
                            refreshToken = dto.refreshToken.ifBlank { session.refreshToken },
                            expiresAtMs = System.currentTimeMillis() + dto.expiresIn * 1000,
                            userId = dto.user?.id ?: session.userId,
                            email = dto.user?.email ?: session.email
                        )
                    )
                    true
                }
            } catch (error: Throwable) {
                false
            }
        }
    }

    // ---------------------------------------------------------------- auth
    suspend fun signIn(email: String, password: String): CloudResult<CloudSession> =
        withContext(Dispatchers.IO) {
            val config = configRepository.snapshot()
            if (!config.isConfigured) return@withContext CloudResult.NotConfigured
            val body = buildJsonObject {
                put("email", email)
                put("password", password)
            }.toString().toRequestBody(JSON_MEDIA)
            try {
                val request = Request.Builder()
                    .url("${config.supabaseUrl}/auth/v1/token?grant_type=password")
                    .post(body)
                    .header("apikey", config.supabaseAnonKey)
                    .header("Content-Type", "application/json")
                    .build()
                httpClient.newCall(request).execute().use { response ->
                    val text = response.body?.string().orEmpty()
                    if (!response.isSuccessful) {
                        val code = if (response.code == 400) "invalid_credentials" else "auth_${response.code}"
                        val message = when {
                            response.code == 400 -> "Incorrect email or password"
                            response.code == 429 -> "Too many sign-in attempts. Try again shortly."
                            else -> "Sign-in failed (HTTP ${response.code})"
                        }
                        return@withContext CloudResult.Failure(code, message, response.code)
                    }
                    val dto = json.decodeFromString(CloudAuthSessionDto.serializer(), text)
                    val session = CloudSession(
                        accessToken = dto.accessToken,
                        refreshToken = dto.refreshToken,
                        expiresAtMs = System.currentTimeMillis() + dto.expiresIn * 1000,
                        userId = dto.user?.id ?: "",
                        email = dto.user?.email ?: email
                    )
                    sessionStore.save(session)
                    CloudResult.Success(session)
                }
            } catch (error: Throwable) {
                transportFailure(error)
            }
        }

    suspend fun register(email: String, password: String, displayName: String?, turnstileToken: String?): CloudResult<String> =
        decoded("POST", "/v1/auth/register", buildJsonObject {
            put("email", email)
            put("password", password)
            if (displayName != null) put("displayName", displayName)
            if (turnstileToken != null) put("turnstileToken", turnstileToken)
        }, authenticated = false) { _ -> "Account created. Check your email to confirm it, then sign in." }

    suspend fun requestPasswordRecovery(email: String, turnstileToken: String?): CloudResult<String> =
        decoded("POST", "/v1/auth/recover", buildJsonObject {
            put("email", email)
            if (turnstileToken != null) put("turnstileToken", turnstileToken)
        }, authenticated = false) { _ -> "Recovery email requested. Check your inbox." }

    fun signOut() = sessionStore.clear()

    // ---------------------------------------------------------------- meta / account
    suspend fun health(): CloudResult<CloudHealthDto> =
        decoded("GET", "/health", authenticated = false) { json.decodeFromJsonElement(CloudHealthDto.serializer(), it) }

    suspend fun meta(): CloudResult<CloudMetaDto> =
        decoded("GET", "/v1/meta", authenticated = false) { json.decodeFromJsonElement(CloudMetaDto.serializer(), it) }

    suspend fun account(): CloudResult<CloudAccountDto> =
        decoded("GET", "/v1/account") { json.decodeFromJsonElement(CloudAccountDto.serializer(), it) }

    suspend fun usage(): CloudResult<CloudAccountDto> = account()

    suspend fun stats(): CloudResult<CloudStatsDto> =
        decoded("GET", "/v1/stats") { json.decodeFromJsonElement(CloudStatsDto.serializer(), it) }

    suspend fun security(): CloudResult<CloudSecurityDto> =
        decoded("GET", "/v1/security") { json.decodeFromJsonElement(CloudSecurityDto.serializer(), it) }

    suspend fun audit(limit: Int = 100): CloudResult<CloudAuditListDto> =
        decoded("GET", "/v1/audit?limit=$limit") { json.decodeFromJsonElement(CloudAuditListDto.serializer(), it) }

    suspend fun updateAccount(displayName: String?): CloudResult<Boolean> =
        decoded("PATCH", "/v1/account", buildJsonObject {
            if (displayName != null) put("displayName", displayName)
        }) { true }

    // ---------------------------------------------------------------- files
    suspend fun listFiles(
        parentId: String? = null,
        category: String = "all",
        query: String? = null,
        sort: String = "name",
        direction: String = "asc",
        cursor: String? = null,
        limit: Int = 50
    ): CloudResult<CloudPageDto> {
        val params = buildList {
            if (parentId != null) add("parentId=$parentId")
            if (category != "all") add("category=$category")
            if (!query.isNullOrBlank()) add("q=${java.net.URLEncoder.encode(query, "UTF-8")}")
            add("sort=$sort")
            add("direction=$direction")
            if (cursor != null) add("cursor=${java.net.URLEncoder.encode(cursor, "UTF-8")}")
            add("limit=$limit")
        }.joinToString("&")
        return decoded("GET", "/v1/files?$params") { json.decodeFromJsonElement(CloudPageDto.serializer(), it) }
    }

    suspend fun nodeDetail(nodeId: String): CloudResult<CloudNodeDetailDto> =
        decoded("GET", "/v1/files/$nodeId") { json.decodeFromJsonElement(CloudNodeDetailDto.serializer(), it) }

    suspend fun createFolder(name: String, parentId: String?): CloudResult<CloudNodeDto> =
        decoded("POST", "/v1/folders", buildJsonObject {
            put("name", name)
            if (parentId != null) put("parentId", parentId)
        }) { json.decodeFromJsonElement(FileEnvelope.serializer(), it).folder }

    suspend fun rename(nodeId: String, name: String): CloudResult<CloudNodeDto> =
        decoded("POST", "/v1/files/$nodeId/rename", buildJsonObject { put("name", name) }) {
            json.decodeFromJsonElement(FileEnvelope.serializer(), it).node
        }

    suspend fun move(nodeId: String, parentId: String?): CloudResult<CloudNodeDto> =
        decoded("POST", "/v1/files/$nodeId/move", buildJsonObject {
            if (parentId != null) put("parentId", parentId) else put("parentId", "")
        }) { json.decodeFromJsonElement(FileEnvelope.serializer(), it).node }

    suspend fun copy(nodeId: String, parentId: String?): CloudResult<CloudNodeDto> =
        decoded("POST", "/v1/files/$nodeId/copy", buildJsonObject {
            if (parentId != null) put("parentId", parentId)
        }) { json.decodeFromJsonElement(FileEnvelope.serializer(), it).node }

    suspend fun trash(nodeId: String): CloudResult<Int> =
        decoded("POST", "/v1/files/$nodeId/trash", buildJsonObject { }) {
            it.jsonObject["trashed"]?.jsonPrimitive?.content?.toIntOrNull() ?: 1
        }

    suspend fun restore(nodeId: String): CloudResult<Int> =
        decoded("POST", "/v1/files/$nodeId/restore", buildJsonObject { }) {
            it.jsonObject["restored"]?.jsonPrimitive?.content?.toIntOrNull() ?: 1
        }

    suspend fun purge(nodeId: String): CloudResult<Long> =
        decoded("DELETE", "/v1/files/$nodeId") {
            it.jsonObject["freedBytes"]?.jsonPrimitive?.content?.toLongOrNull() ?: 0L
        }

    suspend fun emptyTrash(): CloudResult<Long> =
        decoded("DELETE", "/v1/trash") {
            it.jsonObject["freedBytes"]?.jsonPrimitive?.content?.toLongOrNull() ?: 0L
        }

    suspend fun trashList(): CloudResult<CloudTrashEnvelope> =
        decoded("GET", "/v1/trash") { json.decodeFromJsonElement(CloudTrashEnvelope.serializer(), it) }

    suspend fun search(query: String, limit: Int = 50): CloudResult<CloudPageDto> =
        decoded("GET", "/v1/search?q=${java.net.URLEncoder.encode(query, "UTF-8")}&limit=$limit") {
            json.decodeFromJsonElement(CloudPageDto.serializer(), it)
        }

    suspend fun versions(nodeId: String): CloudResult<CloudVersionsDto> =
        decoded("GET", "/v1/files/$nodeId/versions") { json.decodeFromJsonElement(CloudVersionsDto.serializer(), it) }

    suspend fun restoreVersion(nodeId: String, versionId: String): CloudResult<Int> =
        decoded("POST", "/v1/files/$nodeId/versions/$versionId/restore", buildJsonObject { }) {
            it.jsonObject["currentVersion"]?.jsonPrimitive?.content?.toIntOrNull() ?: 0
        }

    suspend fun verifyIntegrity(nodeId: String): CloudResult<CloudVerifyDto> =
        decoded("POST", "/v1/files/$nodeId/verify", buildJsonObject { }) {
            json.decodeFromJsonElement(CloudVerifyDto.serializer(), it)
        }

    suspend fun releaseQuarantine(nodeId: String): CloudResult<Boolean> =
        decoded("POST", "/v1/files/$nodeId/release", buildJsonObject { }) { true }

    suspend fun downloadTicket(nodeId: String, preview: Boolean = false): CloudResult<CloudDownloadTicketDto> =
        decoded("GET", "/v1/files/$nodeId/${if (preview) "preview" else "download"}") {
            json.decodeFromJsonElement(CloudDownloadTicketDto.serializer(), it)
        }

    // ---------------------------------------------------------------- shares / links
    suspend fun createShare(
        nodeId: String,
        expiresInSeconds: Long,
        maxDownloads: Int,
        password: String?,
        allowPreview: Boolean
    ): CloudResult<CloudCreatedShareDto> =
        decoded("POST", "/v1/shares", buildJsonObject {
            put("nodeId", nodeId)
            put("expiresInSeconds", expiresInSeconds)
            put("maxDownloads", maxDownloads)
            put("allowPreview", allowPreview)
            if (!password.isNullOrBlank()) put("password", password)
        }) { json.decodeFromJsonElement(CloudCreatedShareDto.serializer(), it) }

    suspend fun listShares(): CloudResult<List<CloudShareDto>> =
        decoded("GET", "/v1/shares") { json.decodeFromJsonElement(CloudShareListDto.serializer(), it).shares }

    suspend fun revokeShare(shareId: String): CloudResult<Boolean> =
        decoded("DELETE", "/v1/shares/$shareId") { true }

    // ---------------------------------------------------------------- backups
    suspend fun initBackup(size: Long, sha256: String, kind: String, label: String): CloudResult<CloudBackupInitDto> =
        decoded("POST", "/v1/backups/init", buildJsonObject {
            put("size", size)
            put("sha256", sha256)
            put("kind", kind)
            put("label", label)
            put("appVersion", com.adshield.pro.BuildConfig.VERSION_NAME)
        }) { json.decodeFromJsonElement(CloudBackupInitDto.serializer(), it) }

    suspend fun listBackups(kind: String? = null): CloudResult<CloudBackupListDto> =
        decoded("GET", if (kind != null) "/v1/backups?kind=$kind" else "/v1/backups") {
            json.decodeFromJsonElement(CloudBackupListDto.serializer(), it)
        }

    suspend fun verifyBackup(backupId: String): CloudResult<CloudBackupVerifyDto> =
        decoded("POST", "/v1/backups/$backupId/verify", buildJsonObject { }) {
            json.decodeFromJsonElement(CloudBackupVerifyDto.serializer(), it)
        }

    suspend fun backupRestoreTicket(backupId: String): CloudResult<CloudBackupRestoreDto> =
        decoded("POST", "/v1/backups/$backupId/restore", buildJsonObject { }) {
            json.decodeFromJsonElement(CloudBackupRestoreDto.serializer(), it)
        }

    suspend fun markBackupRestored(backupId: String): CloudResult<Boolean> =
        decoded("POST", "/v1/backups/$backupId/restored", buildJsonObject { }) { true }

    suspend fun deleteBackup(backupId: String): CloudResult<Long> =
        decoded("DELETE", "/v1/backups/$backupId") {
            it.jsonObject["freedBytes"]?.jsonPrimitive?.content?.toLongOrNull() ?: 0L
        }

    // ---------------------------------------------------------------- uploads
    suspend fun initUpload(
        name: String,
        size: Long,
        parentId: String?,
        mime: String,
        sha256: String?,
        encrypted: Boolean,
        dedupeMode: String = "reference"
    ): CloudResult<CloudInitUploadDto> =
        decoded("POST", "/v1/uploads", buildJsonObject {
            put("name", name)
            put("size", size)
            put("mime", mime)
            if (parentId != null) put("parentId", parentId)
            if (sha256 != null) put("sha256", sha256)
            put("encrypted", encrypted)
            put("dedupeMode", dedupeMode)
        }) { json.decodeFromJsonElement(CloudInitUploadDto.serializer(), it) }

    suspend fun initVersionUpload(
        nodeId: String,
        size: Long,
        mime: String,
        sha256: String?,
        encrypted: Boolean
    ): CloudResult<CloudInitUploadDto> =
        decoded("POST", "/v1/files/$nodeId/versions/init", buildJsonObject {
            put("size", size)
            put("mime", mime)
            if (sha256 != null) put("sha256", sha256)
            put("encrypted", encrypted)
        }) { json.decodeFromJsonElement(CloudInitUploadDto.serializer(), it) }

    suspend fun uploadState(uploadId: String): CloudResult<CloudUploadStateDto> =
        decoded("GET", "/v1/uploads/$uploadId") { json.decodeFromJsonElement(CloudUploadStateDto.serializer(), it) }

    suspend fun activeUploads(): CloudResult<List<CloudUploadStateDto>> =
        decoded("GET", "/v1/uploads") { json.decodeFromJsonElement(CloudUploadListDto.serializer(), it).uploads }

    suspend fun completeUpload(uploadId: String): CloudResult<CloudCompleteUploadDto> =
        decoded("POST", "/v1/uploads/$uploadId/complete", buildJsonObject { }) {
            json.decodeFromJsonElement(CloudCompleteUploadDto.serializer(), it)
        }

    suspend fun abortUpload(uploadId: String): CloudResult<Boolean> =
        decoded("POST", "/v1/uploads/$uploadId/abort", buildJsonObject { }) { true }

    /** Raw PUT used by the upload engine for chunked progress reporting. */
    fun uploadRequest(url: String, body: RequestBody, contentType: String): Request =
        Request.Builder()
            .url(url)
            .put(body)
            .header("Content-Type", contentType)
            .header("X-Client-Version", com.adshield.pro.BuildConfig.VERSION_NAME)
            .build()

    /** Unauthenticated GET for signed download URLs (the signature *is* the credential). */
    fun signedDownloadRequest(url: String, rangeStart: Long? = null): Request {
        val builder = Request.Builder().url(url).get()
        if (rangeStart != null && rangeStart > 0) builder.header("Range", "bytes=$rangeStart-")
        return builder.build()
    }

    fun downloadRequest(ticketUrl: String, rangeStart: Long? = null): Request = signedDownloadRequest(ticketUrl, rangeStart)

    fun execute(request: Request): Response = httpClient.newCall(request).execute()

    /** Validates that a user-supplied deployment URL is structurally sane. */
    fun validateBaseUrl(candidate: String): String? {
        val url = candidate.trim().trimEnd('/').toHttpUrlOrNull() ?: return "Enter a valid URL"
        if (url.scheme != "https" && url.host !in setOf("localhost", "127.0.0.1", "10.0.2.2")) {
            return "Cloud endpoints must use HTTPS"
        }
        return null
    }

    fun describeFailure(failure: CloudResult.Failure): String = when (failure.code) {
        "quota_exceeded" -> "Storage quota reached. ${failure.message}"
        "rate_limited" -> "Rate limited. ${failure.message}"
        "file_quarantined" -> "Blocked by malware protection: ${failure.message}"
        else -> failure.message
    }

    fun formatBytes(bytes: Long): String = ByteFormat.human(bytes)

    private companion object {
        val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()
    }
}

@kotlinx.serialization.Serializable
internal data class FileEnvelope(
    val node: CloudNodeDto = CloudNodeDto(),
    val folder: CloudNodeDto = CloudNodeDto()
)

@kotlinx.serialization.Serializable
internal data class CloudTrashEnvelope(
    val retentionDays: Int = 30,
    val items: List<CloudNodeDto> = emptyList()
)
