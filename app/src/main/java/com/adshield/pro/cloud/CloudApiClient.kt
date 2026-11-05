package com.adshield.pro.cloud

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Thin REST client for the AdShield cloud Worker. Every call goes to the user-configured
 * HTTPS Worker endpoint; object bytes move through short-lived signed URLs the Worker issues
 * after an ownership check, so no R2/D1 credential is ever present in the APK.
 */
@Singleton
class CloudApiClient @Inject constructor() {

    private val json = Json { ignoreUnknownKeys = true; coerceInputValues = true }

    private val http: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(20, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(120, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .build()
    }

    class CloudException(val statusCode: Int, message: String) : IOException(message)

    private fun requireBaseUrl(baseUrl: String): String {
        require(CloudConfig.isValidApiBaseUrl(baseUrl)) {
            "Cloud backend not configured. Deploy the free-tier Worker (cloud-worker/README.md) " +
                "and enter its https:// URL in Cloud → Settings."
        }
        return baseUrl
    }

    private suspend fun <T> call(
        baseUrl: String,
        path: String,
        method: String,
        token: String?,
        body: String? = null,
        parse: (String) -> T
    ): T = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(requireBaseUrl(baseUrl) + path)
            .header("Accept", "application/json")
            .apply {
                if (!token.isNullOrBlank()) header("Authorization", "Bearer $token")
                when (method) {
                    "GET" -> get()
                    "DELETE" -> delete()
                    else -> {
                        val mediaType = "application/json".toMediaType()
                        post((body ?: "{}").toRequestBody(mediaType))
                    }
                }
            }
            .build()
        http.newCall(request).execute().use { response ->
            val responseBody = response.body?.string() ?: ""
            if (!response.isSuccessful) {
                val message = runCatching {
                    json.decodeFromString<ApiErrorBody>(responseBody).error
                }.getOrElse { responseBody.ifBlank { "HTTP ${response.code}" } }
                throw CloudException(response.code, message)
            }
            parse(responseBody)
        }
    }

    // --- Auth (proxied to the free-tier Supabase Auth instance by the Worker) ---

    suspend fun signUp(baseUrl: String, email: String, password: String): AuthSession =
        call(baseUrl, "/auth/signup", "POST", null, """{"email":${jsonString(email)},"password":${jsonString(password)}}""") {
            json.decodeFromString(it)
        }

    suspend fun signIn(baseUrl: String, email: String, password: String): AuthSession =
        call(baseUrl, "/auth/login", "POST", null, """{"email":${jsonString(email)},"password":${jsonString(password)}}""") {
            json.decodeFromString(it)
        }

    // --- Metadata API (D1) ---

    suspend fun quota(baseUrl: String, token: String): QuotaInfo =
        call(baseUrl, "/api/quota", "GET", token) { json.decodeFromString(it) }

    suspend fun listFiles(baseUrl: String, token: String, folder: String, kind: String?): List<CloudFile> =
        call(baseUrl, "/api/files?folder=${enc(folder)}" + (kind?.let { "&kind=$it" } ?: ""), "GET", token) {
            json.decodeFromString(it)
        }

    suspend fun createFolder(baseUrl: String, token: String, path: String): CloudFile =
        call(baseUrl, "/api/folders", "POST", token, """{"path":${jsonString(path)}}""") {
            json.decodeFromString(it)
        }

    suspend fun renameFile(baseUrl: String, token: String, id: String, newName: String) =
        call(baseUrl, "/api/files/$id/rename", "POST", token, """{"name":${jsonString(newName)}}""") { }

    suspend fun moveFile(baseUrl: String, token: String, id: String, folderPath: String) =
        call(baseUrl, "/api/files/$id/move", "POST", token, """{"folder":${jsonString(folderPath)}}""") { }

    suspend fun copyFile(baseUrl: String, token: String, id: String, folderPath: String): CloudFile =
        call(baseUrl, "/api/files/$id/copy", "POST", token, """{"folder":${jsonString(folderPath)}}""") {
            json.decodeFromString(it)
        }

    suspend fun deleteFile(baseUrl: String, token: String, id: String, permanent: Boolean) =
        call(baseUrl, "/api/files/$id?permanent=$permanent", "DELETE", token) { }

    suspend fun restoreFile(baseUrl: String, token: String, id: String) =
        call(baseUrl, "/api/files/$id/restore", "POST", token) { }

    suspend fun versions(baseUrl: String, token: String, id: String): List<CloudFileVersion> =
        call(baseUrl, "/api/files/$id/versions", "GET", token) { json.decodeFromString(it) }

    suspend fun share(baseUrl: String, token: String, id: String, ttlHours: Int, maxDownloads: Int): ShareLink =
        call(baseUrl, "/api/files/$id/share", "POST", token, """{"ttlHours":$ttlHours,"maxDownloads":$maxDownloads}""") {
            json.decodeFromString(it)
        }

    suspend fun listShares(baseUrl: String, token: String): List<ShareLink> =
        call(baseUrl, "/api/shares", "GET", token) { json.decodeFromString(it) }

    suspend fun backups(baseUrl: String, token: String): List<DnsBackupRecord> =
        call(baseUrl, "/api/backups", "GET", token) { json.decodeFromString(it) }

    // --- Signed URLs (short-lived; bytes flow through these, never through D1) ---

    suspend fun signedUploadUrl(baseUrl: String, token: String, fileId: String, sizeBytes: Long, sha256: String): SignedUrlResponse =
        call(
            baseUrl, "/api/files/$fileId/sign-upload", "POST", token,
            """{"sizeBytes":$sizeBytes,"sha256":${jsonString(sha256)}}"""
        ) { json.decodeFromString(it) }

    suspend fun signedChunkUrl(baseUrl: String, token: String, fileId: String, partNumber: Int, uploadId: String): SignedUrlResponse =
        call(
            baseUrl,
            "/api/files/$fileId/sign-chunk?part=$partNumber&uploadId=${enc(uploadId)}",
            "POST", token
        ) { json.decodeFromString(it) }

    suspend fun completeMultipart(baseUrl: String, token: String, fileId: String, uploadId: String, parts: List<Int>): CloudFile =
        call(
            baseUrl, "/api/files/$fileId/complete", "POST", token,
            """{"uploadId":${jsonString(uploadId)},"parts":${parts.joinToString(",", "[", "]")}}"""
        ) { json.decodeFromString(it) }

    suspend fun signedDownloadUrl(baseUrl: String, token: String, fileId: String): SignedUrlResponse =
        call(baseUrl, "/api/files/$fileId/sign-download", "POST", token) { json.decodeFromString(it) }

    suspend fun createFileRecord(
        baseUrl: String, token: String, name: String, folderPath: String,
        sizeBytes: Long, mimeType: String, sha256: String, multipart: Boolean
    ): CloudFile = call(
        baseUrl, "/api/files", "POST", token,
        """{"name":${jsonString(name)},"folder":${jsonString(folderPath)},"sizeBytes":$sizeBytes,"mimeType":${jsonString(mimeType)},"sha256":${jsonString(sha256)},"multipart":$multipart}"""
    ) { json.decodeFromString(it) }

    private fun jsonString(value: String): String = json.encodeToString(value)
    private fun enc(value: String): String = java.net.URLEncoder.encode(value, "UTF-8")
}
