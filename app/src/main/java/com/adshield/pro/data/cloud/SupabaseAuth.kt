package com.adshield.pro.data.cloud

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

@Serializable
private data class SupabaseErrorDto(
    val msg: String? = null,
    @SerialName("error_description") val errorDescription: String? = null,
    val error: String? = null
)

@Serializable
data class SupabaseUserDto(
    val id: String = "",
    val email: String? = null
)

@Serializable
private data class SupabaseAuthResponseDto(
    @SerialName("access_token") val accessToken: String? = null,
    @SerialName("refresh_token") val refreshToken: String? = null,
    @SerialName("expires_in") val expiresIn: Long? = null,
    @SerialName("expires_at") val expiresAt: Long? = null,
    @SerialName("token_type") val tokenType: String? = null,
    val user: SupabaseUserDto? = null
)

/**
 * Real Supabase GoTrue calls. No SDK dependency: three endpoints, each verifiable by hand.
 */
class SupabaseAuthClient internal constructor(
    private val http: OkHttpClient,
    private val endpoints: CloudEndpoints
) {
    suspend fun signUp(email: String, password: String, turnstileToken: String? = null): CloudSession =
        authenticate("/auth/v1/signup", Credentials(email, password, turnstileToken))

    suspend fun signIn(email: String, password: String, turnstileToken: String? = null): CloudSession =
        authenticate("/auth/v1/token?grant_type=password", Credentials(email, password, turnstileToken))

    suspend fun refresh(refreshToken: String): CloudSession =
        authenticate("/auth/v1/token?grant_type=refresh_token", RefreshRequest(refreshToken))

    /** Account recovery: Supabase emails a one-time link. Returns false when the call is refused. */
    suspend fun requestPasswordReset(email: String): Boolean = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(url("/auth/v1/recover"))
            .post(defaultCloudJson().encodeToString(RecoveryRequest(email)).toRequestBody(JSON))
            .addHeader("apikey", endpoints.supabaseAnonKey)
            .addHeader("Content-Type", "application/json")
            .build()
        http.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                val body = response.body?.string().orEmpty()
                val message = decodeError(body)
                throw CloudException(response.code, message ?: "password reset was refused")
            }
            true
        }
    }

    /** Confirms the stored token still authenticates — used by the Cloud Security screen. */
    suspend fun whoAmI(accessToken: String): SupabaseUserDto = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(url("/auth/v1/user"))
            .get()
            .addHeader("apikey", endpoints.supabaseAnonKey)
            .addHeader("Authorization", "Bearer $accessToken")
            .build()
        val raw = http.newCall(request).execute().use { response ->
            val body = response.body?.string().orEmpty()
            if (!response.isSuccessful) throw CloudException(response.code, "session is no longer valid")
            body
        }
        defaultCloudJson().decodeFromString(raw)
    }

    private suspend inline fun <reified T> authenticate(path: String, payload: T): CloudSession = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(url(path))
            .post(defaultCloudJson().encodeToString(payload).toRequestBody(JSON))
            .addHeader("apikey", endpoints.supabaseAnonKey)
            .addHeader("Content-Type", "application/json")
            .build()
        val raw = http.newCall(request).execute().use { response ->
            val body = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                val message = decodeError(body)
                throw CloudException(response.code, message ?: "authentication failed (http ${response.code})")
            }
            body
        }
        val parsed = defaultCloudJson().decodeFromString<SupabaseAuthResponseDto>(raw)
        val accessToken = parsed.accessToken
            ?: throw CloudException(200, "email confirmation is required: open the link in your inbox, then sign in")
        val now = System.currentTimeMillis()
        val expiresAt = when {
            parsed.expiresAt != null && parsed.expiresAt > 1_000_000_000L -> parsed.expiresAt * 1000L
            parsed.expiresIn != null -> now + parsed.expiresIn * 1000L
            else -> now + 3_600_000L
        }
        CloudSession(
            accessToken = accessToken,
            refreshToken = parsed.refreshToken.orEmpty(),
            expiresAtEpochMs = expiresAt,
            userId = parsed.user?.id.orEmpty(),
            email = parsed.user?.email ?: (payload as? Credentials)?.email ?: ""
        )
    }

    private fun decodeError(body: String): String? {
        val parsed = runCatching { defaultCloudJson().decodeFromString<SupabaseErrorDto>(body) }.getOrNull()
            ?: return null
        return listOfNotNull(parsed.msg, parsed.errorDescription, parsed.error)
            .firstOrNull { it.isNotBlank() }
    }

    private fun url(path: String) = (endpoints.supabaseUrl.trimEnd('/') + "/" + path.trimStart('/')).toHttpUrl()

    @Serializable
    private class Credentials(val email: String, val password: String, val turnstileToken: String? = null)

    @Serializable
    private class RefreshRequest(val refreshToken: String)

    @Serializable
    private class RecoveryRequest(val email: String)

    private companion object {
        val JSON = "application/json".toMediaType()
    }
}

/**
 * Owns the signed-in session, refreshes the access token, and hands it to the API client.
 */
@Singleton
class CloudAccountManager @Inject constructor(
    private val store: CloudSessionStore
) : CloudTokenProvider {

    private val mutex = Mutex()
    private val mutableSession = MutableStateFlow(store.load())
    val session: StateFlow<CloudSession?> = mutableSession.asStateFlow()

    private val http: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private fun client(): SupabaseAuthClient = SupabaseAuthClient(http, store.endpoints())

    val endpoints: CloudEndpoints get() = store.endpoints()

    fun saveEndpoints(endpoints: CloudEndpoints) {
        store.saveEndpoints(endpoints)
    }

    suspend fun signUp(email: String, password: String, turnstileToken: String? = null): CloudSession {
        val session = client().signUp(email, password, turnstileToken)
        store.save(session)
        mutableSession.value = session
        return session
    }

    suspend fun signIn(email: String, password: String, turnstileToken: String? = null): CloudSession {
        val session = client().signIn(email, password, turnstileToken)
        store.save(session)
        mutableSession.value = session
        return session
    }

    suspend fun resetPassword(email: String): Boolean = client().requestPasswordReset(email)

    suspend fun signOut() {
        store.clear()
        mutableSession.value = null
    }

    /** Returns a token that is still valid, refreshing it first when it is about to expire. */
    override suspend fun accessToken(): String? = mutex.withLock {
        val current = mutableSession.value ?: store.load()
        if (current == null || !current.isSignedIn) return null
        if (!current.expiresSoon) return current.accessToken
        if (current.refreshToken.isBlank()) return current.accessToken
        val refreshed = runCatching { client().refresh(current.refreshToken) }.getOrNull()
        if (refreshed == null) {
            store.clear()
            mutableSession.value = null
            return null
        }
        store.save(refreshed)
        mutableSession.value = refreshed
        refreshed.accessToken
    }

    suspend fun verifySession(): Boolean {
        val token = accessToken() ?: return false
        return runCatching { client().whoAmI(token) }.isSuccess
    }
}
