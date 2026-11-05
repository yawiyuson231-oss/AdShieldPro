package com.adshield.pro.cybershield.data

import android.content.Context
import com.adshield.pro.cybershield.CloudProviderStatus
import com.adshield.pro.cybershield.ComplianceReportJson.jsonString
import com.adshield.pro.cybershield.CsLoadState
import com.adshield.pro.cybershield.JsonLite
import com.adshield.pro.cybershield.JValue
import com.adshield.pro.cybershield.StatuspageParser
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Real cloud-provider platform status via the public Statuspage v2 API
 * (GitHub, Cloudflare, DigitalOcean) plus user-added custom endpoints.
 *
 * Honesty contract: this monitors the PROVIDER's published platform status.
 * The security posture of the user's own cloud tenant requires authenticated,
 * provider-specific APIs and is reported as not connected. Optional bearer
 * tokens for custom endpoints are encrypted with the Android Keystore.
 */
@Singleton
class CloudStatusRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val prefs: CyberShieldPrefs,
    private val secretStore: KeystoreSecretStore
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()
    private val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(12, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .build()
    }
    private val secretPrefs by lazy {
        context.getSharedPreferences("cybershield_secrets", Context.MODE_PRIVATE)
    }
    private val cacheFile: File by lazy {
        File(context.filesDir, "cybershield").apply { mkdirs() }.resolve("cloud_cache.json")
    }

    private val _statuses = MutableStateFlow(defaultProviders())
    val statuses: StateFlow<List<CloudProviderStatus>> = _statuses.asStateFlow()

    private val _isRefreshing = MutableStateFlow(false)
    val isRefreshing: StateFlow<Boolean> = _isRefreshing.asStateFlow()

    init {
        scope.launch {
            restoreConfiguration()
        }
    }

    private suspend fun restoreConfiguration() = withContext(Dispatchers.IO) {
        val custom = readCustomEndpoints()
        val cache = readCache()
        _statuses.value = (defaultProviders() + custom).map { provider ->
            cache[provider.id]?.let { cached ->
                cached.copy(isCustom = provider.isCustom, hasToken = provider.hasToken, statusUrl = provider.statusUrl)
            } ?: provider
        }
    }

    fun refreshAll() {
        scope.launch {
            mutex.withLock {
                if (_isRefreshing.value) return@withLock
                _isRefreshing.value = true
                try {
                    val current = _statuses.value
                    _statuses.value = current.map {
                        if (it.loadState == CsLoadState.LOADING) it
                        else it.copy(loadState = CsLoadState.LOADING, error = null)
                    }
                    val updated = coroutineScope {
                        _statuses.value.map { provider ->
                            async { fetchOne(provider) }
                        }.awaitAll()
                    }
                    _statuses.value = updated
                    writeCache(updated)
                } finally {
                    _isRefreshing.value = false
                }
            }
        }
    }

    private fun fetchOne(provider: CloudProviderStatus): CloudProviderStatus {
        return runCatching {
            val builder = Request.Builder()
                .url(provider.statusUrl)
                .header("User-Agent", "AdShieldPro-CyberShield/1.0")
                .header("Accept", "application/json")
                .get()
            if (provider.isCustom) {
                secretPrefs.getString(tokenKey(provider.id), null)?.let { encrypted ->
                    secretStore.decrypt(encrypted)?.let { token ->
                        builder.header("Authorization", "Bearer $token")
                    }
                }
            }
            client.newCall(builder.build()).execute().use { response ->
                if (!response.isSuccessful) throw IllegalStateException("HTTP ${response.code}")
                val body = response.body?.string() ?: throw IllegalStateException("Empty response")
                StatuspageParser.parseInto(provider, body, System.currentTimeMillis())
            }
        }.getOrElse { e ->
            val hadData = provider.fetchedAtEpochMs != null
            provider.copy(
                loadState = if (hadData) CsLoadState.CACHED else CsLoadState.ERROR,
                error = when (e) {
                    is java.net.UnknownHostException -> "Offline — no connection"
                    is java.net.SocketTimeoutException -> "Request timed out"
                    else -> e.message ?: e.javaClass.simpleName
                }
            )
        }
    }

    /** Adds a custom Statuspage-compatible endpoint. Returns an error string or null. */
    fun addCustomEndpoint(name: String, url: String, bearerToken: String?): String? {
        val trimmedName = name.trim()
        val trimmedUrl = url.trim()
        if (trimmedName.isBlank() || trimmedName.length > 40) return "Enter a name (max 40 characters)."
        if (!trimmedUrl.startsWith("https://") || trimmedUrl.length > 300) {
            return "Endpoint must be an https:// URL (Statuspage v2 status.json)."
        }
        if (runCatching { java.net.URI(trimmedUrl).host }.getOrNull().isNullOrBlank()) {
            return "Invalid URL."
        }
        val id = "custom_" + java.util.UUID.randomUUID().toString().take(8)
        if (!bearerToken.isNullOrBlank()) {
            val encrypted = secretStore.encrypt(bearerToken.trim())
                ?: return "Could not encrypt the token on this device (Keystore unavailable)."
            secretPrefs.edit().putString(tokenKey(id), encrypted).apply()
        }
        val endpoints = readCustomEndpointsRaw().toMutableList()
        endpoints.add(
            CustomEndpoint(id, trimmedName, trimmedUrl, !bearerToken.isNullOrBlank())
        )
        persistCustomEndpoints(endpoints)
        _statuses.value = _statuses.value + CloudProviderStatus(
            id = id, name = trimmedName, statusUrl = trimmedUrl,
            isCustom = true, hasToken = !bearerToken.isNullOrBlank()
        )
        refreshAll()
        return null
    }

    fun removeCustomEndpoint(id: String) {
        if (!id.startsWith("custom_")) return
        secretPrefs.edit().remove(tokenKey(id)).apply()
        persistCustomEndpoints(readCustomEndpointsRaw().filterNot { it.id == id })
        _statuses.value = _statuses.value.filterNot { it.id == id }
        scope.launch { writeCache(_statuses.value) }
    }

    // --- persistence -------------------------------------------------------

    private data class CustomEndpoint(val id: String, val name: String, val url: String, val hasToken: Boolean)

    private fun tokenKey(id: String) = "token_$id"

    private fun readCustomEndpointsRaw(): List<CustomEndpoint> = runCatching {
        val root = JsonLite.parse(prefs.cloudEndpointsJson)
        root.asListOrNull().orEmpty().mapNotNull { item ->
            val obj = item as? JValue.JObj ?: return@mapNotNull null
            val id = obj.str("id") ?: return@mapNotNull null
            val name = obj.str("name") ?: return@mapNotNull null
            val url = obj.str("url") ?: return@mapNotNull null
            CustomEndpoint(id, name, url, obj.bool("hasToken") ?: false)
        }
    }.getOrDefault(emptyList())

    private fun readCustomEndpoints(): List<CloudProviderStatus> =
        readCustomEndpointsRaw().map {
            CloudProviderStatus(
                id = it.id, name = it.name, statusUrl = it.url,
                isCustom = true, hasToken = it.hasToken
            )
        }

    private fun persistCustomEndpoints(endpoints: List<CustomEndpoint>) {
        val json = endpoints.joinToString(",", "[", "]") { e ->
            "{\"id\":${jsonString(e.id)},\"name\":${jsonString(e.name)},\"url\":${jsonString(e.url)},\"hasToken\":${e.hasToken}}"
        }
        prefs.cloudEndpointsJson = json
    }

    private fun writeCache(statuses: List<CloudProviderStatus>) {
        runCatching {
            val entries = statuses.filter { it.fetchedAtEpochMs != null }.joinToString(",") { s ->
                "${jsonString(s.id)}:{\"indicator\":${jsonString(s.indicator.name)}," +
                    "\"description\":${jsonString(s.description)}," +
                    "\"provider_updated_at\":${s.providerUpdatedAt?.let { jsonString(it) } ?: "null"}," +
                    "\"fetched_at\":${s.fetchedAtEpochMs}}"
            }
            cacheFile.writeText("{$entries}")
        }
    }

    private fun readCache(): Map<String, CloudProviderStatus> = runCatching {
        if (!cacheFile.exists()) return emptyMap()
        val root = JsonLite.parse(cacheFile.readText()) as? JValue.JObj ?: return emptyMap()
        root.fields.mapNotNull { (id, value) ->
            val obj = value as? JValue.JObj ?: return@mapNotNull null
            val indicator = runCatching {
                com.adshield.pro.cybershield.CloudIndicator.valueOf(obj.str("indicator") ?: "")
            }.getOrNull() ?: return@mapNotNull null
            id to CloudProviderStatus(
                id = id,
                name = id,
                statusUrl = "",
                indicator = indicator,
                description = obj.str("description") ?: "",
                providerUpdatedAt = obj.str("provider_updated_at"),
                fetchedAtEpochMs = obj.num("fetched_at")?.toLong(),
                loadState = CsLoadState.CACHED
            )
        }.toMap()
    }.getOrDefault(emptyMap())

    private fun defaultProviders(): List<CloudProviderStatus> = listOf(
        CloudProviderStatus(
            id = "github", name = "GitHub",
            statusUrl = "https://www.githubstatus.com/api/v2/status.json"
        ),
        CloudProviderStatus(
            id = "cloudflare", name = "Cloudflare",
            statusUrl = "https://www.cloudflarestatus.com/api/v2/status.json"
        ),
        CloudProviderStatus(
            id = "digitalocean", name = "DigitalOcean",
            statusUrl = "https://status.digitalocean.com/api/v2/status.json"
        )
    )
}
