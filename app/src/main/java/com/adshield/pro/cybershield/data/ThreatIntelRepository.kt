package com.adshield.pro.cybershield.data

import android.content.Context
import com.adshield.pro.cybershield.CsLoadState
import com.adshield.pro.cybershield.FeodoParser
import com.adshield.pro.cybershield.IntelSnapshot
import com.adshield.pro.cybershield.IntelUiState
import com.adshield.pro.cybershield.JsonLite
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
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
 * Verified external threat intelligence with honest load states.
 *
 * Source: Feodo Tracker (abuse.ch) botnet C2 blocklist — free, CC0, no API key.
 * The last successful fetch is cached on disk so the map keeps working offline
 * with a visible "cached" badge and age. Failures never fabricate indicators.
 */
@Singleton
class ThreatIntelRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val prefs: CyberShieldPrefs
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()
    private val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(25, TimeUnit.SECONDS)
            .build()
    }
    private val cacheFile: File by lazy {
        File(context.filesDir, "cybershield").apply { mkdirs() }
            .resolve("intel_cache.json")
    }

    private val _state = MutableStateFlow(IntelUiState(enabled = prefs.intelEnabled))
    val state: StateFlow<IntelUiState> = _state.asStateFlow()

    init {
        scope.launch { loadCache() }
    }

    fun setEnabled(enabled: Boolean) {
        prefs.intelEnabled = enabled
        _state.value = _state.value.copy(enabled = enabled, loadState = when {
            !enabled -> CsLoadState.DISABLED
            _state.value.snapshot != null -> _state.value.loadState
            else -> CsLoadState.NEVER_LOADED
        })
        if (enabled) refresh(force = false)
    }

    fun isStale(maxAgeMs: Long = DEFAULT_MAX_AGE_MS): Boolean {
        val snap = _state.value.snapshot ?: return true
        return System.currentTimeMillis() - snap.fetchedAtEpochMs > maxAgeMs
    }

    /** Fetches the real feed. [force] bypasses the freshness window. */
    fun refresh(force: Boolean = false) {
        if (!prefs.intelEnabled) {
            _state.value = _state.value.copy(enabled = false, loadState = CsLoadState.DISABLED)
            return
        }
        scope.launch { refreshAwait(force) }
    }

    /** Suspend variant used by WorkManager; returns true when live data was fetched. */
    suspend fun refreshAwait(force: Boolean = true): Boolean = mutex.withLock {
        if (!prefs.intelEnabled) {
            _state.value = _state.value.copy(enabled = false, loadState = CsLoadState.DISABLED)
            return@withLock false
        }
        if (!force && !isStale() && _state.value.loadState == CsLoadState.LIVE) return@withLock true
        _state.value = _state.value.copy(loadState = CsLoadState.LOADING, error = null, enabled = true)
        val result = runCatching { fetchRemote() }
        result.onSuccess { snapshot ->
            _state.value = IntelUiState(
                loadState = CsLoadState.LIVE, snapshot = snapshot, error = null, enabled = true
            )
        }.onFailure { e ->
            val cached = _state.value.snapshot ?: readCache()
            _state.value = if (cached != null) {
                IntelUiState(
                    loadState = CsLoadState.CACHED, snapshot = cached,
                    error = "Refresh failed (${e.javaClass.simpleName}). Showing cached intel.",
                    enabled = true
                )
            } else {
                IntelUiState(
                    loadState = CsLoadState.ERROR, snapshot = null,
                    error = friendlyError(e), enabled = true
                )
            }
        }
        result.isSuccess
    }

    private suspend fun loadCache() = withContext(Dispatchers.IO) {
        if (!prefs.intelEnabled) {
            _state.value = IntelUiState(loadState = CsLoadState.DISABLED, enabled = false)
            return@withContext
        }
        val cached = readCache()
        if (cached != null) {
            _state.value = IntelUiState(loadState = CsLoadState.CACHED, snapshot = cached, enabled = true)
        }
    }

    private fun fetchRemote(): IntelSnapshot {
        val request = Request.Builder()
            .url(FeodoParser.FEED_URL)
            .header("User-Agent", "AdShieldPro-CyberShield/1.0 (on-device security dashboard)")
            .get()
            .build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw IllegalStateException("HTTP ${response.code} from threat feed")
            }
            val body = response.body?.string() ?: throw IllegalStateException("Empty threat feed body")
            val now = System.currentTimeMillis()
            val snapshot = FeodoParser.parse(body, now)
            writeCache(body, now)
            return snapshot
        }
    }

    private fun writeCache(rawPayload: String, fetchedAt: Long) {
        runCatching {
            val escaped = com.adshield.pro.cybershield.ComplianceReportJson.jsonString(rawPayload)
            cacheFile.writeText("{\"fetched_at\":$fetchedAt,\"payload\":$escaped}")
        }
    }

    private fun readCache(): IntelSnapshot? = runCatching {
        if (!cacheFile.exists()) return null
        val root = JsonLite.parse(cacheFile.readText())
        val fetchedAt = root.num("fetched_at")?.toLong() ?: return null
        val payload = root.str("payload") ?: return null
        FeodoParser.parse(payload, fetchedAt)
    }.getOrNull()

    private fun friendlyError(e: Throwable): String = when (e) {
        is java.net.UnknownHostException -> "No internet connection. Threat intel is unavailable until you reconnect."
        is java.net.SocketTimeoutException -> "Threat feed timed out. Try again."
        else -> "Threat feed unavailable: ${e.message ?: e.javaClass.simpleName}"
    }

    companion object {
        const val DEFAULT_MAX_AGE_MS = 30 * 60_000L
    }
}
