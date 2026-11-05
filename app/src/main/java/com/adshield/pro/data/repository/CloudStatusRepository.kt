package com.adshield.pro.data.repository

import com.adshield.pro.engine.cloud.CloudConnection
import com.adshield.pro.engine.cloud.CloudProvider
import com.adshield.pro.engine.cloud.CloudServiceStatus
import com.adshield.pro.engine.cloud.CloudStatusParser
import com.adshield.pro.engine.cloud.CloudStatusState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Polls the official public status pages of supported cloud providers on demand.
 *
 * No credentials, no account access: this is the provider's own published operational status.
 * A provider that has not been checked stays NOT_CHECKED ("Not connected") — the UI never
 * upgrades that to "secure". Account-level cloud security posture is out of scope and the
 * Cloud screen says so explicitly.
 */
@Singleton
class CloudStatusRepository @Inject constructor() {

    private val _state = MutableStateFlow(CloudStatusState())
    val state: StateFlow<CloudStatusState> = _state.asStateFlow()

    private val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .build()
    }

    /** Refreshes one provider, or all of them when [provider] is null. */
    suspend fun refresh(provider: CloudProvider? = null) = withContext(Dispatchers.IO) {
        val targets = provider?.let { listOf(it) } ?: CloudProvider.entries
        _state.update { it.copy(isRefreshing = true) }
        try {
            val results = coroutineScope {
                targets.map { target ->
                    async { target to fetchOne(target) }
                }.map { it.await() }
            }
            _state.update { current ->
                current.copy(
                    services = current.services.map { existing ->
                        results.firstOrNull { it.first == existing.provider }?.second ?: existing
                    },
                    isRefreshing = false
                )
            }
        } catch (t: Throwable) {
            _state.update { it.copy(isRefreshing = false) }
            throw t
        }
    }

    private fun fetchOne(provider: CloudProvider): CloudServiceStatus {
        val now = System.currentTimeMillis()
        return try {
            val request = Request.Builder()
                .url(provider.summaryEndpoint)
                .header("Accept", "application/json")
                .build()
            val body = client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw CloudStatusParser.CloudParseException("HTTP ${response.code} from ${provider.displayName}")
                }
                response.body?.string()
                    ?: throw CloudStatusParser.CloudParseException("Empty response from ${provider.displayName}")
            }
            CloudStatusParser.parse(provider, body, now)
        } catch (e: Exception) {
            CloudServiceStatus(
                provider = provider,
                connection = CloudConnection.ERROR,
                fetchedAtEpochMs = now,
                error = e.message ?: e.javaClass.simpleName
            )
        }
    }
}
