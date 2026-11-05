package com.adshield.pro.data.repository

import com.adshield.pro.data.local.db.AdShieldDao
import com.adshield.pro.data.local.db.IntelIndicatorEntity
import com.adshield.pro.data.local.db.IntelMetaEntity
import com.adshield.pro.engine.intel.FeedFetchStatus
import com.adshield.pro.engine.intel.IndicatorKind
import com.adshield.pro.engine.intel.IntelFeedState
import com.adshield.pro.engine.intel.IntelIndicator
import com.adshield.pro.engine.intel.IntelSource
import com.adshield.pro.engine.intel.ThreatIntelParser
import com.adshield.pro.engine.intel.ThreatIntelState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Downloads, parses and caches the public abuse.ch threat-intelligence feeds.
 *
 * Honesty contract:
 *  - a feed that has never been fetched is NOT_FETCHED, not "0 threats";
 *  - a failed fetch keeps the previous Room cache and records the real error + fetch time,
 *    so the UI can label the data stale instead of pretending it is live;
 *  - only indicators that actually carry a country code are ever drawn on the map.
 */
@Singleton
class ThreatIntelRepository @Inject constructor(
    private val dao: AdShieldDao
) {
    private val refreshMutex = Mutex()
    private val _isRefreshing = MutableStateFlow(false)

    private val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(12, TimeUnit.SECONDS)
            .readTimeout(25, TimeUnit.SECONDS)
            .build()
    }

    val state: Flow<ThreatIntelState> = combine(
        dao.observeIntelIndicators(),
        dao.observeIntelMeta(),
        _isRefreshing
    ) { indicatorEntities, metaEntities, refreshing ->
        val feeds = IntelSource.entries.map { source ->
            val meta = metaEntities.firstOrNull { it.sourceId == source.id }
            if (meta == null) {
                IntelFeedState(source.id)
            } else {
                IntelFeedState(
                    sourceId = meta.sourceId,
                    status = runCatching { FeedFetchStatus.valueOf(meta.status) }.getOrDefault(FeedFetchStatus.NOT_FETCHED),
                    lastFetchEpochMs = meta.lastFetchEpochMs,
                    lastError = meta.lastError,
                    itemCount = meta.itemCount
                )
            }
        }
        ThreatIntelState(
            feeds = feeds,
            indicators = indicatorEntities.map { it.toDomain() },
            isRefreshing = refreshing
        )
    }.flowOn(Dispatchers.IO)

    /**
     * Fetches every source. Each source succeeds or fails independently; one broken feed never
     * wipes the other's cache. Returns the number of indicators stored across both feeds.
     */
    suspend fun refresh(): Result<Int> = withContext(Dispatchers.IO) {
        if (refreshMutex.isLocked) return@withContext Result.failure(IllegalStateException("A threat-intel sync is already running."))
        refreshMutex.withLock {
            _isRefreshing.value = true
            try {
                var stored = 0
                var failures = 0
                IntelSource.entries.forEach { source ->
                    val outcome = runCatching { fetchAndStore(source) }
                    outcome.fold(
                        onSuccess = { count -> stored += count },
                        onFailure = { error ->
                            failures++
                            // Keep the previous successful fetch time/count so the UI can show
                            // exactly how old the retained cache is.
                            val previous = dao.getIntelMetaNow(source.id)
                            dao.upsertIntelMeta(
                                IntelMetaEntity(
                                    sourceId = source.id,
                                    status = FeedFetchStatus.ERROR.name,
                                    lastFetchEpochMs = previous?.lastFetchEpochMs ?: 0L,
                                    lastError = error.message ?: error.javaClass.simpleName,
                                    itemCount = previous?.itemCount ?: 0
                                )
                            )
                        }
                    )
                }
                if (failures == IntelSource.entries.size) {
                    Result.failure(IllegalStateException("All threat-intel feeds failed. Cached data (if any) was kept."))
                } else {
                    Result.success(stored)
                }
            } finally {
                _isRefreshing.value = false
            }
        }
    }

    private suspend fun fetchAndStore(source: IntelSource): Int {
        val request = Request.Builder()
            .url(source.feedUrl)
            .header("User-Agent", "AdShieldPro-ThreatIntel/1.0")
            .build()
        val body = client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw ThreatIntelParser.IntelParseException("${source.displayName} HTTP ${response.code}")
            }
            response.body?.string() ?: throw ThreatIntelParser.IntelParseException("${source.displayName} returned no body")
        }
        val indicators = when (source) {
            IntelSource.FEODO_TRACKER -> ThreatIntelParser.parseFeodo(body)
            IntelSource.URLHAUS -> ThreatIntelParser.parseUrlhaus(body).take(MAX_URLHAUS_ITEMS)
        }
        if (indicators.isEmpty()) {
            throw ThreatIntelParser.IntelParseException("${source.displayName} payload contained no usable indicators")
        }
        val now = System.currentTimeMillis()
        dao.deleteIntelIndicatorsForSource(source.id)
        dao.upsertIntelIndicators(indicators.map { it.toEntity(now) })
        dao.upsertIntelMeta(
            IntelMetaEntity(
                sourceId = source.id,
                status = FeedFetchStatus.OK.name,
                lastFetchEpochMs = now,
                lastError = null,
                itemCount = indicators.size
            )
        )
        return indicators.size
    }

    companion object {
        /** Recent URLhaus entries are numerous; keep the newest batch bounded for low-RAM devices. */
        const val MAX_URLHAUS_ITEMS = 1000
    }
}

private fun IntelIndicatorEntity.toDomain(): IntelIndicator = IntelIndicator(
    key = key,
    sourceId = sourceId,
    kind = runCatching { IndicatorKind.valueOf(kind) }.getOrDefault(IndicatorKind.MALWARE_URL),
    value = value,
    host = host,
    port = port,
    country = country,
    malwareFamily = malwareFamily,
    threat = threat,
    status = status,
    firstSeenUtc = firstSeenUtc,
    lastOnlineUtc = lastOnlineUtc,
    referenceUrl = referenceUrl
)

private fun IntelIndicator.toEntity(fetchedAtEpochMs: Long): IntelIndicatorEntity = IntelIndicatorEntity(
    key = key,
    sourceId = sourceId,
    kind = kind.name,
    value = value,
    host = host,
    port = port,
    country = country,
    malwareFamily = malwareFamily,
    threat = threat,
    status = status,
    firstSeenUtc = firstSeenUtc,
    lastOnlineUtc = lastOnlineUtc,
    referenceUrl = referenceUrl,
    fetchedAtEpochMs = fetchedAtEpochMs
)
