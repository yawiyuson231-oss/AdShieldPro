package com.adshield.pro.data.repository

import com.adshield.pro.data.local.db.IntelligenceEventDao
import com.adshield.pro.data.local.db.IntelligenceEventEntity
import com.adshield.pro.domain.intelligence.IntelligenceAction
import com.adshield.pro.domain.intelligence.IntelligenceEvent
import com.adshield.pro.domain.intelligence.IntelligenceEventType
import com.adshield.pro.domain.intelligence.IntelligenceMetric
import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.domain.intelligence.IntelligenceSeverity
import com.adshield.pro.engine.intelligence.IntelligenceEventSanitizer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.util.concurrent.atomic.AtomicInteger
import javax.inject.Inject
import javax.inject.Singleton

/** Hard bounds that keep the live map cheap on low-memory devices. */
object IntelligenceLimits {
    /** Rows kept in Room. Older rows are trimmed after every prune cycle. */
    const val MAX_STORED_EVENTS = 800

    /** Rows observed by the UI. Everything above the newest N stays available to retention only. */
    const val LOADED_EVENTS = 600

    /** Age bound, independent of the row bound. */
    const val RETENTION_DAYS = 14

    const val RETENTION_MS = RETENTION_DAYS * 24L * 60L * 60L * 1_000L

    /** Prune/trim cadence expressed in inserted rows, not in a timer. */
    const val PRUNE_EVERY_INSERTS = 16
}

/**
 * Bounded, observable store for intelligence events.
 *
 * Reads are mapped on [Dispatchers.Default] and de-duplicated so a Room invalidation that does not
 * change the visible rows cannot recompose the map. Writes are validated, sanitised and pruned.
 */
@Singleton
class IntelligenceRepository @Inject constructor(
    private val dao: IntelligenceEventDao
) {
    private val json = Json { ignoreUnknownKeys = true }
    private val stringListSerializer = ListSerializer(String.serializer())
    private val metricListSerializer = ListSerializer(IntelligenceMetric.serializer())
    private val insertCounter = AtomicInteger(0)

    val events: Flow<List<IntelligenceEvent>> = dao.observeRecent(IntelligenceLimits.LOADED_EVENTS)
        .map { rows -> rows.mapNotNull(::toDomain) }
        .distinctUntilChanged()
        .flowOn(Dispatchers.Default)

    fun observeModule(module: IntelligenceModule, limit: Int = 120): Flow<List<IntelligenceEvent>> =
        dao.observeForModule(module.id, limit)
            .map { rows -> rows.mapNotNull(::toDomain) }
            .distinctUntilChanged()
            .flowOn(Dispatchers.Default)

    /**
     * Validates, sanitises and persists [draft]. Returns the stored copy (with its assigned id) or
     * `null` when the draft carried no usable evidence.
     */
    suspend fun record(draft: IntelligenceEvent, nowEpochMs: Long = System.currentTimeMillis()): IntelligenceEvent? {
        val sanitized = IntelligenceEventSanitizer.sanitize(draft, nowEpochMs).event ?: return null
        val id = dao.insert(sanitized.toEntity(json, stringListSerializer, metricListSerializer))
        if (insertCounter.incrementAndGet() % IntelligenceLimits.PRUNE_EVERY_INSERTS == 0) {
            prune(nowEpochMs)
        }
        return sanitized.copy(id = id)
    }

    /** Age prune followed by a row cap; returns how many rows were removed. */
    suspend fun prune(nowEpochMs: Long = System.currentTimeMillis()): Int {
        val byAge = dao.pruneBefore(nowEpochMs - IntelligenceLimits.RETENTION_MS)
        val byCount = dao.trimToLimit(IntelligenceLimits.MAX_STORED_EVENTS)
        return byAge + byCount
    }

    suspend fun count(): Int = dao.count()

    suspend fun clear() = dao.clearAll()

    private fun toDomain(row: IntelligenceEventEntity): IntelligenceEvent? {
        val type = IntelligenceEventType.fromCodeOrNull(row.typeCode) ?: return null
        val module = IntelligenceModule.fromIdOrNull(row.module) ?: type.module
        val severity = IntelligenceSeverity.fromNameOrNull(row.severity) ?: type.defaultSeverity
        val related = runCatching {
            json.decodeFromString(stringListSerializer, row.relatedIdsJson)
        }.getOrDefault(emptyList())
        val metrics = runCatching {
            json.decodeFromString(metricListSerializer, row.metricsJson)
        }.getOrDefault(emptyList())
        val actions = row.actionsCsv.split(',')
            .mapNotNull { IntelligenceAction.fromNameOrNull(it.trim()) }
            .distinct()
        return IntelligenceEvent(
            id = row.id,
            module = module,
            type = type,
            severity = severity,
            timestampEpochMs = row.timestampEpochMs,
            title = row.title,
            description = row.description,
            evidence = row.evidence,
            evidenceRef = row.evidenceRef,
            relatedObjectIds = related,
            actions = actions,
            metrics = metrics
        )
    }

    private fun IntelligenceEvent.toEntity(
        json: Json,
        stringListSerializer: ListSerializer<String>,
        metricListSerializer: ListSerializer<IntelligenceMetric>
    ): IntelligenceEventEntity = IntelligenceEventEntity(
        id = this.id,
        module = module.id,
        typeCode = type.code,
        severity = severity.name,
        timestampEpochMs = timestampEpochMs,
        title = title,
        description = description,
        evidence = evidence,
        evidenceRef = evidenceRef,
        relatedIdsJson = json.encodeToString(stringListSerializer, relatedObjectIds),
        metricsJson = json.encodeToString(metricListSerializer, metrics),
        actionsCsv = actions.joinToString(",") { it.name }
    )
}
