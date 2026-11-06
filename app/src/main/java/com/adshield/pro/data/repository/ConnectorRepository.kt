package com.adshield.pro.data.repository

import com.adshield.pro.data.local.db.ConnectorDao
import com.adshield.pro.data.local.db.ConnectorStateEntity
import com.adshield.pro.data.local.db.LookupCacheDao
import com.adshield.pro.data.local.db.LookupCacheEntity
import com.adshield.pro.data.local.db.ThreatIndicatorEntity
import com.adshield.pro.domain.connectors.ConnectorModuleSummary
import com.adshield.pro.domain.connectors.ConnectorRuntime
import com.adshield.pro.domain.connectors.ConnectorSnapshot
import com.adshield.pro.domain.connectors.ConnectorSpec
import com.adshield.pro.domain.connectors.ConnectorStatus
import com.adshield.pro.domain.connectors.IndicatorKind
import com.adshield.pro.domain.connectors.LookupEvidence
import com.adshield.pro.domain.connectors.LookupField
import com.adshield.pro.domain.connectors.LookupFinding
import com.adshield.pro.domain.connectors.LookupQuery
import com.adshield.pro.domain.connectors.LookupReport
import com.adshield.pro.domain.connectors.SyncOutcome
import com.adshield.pro.domain.connectors.ThreatIndicator
import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.engine.connectors.ConnectorCatalogue
import com.adshield.pro.engine.connectors.ConnectorParsers
import com.adshield.pro.engine.connectors.ConnectorSyncEngine
import com.adshield.pro.engine.connectors.IndicatorRisk
import com.adshield.pro.engine.connectors.IntelLookupEngine
import com.adshield.pro.engine.connectors.NativeConnectorProbes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Single owner of connector state and the local intelligence cache.
 *
 * Truthfulness rules implemented here:
 *  - a status is written only from an outcome the engine/probe actually returned;
 *  - `lastSuccessEpochMs` is only set when a real, valid response (or a real native measurement)
 *    was received, so "CONNECTED" cannot be faked by an empty cache;
 *  - indicators are stored with their source and expiry, replaced atomically per source;
 *  - stale rows are pruned instead of being served as current intelligence.
 */
@Singleton
class ConnectorRepository @Inject constructor(
    private val dao: ConnectorDao,
    private val engine: ConnectorSyncEngine,
    private val probes: NativeConnectorProbes,
    private val lookupCacheDao: LookupCacheDao,
    private val lookupEngine: IntelLookupEngine
) {

    private val syncMutex = Mutex()

    val snapshots: Flow<List<ConnectorSnapshot>> = dao.observeStates()
        .map { rows ->
            val byId = rows.associateBy { it.connectorId }
            val now = System.currentTimeMillis()
            ConnectorCatalogue.all.map { spec ->
                ConnectorSnapshot(spec, byId[spec.id]?.toDomain() ?: ConnectorRuntime.initial(spec), now)
            }
        }
        .distinctUntilChanged()
        .flowOn(Dispatchers.Default)

    val summaries: Flow<Map<IntelligenceModule, ConnectorModuleSummary>> = snapshots
        .map { list -> list.groupBy { it.spec.module }.mapValues { (module, items) -> summarise(module, items) } }
        .distinctUntilChanged()
        .flowOn(Dispatchers.Default)

    fun summarise(module: IntelligenceModule, items: List<ConnectorSnapshot>): ConnectorModuleSummary {
        val implemented = items.filter { it.spec.implemented }
        return ConnectorModuleSummary(
            module = module,
            total = items.size,
            implemented = implemented.size,
            connected = items.count { it.effectiveStatus == ConnectorStatus.CONNECTED },
            degraded = items.count {
                it.effectiveStatus == ConnectorStatus.DEGRADED ||
                    it.effectiveStatus == ConnectorStatus.RATE_LIMITED ||
                    it.effectiveStatus == ConnectorStatus.OFFLINE ||
                    it.effectiveStatus == ConnectorStatus.ERROR
            },
            notConfigured = items.count {
                it.effectiveStatus == ConnectorStatus.NOT_CONFIGURED ||
                    it.effectiveStatus == ConnectorStatus.NOT_IMPLEMENTED
            },
            lastSuccessEpochMs = items.mapNotNull { it.runtime.lastSuccessEpochMs }.maxOrNull()
        )
    }

    fun spec(id: String): ConnectorSpec? = ConnectorCatalogue.find(id)

    /** Sync one connector now. Returns the persisted snapshot, or null for an unknown id. */
    suspend fun sync(id: String): ConnectorSnapshot? = withContext(Dispatchers.IO) {
        syncMutex.withLock {
            val spec = ConnectorCatalogue.find(id) ?: return@withLock null
            val previous = dao.stateFor(id)?.toDomain() ?: ConnectorRuntime.initial(spec)
            val now = System.currentTimeMillis()

            if (spec.isLookup) {
                // Lookups are user-driven: syncing them as feeds would send an empty query and
                // turn a working provider into a misleading error.
                dao.upsertState(
                    previous.copy(lastError = "On-demand lookup — enter a value in the check panel").toEntity()
                )
                return@withLock dao.stateFor(id)?.toDomain()
            }

            if (spec.requiresKey) {
                val blocked = previous.copy(
                    status = ConnectorStatus.NOT_CONFIGURED,
                    lastAttemptEpochMs = now,
                    lastError = "provider requires credentials; none are bundled"
                )
                dao.upsertState(blocked.toEntity())
                return@withLock snapshotOf(spec, blocked)
            }
            if (!spec.implemented) {
                val blocked = previous.copy(status = ConnectorStatus.NOT_IMPLEMENTED, lastAttemptEpochMs = now)
                dao.upsertState(blocked.toEntity())
                return@withLock snapshotOf(spec, blocked)
            }

            val attempting = previous.copy(enabled = true, status = ConnectorStatus.SYNCING, lastAttemptEpochMs = now)
            dao.upsertState(attempting.toEntity())

            val updated = if (spec.isFeed) {
                val outcome = engine.sync(spec, attempting)
                if (outcome is SyncOutcome.Success && !outcome.notModified && outcome.indicators.isNotEmpty()) {
                    storeIndicators(spec, outcome.indicators, now)
                }
                applyFeedOutcome(spec, attempting, outcome, now)
            } else {
                applyProbeResult(spec, attempting, now)
            }
            dao.upsertState(updated.toEntity())
            snapshotOf(spec, updated)
        }
    }

    suspend fun syncModule(module: IntelligenceModule, limit: Int = 12): Int = withContext(Dispatchers.IO) {
        var done = 0
        ConnectorCatalogue.forModule(module)
            .filter { it.implemented }
            .take(limit)
            .forEach { spec ->
                sync(spec.id)
                done++
            }
        done
    }

    /** Background entry point: only default-enabled, due HTTP feeds (cheap on battery/data). */
    suspend fun syncDueFeeds(): Int = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        var synced = 0
        ConnectorCatalogue.feeds
            .filter { it.implemented && it.defaultEnabled && !it.requiresKey && !it.isLookup }
            .forEach { spec ->
                val previous = dao.stateFor(spec.id)?.toDomain() ?: ConnectorRuntime.initial(spec)
                val due = previous.lastAttemptEpochMs == null ||
                    now - (previous.lastAttemptEpochMs ?: 0L) > spec.cacheTtlMs
                if (due) {
                    sync(spec.id)
                    synced++
                }
            }
        synced
    }

    suspend fun setEnabled(id: String, enabled: Boolean) = withContext(Dispatchers.IO) {
        val spec = ConnectorCatalogue.find(id) ?: return@withContext
        val previous = dao.stateFor(id)?.toDomain() ?: ConnectorRuntime.initial(spec)
        val next = previous.copy(
            enabled = enabled,
            status = if (!enabled) ConnectorStatus.DISABLED else if (previous.lastSuccessEpochMs != null) {
                ConnectorStatus.CONNECTED
            } else {
                ConnectorStatus.DEGRADED
            }
        )
        dao.upsertState(next.toEntity())
    }

    suspend fun prune(): Int = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        dao.pruneExpired(now) + dao.trimToLimit(MAX_CACHED_INDICATORS)
    }

    suspend fun indicatorCounts(): Map<IndicatorKind, Int> = withContext(Dispatchers.IO) {
        dao.countsByKind().mapNotNull { row ->
            runCatching { IndicatorKind.valueOf(row.kind) }.getOrNull()?.let { it to row.count }
        }.toMap()
    }

    suspend fun totalIndicators(): Int = withContext(Dispatchers.IO) { dao.countAll() }

    /**
     * Matches a user-supplied value (or an observed one) against cached intelligence.
     * URLs additionally match their host, so a cached malicious domain catches a full URL.
     */
    suspend fun assess(rawValue: String, localRisk: Int = 0): IndicatorRisk.Assessment = withContext(Dispatchers.IO) {
        val value = IndicatorRisk.normalise(rawValue)
        val kind = IndicatorRisk.kindForValue(value)
            ?: return@withContext IndicatorRisk.assess(emptyList(), 0)
        val now = System.currentTimeMillis()
        val candidates = mutableListOf<ThreatIndicator>()
        candidates += dao.match(kind.name, listOf(value), now).map { it.toDomain() }
        if (kind == IndicatorKind.URL) {
            ConnectorParsers.hostOf(value)?.let { host ->
                candidates += dao.match(IndicatorKind.DOMAIN.name, listOf(host), now).map { it.toDomain() }
            }
        }
        if (kind == IndicatorKind.IP) {
            // CIDR feeds (FireHOL, Spamhaus DROP) are stored as networks; containment is checked
            // locally so a /12 entry actually matches the addresses inside it.
            candidates += dao.activeCidrs(now)
                .filter { IndicatorRisk.ipInCidr(value, it.value) }
                .map { it.toDomain() }
        }
        val distinct = candidates.distinctBy { it.sourceId to it.value }
        IndicatorRisk.assess(distinct, localRisk)
    }

    /**
     * Runs every implemented, key-free lookup connector that accepts this kind of value.
     *
     * Behaviour:
     *  - a fresh cache entry (inside its TTL) is served without a network request;
     *  - an expired entry is refreshed, and is used as an explicit offline fallback if the
     *    provider is unreachable;
     *  - a connector that needs a key or is unimplemented is never contacted and never appears
     *    as a verified answer.
     *
     * The returned report keeps per-provider errors, so a partial answer is visible as partial.
     */
    suspend fun lookup(rawValue: String, fieldHint: LookupField? = null): LookupReport = withContext(Dispatchers.IO) {
        val trimmed = rawValue.trim()
        val field = fieldHint ?: LookupField.detect(trimmed)
            ?: return@withContext LookupReport(
                query = LookupQuery(LookupField.DOMAIN, trimmed),
                findings = emptyList(),
                offline = false,
                notes = listOf("Unsupported value. Use a domain, URL, IPv4 address, CVE, SHA-256 or ecosystem:name@version.")
            )
        val query = LookupQuery(field, trimmed)
        val prepared = lookupEngine.prepare(query)
        if (prepared is IntelLookupEngine.Prepared.Invalid) {
            return@withContext LookupReport(
                query = query,
                findings = emptyList(),
                offline = false,
                notes = listOf(prepared.reason)
            )
        }
        val target = (prepared as IntelLookupEngine.Prepared.Ready).target
        val specs = ConnectorCatalogue.all
            .filter { it.isLookup && it.implemented && !it.requiresKey && it.queryField == field }
        val now = System.currentTimeMillis()
        val findings = mutableListOf<LookupFinding>()
        var attempted = 0
        var offlineCount = 0
        specs.forEach { spec ->
            val cacheKey = spec.id + "|" + field.name + "|" + target.canonical
            val cached = runCatching { lookupCacheDao.get(cacheKey) }.getOrNull()
            if (cached != null && cached.expiresAtEpochMs > now) {
                findings += cached.toFinding(query)
                return@forEach
            }
            attempted++
            val finding = lookupEngine.execute(spec, query, prepared)
            if (finding.error == null) {
                runCatching {
                    lookupCacheDao.upsert(
                        LookupCacheEntity(
                            cacheKey = cacheKey,
                            connectorId = spec.id,
                            field = field.name,
                            query = target.canonical,
                            found = finding.found,
                            riskScore = finding.riskScore,
                            headline = finding.headline.take(300),
                            evidenceJson = encodeEvidence(finding.evidence),
                            attribution = finding.attribution.take(200),
                            fetchedAtEpochMs = finding.fetchedAtEpochMs,
                            expiresAtEpochMs = finding.fetchedAtEpochMs + spec.cacheTtlMs,
                            httpCode = finding.httpCode
                        )
                    )
                }
                findings += finding
            } else {
                if (finding.error.contains("offline", ignoreCase = true)) offlineCount++
                findings += if (cached != null) {
                    cached.toFinding(query).copy(
                        fromCache = true,
                        limitation = "Live query failed (${finding.error}); showing the cached answer from " +
                            formatAge(now - cached.fetchedAtEpochMs) + " ago."
                    )
                } else {
                    finding
                }
            }
        }
        val notes = mutableListOf<String>()
        notes += "Lookups run only when you ask; no background requests are made for them."
        if (specs.isEmpty()) {
            notes += "No implemented free connector accepts ${field.label}."
        } else {
            notes += "${specs.size} connector(s) can answer ${field.label}; $attempted live request(s) this time."
        }
        if (offlineCount > 0) {
            notes += "$offlineCount provider(s) looked unreachable; cached answers are marked as cached."
        }
        notes += "Risk numbers are local deterministic weights, not provider verdicts and not a malware verdict."
        LookupReport(
            query = query,
            findings = findings,
            offline = offlineCount > 0,
            notes = notes
        )
    }

    suspend fun lookupCacheCount(): Int = withContext(Dispatchers.IO) {
        runCatching { lookupCacheDao.count() }.getOrDefault(0)
    }

    suspend fun clearLookupCache(): Int = withContext(Dispatchers.IO) {
        runCatching { lookupCacheDao.clear() }.getOrDefault(0)
    }

    private fun LookupCacheEntity.toFinding(query: LookupQuery): LookupFinding = LookupFinding(
        connectorId = connectorId,
        connectorName = ConnectorCatalogue.find(connectorId)?.name ?: connectorId,
        provider = ConnectorCatalogue.find(connectorId)?.provider ?: attribution,
        module = ConnectorCatalogue.find(connectorId)?.module ?: IntelligenceModule.CYBER_DEFENSE,
        query = query,
        found = found,
        riskScore = riskScore,
        headline = headline,
        evidence = decodeEvidence(evidenceJson),
        attribution = attribution,
        fetchedAtEpochMs = fetchedAtEpochMs,
        fromCache = true,
        httpCode = httpCode,
        limitation = "Cached answer; freshness depends on the provider TTL."
    )

    private fun encodeEvidence(evidence: List<LookupEvidence>): String = evidence
        .take(12)
        .joinToString("\n") { item ->
            item.label.replace('\n', ' ').replace('\u001f', ' ') + "\u001f" +
                item.value.replace('\n', ' ').replace('\u001f', ' ')
        }

    private fun decodeEvidence(raw: String): List<LookupEvidence> = raw
        .lineSequence()
        .filter { it.isNotBlank() }
        .mapNotNull { line ->
            val parts = line.split('\u001f', limit = 2)
            if (parts.size != 2) null else LookupEvidence(parts[0], parts[1])
        }
        .toList()

    private fun formatAge(ageMs: Long): String {
        val minutes = (ageMs / 60_000L).coerceAtLeast(0L)
        return when {
            minutes < 60 -> "$minutes min"
            minutes < 1_440 -> "${minutes / 60} h"
            else -> "${minutes / 1_440} d"
        }
    }

    private suspend fun storeIndicators(spec: ConnectorSpec, indicators: List<ThreatIndicator>, now: Long) {
        dao.deleteForSource(spec.id)
        // MISP warninglists exist to *remove* false positives, so they are stored with confidence 0
        // and can only ever suppress a match; they never contribute risk points.
        val suppression = spec.id.contains("misp") || spec.id.contains("warninglist")
        indicators.chunked(400).forEach { chunk ->
            dao.insertIndicators(
                chunk.map { indicator ->
                    ThreatIndicatorEntity(
                        kind = indicator.kind.name,
                        value = indicator.value,
                        sourceId = indicator.sourceId,
                        module = indicator.module.id,
                        label = indicator.label.take(120),
                        confidence = if (suppression) 0 else indicator.confidence.coerceIn(0, 100),
                        firstSeenEpochMs = indicator.firstSeenEpochMs,
                        expiresAtEpochMs = indicator.expiresAtEpochMs.coerceAtLeast(now + 60_000L),
                        attribution = indicator.attribution.take(120)
                    )
                }
            )
        }
    }

    private fun applyFeedOutcome(
        spec: ConnectorSpec,
        previous: ConnectorRuntime,
        outcome: SyncOutcome,
        now: Long
    ): ConnectorRuntime = when (outcome) {
        is SyncOutcome.Success -> previous.copy(
            status = ConnectorStatus.CONNECTED,
            lastSuccessEpochMs = now,
            lastError = null,
            httpCode = outcome.httpCode,
            indicatorCount = if (outcome.notModified) previous.indicatorCount else outcome.indicators.size,
            etag = outcome.etag ?: previous.etag,
            lastModified = outcome.lastModified ?: previous.lastModified,
            nextAllowedEpochMs = now + spec.cacheTtlMs,
            consecutiveFailures = 0,
            lastSummary = outcome.summary,
            latencyMs = outcome.latencyMs
        )

        is SyncOutcome.Retryable -> previous.copy(
            status = when {
                outcome.httpCode == 429 -> ConnectorStatus.RATE_LIMITED
                outcome.offline -> ConnectorStatus.OFFLINE
                else -> ConnectorStatus.ERROR
            },
            lastError = outcome.reason,
            httpCode = outcome.httpCode,
            nextAllowedEpochMs = now + (outcome.retryAfterMs ?: ConnectorSyncEngine.backoffFor(previous.consecutiveFailures + 1)),
            consecutiveFailures = previous.consecutiveFailures + 1,
            latencyMs = outcome.latencyMs
        )

        is SyncOutcome.Failed -> previous.copy(
            status = if (outcome.httpCode == 401 || outcome.httpCode == 403) {
                ConnectorStatus.NOT_CONFIGURED
            } else {
                ConnectorStatus.ERROR
            },
            lastError = outcome.reason,
            httpCode = outcome.httpCode,
            nextAllowedEpochMs = now + ConnectorSyncEngine.RATE_LIMIT_COOLDOWN_MS,
            consecutiveFailures = previous.consecutiveFailures + 1,
            latencyMs = outcome.latencyMs
        )

        SyncOutcome.NotConfigured -> previous.copy(
            status = ConnectorStatus.NOT_CONFIGURED,
            lastError = "provider requires credentials; none are bundled"
        )

        SyncOutcome.Skipped -> previous.copy(status = ConnectorStatus.DISABLED)
    }

    private suspend fun applyProbeResult(
        spec: ConnectorSpec,
        previous: ConnectorRuntime,
        now: Long
    ): ConnectorRuntime {
        val result = probes.run(spec.handlerId)
        return previous.copy(
            status = result.status,
            lastSuccessEpochMs = if (result.available) now else previous.lastSuccessEpochMs,
            lastError = result.restriction ?: if (!result.available) result.summary else null,
            httpCode = null,
            indicatorCount = previous.indicatorCount,
            nextAllowedEpochMs = now + spec.cacheTtlMs,
            consecutiveFailures = if (result.available) 0 else previous.consecutiveFailures + 1,
            lastSummary = result.summary,
            latencyMs = null
        )
    }

    private fun snapshotOf(spec: ConnectorSpec, runtime: ConnectorRuntime) =
        ConnectorSnapshot(spec, runtime, System.currentTimeMillis())

    private fun ConnectorStateEntity.toDomain() = ConnectorRuntime(
        connectorId = connectorId,
        status = runCatching { ConnectorStatus.valueOf(status) }.getOrDefault(ConnectorStatus.ERROR),
        enabled = enabled,
        lastAttemptEpochMs = lastAttemptEpochMs,
        lastSuccessEpochMs = lastSuccessEpochMs,
        lastError = lastError,
        httpCode = httpCode,
        indicatorCount = indicatorCount,
        etag = etag,
        lastModified = lastModified,
        nextAllowedEpochMs = nextAllowedEpochMs,
        consecutiveFailures = consecutiveFailures,
        lastSummary = lastSummary,
        latencyMs = latencyMs
    )

    private fun ConnectorRuntime.toEntity() = ConnectorStateEntity(
        connectorId = connectorId,
        status = status.name,
        enabled = enabled,
        lastAttemptEpochMs = lastAttemptEpochMs,
        lastSuccessEpochMs = lastSuccessEpochMs,
        lastError = lastError?.take(300),
        httpCode = httpCode,
        indicatorCount = indicatorCount,
        etag = etag,
        lastModified = lastModified,
        nextAllowedEpochMs = nextAllowedEpochMs,
        consecutiveFailures = consecutiveFailures,
        lastSummary = lastSummary?.take(200),
        latencyMs = latencyMs
    )

    private fun ThreatIndicatorEntity.toDomain() = ThreatIndicator(
        kind = runCatching { IndicatorKind.valueOf(kind) }.getOrDefault(IndicatorKind.DOMAIN),
        value = value,
        sourceId = sourceId,
        module = IntelligenceModule.fromIdOrNull(module) ?: IntelligenceModule.CYBER_DEFENSE,
        label = label,
        confidence = confidence,
        firstSeenEpochMs = firstSeenEpochMs,
        expiresAtEpochMs = expiresAtEpochMs,
        attribution = attribution
    )

    companion object {
        /** Bound so a hostile/mistaken feed cannot grow the cache without limit. */
        const val MAX_CACHED_INDICATORS = 40_000
    }
}
