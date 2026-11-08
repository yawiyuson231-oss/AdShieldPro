package com.adshield.pro.data.worldmonitor

import android.content.Context
import com.adshield.pro.data.repository.ProviderCredentialStore
import com.adshield.pro.domain.worldmonitor.BuildingFootprint3D
import com.adshield.pro.domain.worldmonitor.EntityTrail
import com.adshield.pro.domain.worldmonitor.GeoSearchResult
import com.adshield.pro.domain.worldmonitor.GlobeViewport
import com.adshield.pro.domain.worldmonitor.ProviderSyncStatus
import com.adshield.pro.domain.worldmonitor.TrailVertex
import com.adshield.pro.domain.worldmonitor.WatchAlertRecord
import com.adshield.pro.domain.worldmonitor.WatchRegion
import com.adshield.pro.domain.worldmonitor.WorldEntity
import com.adshield.pro.domain.worldmonitor.WorldIntelCategory
import com.adshield.pro.domain.worldmonitor.WorldProviderRuntimeState
import com.adshield.pro.domain.worldmonitor.WorldProviderSpec
import com.adshield.pro.engine.worldmonitor.BaselineReferenceStore
import com.adshield.pro.engine.worldmonitor.WatchtowerManager
import com.adshield.pro.engine.worldmonitor.WorldMonitorNormalizers
import com.adshield.pro.engine.worldmonitor.WorldMonitorProviderRegistry
import com.adshield.pro.engine.worldmonitor.WorldMonitorSyncEngine
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Offline-First Repository for OMNISHIELD X INFINITY — WORLD MONITOR 2035.
 *
 * Manages SQLite caching, spatial/temporal queries, kinematic trail history, RainViewer radar
 * frames, 3D OSM buildings, optional encrypted user credentials, and Watchtower geofence evaluation.
 */
@Singleton
class WorldMonitorRepository @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val dao: WorldMonitorDao,
    private val syncEngine: WorldMonitorSyncEngine,
    private val credentialStore: ProviderCredentialStore
) {
    private val syncSemaphore = Semaphore(4)

    private val _rainViewerFrames = MutableStateFlow<List<WorldMonitorNormalizers.RainViewerFrame>>(emptyList())
    val rainViewerFrames: StateFlow<List<WorldMonitorNormalizers.RainViewerFrame>> = _rainViewerFrames.asStateFlow()

    private val _buildings3D = MutableStateFlow<List<BuildingFootprint3D>>(emptyList())
    val buildings3D: StateFlow<List<BuildingFootprint3D>> = _buildings3D.asStateFlow()

    val entitiesFlow: Flow<List<WorldEntity>> = dao.observeActiveEntities(5_000)
        .map { rows ->
            val now = System.currentTimeMillis()
            rows.map { it.toDomain(now) }
        }

    val providerStatesFlow: Flow<List<WorldProviderRuntimeState>> = dao.observeProviderStates()
        .map { rows ->
            val byId = rows.associateBy { it.providerId }
            WorldMonitorProviderRegistry.ALL.map { spec ->
                byId[spec.id]?.toDomain() ?: defaultProviderState(spec)
            }
        }

    val watchRegionsFlow: Flow<List<WatchRegion>> = dao.observeWatchRegions()
        .map { list -> list.map { it.toDomain() } }

    val watchAlertsFlow: Flow<List<WatchAlertRecord>> = dao.observeWatchAlerts(200)
        .map { list -> list.map { it.toDomain() } }

    val unacknowledgedAlertCountFlow: Flow<Int> = dao.observeUnacknowledgedAlertCount()

    suspend fun ensureBaselineSeeded() = withContext(Dispatchers.IO) {
        val state = dao.getProviderState("wm.infra.baseline")
        if (state == null || state.cachedItemCount == 0) {
            val now = System.currentTimeMillis()
            val entities = BaselineReferenceStore.buildBaselineEntities(now)
            dao.upsertEntities(entities.map { it.toEntity(365L * 24 * 3_600_000L) })
            dao.upsertProviderState(
                WorldProviderStateEntity(
                    providerId = "wm.infra.baseline",
                    enabled = true,
                    status = ProviderSyncStatus.HEALTHY.name,
                    lastSyncEpochMs = now,
                    lastSuccessEpochMs = now,
                    nextEligibleEpochMs = 0L,
                    lastHttpCode = 200,
                    lastError = null,
                    etag = "bundled-v1",
                    lastModifiedHeader = null,
                    cachedItemCount = entities.size,
                    consecutiveFailures = 0
                )
            )
        }
    }

    suspend fun syncEnabledProviders(
        categories: Set<WorldIntelCategory> = WorldIntelCategory.entries.toSet(),
        viewport: GlobeViewport? = null,
        force: Boolean = false,
        notifyWatchtower: Boolean = true
    ): Int = withContext(Dispatchers.IO) {
        ensureBaselineSeeded()
        val now = System.currentTimeMillis()
        dao.pruneExpiredEntities(now)
        dao.pruneOldTrails(now - 12L * 3_600_000L)

        val specs = WorldMonitorProviderRegistry.ALL.filter { spec ->
            spec.category in categories &&
                spec.id != "wm.infra.baseline" &&
                spec.id != "wm.infra.overpass" &&
                (force || spec.enabledByDefault || dao.getProviderState(spec.id)?.enabled == true)
        }

        val outcomes = coroutineScope {
            specs.map { spec ->
                async {
                    syncSemaphore.withPermit {
                        val outcome = syncEngine.syncProvider(spec, viewport = viewport, force = force, nowEpochMs = now)
                        persistOutcome(spec, outcome, now)
                        outcome
                    }
                }
            }.awaitAll()
        }

        val freshEntities = outcomes.flatMap { it.entities }
        if (freshEntities.isNotEmpty()) {
            WatchtowerManager.evaluateAndPersist(
                context = appContext,
                dao = dao,
                candidates = freshEntities,
                notifyUser = notifyWatchtower
            )
        }
        outcomes.count { it.status == ProviderSyncStatus.HEALTHY }
    }

    suspend fun syncSingleProvider(
        providerId: String,
        viewport: GlobeViewport? = null,
        force: Boolean = true
    ): WorldMonitorSyncEngine.ProviderFetchOutcome = withContext(Dispatchers.IO) {
        val spec = WorldMonitorProviderRegistry.byId(providerId)
            ?: return@withContext WorldMonitorSyncEngine.ProviderFetchOutcome(
                providerId,
                ProviderSyncStatus.ERROR,
                errorMessage = "Unknown provider $providerId"
            )
        val now = System.currentTimeMillis()
        val outcome = syncEngine.syncProvider(spec, viewport = viewport, force = force, nowEpochMs = now)
        persistOutcome(spec, outcome, now)
        if (outcome.entities.isNotEmpty()) {
            WatchtowerManager.evaluateAndPersist(appContext, dao, outcome.entities, notifyUser = false)
        }
        outcome
    }

    suspend fun syncBuildingsAndStreetInfra(viewport: GlobeViewport): WorldMonitorSyncEngine.ProviderFetchOutcome {
        return syncSingleProvider("wm.infra.overpass", viewport = viewport, force = true)
    }

    private suspend fun persistOutcome(
        spec: WorldProviderSpec,
        outcome: WorldMonitorSyncEngine.ProviderFetchOutcome,
        nowEpochMs: Long
    ) {
        if (outcome.rainViewerFrames.isNotEmpty()) {
            _rainViewerFrames.value = outcome.rainViewerFrames
        }
        if (outcome.buildings3D.isNotEmpty()) {
            _buildings3D.value = outcome.buildings3D
        }
        if (outcome.entities.isNotEmpty()) {
            if (spec.category == WorldIntelCategory.AVIATION && spec.id != "wm.aviation.ourairports") {
                dao.deleteEntitiesForProvider(spec.id)
            }
            dao.upsertEntities(outcome.entities.map { it.toEntity(spec.cacheTtlMs) })

            // Record kinematic position trails for moving aircraft, vessels, and ISS
            if (spec.category == WorldIntelCategory.AVIATION ||
                spec.category == WorldIntelCategory.MARITIME ||
                spec.id == "wm.space.iss"
            ) {
                val trailRows = outcome.entities
                    .filter { it.speedValue != null || spec.id == "wm.space.iss" }
                    .take(220)
                    .map { e ->
                        WorldEntityTrailPointEntity(
                            entityId = e.id,
                            category = e.category.name,
                            latitude = e.latitude,
                            longitude = e.longitude,
                            altitudeMeters = e.altitudeMeters,
                            timestampEpochMs = nowEpochMs
                        )
                    }
                if (trailRows.isNotEmpty()) {
                    dao.insertTrailPoints(trailRows)
                }
            }
        }
    }

    suspend fun loadRecentTrails(categories: Set<WorldIntelCategory>): List<EntityTrail> = withContext(Dispatchers.IO) {
        val since = System.currentTimeMillis() - 3L * 3_600_000L
        val out = ArrayList<EntityTrail>()
        for (cat in categories) {
            if (cat != WorldIntelCategory.AVIATION && cat != WorldIntelCategory.MARITIME && cat != WorldIntelCategory.SPACE) continue
            val points = dao.queryRecentTrailsForCategory(cat.name, since, 1_800)
            points.groupBy { it.entityId }.forEach { (entityId, rows) ->
                if (rows.size >= 2) {
                    out += EntityTrail(
                        entityId = entityId,
                        category = cat,
                        points = rows.sortedBy { it.timestampEpochMs }.map { r ->
                            TrailVertex(
                                latitude = r.latitude,
                                longitude = r.longitude,
                                altitudeMeters = r.altitudeMeters,
                                timestampEpochMs = r.timestampEpochMs
                            )
                        }
                    )
                }
            }
        }
        out
    }

    suspend fun setProviderEnabled(providerId: String, enabled: Boolean) = withContext(Dispatchers.IO) {
        val existing = dao.getProviderState(providerId)
        if (existing != null) {
            dao.setProviderEnabled(providerId, enabled)
        } else {
            val spec = WorldMonitorProviderRegistry.byId(providerId) ?: return@withContext
            dao.upsertProviderState(
                WorldProviderStateEntity(
                    providerId = spec.id,
                    enabled = enabled,
                    status = if (enabled) ProviderSyncStatus.IDLE.name else ProviderSyncStatus.DISABLED.name,
                    lastSyncEpochMs = null,
                    lastSuccessEpochMs = null,
                    nextEligibleEpochMs = 0L,
                    lastHttpCode = null,
                    lastError = null,
                    etag = null,
                    lastModifiedHeader = null,
                    cachedItemCount = 0,
                    consecutiveFailures = 0
                )
            )
        }
    }

    fun hasCredential(slot: String): Boolean = !credentialStore.get(slot).isNullOrBlank()

    fun saveCredential(slot: String, value: String) {
        val clean = value.trim()
        if (clean.isEmpty()) credentialStore.remove(slot) else credentialStore.put(slot, clean)
    }

    fun removeCredential(slot: String) {
        credentialStore.remove(slot)
    }

    suspend fun addWatchRegion(region: WatchRegion) = withContext(Dispatchers.IO) {
        dao.upsertWatchRegion(region.toEntity())
    }

    suspend fun deleteWatchRegion(id: String) = withContext(Dispatchers.IO) {
        dao.deleteWatchRegion(id)
    }

    suspend fun acknowledgeAllAlerts() = withContext(Dispatchers.IO) {
        dao.acknowledgeAllAlerts()
    }

    suspend fun clearAlerts() = withContext(Dispatchers.IO) {
        dao.clearAllWatchAlerts()
    }

    suspend fun searchLocations(query: String): List<GeoSearchResult> =
        syncEngine.searchLocations(query)

    suspend fun lookupElevationAndPlace(lat: Double, lon: Double): Pair<Int?, String?> =
        syncEngine.lookupElevationAndPlace(lat, lon)

    suspend fun fetchLiveWorldBankPopulation(iso2: String): Pair<Long, Int>? =
        syncEngine.fetchLiveWorldBankPopulation(iso2)

    private fun defaultProviderState(spec: WorldProviderSpec): WorldProviderRuntimeState {
        val status = when {
            !spec.implemented -> ProviderSyncStatus.REQUIRES_KEY
            spec.credentialSlot != null &&
                spec.authRequirement == com.adshield.pro.domain.worldmonitor.ProviderAuthRequirement.REQUIRED_USER_API_KEY &&
                !hasCredential(spec.credentialSlot) -> ProviderSyncStatus.REQUIRES_KEY
            spec.enabledByDefault -> ProviderSyncStatus.IDLE
            else -> ProviderSyncStatus.DISABLED
        }
        return WorldProviderRuntimeState(
            providerId = spec.id,
            enabled = spec.enabledByDefault,
            status = status,
            lastError = spec.limitationNote
        )
    }
}
