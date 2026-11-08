package com.adshield.pro.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.data.worldmonitor.WorldMonitorRepository
import com.adshield.pro.domain.worldmonitor.AiAnalystResponse
import com.adshield.pro.domain.worldmonitor.BasemapStyle
import com.adshield.pro.domain.worldmonitor.BuildingFootprint3D
import com.adshield.pro.domain.worldmonitor.CorrelatedIncident
import com.adshield.pro.domain.worldmonitor.DigitalTwinSnapshot
import com.adshield.pro.domain.worldmonitor.FreshnessClass
import com.adshield.pro.domain.worldmonitor.GeoSearchResult
import com.adshield.pro.domain.worldmonitor.GlobePerformanceMode
import com.adshield.pro.domain.worldmonitor.GlobeProjection
import com.adshield.pro.domain.worldmonitor.GlobeViewport
import com.adshield.pro.domain.worldmonitor.HistoricalSplitState
import com.adshield.pro.domain.worldmonitor.LayerVisualConfig
import com.adshield.pro.domain.worldmonitor.MapStylePreset
import com.adshield.pro.domain.worldmonitor.SatellitePassPrediction
import com.adshield.pro.domain.worldmonitor.SimulationKind
import com.adshield.pro.domain.worldmonitor.SimulationResult
import com.adshield.pro.domain.worldmonitor.TimelineWindowPreset
import com.adshield.pro.domain.worldmonitor.WatchAlertRecord
import com.adshield.pro.domain.worldmonitor.WatchRegion
import com.adshield.pro.domain.worldmonitor.WorldEntity
import com.adshield.pro.domain.worldmonitor.WorldIntelCategory
import com.adshield.pro.domain.worldmonitor.WorldProviderRuntimeState
import com.adshield.pro.domain.worldmonitor.WorldSeverity
import com.adshield.pro.engine.worldmonitor.BaselineReferenceStore
import com.adshield.pro.engine.worldmonitor.CzmlAndGeoJsonBuilder
import com.adshield.pro.engine.worldmonitor.DigitalTwinEngine
import com.adshield.pro.engine.worldmonitor.EventCorrelationEngine
import com.adshield.pro.engine.worldmonitor.SimulationLabEngine
import com.adshield.pro.engine.worldmonitor.WorldMonitorAiAnalyst
import com.adshield.pro.engine.worldmonitor.WorldMonitorJsBridge
import com.adshield.pro.engine.worldmonitor.WorldMonitorProviderRegistry
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.Locale
import java.util.UUID
import javax.inject.Inject

enum class WorldMonitorDeckTab(val label: String) {
    FEED("Intel Feed"),
    LAYERS("Layers & 3D"),
    TWIN("Digital Twin"),
    CORRELATE("Correlate"),
    AI_ANALYST("AI Analyst"),
    SIM_LAB("Sim Lab"),
    TIMELINE("Timeline"),
    WATCHTOWER("Watchtower"),
    SOURCES("Sources")
}

data class ClickedLocationInfo(
    val latitude: Double,
    val longitude: Double,
    val elevationMeters: Int,
    val placeName: String?,
    val countryName: String?,
    val population: Long?
)

data class WorldMonitorUiState(
    val globeReady: Boolean = false,
    val globeError: String? = null,
    val cesiumVersion: String = "1.147.0",
    val fullscreenMode: Boolean = false,
    val deckExpanded: Boolean = true,
    val activeTab: WorldMonitorDeckTab = WorldMonitorDeckTab.FEED,
    val isSyncing: Boolean = false,
    val statusBanner: String? = null,
    val viewport: GlobeViewport = GlobeViewport(),
    val basemap: BasemapStyle = BasemapStyle.SATELLITE_HYBRID,
    val projection: GlobeProjection = GlobeProjection.GLOBE_3D,
    val stylePreset: MapStylePreset = MapStylePreset.STANDARD_SATELLITE,
    val performanceMode: GlobePerformanceMode = GlobePerformanceMode.STANDARD,
    val terrain3dEnabled: Boolean = true,
    val bordersEnabled: Boolean = true,
    val atmosphereEnabled: Boolean = true,
    val dayNightLightingEnabled: Boolean = true,
    val labelsEnabled: Boolean = true,
    val cloudsOverlayEnabled: Boolean = false,
    val radarOverlayEnabled: Boolean = false,
    val trailsEnabled: Boolean = true,
    val historicalSplit: HistoricalSplitState = HistoricalSplitState(),
    val layerConfigs: Map<WorldIntelCategory, LayerVisualConfig> = defaultLayerConfigs(),
    val minSeverityFilter: WorldSeverity = WorldSeverity.INFO,
    val timelinePreset: TimelineWindowPreset = TimelineWindowPreset.ALL_CACHED,
    val timelineProgress: Float = 1.0f, // 0f..1f scrub across selected window
    val timelinePlaying: Boolean = false,
    val allEntities: List<WorldEntity> = emptyList(),
    val filteredEntities: List<WorldEntity> = emptyList(),
    val categoryCounts: Map<WorldIntelCategory, Int> = emptyMap(),
    val selectedEntity: WorldEntity? = null,
    val clickedLocation: ClickedLocationInfo? = null,
    val satellitePasses: List<SatellitePassPrediction> = emptyList(),
    val correlations: List<CorrelatedIncident> = emptyList(),
    val digitalTwin: DigitalTwinSnapshot? = null,
    val compareCountryIso: String = "JP",
    val aiResponse: AiAnalystResponse? = null,
    val simulation: SimulationResult = SimulationResult(
        active = false,
        kind = SimulationKind.WEATHER_PLUME,
        label = "Inactive",
        centerLat = 14.5995,
        centerLon = 120.9842,
        primaryParameterLabel = ""
    ),
    val searchQuery: String = "",
    val isSearching: Boolean = false,
    val searchResults: List<GeoSearchResult> = emptyList(),
    val providerStates: List<WorldProviderRuntimeState> = emptyList(),
    val watchRegions: List<WatchRegion> = emptyList(),
    val watchAlerts: List<WatchAlertRecord> = emptyList(),
    val unacknowledgedAlertCount: Int = 0,
    val hasOpenSkyKey: Boolean = false,
    val hasFirmsKey: Boolean = false,
    val hasAisStreamKey: Boolean = false
) {
    companion object {
        fun defaultLayerConfigs(): Map<WorldIntelCategory, LayerVisualConfig> =
            WorldIntelCategory.entries.associateWith { cat ->
                LayerVisualConfig(
                    category = cat,
                    enabled = true,
                    opacity = 1.0f,
                    clusteringEnabled = cat == WorldIntelCategory.AVIATION || cat == WorldIntelCategory.INFRASTRUCTURE,
                    heatmapEnabled = false,
                    showTrails = cat == WorldIntelCategory.AVIATION || cat == WorldIntelCategory.MARITIME || cat == WorldIntelCategory.SPACE
                )
            }
    }
}

@HiltViewModel
class WorldMonitorViewModel @Inject constructor(
    private val repository: WorldMonitorRepository
) : ViewModel(), WorldMonitorJsBridge.Listener {

    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = true }

    private val _uiState = MutableStateFlow(
        WorldMonitorUiState(
            hasOpenSkyKey = repository.hasCredential("wm.cred.opensky"),
            hasFirmsKey = repository.hasCredential("wm.cred.nasa_firms"),
            hasAisStreamKey = repository.hasCredential("wm.cred.aisstream")
        )
    )
    val uiState: StateFlow<WorldMonitorUiState> = _uiState.asStateFlow()

    /** Outbound JS expressions evaluated on the WebView main thread. */
    private val _jsCommands = MutableSharedFlow<String>(extraBufferCapacity = 64)
    val jsCommands: SharedFlow<String> = _jsCommands.asSharedFlow()

    private var timelinePlayJob: Job? = null

    init {
        viewModelScope.launch {
            repository.ensureBaselineSeeded()
            syncAllEnabled(force = false)
        }
        viewModelScope.launch {
            repository.entitiesFlow.collectLatest { entities ->
                recomputeDerivedIntelligence(entities)
            }
        }
        viewModelScope.launch {
            repository.providerStatesFlow.collectLatest { states ->
                _uiState.update { it.copy(providerStates = states) }
            }
        }
        viewModelScope.launch {
            repository.watchRegionsFlow.collectLatest { regions ->
                _uiState.update { it.copy(watchRegions = regions) }
                pushWatchRegionsToGlobe(regions)
            }
        }
        viewModelScope.launch {
            repository.watchAlertsFlow.collectLatest { alerts ->
                _uiState.update { it.copy(watchAlerts = alerts) }
            }
        }
        viewModelScope.launch {
            repository.unacknowledgedAlertCountFlow.collectLatest { count ->
                _uiState.update { it.copy(unacknowledgedAlertCount = count) }
            }
        }
        viewModelScope.launch {
            repository.buildings3D.collectLatest { buildings ->
                if (buildings.isNotEmpty()) pushBuildingsToGlobe(buildings)
            }
        }
    }

    // ── Bridge Listener Callbacks (may arrive on WebView JavaBridge thread) ──

    override fun onGlobeReady(webglSupported: Boolean, cesiumVersion: String) {
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    globeReady = webglSupported,
                    cesiumVersion = cesiumVersion,
                    globeError = if (webglSupported) null else "WebGL hardware context unavailable on this device."
                )
            }
            pushFullStateToGlobe()
        }
    }

    override fun onGlobeError(errorMessage: String) {
        viewModelScope.launch {
            _uiState.update { it.copy(globeError = errorMessage) }
        }
    }

    override fun onViewportChanged(viewport: GlobeViewport) {
        viewModelScope.launch {
            _uiState.update { it.copy(viewport = viewport) }
        }
    }

    override fun onEntitySelected(entityId: String) {
        viewModelScope.launch {
            val match = _uiState.value.allEntities.firstOrNull { it.id == entityId }
            _uiState.update {
                it.copy(
                    selectedEntity = match,
                    satellitePasses = emptyList()
                )
            }
            if (match != null && match.category == WorldIntelCategory.SPACE && !match.tleLine1.isNullOrBlank()) {
                computePassesForSelectedSatellite(match)
            }
        }
    }

    override fun onBuildingSelected(
        id: String,
        name: String,
        heightMeters: Double,
        levels: Int,
        lat: Double,
        lon: Double
    ) {
        viewModelScope.launch {
            val country = BaselineReferenceStore.nearestCountry(lat, lon)
            _uiState.update {
                it.copy(
                    clickedLocation = ClickedLocationInfo(
                        latitude = lat,
                        longitude = lon,
                        elevationMeters = heightMeters.toInt(),
                        placeName = "$name (${heightMeters.toInt()}m · ${if (levels > 0) "$levels floors" else "OSM 3D Footprint"})",
                        countryName = country?.name,
                        population = country?.population
                    )
                )
            }
        }
    }

    override fun onLocationSelected(lat: Double, lon: Double, terrainElevationMeters: Int) {
        viewModelScope.launch {
            val country = BaselineReferenceStore.nearestCountry(lat, lon)
            _uiState.update {
                it.copy(
                    clickedLocation = ClickedLocationInfo(
                        latitude = lat,
                        longitude = lon,
                        elevationMeters = terrainElevationMeters,
                        placeName = country?.let { c -> "Sector near ${c.capital}, ${c.name}" },
                        countryName = country?.name,
                        population = country?.population
                    )
                )
            }
            val (liveElev, reverseName) = repository.lookupElevationAndPlace(lat, lon)
            _uiState.update { cur ->
                val loc = cur.clickedLocation ?: return@update cur
                cur.copy(
                    clickedLocation = loc.copy(
                        elevationMeters = liveElev ?: loc.elevationMeters,
                        placeName = reverseName ?: loc.placeName
                    )
                )
            }
        }
    }

    override fun onSatellitePassesComputed(
        noradId: String,
        satName: String,
        passes: List<SatellitePassPrediction>
    ) {
        viewModelScope.launch {
            _uiState.update { it.copy(satellitePasses = passes) }
        }
    }

    // ── User Actions ─────────────────────────────────────────────────────────

    fun selectTab(tab: WorldMonitorDeckTab) {
        _uiState.update { it.copy(activeTab = tab, deckExpanded = true) }
        if (tab == WorldMonitorDeckTab.TWIN) {
            refreshDigitalTwin()
        } else if (tab == WorldMonitorDeckTab.AI_ANALYST && _uiState.value.aiResponse == null) {
            askAiAnalyst("Summarize current global intelligence posture and major hazards")
        }
    }

    fun toggleDeckExpanded() {
        _uiState.update { it.copy(deckExpanded = !it.deckExpanded) }
    }

    fun toggleFullscreen() {
        _uiState.update { cur ->
            val next = !cur.fullscreenMode
            cur.copy(fullscreenMode = next, deckExpanded = !next)
        }
    }

    fun dismissSelectedEntity() {
        _uiState.update { it.copy(selectedEntity = null, satellitePasses = emptyList()) }
    }

    fun dismissClickedLocation() {
        _uiState.update { it.copy(clickedLocation = null) }
    }

    fun syncAllEnabled(force: Boolean = true) {
        if (_uiState.value.isSyncing) return
        viewModelScope.launch {
            _uiState.update { it.copy(isSyncing = true, statusBanner = "Synchronizing live global feeds…") }
            val vp = _uiState.value.viewport
            val okCount = repository.syncEnabledProviders(
                categories = _uiState.value.layerConfigs.filterValues { it.enabled }.keys,
                viewport = vp,
                force = force,
                notifyWatchtower = false
            )
            refreshTrailsOnGlobe()
            if (_uiState.value.radarOverlayEnabled) {
                pushRadarStateToGlobe(true)
            }
            _uiState.update {
                it.copy(
                    isSyncing = false,
                    statusBanner = "Synced $okCount live feed(s) · Cached ${_uiState.value.allEntities.size} entities"
                )
            }
        }
    }

    fun syncSingleProvider(providerId: String) {
        viewModelScope.launch {
            _uiState.update { it.copy(statusBanner = "Refreshing $providerId…") }
            val outcome = repository.syncSingleProvider(providerId, viewport = _uiState.value.viewport, force = true)
            _uiState.update {
                it.copy(
                    statusBanner = outcome.errorMessage ?: "Provider $providerId updated (${outcome.entities.size} records)"
                )
            }
        }
    }

    fun load3dBuildingsAtViewport() {
        viewModelScope.launch {
            val vp = _uiState.value.viewport
            _uiState.update { it.copy(statusBanner = "Querying OpenStreetMap 3D buildings & local infrastructure…") }
            val outcome = repository.syncBuildingsAndStreetInfra(vp)
            _uiState.update {
                it.copy(
                    statusBanner = outcome.errorMessage
                        ?: "Rendered ${outcome.buildings3D.size} 3D building(s) & ${outcome.entities.size} street infra node(s)"
                )
            }
        }
    }

    // ── Globe & Layer Controls ───────────────────────────────────────────────

    fun setBasemap(style: BasemapStyle) {
        _uiState.update { it.copy(basemap = style) }
        sendCommand("SET_BASEMAP", """{"style":"${style.name}"}""")
    }

    fun setProjection(projection: GlobeProjection) {
        _uiState.update { it.copy(projection = projection) }
        sendCommand("SET_PROJECTION", """{"projection":"${projection.name}"}""")
    }

    fun setStylePreset(preset: MapStylePreset) {
        _uiState.update { it.copy(stylePreset = preset) }
        sendCommand("SET_STYLE_PRESET", """{"preset":"${preset.name}"}""")
    }

    fun setPerformanceMode(mode: GlobePerformanceMode) {
        _uiState.update { it.copy(performanceMode = mode) }
        sendCommand("SET_PERFORMANCE_MODE", """{"mode":"${mode.name}"}""")
    }

    fun setTerrainEnabled(enabled: Boolean) {
        _uiState.update { it.copy(terrain3dEnabled = enabled) }
        sendCommand("SET_TERRAIN", """{"enabled":$enabled}""")
    }

    fun updateSceneFlags(
        borders: Boolean = _uiState.value.bordersEnabled,
        atmosphere: Boolean = _uiState.value.atmosphereEnabled,
        dayNight: Boolean = _uiState.value.dayNightLightingEnabled,
        labels: Boolean = _uiState.value.labelsEnabled
    ) {
        _uiState.update {
            it.copy(
                bordersEnabled = borders,
                atmosphereEnabled = atmosphere,
                dayNightLightingEnabled = dayNight,
                labelsEnabled = labels
            )
        }
        sendCommand(
            "SET_SCENE_FLAGS",
            """{"borders":$borders,"atmosphere":$atmosphere,"dayNightLighting":$dayNight,"labels":$labels}"""
        )
    }

    fun setCloudsOverlay(enabled: Boolean) {
        _uiState.update { it.copy(cloudsOverlayEnabled = enabled) }
        sendCommand("SET_CLOUDS", """{"enabled":$enabled,"opacity":0.55}""")
    }

    fun setRadarOverlay(enabled: Boolean) {
        _uiState.update { it.copy(radarOverlayEnabled = enabled) }
        viewModelScope.launch {
            if (enabled && repository.rainViewerFrames.value.isEmpty()) {
                repository.syncSingleProvider("wm.weather.rainviewer", force = true)
            }
            pushRadarStateToGlobe(enabled)
        }
    }

    fun updateHistoricalSplit(
        enabled: Boolean = _uiState.value.historicalSplit.enabled,
        leftDateIso: String = _uiState.value.historicalSplit.leftDateIso,
        rightDateIso: String = _uiState.value.historicalSplit.rightDateIso,
        splitPosition: Float = _uiState.value.historicalSplit.splitPosition
    ) {
        val next = HistoricalSplitState(
            enabled = enabled,
            leftDateIso = leftDateIso,
            rightDateIso = rightDateIso,
            splitPosition = splitPosition.coerceIn(0.05f, 0.95f)
        )
        _uiState.update { it.copy(historicalSplit = next) }
        val payload = buildJsonObject {
            put("enabled", next.enabled)
            put("leftDateIso", next.leftDateIso)
            put("rightDateIso", next.rightDateIso)
            put("splitPosition", next.splitPosition.toDouble())
        }.toString()
        sendCommand("SET_HISTORICAL_SPLIT", payload)
    }

    fun updateLayerConfig(
        category: WorldIntelCategory,
        enabled: Boolean? = null,
        opacity: Float? = null,
        clustering: Boolean? = null,
        heatmap: Boolean? = null
    ) {
        val cur = _uiState.value.layerConfigs[category] ?: return
        val updated = cur.copy(
            enabled = enabled ?: cur.enabled,
            opacity = (opacity ?: cur.opacity).coerceIn(0.15f, 1.0f),
            clusteringEnabled = clustering ?: cur.clusteringEnabled,
            heatmapEnabled = heatmap ?: cur.heatmapEnabled
        )
        _uiState.update { state ->
            state.copy(layerConfigs = state.layerConfigs + (category to updated))
        }
        val payload = buildJsonObject {
            put("category", category.name)
            put("enabled", updated.enabled)
            put("opacity", updated.opacity.toDouble())
            put("clusteringEnabled", updated.clusteringEnabled)
            put("heatmapEnabled", updated.heatmapEnabled)
        }.toString()
        sendCommand("SET_LAYER_STATE", payload)
        recomputeDerivedIntelligence(_uiState.value.allEntities)
    }

    fun setTrailsEnabled(enabled: Boolean) {
        _uiState.update { it.copy(trailsEnabled = enabled) }
        viewModelScope.launch { refreshTrailsOnGlobe() }
    }

    fun setMinSeverityFilter(severity: WorldSeverity) {
        _uiState.update { it.copy(minSeverityFilter = severity) }
        recomputeDerivedIntelligence(_uiState.value.allEntities)
    }

    // ── Camera & Geographic Search ───────────────────────────────────────────

    fun cameraAction(action: String) {
        sendCommand("CAMERA_ACTION", """{"action":"$action"}""")
    }

    fun flyTo(lat: Double, lon: Double, altitudeMeters: Double = 350_000.0, pitchDeg: Double = -55.0) {
        val payload = buildJsonObject {
            put("lat", lat)
            put("lon", lon)
            put("altitudeMeters", altitudeMeters)
            put("pitchDeg", pitchDeg)
        }.toString()
        sendCommand("FLY_TO", payload)
    }

    fun focusEntity(entity: WorldEntity) {
        _uiState.update { it.copy(selectedEntity = entity) }
        val targetAlt = when (entity.category) {
            WorldIntelCategory.SPACE -> (entity.altitudeMeters ?: 420_000.0).coerceAtLeast(900_000.0)
            WorldIntelCategory.AVIATION, WorldIntelCategory.MARITIME -> 85_000.0
            else -> 220_000.0
        }
        flyTo(entity.latitude, entity.longitude, targetAlt, -50.0)
        if (entity.category == WorldIntelCategory.SPACE && !entity.tleLine1.isNullOrBlank()) {
            showSatelliteOrbit(entity)
            computePassesForSelectedSatellite(entity)
        }
    }

    fun showSatelliteOrbit(entity: WorldEntity) {
        val l1 = entity.tleLine1 ?: return
        val l2 = entity.tleLine2 ?: return
        val payload = buildJsonObject {
            put("line1", l1)
            put("line2", l2)
        }.toString()
        sendCommand("SELECT_SATELLITE_ORBIT", payload)
    }

    fun computePassesForSelectedSatellite(entity: WorldEntity) {
        val l1 = entity.tleLine1 ?: return
        val l2 = entity.tleLine2 ?: return
        val vp = _uiState.value.viewport
        val payload = buildJsonObject {
            put("noradId", entity.attributes["NORAD ID"] ?: entity.id)
            put("name", entity.title)
            put("line1", l1)
            put("line2", l2)
            put("observerLat", vp.latitude)
            put("observerLon", vp.longitude)
        }.toString()
        sendCommand("COMPUTE_SATELLITE_PASSES", payload)
    }

    fun updateSearchQuery(query: String) {
        _uiState.update { it.copy(searchQuery = query) }
    }

    fun submitGeographicSearch() {
        val q = _uiState.value.searchQuery.trim()
        if (q.length < 2) return
        viewModelScope.launch {
            _uiState.update { it.copy(isSearching = true) }
            val results = repository.searchLocations(q)
            _uiState.update { it.copy(isSearching = false, searchResults = results) }
            results.firstOrNull()?.let { top ->
                flyTo(top.latitude, top.longitude, top.recommendedAltitudeMeters, -55.0)
            }
        }
    }

    fun selectSearchResult(result: GeoSearchResult) {
        _uiState.update { it.copy(searchResults = emptyList(), searchQuery = result.displayName) }
        flyTo(result.latitude, result.longitude, result.recommendedAltitudeMeters, -55.0)
    }

    // ── Digital Twin, AI Analyst, Simulation Lab, Timeline, Watchtower ───────

    fun refreshDigitalTwin(compareCountryIso: String = _uiState.value.compareCountryIso) {
        viewModelScope.launch(Dispatchers.Default) {
            val vp = _uiState.value.viewport
            val nearest = BaselineReferenceStore.nearestCountry(vp.latitude, vp.longitude)
            val livePop = nearest?.iso2?.let { repository.fetchLiveWorldBankPopulation(it) }
            val elev = _uiState.value.clickedLocation?.elevationMeters ?: 0
            val snapshot = DigitalTwinEngine.buildRegionalTwin(
                latitude = vp.latitude,
                longitude = vp.longitude,
                elevationMeters = elev,
                radiusKm = 450.0,
                allEntities = _uiState.value.allEntities,
                compareCountryIso = compareCountryIso,
                liveWorldBankPop = livePop
            )
            _uiState.update { it.copy(digitalTwin = snapshot, compareCountryIso = compareCountryIso) }
        }
    }

    fun askAiAnalyst(query: String) {
        viewModelScope.launch(Dispatchers.Default) {
            val s = _uiState.value
            val response = WorldMonitorAiAnalyst.analyze(
                userQuery = query,
                allEntities = s.allEntities,
                correlations = s.correlations,
                providerStates = s.providerStates,
                selectedEntity = s.selectedEntity,
                focusLat = s.viewport.latitude,
                focusLon = s.viewport.longitude
            )
            _uiState.update { it.copy(aiResponse = response, activeTab = WorldMonitorDeckTab.AI_ANALYST, deckExpanded = true) }
        }
    }

    fun runSimulation(kind: SimulationKind, parameterValue: Double, bearingDeg: Double = 285.0) {
        viewModelScope.launch(Dispatchers.Default) {
            val vp = _uiState.value.viewport
            val result = SimulationLabEngine.runScenario(
                kind = kind,
                centerLat = vp.latitude,
                centerLon = vp.longitude,
                intensityOrRadiusParameter = parameterValue,
                windBearingDeg = bearingDeg,
                referenceEntities = _uiState.value.allEntities
            )
            _uiState.update { it.copy(simulation = result) }
            sendCommand("SET_SIMULATION_OVERLAY", json.encodeToString(result))
            flyTo(result.centerLat, result.centerLon, 950_000.0, -52.0)
        }
    }

    fun clearSimulation() {
        val cleared = _uiState.value.simulation.copy(active = false, rings = emptyList(), waypoints = emptyList())
        _uiState.update { it.copy(simulation = cleared) }
        sendCommand("SET_SIMULATION_OVERLAY", """{"active":false}""")
    }

    fun setTimelinePreset(preset: TimelineWindowPreset) {
        _uiState.update { it.copy(timelinePreset = preset, timelineProgress = 1.0f) }
        recomputeDerivedIntelligence(_uiState.value.allEntities)
    }

    fun setTimelineProgress(progress: Float) {
        _uiState.update { it.copy(timelineProgress = progress.coerceIn(0.05f, 1.0f)) }
        recomputeDerivedIntelligence(_uiState.value.allEntities)
    }

    fun toggleTimelinePlayback() {
        val nextPlaying = !_uiState.value.timelinePlaying
        _uiState.update { it.copy(timelinePlaying = nextPlaying) }
        timelinePlayJob?.cancel()
        if (nextPlaying) {
            timelinePlayJob = viewModelScope.launch {
                var p = if (_uiState.value.timelineProgress >= 0.98f) 0.10f else _uiState.value.timelineProgress
                while (isActive && _uiState.value.timelinePlaying) {
                    delay(900L)
                    p += 0.08f
                    if (p >= 1.0f) {
                        setTimelineProgress(1.0f)
                        _uiState.update { it.copy(timelinePlaying = false) }
                        break
                    } else {
                        setTimelineProgress(p)
                    }
                }
            }
        }
    }

    fun createWatchRegionAtViewport(
        name: String,
        radiusKm: Double,
        minSeverity: WorldSeverity,
        categories: Set<WorldIntelCategory>
    ) {
        viewModelScope.launch {
            val vp = _uiState.value.viewport
            val region = WatchRegion(
                id = "watch:${UUID.randomUUID().toString().take(8)}",
                name = name.trim().ifBlank {
                    "Sector %.2f°, %.2f°".format(Locale.US, vp.latitude, vp.longitude)
                },
                latitude = vp.latitude,
                longitude = vp.longitude,
                radiusKm = radiusKm.coerceIn(15.0, 2_500.0),
                minSeverity = minSeverity,
                categories = categories,
                enabled = true
            )
            repository.addWatchRegion(region)
            _uiState.update { it.copy(statusBanner = "Watchtower geofence '${region.name}' armed") }
        }
    }

    fun deleteWatchRegion(id: String) {
        viewModelScope.launch { repository.deleteWatchRegion(id) }
    }

    fun acknowledgeAllWatchAlerts() {
        viewModelScope.launch { repository.acknowledgeAllAlerts() }
    }

    fun clearWatchAlerts() {
        viewModelScope.launch { repository.clearAlerts() }
    }

    fun setProviderEnabled(providerId: String, enabled: Boolean) {
        viewModelScope.launch {
            repository.setProviderEnabled(providerId, enabled)
            if (enabled) syncSingleProvider(providerId)
        }
    }

    fun saveApiCredential(slot: String, secret: String) {
        repository.saveCredential(slot, secret)
        _uiState.update {
            it.copy(
                hasOpenSkyKey = repository.hasCredential("wm.cred.opensky"),
                hasFirmsKey = repository.hasCredential("wm.cred.nasa_firms"),
                hasAisStreamKey = repository.hasCredential("wm.cred.aisstream"),
                statusBanner = if (secret.isBlank()) "Removed credential $slot" else "Encrypted credential saved in Android Keystore ($slot)"
            )
        }
        WorldMonitorProviderRegistry.ALL.firstOrNull { it.credentialSlot == slot }?.let { spec ->
            if (secret.isNotBlank() && spec.implemented) syncSingleProvider(spec.id)
        }
    }

    fun exportVisibleGeoJson(): String =
        CzmlAndGeoJsonBuilder.toGeoJsonFeatureCollection(_uiState.value.filteredEntities)

    fun exportVisibleCzml(): String =
        CzmlAndGeoJsonBuilder.toCzmlDocument(_uiState.value.filteredEntities)

    // ── Internal State Synchronization with CesiumJS ─────────────────────────

    private fun recomputeDerivedIntelligence(entities: List<WorldEntity>) {
        viewModelScope.launch(Dispatchers.Default) {
            val state = _uiState.value
            val now = System.currentTimeMillis()
            val counts = entities.groupingBy { it.category }.eachCount()

            val windowHorizon = state.timelinePreset.durationMs
            val cutoffStart = if (windowHorizon != null) now - windowHorizon else 0L
            val cutoffEnd = if (windowHorizon != null) {
                cutoffStart + (windowHorizon * state.timelineProgress).toLong()
            } else {
                Long.MAX_VALUE
            }

            val visible = entities.filter { e ->
                val cfg = state.layerConfigs[e.category]
                val catOk = cfg?.enabled != false
                val sevOk = e.severity.rank >= state.minSeverityFilter.rank
                val timeOk = e.freshness == FreshnessClass.HISTORICAL ||
                    (e.eventTimeEpochMs in cutoffStart..cutoffEnd)
                catOk && sevOk && timeOk
            }

            val corrs = EventCorrelationEngine.correlate(visible)
            _uiState.update {
                it.copy(
                    allEntities = entities,
                    filteredEntities = visible,
                    categoryCounts = counts,
                    correlations = corrs
                )
            }
            pushEntitiesAndCorrelationsToGlobe(visible, corrs)
        }
    }

    private suspend fun pushFullStateToGlobe() {
        val s = _uiState.value
        setBasemap(s.basemap)
        setProjection(s.projection)
        setStylePreset(s.stylePreset)
        setPerformanceMode(s.performanceMode)
        setTerrainEnabled(s.terrain3dEnabled)
        updateSceneFlags(s.bordersEnabled, s.atmosphereEnabled, s.dayNightLightingEnabled, s.labelsEnabled)
        s.layerConfigs.values.forEach { cfg ->
            val payload = buildJsonObject {
                put("category", cfg.category.name)
                put("enabled", cfg.enabled)
                put("opacity", cfg.opacity.toDouble())
                put("clusteringEnabled", cfg.clusteringEnabled)
                put("heatmapEnabled", cfg.heatmapEnabled)
            }.toString()
            sendCommand("SET_LAYER_STATE", payload)
        }
        pushEntitiesAndCorrelationsToGlobe(s.filteredEntities, s.correlations)
        pushWatchRegionsToGlobe(s.watchRegions)
        refreshTrailsOnGlobe()
    }

    private fun pushEntitiesAndCorrelationsToGlobe(
        entities: List<WorldEntity>,
        correlations: List<CorrelatedIncident>
    ) {
        if (!_uiState.value.globeReady) return
        val capped = entities.take(2_500)
        val entitiesPayload = buildJsonObject {
            put("entities", json.parseToJsonElement(json.encodeToString(capped)))
        }.toString()
        sendCommand("UPDATE_ENTITIES", entitiesPayload)

        val corrPayload = buildJsonObject {
            put("incidents", json.parseToJsonElement(json.encodeToString(correlations)))
        }.toString()
        sendCommand("UPDATE_CORRELATIONS", corrPayload)
    }

    private suspend fun refreshTrailsOnGlobe() {
        if (!_uiState.value.globeReady) return
        if (!_uiState.value.trailsEnabled) {
            sendCommand("UPDATE_TRAILS", """{"trails":[]}""")
            return
        }
        val activeCats = _uiState.value.layerConfigs.filterValues { it.enabled && it.showTrails }.keys
        val trails = repository.loadRecentTrails(activeCats)
        val payload = buildJsonObject {
            put("trails", json.parseToJsonElement(json.encodeToString(trails)))
        }.toString()
        sendCommand("UPDATE_TRAILS", payload)
    }

    private fun pushWatchRegionsToGlobe(regions: List<WatchRegion>) {
        if (!_uiState.value.globeReady) return
        val payload = buildJsonObject {
            put("regions", json.parseToJsonElement(json.encodeToString(regions)))
        }.toString()
        sendCommand("UPDATE_WATCH_REGIONS", payload)
    }

    private fun pushBuildingsToGlobe(buildings: List<BuildingFootprint3D>) {
        if (!_uiState.value.globeReady) return
        val payload = buildJsonObject {
            put("buildings", json.parseToJsonElement(json.encodeToString(buildings)))
        }.toString()
        sendCommand("UPDATE_BUILDINGS_3D", payload)
    }

    private fun pushRadarStateToGlobe(enabled: Boolean) {
        val frames = repository.rainViewerFrames.value
        val payload = buildJsonObject {
            put("enabled", enabled)
            put("opacity", 0.58)
            put("frames", buildJsonArray {
                frames.forEach { f ->
                    add(buildJsonObject {
                        put("path", f.path)
                        put("timeSec", f.timeEpochSec)
                    })
                }
            })
        }.toString()
        sendCommand("SET_RADAR", payload)
    }

    private fun sendCommand(type: String, payloadJsonObject: String) {
        val jsExpr = WorldMonitorJsBridge.buildJsDispatchExpression(type, payloadJsonObject)
        _jsCommands.tryEmit(jsExpr)
    }
}
