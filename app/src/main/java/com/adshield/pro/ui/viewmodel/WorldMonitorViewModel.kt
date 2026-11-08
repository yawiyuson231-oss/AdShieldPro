package com.adshield.pro.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.data.worldmonitor.WorldMonitorRepository
import com.adshield.pro.domain.worldmonitor.AiAnalystResponse
import com.adshield.pro.domain.worldmonitor.CorrelatedIncident
import com.adshield.pro.domain.worldmonitor.DigitalTwinSnapshot
import com.adshield.pro.domain.worldmonitor.FreshnessClass
import com.adshield.pro.domain.worldmonitor.GeocodeSearchResult
import com.adshield.pro.domain.worldmonitor.GlobeBasemap
import com.adshield.pro.domain.worldmonitor.GlobeProjection
import com.adshield.pro.domain.worldmonitor.GlobeStylePreset
import com.adshield.pro.domain.worldmonitor.GraphicsPerformanceMode
import com.adshield.pro.domain.worldmonitor.HistoricalImagerySplitState
import com.adshield.pro.domain.worldmonitor.OsmBuilding3D
import com.adshield.pro.domain.worldmonitor.SatellitePassPrediction
import com.adshield.pro.domain.worldmonitor.SimulationKind
import com.adshield.pro.domain.worldmonitor.SimulationResult
import com.adshield.pro.domain.worldmonitor.WatchtowerAlert
import com.adshield.pro.domain.worldmonitor.WatchtowerRegion
import com.adshield.pro.domain.worldmonitor.WorldEntity
import com.adshield.pro.domain.worldmonitor.WorldIntelCategory
import com.adshield.pro.domain.worldmonitor.WorldProviderRuntimeState
import com.adshield.pro.domain.worldmonitor.WorldSeverity
import com.adshield.pro.domain.worldmonitor.WorldTimelineWindow
import com.adshield.pro.domain.worldmonitor.WorldViewport
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
import kotlinx.serialization.json.JsonNull
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

data class LayerUiState(
    val category: WorldIntelCategory,
    val visible: Boolean = true,
    val opacity: Float = 1.0f
)

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
    val reloadNonce: Int = 0,
    val fullscreenMode: Boolean = false,
    val deckExpanded: Boolean = false,
    val activeTab: WorldMonitorDeckTab = WorldMonitorDeckTab.FEED,
    val isSyncing: Boolean = false,
    val statusBanner: String? = null,
    val viewport: WorldViewport = WorldViewport(),
    val basemap: GlobeBasemap = GlobeBasemap.SATELLITE_ESRI,
    val projection: GlobeProjection = GlobeProjection.GLOBE_3D,
    val stylePreset: GlobeStylePreset = GlobeStylePreset.CYBER_TACTICAL,
    val performanceMode: GraphicsPerformanceMode = GraphicsPerformanceMode.BALANCED,
    val terrain3dEnabled: Boolean = false,
    val bordersEnabled: Boolean = true,
    val atmosphereEnabled: Boolean = true,
    val dayNightLightingEnabled: Boolean = true,
    val labelsEnabled: Boolean = true,
    val clusteringEnabled: Boolean = true,
    val heatmapEnabled: Boolean = false,
    val cloudsOverlayEnabled: Boolean = false,
    val radarOverlayEnabled: Boolean = false,
    val trailsEnabled: Boolean = true,
    val historicalSplit: HistoricalImagerySplitState = HistoricalImagerySplitState(),
    val layerStates: Map<WorldIntelCategory, LayerUiState> =
        WorldIntelCategory.entries.associateWith { LayerUiState(it, visible = true, opacity = 1.0f) },
    val minSeverityFilter: WorldSeverity = WorldSeverity.INFO,
    val timelineWindow: WorldTimelineWindow = WorldTimelineWindow.ALL_CACHED,
    val timelineProgress: Float = 1.0f,
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
    val searchResults: List<GeocodeSearchResult> = emptyList(),
    val providerStates: List<WorldProviderRuntimeState> = emptyList(),
    val watchRegions: List<WatchtowerRegion> = emptyList(),
    val watchAlerts: List<WatchtowerAlert> = emptyList(),
    val hasOpenSkyKey: Boolean = false,
    val hasFirmsKey: Boolean = false,
    val hasAisStreamKey: Boolean = false
)

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

    private val _jsCommands = MutableSharedFlow<String>(extraBufferCapacity = 256)
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
            repository.buildings3D.collectLatest { buildings ->
                if (buildings.isNotEmpty()) pushBuildingsToGlobe(buildings)
            }
        }
    }

    // ── Bridge Listener Callbacks ────────────────────────────────────────────

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

    override fun onViewportChanged(viewport: WorldViewport) {
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
        heightEstimated: Boolean,
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
                        placeName = "$name (${heightMeters.toInt()} m · ${if (heightEstimated) "OSM Levels Est." else "Surveyed"})",
                        countryName = country?.name,
                        population = country?.population
                    )
                )
            }
        }
    }

    override fun onLocationSelected(lat: Double, lon: Double, terrainElevationMeters: Int, countryHint: String) {
        viewModelScope.launch {
            val country = BaselineReferenceStore.nearestCountry(lat, lon)
            _uiState.update {
                it.copy(
                    clickedLocation = ClickedLocationInfo(
                        latitude = lat,
                        longitude = lon,
                        elevationMeters = terrainElevationMeters,
                        placeName = countryHint.ifBlank { country?.let { c -> "Sector near ${c.capital}, ${c.name}" } },
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

    override fun onSatellitePassesComputed(entityId: String, passes: List<SatellitePassPrediction>) {
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
            cur.copy(fullscreenMode = next, deckExpanded = if (next) false else cur.deckExpanded)
        }
    }

    fun reloadGlobe() {
        _uiState.update {
            it.copy(
                globeReady = false,
                globeError = null,
                reloadNonce = it.reloadNonce + 1,
                statusBanner = "Reinitializing 3D Digital Earth engine…"
            )
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
                categories = _uiState.value.layerStates.filterValues { it.visible }.keys,
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

    fun setBasemap(basemap: GlobeBasemap) {
        _uiState.update { it.copy(basemap = basemap) }
        sendCommand(buildJsonObject {
            put("type", "SET_BASEMAP")
            put("basemap", basemap.name)
        }.toString())
    }

    fun setProjection(projection: GlobeProjection) {
        _uiState.update { it.copy(projection = projection) }
        sendCommand(buildJsonObject {
            put("type", "SET_PROJECTION")
            put("projection", projection.name)
        }.toString())
    }

    fun setStylePreset(preset: GlobeStylePreset) {
        _uiState.update { it.copy(stylePreset = preset) }
        sendCommand(buildJsonObject {
            put("type", "SET_STYLE_PRESET")
            put("stylePreset", preset.name)
        }.toString())
    }

    fun setPerformanceMode(mode: GraphicsPerformanceMode) {
        _uiState.update { it.copy(performanceMode = mode) }
        sendCommand(buildJsonObject {
            put("type", "SET_PERFORMANCE_MODE")
            put("mode", mode.name)
        }.toString())
    }

    fun setTerrainEnabled(enabled: Boolean) {
        _uiState.update { it.copy(terrain3dEnabled = enabled) }
        sendCommand(buildJsonObject {
            put("type", "SET_TERRAIN")
            put("enabled", enabled)
        }.toString())
    }

    fun updateSceneFlags(
        borders: Boolean = _uiState.value.bordersEnabled,
        atmosphere: Boolean = _uiState.value.atmosphereEnabled,
        dayNight: Boolean = _uiState.value.dayNightLightingEnabled,
        labels: Boolean = _uiState.value.labelsEnabled,
        clustering: Boolean = _uiState.value.clusteringEnabled,
        heatmap: Boolean = _uiState.value.heatmapEnabled
    ) {
        _uiState.update {
            it.copy(
                bordersEnabled = borders,
                atmosphereEnabled = atmosphere,
                dayNightLightingEnabled = dayNight,
                labelsEnabled = labels,
                clusteringEnabled = clustering,
                heatmapEnabled = heatmap
            )
        }
        sendCommand(buildJsonObject {
            put("type", "SET_SCENE_FLAGS")
            put("borders", borders)
            put("atmosphere", atmosphere)
            put("dayNightLighting", dayNight)
            put("labels", labels)
            put("clustering", clustering)
            put("heatmap", heatmap)
        }.toString())
    }

    fun setCloudsOverlay(enabled: Boolean) {
        _uiState.update { it.copy(cloudsOverlayEnabled = enabled) }
        sendCommand(buildJsonObject {
            put("type", "SET_CLOUDS")
            put("enabled", enabled)
            put("opacity", 0.55)
        }.toString())
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
        val next = HistoricalImagerySplitState(
            enabled = enabled,
            leftDateIso = leftDateIso,
            rightDateIso = rightDateIso,
            splitPosition = splitPosition.coerceIn(0.1f, 0.9f)
        )
        _uiState.update { it.copy(historicalSplit = next) }
        sendCommand(buildJsonObject {
            put("type", "SET_HISTORICAL_SPLIT")
            put("enabled", next.enabled)
            put("leftDateIso", next.leftDateIso)
            put("rightDateIso", next.rightDateIso)
            put("splitPosition", next.splitPosition.toDouble())
        }.toString())
    }

    fun updateLayerState(
        category: WorldIntelCategory,
        visible: Boolean? = null,
        opacity: Float? = null
    ) {
        val cur = _uiState.value.layerStates[category] ?: LayerUiState(category)
        val updated = cur.copy(
            visible = visible ?: cur.visible,
            opacity = (opacity ?: cur.opacity).coerceIn(0.15f, 1.0f)
        )
        _uiState.update { s -> s.copy(layerStates = s.layerStates + (category to updated)) }
        sendCommand(buildJsonObject {
            put("type", "SET_LAYER_STATE")
            put("category", category.name)
            put("visible", updated.visible)
            put("opacity", updated.opacity.toDouble())
        }.toString())
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
        if (action == "TILT_3D") {
            if (_uiState.value.projection != GlobeProjection.GLOBE_3D) {
                setProjection(GlobeProjection.GLOBE_3D)
            }
            sendCommand(buildJsonObject {
                put("type", "CAMERA_ACTION")
                put("action", "TILT_3D")
            }.toString())
            return
        }
        sendCommand(buildJsonObject {
            put("type", "CAMERA_ACTION")
            put("action", if (action == "HOME") "HOME_GLOBE" else action)
        }.toString())
    }

    fun flyTo(lat: Double, lon: Double, altitudeMeters: Double = 350_000.0, pitchDeg: Double = -58.0) {
        sendCommand(buildJsonObject {
            put("type", "FLY_TO")
            put("lat", lat)
            put("lon", lon)
            put("altitudeMeters", altitudeMeters)
            put("pitchDeg", pitchDeg)
        }.toString())
    }

    fun focusEntity(entity: WorldEntity) {
        _uiState.update { it.copy(selectedEntity = entity) }
        val targetAlt = when (entity.category) {
            WorldIntelCategory.SPACE -> (entity.altitudeMeters ?: 420_000.0).coerceAtLeast(1_200_000.0)
            WorldIntelCategory.AVIATION, WorldIntelCategory.MARITIME -> 85_000.0
            else -> 220_000.0
        }
        flyTo(entity.latitude, entity.longitude, targetAlt, -55.0)
        if (entity.category == WorldIntelCategory.SPACE && !entity.tleLine1.isNullOrBlank()) {
            sendCommand(buildJsonObject {
                put("type", "SELECT_SATELLITE_ORBIT")
                put("entityId", entity.id)
            }.toString())
            computePassesForSelectedSatellite(entity)
        }
    }

    fun computePassesForSelectedSatellite(entity: WorldEntity) {
        val vp = _uiState.value.viewport
        sendCommand(buildJsonObject {
            put("type", "COMPUTE_SATELLITE_PASSES")
            put("entityId", entity.id)
            put("lat", vp.centerLat)
            put("lon", vp.centerLon)
            put("hoursAhead", 24)
        }.toString())
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
                flyTo(top.latitude, top.longitude, (top.boundingBoxKm * 2_200.0).coerceIn(8_000.0, 2_800_000.0), -58.0)
            }
        }
    }

    fun selectSearchResult(result: GeocodeSearchResult) {
        _uiState.update { it.copy(searchResults = emptyList(), searchQuery = result.displayName) }
        flyTo(result.latitude, result.longitude, (result.boundingBoxKm * 2_200.0).coerceIn(8_000.0, 2_800_000.0), -58.0)
    }

    // ── Digital Twin, AI Analyst, Simulation Lab, Timeline, Watchtower ───────

    fun refreshDigitalTwin(compareCountryIso: String = _uiState.value.compareCountryIso) {
        viewModelScope.launch(Dispatchers.Default) {
            val vp = _uiState.value.viewport
            val nearest = BaselineReferenceStore.nearestCountry(vp.centerLat, vp.centerLon)
            val livePop = nearest?.iso2?.let { repository.fetchLiveWorldBankPopulation(it) }
            val elev = _uiState.value.clickedLocation?.elevationMeters ?: vp.groundElevationMeters
            val snapshot = DigitalTwinEngine.buildRegionalTwin(
                latitude = vp.centerLat,
                longitude = vp.centerLon,
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
                focusLat = s.viewport.centerLat,
                focusLon = s.viewport.centerLon
            )
            _uiState.update { it.copy(aiResponse = response, activeTab = WorldMonitorDeckTab.AI_ANALYST, deckExpanded = true) }
        }
    }

    fun runSimulation(kind: SimulationKind, parameterValue: Double, bearingDeg: Double = 285.0) {
        viewModelScope.launch(Dispatchers.Default) {
            val vp = _uiState.value.viewport
            val result = SimulationLabEngine.runScenario(
                kind = kind,
                centerLat = vp.centerLat,
                centerLon = vp.centerLon,
                intensityOrRadiusParameter = parameterValue,
                windBearingDeg = bearingDeg,
                referenceEntities = _uiState.value.allEntities
            )
            _uiState.update { it.copy(simulation = result) }
            sendCommand(buildJsonObject {
                put("type", "SET_SIMULATION_OVERLAY")
                put("simulation", json.parseToJsonElement(json.encodeToString(result)))
            }.toString())
            flyTo(result.centerLat, result.centerLon, 950_000.0, -55.0)
        }
    }

    fun clearSimulation() {
        val cleared = _uiState.value.simulation.copy(active = false, rings = emptyList(), waypoints = emptyList())
        _uiState.update { it.copy(simulation = cleared) }
        sendCommand(buildJsonObject {
            put("type", "SET_SIMULATION_OVERLAY")
            put("simulation", JsonNull)
        }.toString())
    }

    fun setTimelineWindow(window: WorldTimelineWindow) {
        _uiState.update { it.copy(timelineWindow = window, timelineProgress = 1.0f) }
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
            val region = WatchtowerRegion(
                id = "watch:${UUID.randomUUID().toString().take(8)}",
                name = name.trim().ifBlank {
                    "Sector %.2f°, %.2f°".format(Locale.US, vp.centerLat, vp.centerLon)
                },
                centerLat = vp.centerLat,
                centerLon = vp.centerLon,
                radiusKm = radiusKm.coerceIn(15.0, 2_500.0),
                categories = categories,
                minSeverity = minSeverity,
                enabled = true,
                createdAtEpochMs = System.currentTimeMillis()
            )
            repository.addWatchRegion(region)
            _uiState.update { it.copy(statusBanner = "Watchtower geofence '${region.name}' armed") }
        }
    }

    fun deleteWatchRegion(id: String) {
        viewModelScope.launch { repository.deleteWatchRegion(id) }
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
        WorldMonitorProviderRegistry.providers.firstOrNull { it.credentialSlot == slot }?.let { spec ->
            if (secret.isNotBlank() && spec.implemented) syncSingleProvider(spec.providerId)
        }
    }

    fun exportVisibleGeoJson(): String =
        CzmlAndGeoJsonBuilder.buildGeoJsonFeatureCollection(_uiState.value.filteredEntities)

    fun exportVisibleCzml(): String =
        CzmlAndGeoJsonBuilder.buildCzmlDocument(_uiState.value.filteredEntities)

    // ── Internal State Synchronization with CesiumJS ─────────────────────────

    private fun recomputeDerivedIntelligence(entities: List<WorldEntity>) {
        viewModelScope.launch(Dispatchers.Default) {
            val state = _uiState.value
            val now = System.currentTimeMillis()
            val counts = entities.groupingBy { it.category }.eachCount()

            val windowHorizon = state.timelineWindow.durationMs
            val cutoffStart = if (windowHorizon != null) now - windowHorizon else 0L
            val cutoffEnd = if (windowHorizon != null) {
                cutoffStart + (windowHorizon * state.timelineProgress).toLong()
            } else {
                Long.MAX_VALUE
            }

            val visible = entities.filter { e ->
                val cfg = state.layerStates[e.category]
                val catOk = cfg?.visible != false
                val sevOk = e.severity.rank >= state.minSeverityFilter.rank
                val timeOk = e.freshness == FreshnessClass.HISTORICAL ||
                    e.freshness == FreshnessClass.ESTIMATED ||
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
        updateSceneFlags(
            borders = s.bordersEnabled,
            atmosphere = s.atmosphereEnabled,
            dayNight = s.dayNightLightingEnabled,
            labels = s.labelsEnabled,
            clustering = s.clusteringEnabled,
            heatmap = s.heatmapEnabled
        )
        s.layerStates.values.forEach { cfg ->
            sendCommand(buildJsonObject {
                put("type", "SET_LAYER_STATE")
                put("category", cfg.category.name)
                put("visible", cfg.visible)
                put("opacity", cfg.opacity.toDouble())
            }.toString())
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
        sendCommand(buildJsonObject {
            put("type", "UPDATE_ENTITIES")
            put("entities", json.parseToJsonElement(json.encodeToString(capped)))
        }.toString())

        sendCommand(buildJsonObject {
            put("type", "UPDATE_CORRELATIONS")
            put("incidents", json.parseToJsonElement(json.encodeToString(correlations)))
        }.toString())
    }

    private suspend fun refreshTrailsOnGlobe() {
        if (!_uiState.value.globeReady) return
        if (!_uiState.value.trailsEnabled) {
            sendCommand("""{"type":"UPDATE_TRAILS","trails":[]}""")
            return
        }
        val activeCats = _uiState.value.layerStates.filterValues { it.visible }.keys
        val trails = repository.loadRecentTrails(activeCats)
        sendCommand(buildJsonObject {
            put("type", "UPDATE_TRAILS")
            put("trails", json.parseToJsonElement(json.encodeToString(trails)))
        }.toString())
    }

    private fun pushWatchRegionsToGlobe(regions: List<WatchtowerRegion>) {
        if (!_uiState.value.globeReady) return
        sendCommand(buildJsonObject {
            put("type", "UPDATE_WATCH_REGIONS")
            put("regions", json.parseToJsonElement(json.encodeToString(regions)))
        }.toString())
    }

    private fun pushBuildingsToGlobe(buildings: List<OsmBuilding3D>) {
        if (!_uiState.value.globeReady) return
        sendCommand(buildJsonObject {
            put("type", "UPDATE_BUILDINGS_3D")
            put("buildings", json.parseToJsonElement(json.encodeToString(buildings)))
        }.toString())
    }

    private fun pushRadarStateToGlobe(enabled: Boolean) {
        val frames = repository.rainViewerFrames.value
        sendCommand(buildJsonObject {
            put("type", "SET_RADAR")
            put("enabled", enabled)
            put("animating", true)
            put("opacity", 0.58)
            put("frames", json.parseToJsonElement(json.encodeToString(frames)))
        }.toString())
    }

    private fun sendCommand(commandJsonObject: String) {
        val jsExpr = WorldMonitorJsBridge.buildJsDispatchExpression(commandJsonObject)
        _jsCommands.tryEmit(jsExpr)
    }
}
