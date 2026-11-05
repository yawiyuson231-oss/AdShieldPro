package com.adshield.pro.gps.ui

import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.gps.data.GeocodingClient
import com.adshield.pro.gps.data.GpsDao
import com.adshield.pro.gps.data.GpsPreferences
import com.adshield.pro.gps.data.OfflineMapPackEntity
import com.adshield.pro.gps.data.RoutingClient
import com.adshield.pro.gps.data.TrafficApiClient
import com.adshield.pro.gps.engine.GpsEngine
import com.adshield.pro.gps.engine.GpsFrame
import com.adshield.pro.gps.engine.IntegrityVerdict
import com.adshield.pro.gps.engine.RadarGeometry
import com.adshield.pro.gps.engine.SatelliteSnapshot
import com.adshield.pro.gps.geo.GeoBounds
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.geo.Geodesy
import com.adshield.pro.gps.geo.MapProjection
import com.adshield.pro.gps.map.MapLibreEngine
import com.adshield.pro.gps.map.OfflineProgressBus
import com.adshield.pro.gps.map.TrafficSegmentGeometry
import com.adshield.pro.gps.nav.NavigationSession
import com.adshield.pro.gps.nav.NavigationState
import com.adshield.pro.gps.nav.TripRecorder
import com.adshield.pro.gps.nav.TtsVoiceGuidance
import com.adshield.pro.gps.offline.OfflinePlanner
import com.adshield.pro.gps.routing.ManeuverType
import com.adshield.pro.gps.routing.RoutePlan
import com.adshield.pro.gps.routing.RouteProgress
import com.adshield.pro.gps.routing.RoutingProvider
import com.adshield.pro.gps.security.EmergencyShareBuilder
import com.adshield.pro.gps.security.LocationPrivacyPolicy
import com.adshield.pro.gps.security.MockLocationDetector
import com.adshield.pro.gps.security.PermissionAudit
import com.adshield.pro.gps.security.SecurityAlertThrottle
import com.adshield.pro.gps.traffic.CongestionLevel
import com.adshield.pro.gps.traffic.IncidentKind
import com.adshield.pro.gps.traffic.RoadSegment
import com.adshield.pro.gps.traffic.SegmentTrafficState
import com.adshield.pro.gps.traffic.TrafficColours
import com.adshield.pro.gps.traffic.TrafficRepository
import com.adshield.pro.gps.traffic.formatAge
import com.adshield.pro.gps.traffic.formatConfidence
import com.adshield.pro.gps.worker.GpsMaintenanceWorker
import com.adshield.pro.service.GpsConsoleService
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject

/**
 * AdShield Pro — GPS module ViewModel.
 *
 * One flat, explicit [GpsUiState] drives the seven GPS tabs. Every field is derived from a real
 * source: measured GNSS, the routing response, the traffic observations or the offline pack table.
 * Where a value is unavailable it is `null` and the screens render "—" / "UNKNOWN" with the reason.
 *
 * The ViewModel owns the lifecycle of location collection: it starts when the GPS tab is opened
 * ([onScreenVisible]) and stops when it leaves ([onScreenHidden]), so the DNS/home tabs never pay
 * for location.
 */
@HiltViewModel
class GpsViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val engine: GpsEngine,
    private val preferences: GpsPreferences,
    private val dao: GpsDao,
    private val navigation: NavigationSession,
    private val traffic: TrafficRepository,
    private val tripRecorder: TripRecorder,
    private val geocoding: GeocodingClient,
    private val routingClient: RoutingClient,
    private val trafficApi: TrafficApiClient,
    private val voice: TtsVoiceGuidance
) : ViewModel() {

    val frame: StateFlow<GpsFrame> = engine.frame.stateIn(
        viewModelScope, SharingStarted.Eagerly, GpsFrame.EMPTY
    )
    val satellites: StateFlow<SatelliteSnapshot?> = engine.satellites.stateIn(
        viewModelScope, SharingStarted.Eagerly, null
    )
    val navigationState: StateFlow<NavigationState> = navigation.state
    val progress: StateFlow<RouteProgress?> = navigation.progress
    val trafficSegments: StateFlow<List<SegmentTrafficState>> = traffic.segments
    val trafficStatus: StateFlow<TrafficRepository.TrafficStatus> = traffic.status
    val trafficGateLog: StateFlow<List<String>> = traffic.gateLog
    val incidents = traffic.incidents

    private val _state = MutableStateFlow(GpsUiState())
    val state: StateFlow<GpsUiState> = _state.asStateFlow()

    private val _events = MutableStateFlow<List<GpsEvent>>(emptyList())
    val events: StateFlow<List<GpsEvent>> = _events.asStateFlow()

    private val alerts = SecurityAlertThrottle()
    private val mockDetector = MockLocationDetector()

    private var observing = false
    private var lastCamera: GeoPoint? = null

    init {
        traffic.initialise()
        GpsMaintenanceWorker.schedule(context)
        viewModelScope.launch {
            preferences.mapStyle.collect { style -> _state.value = _state.value.copy(mapStyleUrl = style) }
        }
        viewModelScope.launch {
            preferences.policy.collect { policy ->
                _state.value = _state.value.copy(policy = policy)
                voice.setGuidanceEnabled(policy.voiceGuidance)
            }
        }
        viewModelScope.launch {
            preferences.trafficBackendUrl.collect { url ->
                _state.value = _state.value.copy(trafficBackendUrl = url.orEmpty())
            }
        }
        viewModelScope.launch {
            var last: GeoPoint? = null
            preferences.lastCamera.collect { last = it; return@collect }
            if (last != null) {
                _state.value = _state.value.copy(cameraCenter = last)
            }
        }
        viewModelScope.launch {
            traffic.incidents.collect { list ->
                _state.value = _state.value.copy(incidentPoints = list.map { it.position })
            }
        }
        viewModelScope.launch {
            dao.observeTrips(30).collect { trips ->
                _state.value = _state.value.copy(
                    trips = trips.map { trip ->
                        TripSummary(
                            id = trip.id,
                            startedAtMs = trip.startedAtMs,
                            endedAtMs = trip.endedAtMs,
                            distanceMeters = trip.distanceMeters,
                            maxSpeedKmh = trip.maxSpeedKmh,
                            averageSpeedKmh = trip.averageSpeedKmh,
                            movingSeconds = trip.movingSeconds,
                            pointCount = trip.pointCount,
                            integrity = trip.integrityVerdict,
                            hasEncryptedTrack = trip.encryptedTrackFile != null
                        )
                    }
                )
            }
        }
        viewModelScope.launch {
            dao.observeOfflinePacks().collect { packs ->
                _state.value = _state.value.copy(offlinePacks = packs.map { it.toUiModel() })
            }
        }
        viewModelScope.launch {
            dao.observeSavedPlaces().collect { places ->
                _state.value = _state.value.copy(
                    savedPlaces = places.map {
                        SavedPlace(
                            id = it.id,
                            label = it.label,
                            position = GeoPoint(it.latitude, it.longitude)
                        )
                    }
                )
            }
        }
        viewModelScope.launch {
            grabObservers()
        }
        refreshPermissionAudit()
    }

    private suspend fun grabObservers() {
        // Feed every fix into the trip recorder and the traffic recorder.
        engine.addFixListener(fixListener)
        OfflineProgressBus.progress.collect { (packId, progress) ->
            val pack = dao.offlinePack(packId) ?: return@collect
            dao.updatePackProgress(
                id = packId,
                state = if (progress.complete) OfflinePackState.READY.name else OfflinePackState.DOWNLOADING.name,
                completed = progress.completed,
                required = progress.required,
                bytes = progress.bytes,
                updatedAt = System.currentTimeMillis(),
                error = null
            )
        }
    }

    private val fixListener: (com.adshield.pro.gps.engine.GnssFix) -> Unit = { fix ->
        val policy = _state.value.policy
        val compromised = frame.value.integrity.shouldRejectObservation
        tripRecorder.onFix(fix, policy, compromised)
        traffic.onFix(fix, policy, compromised)
        navigation.onFrame(frame.value)
        syncRouteGeometry()
    }

    /** Copies the active route and driven trail into the render state (cheap list references). */
    private fun syncRouteGeometry() {
        val plan = navigation.currentPlan
        _state.value = _state.value.copy(
            routeGeometry = plan?.geometry.orEmpty(),
            travelledGeometry = navigation.travelledGeometry()
        )
        if (plan != null) refreshSegmentsFor(plan)
    }

    private fun refreshSegmentsFor(plan: RoutePlan) {
        val segments = TrafficGeometry.segmentsForRoute(plan)
        traffic.updateSegments(segments)
        _state.value = _state.value.copy(
            trafficOverlay = TrafficGeometry.overlayFor(segments, trafficSegments.value, incidents.value.size),
            trafficOverlayReady = true
        )
    }

    // ------------------------------------------------------------ lifecycle
    fun onScreenVisible() {
        if (observing) return
        observing = true
        refreshPermissionAudit()
        engine.start(intervalMs = 1_000L)
        if (!_state.value.policy.recordTripHistory) tripRecorder.finish(_state.value.policy)
        _events.value = listOf(
            GpsEvent("GPS engine started", System.currentTimeMillis(), GpsEventLevel.INFO)
        ) + _events.value.take(19)
    }

    fun onScreenHidden() {
        if (!observing) return
        observing = false
        engine.stop()
        tripRecorder.finish(_state.value.policy)
        traffic.completeTrip(_state.value.policy)
    }

    fun onNavigatingChanged(active: Boolean) {
        val policy = _state.value.policy
        if (!active) {
            GpsConsoleService.stop(context)
            return
        }
        if (policy.backgroundNavigation) {
            GpsConsoleService.start(context)
        }
    }

    // --------------------------------------------------------------- privacy
    fun refreshPermissionAudit() {
        viewModelScope.launch {
            val audit = withContext(Dispatchers.Default) { buildPermissionAudit() }
            _state.value = _state.value.copy(permissionAudit = audit)
        }
    }

    private fun buildPermissionAudit(): PermissionAudit {
        val fine = ContextCompat.checkSelfPermission(context, android.Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
        val coarse = ContextCompat.checkSelfPermission(context, android.Manifest.permission.ACCESS_COARSE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
        val notifications = ContextCompat.checkSelfPermission(context, android.Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        val manager = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
        val locationEnabled = runCatching { manager?.isLocationEnabled == true }.getOrDefault(false)
        val providers = runCatching { manager?.getProviders(true)?.toList().orEmpty() }.getOrDefault(emptyList())
        return PermissionAudit(
            fineLocationGranted = fine,
            coarseLocationGranted = coarse,
            backgroundLocationGranted = false, // This module never requests background location.
            notificationPermissionGranted = notifications,
            locationEnabled = locationEnabled,
            mockLocationApps = emptyList(),
            mockSettingApp = if (GpsEngine.isMockLocationAllowed(context)) "enabled for this app" else null,
            locationProvidersEnabled = providers
        )
    }

    fun setContributeTraffic(enabled: Boolean) = viewModelScope.launch {
        preferences.setContributeTraffic(enabled)
        record("Traffic contribution ${if (enabled) "enabled" else "disabled"}", GpsEventLevel.INFO)
    }

    fun setRecordHistory(enabled: Boolean) = viewModelScope.launch {
        preferences.setRecordTripHistory(enabled)
        if (!enabled) tripRecorder.finish(_state.value.policy)
        record("Trip history ${if (enabled) "enabled" else "disabled"}", GpsEventLevel.INFO)
    }

    fun setCoarseHistory(enabled: Boolean) = viewModelScope.launch {
        preferences.setCoarseHistoryOnly(enabled)
    }

    fun setRetentionDays(days: Int) = viewModelScope.launch {
        preferences.setHistoryRetentionDays(days)
    }

    fun setEmergencySharing(enabled: Boolean) = viewModelScope.launch {
        preferences.setAllowEmergencySharing(enabled)
        record("Emergency sharing ${if (enabled) "allowed" else "off"}", GpsEventLevel.SECURITY)
    }

    fun setEmergencyKillSwitch(disabled: Boolean) = viewModelScope.launch {
        preferences.setEmergencySharingDisabled(disabled)
        record(
            if (disabled) "Emergency sharing kill switch ENGAGED" else "Emergency sharing kill switch released",
            GpsEventLevel.SECURITY
        )
    }

    fun setIncidentReporting(enabled: Boolean) = viewModelScope.launch {
        preferences.setIncidentReporting(enabled)
    }

    fun setVoiceGuidance(enabled: Boolean) = viewModelScope.launch {
        preferences.setVoiceGuidance(enabled)
        voice.setGuidanceEnabled(enabled)
    }

    fun setBackgroundNavigation(enabled: Boolean) = viewModelScope.launch {
        preferences.setBackgroundNavigation(enabled)
        if (!enabled) GpsConsoleService.stop(context)
    }

    fun regenerateReporterToken() = viewModelScope.launch {
        preferences.regenerateReporterToken()
        record("Anonymous reporter token regenerated", GpsEventLevel.SECURITY)
    }

    fun deleteAllLocationData() = viewModelScope.launch {
        tripRecorder.wipeAll()
        traffic.clearLocal()
        record("All location data deleted from this device", GpsEventLevel.SECURITY)
    }

    fun emergencyShareText(): Result<String> {
        val fix = frame.value.fix
        val position = fix?.position
            ?: return Result.failure(IllegalStateException("No GPS fix yet — wait for a position before sharing"))
        return EmergencyShareBuilder.build(
            position = position,
            accuracyMeters = fix.accuracyMeters,
            policy = _state.value.policy,
            label = "AdShield Pro location share"
        ).map { it.text }
    }

    // ------------------------------------------------------------------ map
    fun attachMapEngine(engine: MapLibreEngine) {
        _state.value = _state.value.copy(mapAttached = true)
    }

    fun onCameraIdle(center: GeoPoint, zoom: Double) {
        lastCamera = center
        _state.value = _state.value.copy(cameraCenter = center, cameraZoom = zoom)
        viewModelScope.launch { preferences.rememberCamera(center, zoom) }
        navigation.currentPlan?.let { plan -> refreshSegmentsFor(plan) }
    }

    fun setCameraMode(mode: CameraMode) {
        _state.value = _state.value.copy(cameraMode = mode)
    }

    fun setMapStyle(url: String) = viewModelScope.launch {
        preferences.setMapStyle(url)
    }

    // ----------------------------------------------------------- destination
    fun searchDestination(query: String) {
        if (query.isBlank()) return
        viewModelScope.launch {
            _state.value = _state.value.copy(searching = true, searchError = null)
            val results = geocoding.search(query, limit = 6)
            _state.value = _state.value.copy(
                searching = false,
                searchResults = results.map {
                    PlaceResult(it.shortName, it.displayName, it.position)
                },
                searchError = geocoding.lastError
            )
        }
    }

    fun clearSearch() {
        _state.value = _state.value.copy(searchResults = emptyList(), searchError = null)
    }

    fun planRouteTo(destination: GeoPoint, label: String) {
        val origin = frame.value.fix?.position
        if (origin == null) {
            _state.value = _state.value.copy(routeError = "Waiting for a GPS fix before routing")
            return
        }
        val provider = runCatching { RoutingProvider.valueOf(_state.value.routerProvider) }
            .getOrDefault(RoutingProvider.OSRM)
        navigation.planRoute(origin, destination, label, provider)
        _state.value = _state.value.copy(
            destination = PlaceResult(label, label, destination),
            routeError = null
        )
    }

    fun stopNavigation() {
        navigation.stop()
        GpsConsoleService.stop(context)
        _state.value = _state.value.copy(destination = null)
    }

    fun reroute() {
        frame.value.fix?.position?.let { navigation.reroute(it) }
    }

    fun setRouterProvider(provider: String) = viewModelScope.launch {
        preferences.setRouterPreference(provider)
    }

    fun saveCurrentPlace(label: String) {
        val fix = frame.value.fix ?: return
        viewModelScope.launch {
            dao.insertSavedPlace(
                com.adshield.pro.gps.data.SavedPlaceEntity(
                    label = label.ifBlank { "Saved place" },
                    latitude = fix.position.latitude,
                    longitude = fix.position.longitude,
                    createdAtMs = System.currentTimeMillis()
                )
            )
        }
    }

    fun deleteSavedPlace(id: Long) = viewModelScope.launch { dao.deleteSavedPlace(id) }

    // -------------------------------------------------------------- traffic
    fun setTrafficVisible(visible: Boolean) {
        _state.value = _state.value.copy(trafficVisible = visible)
        if (visible) traffic.syncCommunity()
    }

    fun syncTraffic() = traffic.syncCommunity()

    fun reportIncident(kind: IncidentKind, notes: String?) {
        val outcome = traffic.reportIncident(
            kind = kind,
            fix = frame.value.fix,
            notes = notes,
            integrityCompromised = frame.value.integrity.shouldRejectObservation,
            policy = _state.value.policy
        )
        _state.value = _state.value.copy(reportMessage = outcome.message, reportAccepted = outcome.accepted)
    }

    fun clearReportMessage() {
        _state.value = _state.value.copy(reportMessage = null)
    }

    fun dismissIncident(id: String) = traffic.dismissIncident(id)

    // -------------------------------------------------------------- offline
    fun computeOfflinePlan(bounds: GeoBounds, minZoom: Int, maxZoom: Int) {
        val plan = OfflinePlanner.plan(bounds, minZoom, maxZoom)
        _state.value = _state.value.copy(
            offlinePlan = OfflinePlanPreview(
                bounds = bounds,
                minZoom = plan.minZoom,
                maxZoom = plan.maxZoom,
                tileCount = plan.tileCount,
                estimatedBytes = plan.estimatedBytes,
                withinLimits = plan.withinLimits,
                limitReason = plan.limitReason
            )
        )
    }

    fun autoFitOfflinePlan(bounds: GeoBounds) {
        val plan = OfflinePlanner.autoFit(bounds)
        computeOfflinePlan(bounds, plan.minZoom, plan.maxZoom)
    }

    fun downloadRegion(
        name: String,
        bounds: GeoBounds,
        minZoom: Int,
        maxZoom: Int,
        mapEngine: MapLibreEngine
    ) {
        val plan = OfflinePlanner.plan(bounds, minZoom, maxZoom)
        if (!plan.withinLimits) {
            _state.value = _state.value.copy(offlineMessage = plan.limitReason, offlineError = true)
            return
        }
        val packId = "pack-${System.currentTimeMillis()}"
        val entity = OfflineMapPackEntity(
            id = packId,
            name = name.ifBlank { "Region ${MapProjection.tileKey(0, 0, 0)}" },
            south = bounds.south,
            west = bounds.west,
            north = bounds.north,
            east = bounds.east,
            minZoom = plan.minZoom,
            maxZoom = plan.maxZoom,
            styleUrl = _state.value.mapStyleUrl,
            maplibreRegionId = null,
            state = OfflinePackState.QUEUED.name,
            completedResources = 0,
            requiredResources = plan.tileCount,
            bytesDownloaded = 0,
            createdAtMs = System.currentTimeMillis(),
            updatedAtMs = System.currentTimeMillis()
        )
        viewModelScope.launch {
            dao.upsertOfflinePack(entity)
            _state.value = _state.value.copy(
                offlineMessage = "Queued ${plan.summary()} for $name",
                offlineError = false
            )
        }
        mapEngine.downloadRegion(
            packId = packId,
            name = entity.name,
            styleUrl = entity.styleUrl,
            bounds = bounds,
            minZoom = plan.minZoom,
            maxZoom = plan.maxZoom,
            pixelRatio = context.resources.displayMetrics.density,
            onCreated = { region ->
                viewModelScope.launch {
                    dao.upsertOfflinePack(entity.copy(maplibreRegionId = region.id, state = OfflinePackState.DOWNLOADING.name))
                }
            },
            onError = { error ->
                viewModelScope.launch {
                    dao.updatePackProgress(
                        id = packId,
                        state = OfflinePackState.FAILED.name,
                        completed = 0,
                        required = plan.tileCount,
                        bytes = 0,
                        updatedAt = System.currentTimeMillis(),
                        error = error
                    )
                    _state.value = _state.value.copy(offlineMessage = error, offlineError = true)
                }
            }
        )
    }

    fun updateOfflinePack(pack: OfflinePackUi, mapEngine: MapLibreEngine) {
        val regionId = pack.maplibreRegionId
        if (regionId == null) {
            _state.value = _state.value.copy(
                offlineMessage = "This pack has no MapLibre region id — delete and re-download it",
                offlineError = true
            )
            return
        }
        mapEngine.updateRegion(regionId) { ok ->
            viewModelScope.launch {
                _state.value = _state.value.copy(
                    offlineMessage = if (ok) "Refreshing ${pack.name} from the tile server" else "Update failed for ${pack.name}",
                    offlineError = !ok
                )
            }
        }
    }

    fun deleteOfflinePack(pack: OfflinePackUi, mapEngine: MapLibreEngine) {
        val regionId = pack.maplibreRegionId
        if (regionId != null) mapEngine.deleteRegion(regionId) {}
        viewModelScope.launch {
            pack.graphFileName?.let { name -> withContext(Dispatchers.IO) { File(offlineGraphDir(), name).delete() } }
            dao.deleteOfflinePack(pack.id)
            if (navigation.offlineGraphName == pack.name) navigation.clearOfflineGraph()
        }
    }

    fun importRoutingGraph(packId: String, uri: android.net.Uri) {
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val pack = dao.offlinePack(packId) ?: return@runCatching "Unknown pack"
                    val dir = offlineGraphDir()
                    if (!dir.exists()) dir.mkdirs()
                    val target = File(dir, "graph_$packId.adg.gz")
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        target.outputStream().use { output -> input.copyTo(output) }
                    } ?: return@runCatching "Could not read the selected file"
                    // Validate before accepting: a bad import must fail here, not during navigation.
                    val graph = com.adshield.pro.gps.offline.OfflineRoadGraph.readFile(target)
                    dao.setPackGraph(packId, target.name, target.length())
                    navigation.loadOfflineGraph(pack, target)
                    "Imported ${graph.describe()} for ${pack.name}"
                }.getOrElse { error ->
                    "Import failed: ${error.message ?: error.javaClass.simpleName}"
                }
            }
            _state.value = _state.value.copy(
                offlineMessage = result,
                offlineError = result.startsWith("Import failed") || result.startsWith("Could not") || result.startsWith("Unknown")
            )
        }
    }

    fun loadOfflineGraphForPack(pack: OfflinePackUi) {
        val fileName = pack.graphFileName ?: return
        viewModelScope.launch {
            val message = withContext(Dispatchers.IO) {
                val packEntity = dao.offlinePack(pack.id) ?: return@withContext "Unknown pack"
                val file = File(offlineGraphDir(), fileName)
                if (!file.isFile) return@withContext "Routing graph file is missing"
                navigation.loadOfflineGraph(packEntity, file)
            }
            _state.value = _state.value.copy(offlineMessage = message, offlineError = false)
        }
    }

    fun clearOfflineMessage() {
        _state.value = _state.value.copy(offlineMessage = null, offlineError = false)
    }

    fun offlineGraphDir(): File = File(context.filesDir, "gps_offline_graphs")

    // ----------------------------------------------------------------- misc
    fun testVoice() {
        val text = voice.speakTestPhrase()
        _state.value = _state.value.copy(voiceMessage = "Speaking: \"$text\"")
    }

    fun setVoiceLanguage(tag: String) = viewModelScope.launch {
        preferences.setVoiceLanguage(tag)
        voice.setLanguage(tag)
    }

    fun setTrafficBackend(url: String) = viewModelScope.launch {
        preferences.setEndpoint("traffic", url)
        preferences.setTrafficBackendEnabled(url.isNotBlank())
        traffic.syncCommunity()
    }

    fun setRoutingEndpoint(key: String, url: String) = viewModelScope.launch {
        preferences.setEndpoint(key, url)
    }

    fun deleteTrip(id: Long) {
        viewModelScope.launch {
            val trip = dao.trip(id)
            trip?.encryptedTrackFile?.let { tripRecorder.deleteTrackFile(it) }
            dao.deletePointsForTrip(id)
            dao.deleteTrip(id)
        }
    }

    fun dismissEvent(index: Int) {
        _events.value = _events.value.filterIndexed { position, _ -> position != index }
    }

    private fun record(message: String, level: GpsEventLevel) {
        _events.value = (listOf(GpsEvent(message, System.currentTimeMillis(), level)) + _events.value).take(30)
    }

    /** Live view of the radar so the screen does not recompute projection every frame. */
    fun radarPoints(): List<RadarGeometry.PlotPoint> =
        RadarGeometry.project(satellites.value?.satellites.orEmpty())

    override fun onCleared() {
        engine.removeFixListener(fixListener)
        engine.stop()
        navigation.stop()
        voice.stop()
        super.onCleared()
    }

    private fun OfflineMapPackEntity.toUiModel(): OfflinePackUi = OfflinePackUi(
        id = id,
        name = name,
        bounds = GeoBounds(south, west, north, east),
        minZoom = minZoom,
        maxZoom = maxZoom,
        state = runCatching { OfflinePackState.valueOf(state) }.getOrDefault(OfflinePackState.QUEUED),
        completedResources = completedResources,
        requiredResources = requiredResources,
        bytesDownloaded = bytesDownloaded,
        mapLibreRegionId = maplibreRegionId,
        error = error,
        styleUrl = styleUrl,
        graphFileName = graphFile,
        graphBytes = graphBytes
    )
}

// ------------------------------------------------------------------ models

enum class CameraMode(val label: String) {
    FREE("Free"),
    FOLLOW("Follow"),
    NORTH_UP("North up")
}

enum class OfflinePackState { QUEUED, DOWNLOADING, PAUSED, READY, FAILED }

enum class GpsEventLevel { INFO, SECURITY, WARNING }

data class GpsEvent(val message: String, val atMs: Long, val level: GpsEventLevel)

data class TripSummary(
    val id: Long,
    val startedAtMs: Long,
    val endedAtMs: Long?,
    val distanceMeters: Double,
    val maxSpeedKmh: Double,
    val averageSpeedKmh: Double,
    val movingSeconds: Long,
    val pointCount: Int,
    val integrity: String,
    val hasEncryptedTrack: Boolean
)

data class SavedPlace(val id: Long, val label: String, val position: GeoPoint)

data class PlaceResult(val shortName: String, val fullName: String, val position: GeoPoint)

data class OfflinePackUi(
    val id: String,
    val name: String,
    val bounds: GeoBounds,
    val minZoom: Int,
    val maxZoom: Int,
    val state: OfflinePackState,
    val completedResources: Long,
    val requiredResources: Long,
    val bytesDownloaded: Long,
    val mapLibreRegionId: Long?,
    val error: String?,
    val styleUrl: String,
    val graphFileName: String?,
    val graphBytes: Long
) {
    val progress: Float
        get() = if (requiredResources <= 0) 0f
        else (completedResources.toFloat() / requiredResources).coerceIn(0f, 1f)
    val hasRoutingGraph: Boolean get() = graphFileName != null && graphBytes > 0
}

data class OfflinePlanPreview(
    val bounds: GeoBounds,
    val minZoom: Int,
    val maxZoom: Int,
    val tileCount: Long,
    val estimatedBytes: Long,
    val withinLimits: Boolean,
    val limitReason: String?
)

data class GpsUiState(
    val policy: LocationPrivacyPolicy = LocationPrivacyPolicy(),
    val permissionAudit: PermissionAudit? = null,
    val mapStyleUrl: String = GpsPreferences.DEFAULT_MAP_STYLE,
    val mapAttached: Boolean = false,
    val cameraMode: CameraMode = CameraMode.FOLLOW,
    val cameraCenter: GeoPoint? = null,
    val cameraZoom: Double = 14.0,
    val routerProvider: String = "OSRM",
    val searchResults: List<PlaceResult> = emptyList(),
    val searching: Boolean = false,
    val searchError: String? = null,
    val destination: PlaceResult? = null,
    val routeError: String? = null,
    val trafficVisible: Boolean = true,
    val trafficOverlay: List<TrafficSegmentGeometry> = emptyList(),
    val reportMessage: String? = null,
    val reportAccepted: Boolean = false,
    val offlinePlan: OfflinePlanPreview? = null,
    val offlinePacks: List<OfflinePackUi> = emptyList(),
    val offlineMessage: String? = null,
    val offlineError: Boolean = false,
    val trips: List<TripSummary> = emptyList(),
    val savedPlaces: List<SavedPlace> = emptyList(),
    val voiceMessage: String? = null,
    /** Planned route polyline for the map (empty when no route is active). */
    val routeGeometry: List<GeoPoint> = emptyList(),
    /** Already driven part of the route, drawn in cyan under the route line. */
    val travelledGeometry: List<GeoPoint> = emptyList(),
    /** True once the traffic overlay has been computed for the active route. */
    val trafficOverlayReady: Boolean = false,
    /** Set when the map style could not be loaded (e.g. first launch with no connection). */
    val mapStyleError: String? = null,
    /** Self-hosted community traffic server, blank when the user has not configured one. */
    val trafficBackendUrl: String = "",
    /** Incident markers drawn on the map (real reports, never synthetic). */
    val incidentPoints: List<GeoPoint> = emptyList()
) {
    /** One-line operational status used by the GPS header of every tab. */
    fun statusLine(frame: GpsFrame): String = when {
        !LocationPermissionHelper.anyGranted(permissionAudit) -> "Location permission required"
        permissionAudit?.locationEnabled == false -> "System location is off"
        frame.fix == null -> "Searching for GNSS fix"
        frame.integrity.verdict == IntegrityVerdict.COMPROMISED -> "Integrity check failed"
        frame.fixState.label.isNotBlank() -> "${frame.fixState.label} · ${frame.accuracyBand.label}"
        else -> "Live"
    }
}

object LocationPermissionHelper {
    fun anyGranted(audit: PermissionAudit?): Boolean = audit?.anyGranted ?: true
}

/**
 * Builds the traffic overlay geometry from the active route: one segment per pair of consecutive
 * route vertices that carries a road name, so the overlay lines up with real streets.
 */
object TrafficGeometry {

    fun segmentsForRoute(plan: RoutePlan): List<RoadSegment> {
        val geometry = plan.geometry
        if (geometry.size < 2) return emptyList()
        val result = ArrayList<RoadSegment>()
        plan.steps.forEach { step ->
            val points = step.geometry
            if (points.size >= 2) {
                // Cap segment length so one long motorway step does not become a single blob.
                for (index in 0 until points.size - 1) {
                    val start = points[index]
                    val end = points[index + 1]
                    val distance = Geodesy.distanceMeters(start, end)
                    if (distance < 12.0) continue
                    result += RoadSegment(
                        id = segmentIdFor(start, end),
                        name = step.roadName,
                        start = start,
                        end = end,
                        speedLimitKmh = step.speedLimitKmh,
                        lengthMeters = distance
                    )
                }
            }
        }
        return result
    }

    /** Stable id from the rounded endpoints and the direction, so both directions differ. */
    fun segmentIdFor(start: GeoPoint, end: GeoPoint): String {
        val lat = ((start.latitude + end.latitude) / 2.0 * 10_000).toLong()
        val lon = ((start.longitude + end.longitude) / 2.0 * 10_000).toLong()
        val bearing = (Geodesy.bearingDegrees(start, end) / 45.0).toInt() % 8
        return "seg-$lat-$lon-$bearing"
    }

    fun overlayFor(
        segments: List<RoadSegment>,
        states: List<SegmentTrafficState>,
        incidentCount: Int
    ): List<TrafficSegmentGeometry> {
        val byId = states.associateBy { it.segmentId }
        return segments.map { segment ->
            val state = byId[segment.id]
            TrafficSegmentGeometry(
                points = listOf(segment.start, segment.end),
                level = state?.level ?: CongestionLevel.UNKNOWN,
                name = state?.segmentName ?: segment.name,
                confidence = state?.confidence ?: 0.0,
                ageLabel = when {
                    state?.ageMinutes != null -> formatAge(state.ageMinutes)
                    state != null -> "no observations"
                    else -> "no observations"
                }
            )
        }
    }

    fun colourFor(state: SegmentTrafficState?): String =
        TrafficColours.hexFor(state?.level ?: CongestionLevel.UNKNOWN)

    fun confidenceLabel(state: SegmentTrafficState?): String =
        state?.let { "${formatConfidence(it.confidence)} · ${it.sampleCount} samples" } ?: "no data"
}

/** Reason text used by the route banner when no maneuver is available. */
fun ManeuverType.bannerLabel(): String = label
