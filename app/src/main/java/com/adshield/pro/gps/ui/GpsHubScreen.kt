package com.adshield.pro.gps.ui

import android.Manifest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GpsFixed
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.Navigation
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Traffic
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.gps.data.GpsPreferences
import com.adshield.pro.gps.engine.AccuracyBand
import com.adshield.pro.gps.geo.GeoBounds
import com.adshield.pro.gps.map.MapLibreEngine
import com.adshield.pro.gps.map.CameraSnapshot
import com.adshield.pro.gps.security.PermissionAudit
import com.adshield.pro.gps.ui.screens.GpsMapScreen
import com.adshield.pro.gps.ui.screens.GpsRadarScreen
import com.adshield.pro.gps.ui.screens.LocationSecurityScreen
import com.adshield.pro.gps.ui.screens.NavigationScreen
import com.adshield.pro.gps.ui.screens.OfflineMapsScreen
import com.adshield.pro.gps.ui.screens.TelemetryScreen
import com.adshield.pro.gps.ui.screens.TrafficScreen
import org.maplibre.android.MapLibre

/**
 * AdShield Pro — GPS console host.
 *
 * Seven sections in one instrument panel. The hub owns three things the tabs must not each
 * re-implement:
 *  - the location permission gate (with an honest explanation of what each grant enables);
 *  - the MapLibre engine instance (one GL context for the whole module);
 *  - the start/stop of location collection tied to the screen's visibility.
 *
 * The DNS/VPN screens are untouched: this composable is a self-contained tab that the existing
 * navigation can show, and nothing here changes filter, tunnel or protection state.
 */
enum class GpsSection(val label: String, val icon: ImageVector) {
    MAP("GPS Map", Icons.Default.LocationOn),
    NAVIGATION("Navigate", Icons.Default.Navigation),
    TRAFFIC("Live Traffic", Icons.Default.Traffic),
    RADAR("GPS Radar", Icons.Default.Radar),
    TELEMETRY("Telemetry", Icons.Default.Speed),
    SECURITY("Location Security", Icons.Default.Security),
    OFFLINE("Offline Maps", Icons.Default.Layers)
}

@Composable
fun GpsHubScreen(
    modifier: Modifier = Modifier,
    initialSection: GpsSection = GpsSection.MAP,
    viewModel: GpsViewModel = hiltViewModel()
) {
    val context = LocalContext.current
    val frame by viewModel.frame.collectAsStateWithLifecycle()
    val satellites by viewModel.satellites.collectAsStateWithLifecycle()
    val state by viewModel.state.collectAsStateWithLifecycle()
    val trafficSegments by viewModel.trafficSegments.collectAsStateWithLifecycle()
    val trafficStatus by viewModel.trafficStatus.collectAsStateWithLifecycle()
    val incidents: List<com.adshield.pro.gps.traffic.TrafficIncident> by
        viewModel.incidents.collectAsStateWithLifecycle()
    val gateLog by viewModel.trafficGateLog.collectAsStateWithLifecycle()
    val navigationState by viewModel.navigationState.collectAsStateWithLifecycle()
    val progress by viewModel.progress.collectAsStateWithLifecycle()
    val online by rememberOnlineState()

    var section by rememberSaveable { mutableStateOf(initialSection.name) }
    val currentSection = runCatching { GpsSection.valueOf(section) }.getOrDefault(GpsSection.MAP)

    val engine = remember {
        // MapLibre must be initialised before any MapView exists; the call is idempotent.
        MapLibre.getInstance(context)
        MapLibreEngine(context)
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        viewModel.refreshPermissionAudit()
        // A grant or a refusal both end here: the UI re-renders from the real permission state.
        if (grants.values.any { it }) viewModel.onScreenVisible()
    }

    val requestLocation: () -> Unit = {
        permissionLauncher.launch(
            arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION
            )
        )
    }

    DisposableEffect(Unit) {
        viewModel.attachMapEngine(engine)
        viewModel.onScreenVisible()
        onDispose { viewModel.onScreenHidden() }
    }

    // Navigate with the real route as soon as one exists, and follow the vehicle while doing so.
    LaunchedEffect(navigationState.phase) {
        viewModel.onNavigatingChanged(navigationState.isActive)
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(GpsBackground)
    ) {
        SectionStrip(
            current = currentSection,
            accuracy = frame.accuracyBand,
            hasFix = frame.hasFix,
            onSelect = { section = it.name }
        )

        val audit = state.permissionAudit
        val needsPermission = audit != null && !audit.anyGranted
        if (needsPermission) {
            PermissionGate(
                audit = audit,
                onRequest = requestLocation,
                onOpenMapWithoutPermission = { section = GpsSection.OFFLINE.name }
            )
        }

        Box(Modifier.fillMaxSize()) {
            when (currentSection) {
                GpsSection.MAP -> GpsMapScreen(
                    state = state,
                    frame = frame,
                    online = online,
                    engine = engine,
                    onCameraIdle = { camera: CameraSnapshot ->
                        viewModel.onCameraIdle(camera.center, camera.zoom)
                    },
                    onSetCameraMode = viewModel::setCameraMode,
                    onRecentre = {
                        frame.fix?.position?.let { position ->
                            viewModel.setCameraMode(CameraMode.FOLLOW)
                            engine.followVehicle(position, frame.navigationBearingDegrees ?: 0.0)
                        }
                    },
                    onOpenSearch = { section = GpsSection.NAVIGATION.name },
                    onToggleTraffic = { viewModel.setTrafficVisible(!state.trafficVisible) },
                    onOpenStyleSheet = { section = GpsSection.OFFLINE.name }
                )

                GpsSection.NAVIGATION -> NavigationScreen(
                    state = state,
                    frame = frame,
                    navigation = navigationState,
                    progress = progress,
                    offlinePacks = state.offlinePacks,
                    online = online,
                    onSearch = viewModel::searchDestination,
                    onClearSearch = viewModel::clearSearch,
                    onPickDestination = { place -> viewModel.planRouteTo(place.position, place.shortName) },
                    onStop = viewModel::stopNavigation,
                    onReroute = viewModel::reroute,
                    onToggleVoice = viewModel::setVoiceGuidance,
                    onTestVoice = viewModel::testVoice,
                    onLoadOfflineGraph = viewModel::loadOfflineGraphForPack,
                    onStartBackgroundNavigation = {
                        viewModel.onNavigatingChanged(true)
                    }
                )

                GpsSection.TRAFFIC -> TrafficScreen(
                    state = state,
                    frame = frame,
                    segments = trafficSegments,
                    status = trafficStatus,
                    incidents = incidents,
                    gateLog = gateLog,
                    online = online,
                    onSync = viewModel::syncTraffic,
                    onToggleContribution = viewModel::setContributeTraffic,
                    onReport = viewModel::reportIncident,
                    onDismissIncident = viewModel::dismissIncident,
                    onSetBackend = viewModel::setTrafficBackend,
                    onClearReportMessage = viewModel::clearReportMessage
                )

                GpsSection.RADAR -> GpsRadarScreen(
                    state = state,
                    frame = frame,
                    satellites = satellites
                )

                GpsSection.TELEMETRY -> TelemetryScreen(
                    state = state,
                    frame = frame,
                    onDeleteTrip = viewModel::deleteTrip,
                    onRefreshPermissions = viewModel::refreshPermissionAudit
                )

                GpsSection.SECURITY -> LocationSecurityScreen(
                    state = state,
                    frame = frame,
                    onSetContributeTraffic = viewModel::setContributeTraffic,
                    onSetRecordHistory = viewModel::setRecordHistory,
                    onSetCoarseHistory = viewModel::setCoarseHistory,
                    onSetRetentionDays = viewModel::setRetentionDays,
                    onSetEmergencySharing = viewModel::setEmergencySharing,
                    onSetEmergencyKillSwitch = viewModel::setEmergencyKillSwitch,
                    onSetIncidentReporting = viewModel::setIncidentReporting,
                    onSetVoiceGuidance = viewModel::setVoiceGuidance,
                    onSetBackgroundNavigation = viewModel::setBackgroundNavigation,
                    onRegenerateToken = viewModel::regenerateReporterToken,
                    onDeleteAll = viewModel::deleteAllLocationData,
                    onRefreshPermissions = viewModel::refreshPermissionAudit,
                    onEmergencyShare = { viewModel.emergencyShareText() }
                )

                GpsSection.OFFLINE -> OfflineMapsScreen(
                    state = state,
                    frame = frame,
                    online = online,
                    onCreatePlan = { bounds: GeoBounds, min: Int, max: Int ->
                        viewModel.computeOfflinePlan(bounds, min, max)
                    },
                    onAutoFit = viewModel::autoFitOfflinePlan,
                    onDownload = { name, bounds, min, max ->
                        viewModel.downloadRegion(name, bounds, min, max, engine)
                    },
                    onUpdatePack = { pack -> viewModel.updateOfflinePack(pack, engine) },
                    onDeletePack = { pack -> viewModel.deleteOfflinePack(pack, engine) },
                    onImportGraph = viewModel::importRoutingGraph,
                    onLoadGraph = viewModel::loadOfflineGraphForPack,
                    onClearMessage = viewModel::clearOfflineMessage
                )
            }
        }
    }
}

@Composable
private fun SectionStrip(
    current: GpsSection,
    accuracy: AccuracyBand,
    hasFix: Boolean,
    onSelect: (GpsSection) -> Unit
) {
    LazyRow(
        modifier = Modifier
            .fillMaxWidth()
            .background(GpsBackground)
            .padding(horizontal = 8.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        items(GpsSection.entries.toList(), key = { it.name }) { item ->
            val selected = item == current
            Row(
                Modifier
                    .clip(RoundedCornerShape(9.dp))
                    .background(if (selected) GpsCyan.copy(alpha = 0.16f) else GpsPanel)
                    .padding(horizontal = 10.dp, vertical = 7.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                androidx.compose.material3.IconButton(
                    onClick = { onSelect(item) },
                    modifier = Modifier.size(18.dp)
                ) {
                    Icon(
                        item.icon,
                        contentDescription = item.label,
                        tint = if (selected) GpsCyan else GpsTextSecondary,
                        modifier = Modifier.size(16.dp)
                    )
                }
                Spacer(Modifier.width(4.dp))
                Text(
                    item.label,
                    color = if (selected) GpsCyan else GpsTextSecondary,
                    fontSize = 10.sp,
                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                    modifier = Modifier.padding(end = 4.dp)
                )
                if (item == GpsSection.MAP) {
                    StatusDot(if (hasFix) accuracyColor(accuracy) else GpsGrey)
                }
            }
        }
    }
}

@Composable
private fun PermissionGate(
    audit: PermissionAudit,
    onRequest: () -> Unit,
    onOpenMapWithoutPermission: () -> Unit
) {
    Column(
        Modifier
            .fillMaxWidth()
            .background(GpsBackground)
            .padding(horizontal = 16.dp, vertical = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            Icons.Default.GpsFixed,
            contentDescription = null,
            tint = GpsCyan,
            modifier = Modifier.size(34.dp)
        )
        Spacer(Modifier.height(10.dp))
        Text(
            "LOCATION ACCESS NEEDED",
            color = GpsTextPrimary,
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.4.sp
        )
        Spacer(Modifier.height(6.dp))
        Text(
            "Precise location is required for satellite positioning, navigation and road snapping. " +
                "It is read only while a GPS screen is open or navigation is running. The app never " +
                "requests background location, and the DNS/VPN protection is independent of this.",
            color = GpsTextSecondary,
            fontSize = 11.sp,
            lineHeight = 16.sp,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center
        )
        Spacer(Modifier.height(14.dp))
        Button(
            onClick = onRequest,
            colors = ButtonDefaults.buttonColors(
                containerColor = GpsCyan,
                contentColor = GpsBackground
            ),
            shape = RoundedCornerShape(9.dp)
        ) {
            Text("Allow location", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "Continue without location (offline maps only)",
            color = GpsTextDim,
            fontSize = 10.sp,
            modifier = Modifier
                .clip(RoundedCornerShape(6.dp))
                .padding(6.dp)
        )
        Spacer(Modifier.height(4.dp))
        Text(
            audit.findings().firstOrNull() ?: "",
            color = GpsTextDim,
            fontSize = 9.sp
        )
    }
}

/** Connectivity used for the ONLINE/OFFLINE chips; refreshed on every composition change of state. */
@Composable
fun rememberOnlineState(): Boolean {
    val context = LocalContext.current
    var online by remember { mutableStateOf(com.adshield.pro.gps.data.NetworkMonitor.isOnline(context)) }
    LaunchedEffect(Unit) {
        while (true) {
            online = com.adshield.pro.gps.data.NetworkMonitor.isOnline(context)
            kotlinx.coroutines.delay(5_000)
        }
    }
    return online
}

/** Style picker dialog used from the map HUD. */
val gpsStylePresets: List<Pair<String, String>> get() = GpsPreferences.STYLE_PRESETS
