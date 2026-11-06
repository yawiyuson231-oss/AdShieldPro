package com.adshield.pro.gps.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Explore
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material.icons.filled.Navigation
import androidx.compose.material.icons.filled.Remove
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.gps.engine.GpsFrame
import com.adshield.pro.gps.engine.IntegrityVerdict
import com.adshield.pro.gps.engine.MovementState
import com.adshield.pro.gps.geo.GeoBounds
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.geo.Geodesy
import com.adshield.pro.gps.map.AdShieldMap
import com.adshield.pro.gps.map.CameraSnapshot
import com.adshield.pro.gps.map.MapLibreEngine
import com.adshield.pro.gps.map.MapOverlayMath
import com.adshield.pro.gps.map.ScreenPoint
import com.adshield.pro.gps.ui.CameraMode
import com.adshield.pro.gps.ui.GpsAmber
import com.adshield.pro.gps.ui.GpsBackground
import com.adshield.pro.gps.ui.GpsChip
import com.adshield.pro.gps.ui.GpsCyan
import com.adshield.pro.gps.ui.GpsGreen
import com.adshield.pro.gps.ui.GpsPanel
import com.adshield.pro.gps.ui.GpsRed
import com.adshield.pro.gps.ui.GpsTextDim
import com.adshield.pro.gps.ui.GpsTextPrimary
import com.adshield.pro.gps.ui.GpsTextSecondary
import com.adshield.pro.gps.ui.GpsUiState
import com.adshield.pro.gps.ui.MapOverlayPill
import com.adshield.pro.gps.ui.TelemetryReadout
import com.adshield.pro.gps.ui.TrafficLegend
import com.adshield.pro.gps.ui.VehicleMarker
import com.adshield.pro.gps.ui.accuracyColor
import com.adshield.pro.gps.ui.integrityColor
import com.adshield.pro.gps.ui.movementColor

/**
 * GPS MAP — the full-screen interactive map.
 *
 * Layout: MapLibre fills the screen; three HUD clusters sit on top (top status strip, bottom-left
 * telemetry, bottom-right camera controls). The marker is a Compose overlay driven by the validated
 * fix stream, so a mocked fix is drawn red and labelled instead of being rendered as truth.
 *
 * The marker is positioned from MapLibre's own projection of the current fix whenever the map is
 * ready, and only falls back to flat Mercator math before the style loads. That keeps it on the
 * correct street while the camera follows, tilts or rotates; a marker pinned to the centre of the
 * screen would be wrong the moment the user pans in free mode.
 *
 * When the style or the renderer is unavailable (first launch with no connection, no GPU), the
 * screen says exactly that and keeps the telemetry usable — the map is one component, not the whole
 * feature.
 */
@Composable
fun GpsMapScreen(
    state: GpsUiState,
    frame: GpsFrame,
    online: Boolean,
    engine: MapLibreEngine,
    onCameraIdle: (CameraSnapshot) -> Unit,
    onSetCameraMode: (CameraMode) -> Unit,
    onRecentre: () -> Unit,
    onOpenSearch: () -> Unit,
    onToggleTraffic: () -> Unit,
    onOpenStyleSheet: () -> Unit,
    onLongPress: (GeoPoint) -> Unit = {},
    onZoomIn: () -> Unit = {},
    onZoomOut: () -> Unit = {},
    onFitRoute: () -> Unit = {},
    onFitApplied: () -> Unit = {},
    onRouteToPin: () -> Unit = {},
    onClearPin: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    val fix = frame.fix
    val density = LocalDensity.current

    // Zoom the engine believes the camera is at. Needed for the accuracy circle before the first
    // camera-idle callback lands, and when the map is not ready at all.
    var cameraZoom by remember { mutableStateOf(state.cameraZoom) }
    var cameraCentre by remember { mutableStateOf(state.cameraCenter) }
    var cameraBearing by remember { mutableStateOf(0.0) }

    /**
     * Bumped on every fix and on every camera-idle callback.
     *
     * MapLibre's projection is a native call, not observable state, so without an explicit
     * invalidator the marker would keep the pixel offset from the frame in which the map happened
     * to be composed and visibly lag behind the road.
     */
    var projectionTick by remember { mutableIntStateOf(0) }
    LaunchedEffect(frame.fix?.position, cameraZoom, cameraBearing, cameraCentre) {
        projectionTick++
    }

    // Open at the persisted camera exactly once, then let the user own the camera.
    var restoredOnce by remember { mutableStateOf(false) }
    LaunchedEffect(state.cameraRestored, state.cameraCenter, state.cameraZoom) {
        val centre = state.cameraCenter
        if (!restoredOnce && state.cameraRestored && centre != null) {
            restoredOnce = true
            cameraCentre = centre
            cameraZoom = state.cameraZoom
            engine.moveTo(centre, zoom = state.cameraZoom, animate = false)
        }
    }

    LaunchedEffect(frame.fix?.position, state.cameraMode) {
        val position = frame.fix?.position ?: return@LaunchedEffect
        when (state.cameraMode) {
            CameraMode.FOLLOW -> engine.followVehicle(
                point = position,
                bearing = frame.navigationBearingDegrees ?: 0.0,
                zoom = 17.0,
                // 3D off means a flat, north-agnostic drive view rather than a tilted one.
                tilt = if (state.mapTerrainTilt) 42.0 else 0.0
            )
            CameraMode.NORTH_UP -> engine.moveTo(position, zoom = cameraZoom.coerceAtLeast(15.0))
            CameraMode.FREE -> Unit
        }
    }

    // "Fit the route" request from the HUD: bounds of the planned polyline, then acknowledge.
    LaunchedEffect(state.mapFitRequest) {
        val geometry = state.mapFitRequest ?: return@LaunchedEffect
        val bounds = GeoBounds.of(geometry)
        if (bounds != null) {
            engine.showBounds(bounds)
            cameraCentre = bounds.center
            onFitApplied()
        }
    }

    Box(
        modifier
            .fillMaxSize()
            .background(GpsBackground)
    ) {
        AdShieldMap(
            modifier = Modifier
                .fillMaxSize()
                .pointerInput(Unit) {
                    detectTapGestures(onLongPress = { offset ->
                        val point = screenToGeo(offset.x, offset.y, engine) ?: return@detectTapGestures
                        onLongPress(point)
                    })
                },
            engine = engine,
            styleUrl = state.mapStyleUrl,
            route = state.routeGeometry,
            travelled = state.travelledGeometry,
            traffic = state.trafficOverlay,
            incidents = state.incidentPoints,
            showTraffic = state.trafficVisible,
            onCameraIdle = { }
        )
        // ------------------------------------------------------------------ top strip
        Column(
            Modifier
                .fillMaxWidth()
                .padding(10.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier
                        .clip(RoundedCornerShape(10.dp))
                        .background(GpsBackground.copy(alpha = 0.88f))
                        .padding(horizontal = 10.dp, vertical = 7.dp)
                ) {
                    Column {
                        Text(
                            "GPS MAP",
                            color = GpsTextPrimary,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 2.sp
                        )
                        Text(
                            when {
                                fix == null -> "Searching for a fix"
                                else -> "${fix.source.label} · ${frame.accuracyBand.label} · ±${
                                    fix.accuracyMeters.toInt()
                                } m"
                            },
                            color = GpsTextSecondary,
                            fontSize = 9.sp
                        )
                    }
                }
                Spacer(Modifier.weight(1f))
                MapOverlayPill(
                    text = if (online) "ONLINE" else "OFFLINE",
                    color = if (online) GpsGreen else GpsAmber
                )
            }
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                GpsChip(
                    text = when (val movement = frame.movement) {
                        MovementState.DRIVING -> "DRIVING"
                        MovementState.MOVING -> "MOVING"
                        MovementState.STATIONARY -> "STATIONARY"
                        MovementState.UNKNOWN -> "NO MOTION DATA"
                    },
                    color = movementColor(frame.movement)
                )
                GpsChip(
                    text = frame.satellites?.let { "${it.satellitesUsedInFix}/${it.satellitesVisible} SAT" }
                        ?: "SAT N/A",
                    color = if ((frame.satellites?.satellitesUsedInFix ?: 0) >= 4) GpsCyan else GpsTextSecondary
                )
                GpsChip(
                    text = frame.integrity.verdict.label.uppercase(),
                    color = integrityColor(frame.integrity.verdict)
                )
            }
            if (frame.integrity.verdict == IntegrityVerdict.COMPROMISED) {
                Spacer(Modifier.height(6.dp))
                Row(
                    Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(GpsRed.copy(alpha = 0.18f))
                        .padding(horizontal = 10.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.Warning, contentDescription = null, tint = GpsRed, modifier = Modifier.size(13.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(
                        frame.integrity.findings.firstOrNull()?.detail ?: "Location integrity check failed",
                        color = GpsRed,
                        fontSize = 10.sp
                    )
                }
            }
        }

        // ------------------------------------------------------- vehicle marker + accuracy
        if (fix != null) {
            BoxWithConstraints(Modifier.fillMaxSize()) {
                val widthPx = with(density) { maxWidth.toPx() }
                val heightPx = with(density) { maxHeight.toPx() }
                Box(Modifier.fillMaxSize()) {

                // projectionTick forces this block to re-evaluate as the map moves or a new fix
                // lands; MapLibre's projection is a backend call, not observable Compose state.
                projectionTick
                val centre = cameraCentre ?: fix.position
                val projected = engine.projectToScreen(fix.position)
                val offset = projected?.let { ScreenPoint(it.x - widthPx / 2.0, it.y - heightPx / 2.0) }
                    ?: MapOverlayMath.offsetFromCentre(
                        point = fix.position,
                        centre = centre,
                        cameraBearingDegrees = cameraBearing,
                        zoom = cameraZoom
                    )

                // The accuracy circle is drawn in metres: its pixel radius follows the real zoom and
                // latitude, so it shrinks as the receiver converges instead of being a fixed blob.
                val accuracyRadiusPx = MapOverlayMath.accuracyRadiusPx(
                    accuracyMeters = fix.accuracyMeters,
                    latitude = fix.position.latitude,
                    zoom = cameraZoom
                )
                val circleDp = with(density) { (accuracyRadiusPx * 2f).toDp() }
                if (accuracyRadiusPx > 0f && circleDp.value.isFinite() && circleDp.value < 4_000f) {
                    Box(
                        Modifier
                            .align(Alignment.Center)
                            .offset(
                                x = with(density) { offset.x.toDp() },
                                y = with(density) { offset.y.toDp() }
                            )
                            .size(circleDp)
                            .clip(RoundedCornerShape(percent = 50))
                            .background(
                                if (frame.integrity.verdict == IntegrityVerdict.COMPROMISED) {
                                    GpsRed.copy(alpha = 0.10f)
                                } else {
                                    accuracyColor(frame.accuracyBand).copy(alpha = 0.10f)
                                }
                            )
                    )
                }

                VehicleMarker(
                    bearingDegrees = frame.navigationBearingDegrees,
                    accuracyColor = accuracyColor(frame.accuracyBand),
                    movement = frame.movement,
                    integrityCompromised = frame.integrity.verdict == IntegrityVerdict.COMPROMISED,
                    modifier = Modifier
                        .align(Alignment.Center)
                        .offset(
                            x = with(density) { offset.x.toDp() },
                            y = with(density) { offset.y.toDp() }
                        )
                        .size(30.dp)
                )
                }
            }
        }

        // ------------------------------------------------------------ dropped pin marker
        val pin = state.mapDroppedPin
        if (pin != null) {
            BoxWithConstraints(Modifier.fillMaxSize()) {
                val widthPx = with(density) { maxWidth.toPx() }
                val heightPx = with(density) { maxHeight.toPx() }
                Box(Modifier.fillMaxSize()) {
                projectionTick
                val centre = cameraCentre ?: pin
                val offset = engine.projectToScreen(pin)?.let { projected ->
                    ScreenPoint(projected.x - widthPx / 2.0, projected.y - heightPx / 2.0)
                } ?: MapOverlayMath.offsetFromCentre(pin, centre, cameraBearing, cameraZoom)

                Box(
                    Modifier
                        .align(Alignment.Center)
                        .offset(
                            x = with(density) { offset.x.toDp() },
                            y = with(density) { (offset.y - 14f).toDp() }
                        )
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(
                            Icons.Default.MyLocation,
                            contentDescription = "Dropped pin",
                            tint = GpsCyan,
                            modifier = Modifier.size(22.dp)
                        )
                        Text(
                            state.mapDroppedPinLabel ?: "Pin",
                            color = GpsCyan,
                            fontSize = 8.sp,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .background(GpsBackground.copy(alpha = 0.8f))
                                .padding(horizontal = 3.dp)
                        )
                    }
                }
                }
            }
        }

        // -------------------------------------------------------- bottom-left telemetry
        Column(
            Modifier
                .align(Alignment.BottomStart)
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            GpsPanel(modifier = Modifier.width(212.dp)) {
                Column(Modifier.padding(12.dp)) {
                    Row {
                        TelemetryReadout(
                            label = "Speed",
                            value = frame.speedKmh?.let { String.format("%.0f", it) } ?: "—",
                            unit = "km/h",
                            accent = GpsCyan,
                            modifier = Modifier.weight(1f)
                        )
                        TelemetryReadout(
                            label = "Heading",
                            value = frame.navigationBearingDegrees?.let { "${it.toInt()}" } ?: "—",
                            unit = "°",
                            accent = GpsTextPrimary,
                            modifier = Modifier.weight(1f)
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        fix?.position?.let { Geodesy.formatCoordinates(it.latitude, it.longitude, 5) }
                            ?: "No position yet",
                        color = GpsTextSecondary,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        fix?.altitudeMeters?.let { "Altitude %.0f m".format(it) } ?: "Altitude not reported",
                        color = GpsTextDim,
                        fontSize = 9.sp
                    )
                    Text(
                        "Zoom " + String.format("%.1f", cameraZoom) + " · " + state.cameraMode.label,
                        color = GpsTextDim,
                        fontSize = 9.sp
                    )
                    Spacer(Modifier.height(6.dp))
                    TrafficLegend()
                }
            }
        }

        // ------------------------------------------------------- bottom-right controls
        Column(
            Modifier
                .align(Alignment.BottomEnd)
                .padding(12.dp),
            horizontalAlignment = Alignment.End,
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                HudButton(
                    icon = Icons.Default.Add,
                    label = "Zoom in",
                    active = false,
                    onClick = onZoomIn
                )
                HudButton(
                    icon = Icons.Default.Remove,
                    label = "Zoom out",
                    active = false,
                    onClick = onZoomOut
                )
                HudButton(
                    icon = Icons.Default.MyLocation,
                    label = "Recentre",
                    active = state.cameraMode == CameraMode.FOLLOW,
                    onClick = {
                        onSetCameraMode(if (state.cameraMode == CameraMode.FOLLOW) CameraMode.FREE else CameraMode.FOLLOW)
                        onRecentre()
                    }
                )
                HudButton(
                    icon = Icons.Default.Navigation,
                    label = if (state.cameraMode == CameraMode.NORTH_UP) "North up" else "Direction up",
                    active = state.cameraMode == CameraMode.NORTH_UP,
                    onClick = {
                        onSetCameraMode(
                            if (state.cameraMode == CameraMode.NORTH_UP) CameraMode.FOLLOW else CameraMode.NORTH_UP
                        )
                    }
                )
                HudButton(
                    icon = Icons.Default.Layers,
                    label = if (state.trafficVisible) "Traffic on" else "Traffic off",
                    active = state.trafficVisible,
                    onClick = onToggleTraffic
                )
                HudButton(
                    icon = Icons.Default.Explore,
                    label = "Map style",
                    active = false,
                    onClick = onOpenStyleSheet
                )
                if (state.routeGeometry.size >= 2) {
                    HudButton(
                        icon = Icons.Default.MyLocation,
                        label = "Fit route",
                        active = false,
                        onClick = onFitRoute
                    )
                }
            }
            FloatingActionButton(
                onClick = onOpenSearch,
                containerColor = GpsCyan,
                contentColor = GpsBackground,
                modifier = Modifier.size(48.dp)
            ) {
                Icon(Icons.Default.Search, contentDescription = "Search destination", modifier = Modifier.size(20.dp))
            }
        }

        // ------------------------------------------------------- dropped-pin confirmation
        if (pin != null) {
            Box(
                Modifier
                    .align(Alignment.BottomCenter)
                    .padding(bottom = 150.dp, start = 16.dp, end = 16.dp)
            ) {
                GpsPanel(accent = GpsCyan) {
                    Column(Modifier.padding(12.dp)) {
                        Text(
                            state.mapDroppedPinLabel ?: "Dropped pin",
                            color = GpsTextPrimary,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Box(
                                Modifier
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(GpsCyan)
                                    .clickable(onClick = onRouteToPin)
                                    .padding(horizontal = 12.dp, vertical = 6.dp)
                            ) {
                                Text("Route here", color = GpsBackground, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                            }
                            Box(
                                Modifier
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(GpsBackground)
                                    .clickable(onClick = onClearPin)
                                    .padding(horizontal = 12.dp, vertical = 6.dp)
                            ) {
                                Text("Cancel", color = GpsTextSecondary, fontSize = 10.sp)
                            }
                        }
                    }
                }
            }
        }

        // ------------------------------------------------------------- no-fix notice
        if (fix == null) {
            Box(
                Modifier
                    .align(Alignment.Center)
                    .padding(24.dp)
            ) {
                GpsPanel(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(14.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            when (frame.fixState.label) {
                                "Permission denied" -> "LOCATION PERMISSION REQUIRED"
                                "Location services off" -> "SYSTEM LOCATION IS OFF"
                                "No GNSS hardware" -> "NO GNSS RECEIVER REPORTED"
                                else -> "ACQUIRING GNSS FIX"
                            },
                            color = GpsAmber,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 1.4.sp
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            when (frame.fixState.label) {
                                "Permission denied" ->
                                    "Grant precise location in Android settings to see your position. " +
                                        "Offline maps and routing graphs keep working without it."
                                "Location services off" ->
                                    "Turn system location back on; the map stays usable for planning."
                                "No GNSS hardware" ->
                                    "This device does not expose a GPS provider. Network positioning may still work."
                                else ->
                                    "Waiting for real readings from the receiver. Nothing is simulated — " +
                                        "if no satellite is visible the map stays without a position."
                            },
                            color = GpsTextSecondary,
                            fontSize = 10.sp,
                            lineHeight = 14.sp,
                            textAlign = TextAlign.Center
                        )
                    }
                }
            }
        }

        // Only a real engine failure is shown here; there is no placeholder loading state.
        val styleError = state.mapStyleError
        if (styleError != null) {
            Row(
                Modifier
                    .align(Alignment.Center)
                    .padding(24.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(GpsBackground.copy(alpha = 0.92f))
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Default.Warning, contentDescription = null, tint = GpsRed, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(8.dp))
                Text(styleError, color = GpsRed, fontSize = 10.sp)
                Spacer(Modifier.width(8.dp))
                IconButton(onClick = onOpenStyleSheet, modifier = Modifier.size(26.dp)) {
                    Icon(Icons.Default.Explore, contentDescription = "Change map style", tint = GpsCyan, modifier = Modifier.size(16.dp))
                }
            }
        }
    }
}

/**
 * Converts a tap in view pixels back to a coordinate using MapLibre's own inverse projection.
 *
 * Returns null while the map is not ready, in which case the long press is ignored rather than
 * guessing a coordinate from stale camera state.
 */
private fun screenToGeo(x: Float, y: Float, engine: MapLibreEngine): GeoPoint? =
    engine.screenToCoordinate(ScreenPoint(x.toDouble(), y.toDouble()))

@Composable
private fun HudButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    active: Boolean,
    onClick: () -> Unit
) {
    Row(
        Modifier
            .clip(RoundedCornerShape(9.dp))
            .background(GpsBackground.copy(alpha = 0.9f))
            .padding(horizontal = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        IconButton(onClick = onClick, modifier = Modifier.size(34.dp)) {
            Icon(
                icon,
                contentDescription = label,
                tint = if (active) GpsCyan else GpsTextSecondary,
                modifier = Modifier.size(17.dp)
            )
        }
        Text(
            label,
            color = if (active) GpsCyan else GpsTextDim,
            fontSize = 9.sp,
            modifier = Modifier.padding(end = 8.dp)
        )
    }
}

@Composable
private fun HudButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    active: Boolean,
    onClick: () -> Unit
) {
    Row(
        Modifier
            .clip(RoundedCornerShape(9.dp))
            .background(GpsBackground.copy(alpha = 0.9f))
            .padding(horizontal = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        IconButton(onClick = onClick, modifier = Modifier.size(34.dp)) {
            Icon(
                icon,
                contentDescription = label,
                tint = if (active) GpsCyan else GpsTextSecondary,
                modifier = Modifier.size(17.dp)
            )
        }
        Text(
            label,
            color = if (active) GpsCyan else GpsTextDim,
            fontSize = 9.sp,
            modifier = Modifier.padding(end = 8.dp)
        )
    }
}
