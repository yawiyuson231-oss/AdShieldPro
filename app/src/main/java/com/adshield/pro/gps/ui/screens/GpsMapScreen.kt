package com.adshield.pro.gps.ui.screens

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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Explore
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material.icons.filled.Navigation
import androidx.compose.material.icons.filled.SearchOff
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.gps.engine.GpsFrame
import com.adshield.pro.gps.engine.MovementState
import com.adshield.pro.gps.geo.Geodesy
import com.adshield.pro.gps.map.AdShieldMap
import com.adshield.pro.gps.map.CameraSnapshot
import com.adshield.pro.gps.map.MapLibreEngine
import com.adshield.pro.gps.map.trafficLegend
import com.adshield.pro.gps.ui.CameraMode
import com.adshield.pro.gps.ui.GpsBackground
import com.adshield.pro.gps.ui.GpsChip
import com.adshield.pro.gps.ui.GpsPanel
import com.adshield.pro.gps.ui.GpsTextDim
import com.adshield.pro.gps.ui.GpsTextPrimary
import com.adshield.pro.gps.ui.GpsTextSecondary
import com.adshield.pro.gps.ui.GpsUiState
import com.adshield.pro.gps.ui.MapOverlayPill
import com.adshield.pro.gps.ui.TelemetryReadout
import com.adshield.pro.gps.ui.TrafficLegend
import com.adshield.pro.gps.ui.VehicleMarker
import com.adshield.pro.gps.ui.accuracyColor
import com.adshield.pro.gps.ui.movementColor
import com.adshield.pro.gps.ui.GpsAmber
import com.adshield.pro.gps.ui.GpsCyan
import com.adshield.pro.gps.ui.GpsGreen
import com.adshield.pro.gps.ui.GpsRed

/**
 * GPS MAP — the full-screen interactive map.
 *
 * Layout: MapLibre fills the screen; three HUD clusters sit on top (top status strip, bottom-left
 * telemetry, bottom-right camera controls). The marker is a Compose overlay driven by the validated
 * fix stream, so a mocked fix is drawn red and labelled instead of being rendered as truth.
 *
 * When the Style or the renderer is unavailable (no network on first run, no GPU), the screen says
 * exactly that and keeps the telemetry usable — the map is one component, not the whole feature.
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
    modifier: Modifier = Modifier
) {
    var mapReady by remember { mutableStateOf(true) }
    val fix = frame.fix

    LaunchedEffect(frame.fix?.position, state.cameraMode) {
        val position = frame.fix?.position ?: return@LaunchedEffect
        when (state.cameraMode) {
            CameraMode.FOLLOW -> engine.followVehicle(
                point = position,
                bearing = frame.navigationBearingDegrees ?: 0.0,
                zoom = 17.0,
                tilt = 42.0
            )
            CameraMode.NORTH_UP -> engine.moveTo(position, zoom = state.cameraZoom.coerceAtLeast(15.0))
            CameraMode.FREE -> Unit
        }
    }

    Box(modifier.fillMaxSize().background(GpsBackground)) {
        AdShieldMap(
            modifier = Modifier.fillMaxSize(),
            engine = engine,
            styleUrl = state.mapStyleUrl,
            route = state.routeGeometry, // filled by the ViewModel while navigating
            travelled = state.travelledGeometry,
            traffic = state.trafficOverlay,
            incidents = state.incidentPoints,
            showTraffic = state.trafficVisible,
            onReady = { mapReady = true },
            onCameraIdle = { camera ->
                onCameraIdle(camera)
                mapReady = true
            },
            onMapClick = { }
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
                                frame.fix == null -> "Searching for a fix"
                                else -> "${frame.fix.source.label} · ${frame.accuracyBand.label} · ±${
                                    frame.fix.accuracyMeters.toInt()
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
                    color = com.adshield.pro.gps.ui.integrityColor(frame.integrity.verdict)
                )
            }
            if (frame.integrity.verdict == com.adshield.pro.gps.engine.IntegrityVerdict.COMPROMISED) {
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

        // ------------------------------------------------------------ centre marker
        if (fix != null && state.cameraMode == CameraMode.FREE) {
            VehicleMarker(
                bearingDegrees = frame.navigationBearingDegrees,
                accuracyColor = accuracyColor(frame.accuracyBand),
                movement = frame.movement,
                integrityCompromised = frame.integrity.verdict == com.adshield.pro.gps.engine.IntegrityVerdict.COMPROMISED,
                modifier = Modifier.align(Alignment.Center).size(44.dp)
            )
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
            }
            FloatingActionButton(
                onClick = onOpenSearch,
                containerColor = GpsCyan,
                contentColor = GpsBackground,
                modifier = Modifier.size(48.dp)
            ) {
                Icon(Icons.Default.SearchOff, contentDescription = "Search destination", modifier = Modifier.size(20.dp))
            }
        }

        // ------------------------------------------------------------- no-fix notice
        if (frame.fix == null) {
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
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center
                        )
                    }
                }
            }
        }

        if (!mapReady) {
            Box(
                Modifier
                    .align(Alignment.Center)
                    .padding(32.dp)
            ) {
                Text(
                    "Loading map style…\n(needs a connection the first time; downloaded regions work offline)",
                    color = GpsTextDim,
                    fontSize = 10.sp,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
            }
        }

        if (mapError != null) {
            Box(Modifier.align(Alignment.Center).padding(24.dp)) {
                Text(mapError ?: "", color = GpsRed, fontSize = 11.sp)
            }
        }
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
