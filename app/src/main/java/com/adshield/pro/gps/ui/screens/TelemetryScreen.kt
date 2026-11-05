package com.adshield.pro.gps.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.gps.engine.GpsFrame
import com.adshield.pro.gps.geo.Geodesy
import com.adshield.pro.gps.ui.AccuracyBar
import com.adshield.pro.gps.ui.CompassRose
import com.adshield.pro.gps.ui.GpsAmber
import com.adshield.pro.gps.ui.GpsBackground
import com.adshield.pro.gps.ui.GpsCyan
import com.adshield.pro.gps.ui.GpsEmptyState
import com.adshield.pro.gps.ui.GpsGreen
import com.adshield.pro.gps.ui.GpsGrey
import com.adshield.pro.gps.ui.GpsKeyValue
import com.adshield.pro.gps.ui.GpsPanel
import com.adshield.pro.gps.ui.GpsRed
import com.adshield.pro.gps.ui.GpsSectionTitle
import com.adshield.pro.gps.ui.GpsTextDim
import com.adshield.pro.gps.ui.GpsTextPrimary
import com.adshield.pro.gps.ui.GpsTextSecondary
import com.adshield.pro.gps.ui.GpsUiState
import com.adshield.pro.gps.ui.SpeedGauge
import com.adshield.pro.gps.ui.TelemetryReadout
import com.adshield.pro.gps.ui.TripSummary
import com.adshield.pro.gps.ui.accuracyColor
import com.adshield.pro.gps.ui.movementColor
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.roundToInt

/**
 * TELEMETRY — the instrument cluster.
 *
 * Values are grouped by trust level: measured by the receiver (speed, altitude, accuracy), derived
 * by this module (movement classification, distance, average speed), and unavailable (shown as "not
 * reported" rather than 0). The trip log below is the real recorded history, and each row states
 * whether its track is encrypted on disk.
 */
@Composable
fun TelemetryScreen(
    state: GpsUiState,
    frame: GpsFrame,
    onDeleteTrip: (Long) -> Unit,
    onRefreshPermissions: () -> Unit,
    modifier: Modifier = Modifier
) {
    val fix = frame.fix
    val stats = frame.trackStats

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(GpsBackground)
            .padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item(key = "telemetry-cluster") {
            Spacer(Modifier.height(10.dp))
            GpsPanel {
                Column(Modifier.padding(12.dp)) {
                    GpsSectionTitle("Instrument cluster", accent = GpsCyan)
                    Spacer(Modifier.height(6.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(Modifier.size(112.dp), contentAlignment = Alignment.Center) {
                            SpeedGauge(speedKmh = frame.speedKmh, modifier = Modifier.fillMaxSize())
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text(
                                    frame.speedKmh?.let { "${it.roundToInt()}" } ?: "—",
                                    color = if (frame.speedKmh == null) GpsGrey else GpsCyan,
                                    fontSize = 26.sp,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace
                                )
                                Text("km/h", color = GpsTextDim, fontSize = 9.sp)
                            }
                        }
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(Modifier.size(58.dp)) {
                                    CompassRose(
                                        headingDegrees = frame.navigationBearingDegrees,
                                        modifier = Modifier.fillMaxSize()
                                    )
                                }
                                Spacer(Modifier.width(10.dp))
                                Column {
                                    Text(
                                        frame.navigationBearingDegrees?.let { "${it.roundToInt()}°" } ?: "—",
                                        color = GpsTextPrimary,
                                        fontSize = 16.sp,
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Text(
                                        frame.heading?.source?.label ?: "no compass data",
                                        color = GpsTextDim,
                                        fontSize = 8.sp
                                    )
                                    Text(
                                        frame.heading?.degrees?.let { cardinal(it) } ?: "",
                                        color = GpsTextSecondary,
                                        fontSize = 9.sp
                                    )
                                }
                            }
                            Spacer(Modifier.height(8.dp))
                            AccuracyBar(accuracyMeters = fix?.accuracyMeters, band = frame.accuracyBand)
                            Spacer(Modifier.height(6.dp))
                            Text(
                                "Movement: ${frame.movement.label}",
                                color = movementColor(frame.movement),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Medium
                            )
                        }
                    }
                }
            }
        }

        item(key = "telemetry-derived") {
            GpsPanel {
                Column(Modifier.padding(12.dp)) {
                    GpsSectionTitle("Track statistics", accent = GpsCyan)
                    Spacer(Modifier.height(4.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        TelemetryReadout(
                            "Distance",
                            stats.distanceMeters.let {
                                if (it >= 1000) "%.2f".format(it / 1000.0) else it.roundToInt().toString()
                            },
                            if (stats.distanceMeters >= 1000) "km" else "m",
                            modifier = Modifier.weight(1f)
                        )
                        TelemetryReadout(
                            "Max speed",
                            if (stats.maxSpeedKmh > 0) stats.maxSpeedKmh.roundToInt().toString() else "—",
                            "km/h",
                            modifier = Modifier.weight(1f),
                            accent = GpsTextPrimary
                        )
                        TelemetryReadout(
                            "Moving",
                            Geodesy.formatDuration(stats.movingSeconds.toDouble()),
                            "",
                            modifier = Modifier.weight(1f),
                            accent = GpsTextSecondary
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    GpsKeyValue("Samples accepted", stats.acceptedSamples.toString(), valueColor = GpsGreen)
                    GpsKeyValue(
                        "Samples rejected",
                        stats.rejectedSamples.toString(),
                        valueColor = if (stats.rejectedSamples > 0) GpsAmber else GpsTextDim
                    )
                    GpsKeyValue("Average speed", "%.1f km/h".format(stats.averageSpeedKmh))
                    GpsKeyValue("Fix source", fix?.source?.label ?: "—")
                    GpsKeyValue("Fix age", frame.lastFixAgeMs?.let { "${it / 1000} s" } ?: "—")
                    GpsKeyValue("Fix state", frame.fixState.label)
                }
            }
        }

        item(key = "telemetry-raw") {
            GpsPanel {
                Column(Modifier.padding(12.dp)) {
                    GpsSectionTitle("Receiver readings", accent = GpsCyan)
                    Spacer(Modifier.height(4.dp))
                    GpsKeyValue(
                        "Latitude",
                        fix?.position?.let { "%.6f".format(it.latitude) } ?: "—"
                    )
                    GpsKeyValue(
                        "Longitude",
                        fix?.position?.let { "%.6f".format(it.longitude) } ?: "—"
                    )
                    GpsKeyValue("Altitude", fix?.altitudeMeters?.let { "%.1f m".format(it) } ?: "not reported")
                    GpsKeyValue(
                        "Vertical accuracy",
                        fix?.verticalAccuracyMeters?.let { "±%.1f m".format(it) } ?: "not reported"
                    )
                    GpsKeyValue("Speed accuracy", fix?.speedAccuracyMps?.let { "±%.2f m/s".format(it) } ?: "not reported")
                    GpsKeyValue("Bearing", fix?.bearingDegrees?.let { "%.1f°".format(it) } ?: "not reported")
                    GpsKeyValue(
                        "Bearing accuracy",
                        fix?.bearingAccuracyDegrees?.let { "±%.1f°".format(it) } ?: "not reported"
                    )
                    GpsKeyValue("Timestamp", fix?.timeMs?.let { formatTime(it) } ?: "—")
                    GpsKeyValue("Provider", fix?.source?.label ?: "—")
                    GpsKeyValue(
                        "Mock provider flag",
                        when (fix?.mockProviderFlag) {
                            true -> "TRUE — position is mocked"
                            false -> "false"
                            null -> "—"
                        },
                        valueColor = if (fix?.mockProviderFlag == true) GpsRed else GpsTextPrimary
                    )
                    Spacer(Modifier.height(6.dp))
                    if (fix == null) {
                        GpsEmptyState(
                            title = "No fix yet",
                            detail = "The receiver has not reported a position. Every field above would be " +
                                "invented if it showed a number, so they stay empty.",
                            icon = Icons.Default.Timeline,
                            accent = GpsGrey
                        )
                    }
                }
            }
        }

        if (state.trips.isNotEmpty()) {
            item(key = "telemetry-trips-header") {
                GpsSectionTitle("Trip history (${state.trips.size})", accent = GpsCyan)
            }
            items(state.trips, key = { it.id }, contentType = { "trip" }) { trip ->
                TripRow(trip = trip, onDelete = { onDeleteTrip(trip.id) })
            }
        } else {
            item(key = "telemetry-trips-empty") {
                GpsEmptyState(
                    title = "No trips recorded",
                    detail = if (state.policy.recordTripHistory) {
                        "History is enabled but no trip has been completed yet."
                    } else {
                        "Trip history is off. Turn it on in Location security to record distance, " +
                            "speed and an encrypted track per trip."
                    },
                    icon = Icons.Default.Timeline,
                    accent = GpsGrey,
                    action = {
                        Text(
                            "Check permissions",
                            color = GpsCyan,
                            fontSize = 10.sp,
                            modifier = Modifier.clickable(onClick = onRefreshPermissions)
                        )
                    }
                )
            }
        }

        item(key = "telemetry-footer") {
            Column(Modifier.padding(vertical = 16.dp)) {
                Text(
                    "All values on this screen come from Android's LocationManager and sensor APIs. " +
                        "Nothing is simulated; an unsupported reading is shown as 'not reported'.",
                    color = GpsTextDim,
                    fontSize = 9.sp,
                    lineHeight = 13.sp
                )
            }
        }
    }
}

@Composable
private fun TripRow(trip: TripSummary, onDelete: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(9.dp))
            .background(GpsPanel.copy(alpha = 0.6f))
            .padding(11.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                formatDateTime(trip.startedAtMs),
                color = GpsTextPrimary,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.weight(1f)
            )
            Text(
                trip.integrity,
                color = if (trip.integrity == "TRUSTED") GpsGreen else GpsAmber,
                fontSize = 8.sp
            )
            Spacer(Modifier.width(10.dp))
            Text(
                "delete",
                color = GpsTextDim,
                fontSize = 9.sp,
                modifier = Modifier.clickable(onClick = onDelete).padding(4.dp)
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(
            "%.2f km · avg %.0f km/h · max %.0f km/h · %s moving".format(
                trip.distanceMeters / 1000.0,
                trip.averageSpeedKmh,
                trip.maxSpeedKmh,
                Geodesy.formatDuration(trip.movingSeconds.toDouble())
            ),
            color = GpsTextSecondary,
            fontSize = 10.sp
        )
        Text(
            "${trip.pointCount} points · track " +
                if (trip.hasEncryptedTrack) "encrypted (AES-256-GCM)" else "not stored",
            color = GpsTextDim,
            fontSize = 9.sp
        )
    }
}

/** Eight-point compass label for the heading. */
private fun cardinal(degrees: Double): String {
    val points = listOf("N", "NE", "E", "SE", "S", "SW", "W", "NW")
    val index = (((degrees % 360) + 360) % 360 / 45.0).roundToInt() % 8
    return points[index]
}

private fun formatTime(epochMs: Long): String =
    SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date(epochMs))

private fun formatDateTime(epochMs: Long): String =
    SimpleDateFormat("dd MMM HH:mm", Locale.US).format(Date(epochMs))
