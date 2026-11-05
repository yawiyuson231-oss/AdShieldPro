package com.adshield.pro.gps.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
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
import androidx.compose.material.icons.filled.SatelliteAlt
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.gps.engine.IntegrityFindingKind
import com.adshield.pro.gps.engine.IntegritySeverity
import com.adshield.pro.gps.engine.GpsFrame
import com.adshield.pro.gps.engine.RadarGeometry
import com.adshield.pro.gps.engine.RadarGeometry.PlotPoint
import com.adshield.pro.gps.engine.SatelliteInfo
import com.adshield.pro.gps.engine.SatelliteSnapshot
import com.adshield.pro.gps.ui.GpsBackground
import com.adshield.pro.gps.ui.GpsBorder
import com.adshield.pro.gps.ui.GpsBorderBright
import com.adshield.pro.gps.ui.GpsChip
import com.adshield.pro.gps.ui.GpsCyan
import com.adshield.pro.gps.ui.GpsEmptyState
import com.adshield.pro.gps.ui.GpsGrey
import com.adshield.pro.gps.ui.GpsInlineNotice
import com.adshield.pro.gps.ui.GpsKeyValue
import com.adshield.pro.gps.ui.GpsPanel
import com.adshield.pro.gps.ui.GpsRed
import com.adshield.pro.gps.ui.GpsSectionTitle
import com.adshield.pro.gps.ui.GpsTextDim
import com.adshield.pro.gps.ui.GpsTextPrimary
import com.adshield.pro.gps.ui.GpsTextSecondary
import com.adshield.pro.gps.ui.GpsUiState
import com.adshield.pro.gps.ui.GpsAmber
import com.adshield.pro.gps.ui.constellationColor
import com.adshield.pro.gps.ui.integrityColor
import kotlin.math.min

/**
 * GPS RADAR — real sky plot.
 *
 * The polar plot is drawn from `GnssStatus` azimuth/elevation/SNR: centre is the zenith, the rim is
 * the horizon, and each dot is a satellite that physically exists above the device right now. If the
 * receiver does not expose satellite geometry the screen says so and shows nothing rather than a
 * decorative animation.
 *
 * The same screen carries the integrity readout (jumps, mock-provider detections, clock anomalies)
 * because "is this position trustworthy" belongs next to "what can the receiver see".
 */
@Composable
fun GpsRadarScreen(
    state: GpsUiState,
    frame: GpsFrame,
    satellites: SatelliteSnapshot?,
    modifier: Modifier = Modifier
) {
    val points = RadarGeometry.project(satellites?.satellites.orEmpty())
    val score = RadarGeometry.skyScore(satellites)
    val findings = frame.integrity.findings

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(GpsBackground)
            .padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item(key = "radar-plot") {
            Spacer(Modifier.height(10.dp))
            GpsPanel {
                Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        GpsSectionTitle("Satellite sky plot", accent = GpsCyan, modifier = Modifier.weight(1f))
                        GpsChip(
                            text = "SKY $score",
                            color = when {
                                score >= 70 -> GpsCyan
                                score >= 40 -> GpsAmber
                                else -> GpsGrey
                            }
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    if (points.isEmpty()) {
                        GpsEmptyState(
                            title = "No satellite geometry",
                            detail = RadarGeometry.emptyReason(
                                hasPermission = state.permissionAudit?.fineLocationGranted != false,
                                locationEnabled = state.permissionAudit?.locationEnabled != false,
                                // GNSS hardware is present when the platform exposes the status API;
                                // a snapshot means a report has actually arrived.
                                gnssAvailable = state.gnssStatusSupported,
                                receivedReport = satellites != null
                            ),
                            icon = Icons.Default.SatelliteAlt,
                            accent = GpsGrey
                        )
                    } else {
                        SkyPlot(points = points)
                        Spacer(Modifier.height(8.dp))
                        Text(
                            satellites?.qualityNote() ?: "",
                            color = GpsTextSecondary,
                            fontSize = 10.sp
                        )
                        Spacer(Modifier.height(6.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            satellites?.constellations?.forEach { constellation ->
                                SatelliteLegendDot(constellation)
                            }
                        }
                    }
                }
            }
        }

        item(key = "radar-summary") {
            GpsPanel {
                Column(Modifier.padding(12.dp)) {
                    GpsSectionTitle("Receiver", accent = GpsCyan)
                    Spacer(Modifier.height(6.dp))
                    GpsKeyValue("Satellites in fix", satellites?.satellitesUsedInFix?.toString() ?: "—")
                    GpsKeyValue("Satellites visible", satellites?.satellitesVisible?.toString() ?: "—")
                    GpsKeyValue(
                        "Mean SNR",
                        satellites?.averageSnrDbHz?.let { "%.1f dBHz".format(it) } ?: "—"
                    )
                    GpsKeyValue(
                        "Constellations",
                        satellites?.constellations?.joinToString(", ").orEmpty().ifBlank { "—" }
                    )
                    GpsKeyValue("Accuracy", frame.fix?.accuracyMeters?.let { "±${it.toInt()} m" } ?: "—")
                    GpsKeyValue("Altitude", frame.fix?.altitudeMeters?.let { "%.0f m".format(it) } ?: "not reported")
                    GpsKeyValue("Vertical accuracy", frame.fix?.verticalAccuracyMeters?.let { "±${it.toInt()} m" } ?: "not reported")
                    GpsKeyValue("Doppler speed", frame.fix?.speedKmh?.let { "%.1f km/h".format(it) } ?: "not reported")
                    GpsKeyValue(
                        "Bearing accuracy",
                        frame.fix?.bearingAccuracyDegrees?.let { "±%.1f°".format(it) } ?: "not reported"
                    )
                }
            }
        }

        item(key = "radar-integrity") {
            GpsPanel(accent = integrityColor(frame.integrity.verdict)) {
                Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        GpsSectionTitle("Location integrity", accent = GpsCyan, modifier = Modifier.weight(1f))
                        GpsChip(
                            text = frame.integrity.verdict.label.uppercase(),
                            color = integrityColor(frame.integrity.verdict),
                            filled = true
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    val stats = frame.integrity.statistics
                    Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                        RadarStat("Jumps", stats.jumpsDetected.toString(), if (stats.jumpsDetected > 0) GpsAmber else GpsTextDim)
                        RadarStat("Impossible", stats.impossibleSpeeds.toString(), if (stats.impossibleSpeeds > 0) GpsRed else GpsTextDim)
                        RadarStat("Clock", stats.clockAnomalies.toString(), if (stats.clockAnomalies > 0) GpsAmber else GpsTextDim)
                        RadarStat("Mock", stats.mockDetections.toString(), if (stats.mockDetections > 0) GpsRed else GpsTextDim)
                    }
                    Spacer(Modifier.height(8.dp))
                    if (findings.isEmpty()) {
                        Text(
                            "No anomaly detected in the current track. This is a heuristic check, not proof " +
                                "that the position has not been spoofed at OS level.",
                            color = GpsTextDim,
                            fontSize = 9.sp,
                            lineHeight = 13.sp
                        )
                    } else {
                        findings.take(6).forEach { finding ->
                            Row(
                                Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 3.dp),
                                verticalAlignment = Alignment.Top
                            ) {
                                Box(
                                    Modifier
                                        .padding(top = 4.dp)
                                        .size(5.dp)
                                        .clip(RoundedCornerShape(50))
                                        .background(
                                            when (finding.severity) {
                                                IntegritySeverity.CRITICAL -> GpsRed
                                                IntegritySeverity.WARNING -> GpsAmber
                                                IntegritySeverity.INFO -> GpsCyan
                                            }
                                        )
                                )
                                Spacer(Modifier.width(7.dp))
                                Column {
                                    Text(
                                        finding.kind.label,
                                        color = GpsTextPrimary,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Medium
                                    )
                                    Text(finding.detail, color = GpsTextSecondary, fontSize = 9.sp, lineHeight = 12.sp)
                                }
                            }
                        }
                    }
                    if (findings.any { it.kind == IntegrityFindingKind.MOCK_LOCATION }) {
                        Spacer(Modifier.height(6.dp))
                        GpsInlineNotice(
                            "Mock location is active. Positions are shown for diagnostics only and are " +
                                "excluded from trip history, traffic samples and reports.",
                            GpsRed
                        )
                    }
                }
            }
        }

        if (satellites != null && satellites.satellites.isNotEmpty()) {
            item(key = "radar-list-header") {
                GpsSectionTitle("Satellites (${satellites.satellites.size})", accent = GpsCyan)
            }
            items(satellites.satellites, key = { "${it.constellation}-${it.svid}" }, contentType = { "satellite" }) { satellite ->
                SatelliteRow(satellite)
            }
        }

        item(key = "radar-footer") {
            Column(Modifier.padding(vertical = 16.dp)) {
                Text(
                    "Drawn from Android GnssStatus (azimuth, elevation, C/N0). A device that does not " +
                        "report these values shows no plot; nothing here is animated from fake data.",
                    color = GpsTextDim,
                    fontSize = 9.sp,
                    lineHeight = 13.sp
                )
            }
        }
    }
}

@Composable
private fun SkyPlot(points: List<PlotPoint>) {
    Canvas(
        Modifier
            .fillMaxWidth()
            .aspectRatio(1f)
    ) {
        val radius = min(size.width, size.height) / 2f - 6f
        val centre = Offset(size.width / 2f, size.height / 2f)

        // elevation rings (0 = horizon, 60 = near zenith)
        RadarGeometry.rings().forEach { ring ->
            drawCircle(
                color = GpsBorder.copy(alpha = 0.7f),
                radius = radius * ring,
                center = centre,
                style = androidx.compose.ui.graphics.drawscope.Stroke(width = if (ring == 1f) 2f else 1f)
            )
        }
        // cross hairs
        drawLine(
            color = GpsBorderBright.copy(alpha = 0.5f),
            start = Offset(centre.x - radius, centre.y),
            end = Offset(centre.x + radius, centre.y),
            strokeWidth = 1f
        )
        drawLine(
            color = GpsBorderBright.copy(alpha = 0.5f),
            start = Offset(centre.x, centre.y - radius),
            end = Offset(centre.x, centre.y + radius),
            strokeWidth = 1f
        )
        // points
        points.forEach { point ->
            val position = Offset(
                centre.x + point.x * radius,
                centre.y + point.y * radius
            )
            val colour = constellationColor(point.constellation)
            val dotRadius = 3.5f + point.snrRatio * 6f
            if (point.usedInFix) {
                drawCircle(color = colour.copy(alpha = 0.22f), radius = dotRadius + 5f, center = position)
            }
            drawCircle(
                color = if (point.usedInFix) colour else colour.copy(alpha = 0.45f),
                radius = dotRadius,
                center = position
            )
            if (!point.usedInFix) {
                drawCircle(
                    color = GpsTextDim,
                    radius = dotRadius,
                    center = position,
                    style = androidx.compose.ui.graphics.drawscope.Stroke(width = 1.2f)
                )
            }
        }
    }
}

@Composable
private fun SatelliteLegendDot(constellation: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .size(7.dp)
                .clip(RoundedCornerShape(50))
                .background(constellationColor(constellation))
        )
        Spacer(Modifier.width(4.dp))
        Text(RadarGeometry.constellationCode(constellation), color = GpsTextSecondary, fontSize = 9.sp)
    }
}

@Composable
private fun SatelliteRow(satellite: SatelliteInfo) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(7.dp))
            .background(GpsPanel.copy(alpha = 0.55f))
            .padding(horizontal = 10.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier
                .size(7.dp)
                .clip(RoundedCornerShape(50))
                .background(constellationColor(satellite.constellation))
        )
        Spacer(Modifier.width(8.dp))
        Text(
            RadarGeometry.constellationCode(satellite.constellation),
            color = GpsTextSecondary,
            fontSize = 9.sp,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.width(34.dp)
        )
        Text(
            "SV ${satellite.svid}",
            color = GpsTextPrimary,
            fontSize = 10.sp,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.weight(1f)
        )
        Text(
            "az ${satellite.azimuthDegrees.toInt()}° el ${satellite.elevationDegrees.toInt()}°",
            color = GpsTextSecondary,
            fontSize = 9.sp,
            fontFamily = FontFamily.Monospace
        )
        Spacer(Modifier.width(8.dp))
        Text(
            "%.0f dB".format(satellite.snrDbHz),
            color = when {
                satellite.snrDbHz >= 30 -> GpsCyan
                satellite.snrDbHz >= 20 -> GpsTextPrimary
                else -> GpsTextDim
            },
            fontSize = 9.sp,
            fontFamily = FontFamily.Monospace
        )
        Spacer(Modifier.width(6.dp))
        Text(
            if (satellite.usedInFix) "FIX" else "—",
            color = if (satellite.usedInFix) GpsCyan else GpsTextDim,
            fontSize = 8.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun RadarStat(label: String, value: String, color: Color) {
    Column {
        Text(label.uppercase(), color = GpsTextDim, fontSize = 8.sp)
        Text(value, color = color, fontSize = 14.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
    }
}
