package com.adshield.pro.ui.cybershield

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.adshield.pro.engine.intel.CountryThreat
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.NavyBorder
import kotlin.math.hypot
import kotlin.math.sqrt

/**
 * Interactive world threat map.
 *
 * The land mass is a cached dot grid (the reference console's dotted-world look). Every red
 * marker is a real country aggregate from geolocated threat intelligence — marker size scales
 * with the indicator count. Tapping a marker selects that country; tapping empty ocean clears
 * the selection. No markers, arcs or glows are drawn when there is no data.
 */
@Composable
fun WorldThreatMap(
    countryThreats: List<CountryThreat>,
    selectedCountry: String?,
    onSelectCountry: (String?) -> Unit,
    modifier: Modifier = Modifier
) {
    val density = LocalDensity.current
    val spacingPx = with(density) { 5.dp.toPx() }
    var canvasSize by remember { mutableStateOf(androidx.compose.ui.geometry.Size.Zero) }
    // Land dots are expensive to sample; recompute only when the canvas size actually changes.
    val landDots = remember(canvasSize, spacingPx) {
        if (canvasSize.width <= 0f) emptyList()
        else WorldMapData.landDots(canvasSize.width, canvasSize.height, spacingPx)
    }
    val maxCount = (countryThreats.maxOfOrNull { it.count } ?: 1).coerceAtLeast(1)
    val markerRadiusBase = with(density) { 3.dp.toPx() }
    val markerRadiusMax = with(density) { 9.dp.toPx() }
    val tapSlopPx = with(density) { 22.dp.toPx() }

    // Precompute marker positions for hit testing and drawing.
    val markers = remember(countryThreats, canvasSize, maxCount) {
        countryThreats.mapNotNull { threat ->
            val centroid = WorldMapData.countryCentroids[threat.countryCode] ?: return@mapNotNull null
            val point = WorldMapData.project(centroid.lon, centroid.lat, canvasSize.width, canvasSize.height)
            val radius = markerRadiusBase +
                (markerRadiusMax - markerRadiusBase) * sqrt(threat.count.toFloat() / maxCount)
            MapMarker(threat, Offset(point.x, point.y), radius)
        }
    }

    Box(
        modifier = modifier
            .fillMaxWidth()
            .aspectRatio(2.05f)
            .clip(RoundedCornerShape(10.dp))
            .background(Color(0xFF03101F))
            .semantics {
                contentDescription = if (countryThreats.isEmpty()) {
                    "World threat map. No geolocated intelligence loaded."
                } else {
                    "World threat map. ${countryThreats.size} countries with reported indicators. Tap a marker for details."
                }
            }
            .pointerInput(markers) {
                detectTapGestures { tap ->
                    val hit = markers.minByOrNull { marker ->
                        hypot((marker.center.x - tap.x).toDouble(), (marker.center.y - tap.y).toDouble())
                    }
                    if (hit != null &&
                        hypot((hit.center.x - tap.x).toDouble(), (hit.center.y - tap.y).toDouble()) <= tapSlopPx
                    ) {
                        onSelectCountry(if (hit.threat.countryCode == selectedCountry) null else hit.threat.countryCode)
                    } else {
                        onSelectCountry(null)
                    }
                }
            }
    ) {
        Canvas(Modifier.fillMaxSize()) {
            if (canvasSize != size) canvasSize = size
            // Graticule — faint meridians/parallels like the reference console.
            val graticule = NavyBorder.copy(alpha = 0.22f)
            for (lon in -150..150 step 30) {
                val x = WorldMapData.project(lon.toFloat(), 0f, size.width, size.height).x
                drawLine(graticule, Offset(x, 0f), Offset(x, size.height), 0.6.dp.toPx())
            }
            for (lat in -40..80 step 20) {
                val y = WorldMapData.project(0f, lat.toFloat(), size.width, size.height).y
                drawLine(graticule, Offset(0f, y), Offset(size.width, y), 0.6.dp.toPx())
            }
            // Dotted land mass.
            val dotColor = ElectricBlue.copy(alpha = 0.55f)
            val dotRadius = 0.9.dp.toPx()
            landDots.forEach { dot ->
                drawCircle(dotColor, dotRadius, Offset(dot.x, dot.y))
            }
            // Real markers only.
            markers.forEach { marker ->
                drawThreatMarker(marker, marker.threat.countryCode == selectedCountry)
            }
        }
    }
}

private data class MapMarker(
    val threat: CountryThreat,
    val center: Offset,
    val radius: Float
)

private fun DrawScope.drawThreatMarker(marker: MapMarker, selected: Boolean) {
    val center = marker.center
    val radius = marker.radius
    // Outer glow.
    drawCircle(
        brush = Brush.radialGradient(
            listOf(AlertRed.copy(alpha = 0.45f), Color.Transparent),
            center = center,
            radius = radius * 3.2f
        ),
        radius = radius * 3.2f,
        center = center
    )
    drawCircle(AlertRed.copy(alpha = 0.85f), radius, center)
    drawCircle(Color(0xFFFFD7D7), radius * 0.4f, center)
    if (selected) {
        drawCircle(CyberCyan, radius + 4.dp.toPx(), center, style = androidx.compose.ui.graphics.drawscope.Stroke(1.6.dp.toPx()))
    }
}
