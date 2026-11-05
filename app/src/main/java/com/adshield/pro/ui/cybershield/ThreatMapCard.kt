package com.adshield.pro.ui.cybershield

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Remove
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.cybershield.CountryThreatCluster
import com.adshield.pro.cybershield.CsLoadState
import com.adshield.pro.cybershield.GeoIndex
import com.adshield.pro.cybershield.IntelIndicator
import com.adshield.pro.cybershield.IntelUiState
import com.adshield.pro.cybershield.WorldMap
import com.adshield.pro.cybershield.DemoIntel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlin.math.sqrt

/**
 * Interactive global threat map. Renders bundled Natural Earth geometry with
 * Canvas (no WebView), overlays REAL verified intelligence grouped to country
 * level, and supports pan / pinch-zoom / marker taps / filters. Markers describe
 * where threat infrastructure is hosted — never attacks on this device, and
 * never the device's own location.
 */
@Composable
fun ThreatMapCard(
    intel: IntelUiState,
    demoOverlay: Boolean,
    nowMs: Long,
    onRefresh: () -> Unit,
    onEnableIntel: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var reloadTick by remember { mutableStateOf(0) }
    val world by produceState<WorldMap?>(null, reloadTick) {
        value = withContext(Dispatchers.IO) {
            runCatching {
                GeoIndex.parseWorld(
                    context.assets.open("cybershield_world.json").bufferedReader().use { it.readText() }
                )
            }.getOrNull()
        }
    }
    val centroids by produceState<Map<String, DoubleArray>>(emptyMap(), reloadTick) {
        value = withContext(Dispatchers.IO) {
            runCatching {
                GeoIndex.parseCentroids(
                    context.assets.open("cybershield_centroids.json").bufferedReader().use { it.readText() }
                )
            }.getOrDefault(emptyMap())
        }
    }

    var onlineOnly by rememberSaveable { mutableStateOf(false) }
    var familyFilter by rememberSaveable { mutableStateOf<String?>(null) }
    var selectedCountry by rememberSaveable { mutableStateOf<String?>(null) }
    var zoom by rememberSaveable { mutableStateOf(1f) }
    var panX by rememberSaveable { mutableStateOf(0f) }
    var panY by rememberSaveable { mutableStateOf(0f) }

    val usingDemo = demoOverlay && intel.snapshot == null
    val indicators: List<IntelIndicator> = when {
        demoOverlay -> if (intel.snapshot != null) intel.snapshot.indicators else DemoIntel.indicators
        else -> intel.snapshot?.indicators ?: emptyList()
    }
    val families = remember(indicators) { GeoIndex.topFamilies(indicators, 3) }
    val clusterResult = remember(indicators, centroids, onlineOnly, familyFilter, world) {
        GeoIndex.cluster(
            indicators = indicators,
            centroids = centroids,
            countryNames = world?.namesById ?: emptyMap(),
            onlineOnly = onlineOnly,
            familyFilter = familyFilter
        )
    }
    val selectedCluster = clusterResult.clusters.firstOrNull { it.countryCode == selectedCountry }

    NeonCard(modifier = modifier.fillMaxWidth(), glowColor = Cs.Purple) {
        CardHeader(
            "Global Threat Map", accent = Cs.Purple,
            trailing = {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (demoOverlay) StatusChip("Demo overlay", Cs.Amber)
                    SourceChip(com.adshield.pro.cybershield.CsDataSource.EXTERNAL_INTEL)
                    LoadStateChip(intel.loadState)
                }
            }
        )

        when {
            !intel.enabled && !demoOverlay -> {
                EmptyState("External threat intelligence is disabled. Enable it to load verified, attributed indicators.")
                TextButton(onClick = onEnableIntel) { Text("Enable threat intel", color = Cs.Cyan, fontSize = 12.sp) }
            }
            world == null -> {
                EmptyState("Loading world geometry…", icon = "◌")
                TextButton(onClick = { reloadTick++ }) { Text("Retry", color = Cs.Cyan, fontSize = 12.sp) }
            }
            indicators.isEmpty() -> {
                EmptyState(
                    when (intel.loadState) {
                        CsLoadState.LOADING -> "Fetching verified threat intelligence…"
                        CsLoadState.ERROR -> intel.error ?: "Threat intel unavailable."
                        else -> "No threat intel loaded yet. Connect to the internet and refresh, or enable the demo overlay in dashboard settings."
                    },
                    icon = "⊘"
                )
                TextButton(onClick = onRefresh) { Text("Refresh intel", color = Cs.Cyan, fontSize = 12.sp) }
            }
            else -> {
                // Filter chips
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.fillMaxWidth()) {
                    MapChip("All", !onlineOnly, { onlineOnly = false })
                    MapChip("Online C2", onlineOnly, { onlineOnly = true })
                    families.forEach { family ->
                        MapChip(family, familyFilter == family, {
                            familyFilter = if (familyFilter == family) null else family
                        })
                    }
                }

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(215.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(Cs.BackgroundDeep)
                ) {
                    val w = world
                    if (w != null) {
                        MapCanvas(
                            world = w,
                            clusters = clusterResult.clusters,
                            demo = usingDemo,
                            zoom = zoom,
                            panX = panX,
                            panY = panY,
                            selectedCountry = selectedCountry,
                            onTransform = { centroid, panChange, zoomChange ->
                                val newZoom = (zoom * zoomChange).coerceIn(1f, 6f)
                                zoom = newZoom
                                panX += panChange.x
                                panY += panChange.y
                            },
                            onTap = { pos, sizeW, sizeH ->
                                val base = baseMapRect(sizeW, sizeH)
                                val hit = clusterResult.clusters.minByOrNull { cluster ->
                                    val p = markerScreenPos(cluster, base, zoom, panX, panY, sizeW, sizeH)
                                    (p - pos).getDistance()
                                }
                                selectedCountry = if (hit != null) {
                                    val p = markerScreenPos(hit, base, zoom, panX, panY, sizeW, sizeH)
                                    if ((p - pos).getDistance() < 26.dp.value * 2.2f) hit.countryCode else null
                                } else null
                            },
                            onClampPan = { sizeW, sizeH ->
                                val maxX = sizeW * (zoom - 1f) / 2f + sizeW * 0.2f
                                val maxY = sizeH * (zoom - 1f) / 2f + sizeH * 0.2f
                                panX = panX.coerceIn(-maxX, maxX)
                                panY = panY.coerceIn(-maxY, maxY)
                            }
                        )
                    }
                    // Zoom controls
                    Column(
                        modifier = Modifier.align(Alignment.BottomEnd).padding(4.dp),
                        verticalArrangement = Arrangement.spacedBy(2.dp)
                    ) {
                        IconButton(
                            onClick = { zoom = (zoom * 1.4f).coerceAtMost(6f) },
                            modifier = Modifier.size(28.dp).background(Cs.Surface.copy(alpha = 0.8f), RoundedCornerShape(6.dp))
                        ) { Icon(Icons.Default.Add, "Zoom in", tint = Cs.Cyan, modifier = Modifier.size(16.dp)) }
                        IconButton(
                            onClick = {
                                zoom = (zoom / 1.4f).coerceAtLeast(1f)
                                if (zoom == 1f) { panX = 0f; panY = 0f }
                            },
                            modifier = Modifier.size(28.dp).background(Cs.Surface.copy(alpha = 0.8f), RoundedCornerShape(6.dp))
                        ) { Icon(Icons.Default.Remove, "Zoom out", tint = Cs.Cyan, modifier = Modifier.size(16.dp)) }
                    }
                    Text(
                        "${clusterResult.total} indicators · ${clusterResult.clusters.size} countries",
                        color = Cs.TextFaint, fontSize = 9.sp, fontFamily = Cs.mono,
                        modifier = Modifier.align(Alignment.TopStart).padding(8.dp)
                    )
                }

                // Selected country detail
                if (selectedCluster != null) {
                    CountryDetail(selectedCluster, usingDemo) { selectedCountry = null }
                } else {
                    Text(
                        "Tap a marker for country details · pinch or drag to explore",
                        color = Cs.TextFaint, fontSize = 10.sp
                    )
                }

                intel.error?.let {
                    Text(it, color = Cs.Amber.copy(alpha = 0.8f), fontSize = 10.sp, lineHeight = 14.sp)
                }
                HonestNote(
                    buildString {
                        if (usingDemo) {
                            append("DEMO SAMPLES — documentation IPs, not real threats. ")
                        } else {
                            append("${intel.snapshot?.feedName ?: "Threat intel"} · ${intel.snapshot?.license ?: ""} · ")
                            intel.snapshot?.let { append("updated ${relativeTime(it.fetchedAtEpochMs, nowMs)}. ") }
                        }
                        append("Markers show country-level hosting locations of botnet C2 infrastructure — not attacks against this device. ")
                        if (clusterResult.unlocated > 0) append("${clusterResult.unlocated} indicators have no verified location and are not mapped.")
                    }
                )
            }
        }
    }
}

@Composable
private fun MapChip(label: String, selected: Boolean, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label, fontSize = 10.sp, maxLines = 1) },
        colors = FilterChipDefaults.filterChipColors(
            containerColor = Cs.Surface,
            labelColor = Cs.TextDim,
            selectedContainerColor = Cs.Purple.copy(alpha = 0.22f),
            selectedLabelColor = Cs.Text
        ),
        border = FilterChipDefaults.filterChipBorder(
            enabled = true, selected = selected,
            borderColor = Cs.Border, selectedBorderColor = Cs.Purple.copy(alpha = 0.6f)
        ),
        modifier = Modifier.height(30.dp)
    )
}

private data class MapRect(val left: Float, val top: Float, val width: Float, val height: Float)

private fun baseMapRect(sizeW: Float, sizeH: Float): MapRect {
    val aspect = 360.0 / (GeoIndex.LAT_TOP - GeoIndex.LAT_BOTTOM)
    val w = sizeW
    val h = (w / aspect).toFloat()
    return MapRect(0f, (sizeH - h) / 2f, w, h.coerceAtMost(sizeH))
}

private fun markerScreenPos(
    cluster: CountryThreatCluster, base: MapRect, zoom: Float, panX: Float, panY: Float,
    sizeW: Float, sizeH: Float
): Offset {
    val bx = base.left + GeoIndex.projectX(cluster.lon) * base.width
    val by = base.top + GeoIndex.projectY(cluster.lat) * base.height
    val cx = sizeW / 2f
    val cy = sizeH / 2f
    return Offset((bx - cx) * zoom + cx + panX, (by - cy) * zoom + cy + panY)
}

@Composable
private fun MapCanvas(
    world: WorldMap,
    clusters: List<CountryThreatCluster>,
    demo: Boolean,
    zoom: Float,
    panX: Float,
    panY: Float,
    selectedCountry: String?,
    onTransform: (Offset, Offset, Float) -> Unit,
    onTap: (Offset, Float, Float) -> Unit,
    onClampPan: (Float, Float) -> Unit
) {
    var canvasW by remember { mutableStateOf(1f) }
    var canvasH by remember { mutableStateOf(1f) }
    val paths = remember(world, canvasW, canvasH) {
        val base = baseMapRect(canvasW, canvasH)
        world.countries.map { country ->
            val path = Path()
            for (ring in country.rings) {
                var i = 0
                var first = true
                while (i + 1 < ring.size) {
                    val x = base.left + GeoIndex.projectX(ring[i].toDouble()) * base.width
                    val y = base.top + GeoIndex.projectY(ring[i + 1].toDouble()) * base.height
                    if (first) { path.moveTo(x, y); first = false } else path.lineTo(x, y)
                    i += 2
                }
                path.close()
            }
            country.id to path
        }
    }

    LaunchedEffect(zoom, panX, panY) { onClampPan(canvasW, canvasH) }

    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(215.dp)
            .pointerInput(Unit) {
                detectTransformGestures { centroid, pan, gestureZoom, _ ->
                    onTransform(centroid, pan, gestureZoom)
                }
            }
            .pointerInput(clusters, zoom, panX, panY) {
                detectTapGestures { pos -> onTap(pos, size.width.toFloat(), size.height.toFloat()) }
            }
    ) {
        canvasW = size.width
        canvasH = size.height
        val center = Offset(size.width / 2f, size.height / 2f)

        withTransform({
            translate(panX, panY)
            scale(zoom, zoom, center)
        }) {
            // Graticule
            val base = baseMapRect(size.width, size.height)
            for (lon in -180..180 step 30) {
                val x = base.left + GeoIndex.projectX(lon.toDouble()) * base.width
                drawLine(Cs.Border.copy(alpha = 0.25f), Offset(x, base.top), Offset(x, base.top + base.height), 0.6f)
            }
            for (lat in -30..60 step 30) {
                val y = base.top + GeoIndex.projectY(lat.toDouble()) * base.height
                drawLine(Cs.Border.copy(alpha = 0.25f), Offset(base.left, y), Offset(base.left + base.width, y), 0.6f)
            }
            for ((id, path) in paths) {
                drawPath(path, if (id == selectedCountry) Cs.SurfaceRaised else Color(0xFF0D2036))
                drawPath(path, Cs.BorderBright.copy(alpha = 0.55f), style = Stroke(0.7f))
            }
        }

        // Markers (screen-space so glow size stays readable at any zoom)
        val base = baseMapRect(size.width, size.height)
        for (cluster in clusters) {
            val pos = markerScreenPos(cluster, base, zoom, panX, panY, size.width, size.height)
            if (pos.x < -20 || pos.x > size.width + 20 || pos.y < -20 || pos.y > size.height + 20) continue
            drawThreatMarker(pos, cluster, demo, cluster.countryCode == selectedCountry)
        }
    }
}

private fun DrawScope.drawThreatMarker(
    pos: Offset,
    cluster: CountryThreatCluster,
    demo: Boolean,
    selected: Boolean
) {
    val color = when {
        demo -> Cs.Amber
        cluster.onlineCount > 0 -> Cs.Red
        else -> Cs.Amber
    }
    val r = (4f + sqrt(cluster.count.toFloat()) * 1.6f).coerceAtMost(13f).dp.toPx()
    drawCircle(
        brush = Brush.radialGradient(listOf(color.copy(alpha = 0.35f), Color.Transparent), center = pos, radius = r * 2.4f),
        radius = r * 2.4f, center = pos
    )
    drawCircle(color.copy(alpha = 0.85f), radius = r, center = pos)
    drawCircle(Cs.BackgroundDeep.copy(alpha = 0.55f), radius = r * 0.5f, center = pos)
    if (selected) {
        drawCircle(Color.White.copy(alpha = 0.9f), radius = r + 2.5.dp.toPx(), center = pos, style = Stroke(1.6.dp.toPx()))
    }
}

@Composable
private fun CountryDetail(cluster: CountryThreatCluster, demo: Boolean, onClose: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(Cs.SurfaceRaised.copy(alpha = 0.6f))
            .padding(10.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                cluster.countryName, color = Cs.Text, fontSize = 13.sp,
                fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f)
            )
            if (demo) StatusChip("Demo", Cs.Amber)
            TextButton(onClick = onClose) { Text("Close", color = Cs.TextDim, fontSize = 10.sp) }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("${cluster.count} C2 servers", color = Cs.Text, fontSize = 11.sp, fontFamily = Cs.mono)
            Text("${cluster.onlineCount} online", color = if (cluster.onlineCount > 0) Cs.Red else Cs.TextDim, fontSize = 11.sp, fontFamily = Cs.mono)
        }
        if (cluster.families.isNotEmpty()) {
            Text(
                "Families: " + cluster.families.joinToString { "${it.first} (${it.second})" },
                color = Cs.TextDim, fontSize = 10.sp
            )
        }
        cluster.samples.take(5).forEach { ind ->
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Canvas(Modifier.size(6.dp)) {
                    drawCircle(if (ind.status == "online") Cs.Red else Cs.Steel)
                }
                Text(
                    "${ind.ip}:${ind.port}", color = Cs.Text, fontSize = 10.sp, fontFamily = Cs.mono,
                    modifier = Modifier.weight(1f)
                )
                Text(ind.malware ?: "—", color = Cs.Purple, fontSize = 9.sp, fontFamily = Cs.mono)
                Text(ind.status, color = Cs.TextFaint, fontSize = 9.sp, fontFamily = Cs.mono)
            }
        }
    }
}
