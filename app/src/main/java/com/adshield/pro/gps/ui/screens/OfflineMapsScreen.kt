package com.adshield.pro.gps.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Map
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Route
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.gps.data.GpsPreferences
import com.adshield.pro.gps.engine.GpsFrame
import com.adshield.pro.gps.geo.GeoBounds
import com.adshield.pro.gps.offline.OfflinePlanner
import com.adshield.pro.gps.ui.GpsAmber
import com.adshield.pro.gps.ui.GpsBackground
import com.adshield.pro.gps.ui.GpsBorder
import com.adshield.pro.gps.ui.GpsChip
import com.adshield.pro.gps.ui.GpsCyan
import com.adshield.pro.gps.ui.GpsEmptyState
import com.adshield.pro.gps.ui.GpsGreen
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
import com.adshield.pro.gps.ui.OfflinePackState
import com.adshield.pro.gps.ui.OfflinePackUi
import kotlin.math.roundToInt

/**
 * OFFLINE MAPS — region downloads, the routing graph and local storage.
 *
 * Two independent offline artefacts, and the screen keeps them separate because they fail
 * independently:
 *
 *  1. **map tiles** — vector tiles + style, downloaded through MapLibre's offline database;
 *  2. **routing graph** — an `.adg.gz` file built from an OSM extract, imported by the user.
 *
 * The download size shown before pressing the button is computed from real tile math and the free
 * tile server's published limits. If a request exceeds them the button is disabled with the exact
 * reason, instead of starting a download that the server would refuse.
 */
@Composable
fun OfflineMapsScreen(
    state: GpsUiState,
    frame: GpsFrame,
    online: Boolean,
    onCreatePlan: (GeoBounds, Int, Int) -> Unit,
    onAutoFit: (GeoBounds) -> Unit,
    onDownload: (String, GeoBounds, Int, Int) -> Unit,
    onUpdatePack: (OfflinePackUi) -> Unit,
    onDeletePack: (OfflinePackUi) -> Unit,
    onImportGraph: (String, android.net.Uri) -> Unit,
    onLoadGraph: (OfflinePackUi) -> Unit,
    onClearMessage: () -> Unit,
    modifier: Modifier = Modifier
) {
    val fix = frame.fix
    var regionName by remember { mutableStateOf("") }
    var radiusKm by remember { mutableStateOf(12f) }
    var minZoom by remember { mutableStateOf(11) }
    var maxZoom by remember { mutableStateOf(15) }
    var importTarget by remember { mutableStateOf(state.offlinePacks.firstOrNull()?.id) }
    var showDeleteConfirm by remember { mutableStateOf<String?>(null) }

    val bounds = remember(fix?.position, radiusKm) {
        fix?.position?.let { centre ->
            GeoBounds.around(centre, radiusKm.toDouble() * 1000.0)
        }
    }

    // Recompute the tile budget whenever the region or the zoom range changes. One keyed effect for
    // the whole screen instead of an effect inside a lazy item.
    androidx.compose.runtime.LaunchedEffect(bounds, minZoom, maxZoom) {
        if (bounds != null) onCreatePlan(bounds, minZoom, maxZoom)
    }

    val graphLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        contract = androidx.activity.result.contract.ActivityResultContracts.OpenDocument()
    ) { uri ->
        val target = importTarget
        if (uri != null && target != null) onImportGraph(target, uri)
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(GpsBackground)
            .padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item(key = "offline-new") {
            Spacer(Modifier.height(10.dp))
            GpsPanel {
                Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        GpsSectionTitle("Download a region", accent = GpsCyan, modifier = Modifier.weight(1f))
                        GpsChip(text = if (online) "ONLINE" else "OFFLINE", color = if (online) GpsGreen else GpsAmber)
                    }
                    Spacer(Modifier.height(8.dp))
                    if (fix == null) {
                        GpsInlineNotice(
                            "A GPS fix is needed to centre a region on you. You can still download a region " +
                                "after the map has a position.",
                            GpsAmber
                        )
                    } else {
                        androidx.compose.material3.OutlinedTextField(
                            value = regionName,
                            onValueChange = { regionName = it },
                            modifier = Modifier.fillMaxWidth(),
                            placeholder = { Text("Region name (e.g. Home – Bulacan)", color = GpsTextDim, fontSize = 11.sp) },
                            singleLine = true,
                            colors = androidx.compose.material3.OutlinedTextFieldDefaults.colors(
                                focusedTextColor = GpsTextPrimary,
                                unfocusedTextColor = GpsTextPrimary,
                                focusedBorderColor = GpsCyan,
                                unfocusedBorderColor = GpsBorder
                            )
                        )
                        Spacer(Modifier.height(8.dp))
                        Text("Radius", color = GpsTextSecondary, fontSize = 10.sp)
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            items(listOf(2f, 5f, 12f, 25f, 50f), key = { it }) { radius ->
                                Box(
                                    Modifier
                                        .clip(RoundedCornerShape(7.dp))
                                        .background(if (radiusKm == radius) GpsCyan.copy(alpha = 0.2f) else GpsBackground)
                                        .border(
                                            1.dp,
                                            if (radiusKm == radius) GpsCyan else GpsBorder,
                                            RoundedCornerShape(7.dp)
                                        )
                                        .clickable { radiusKm = radius }
                                        .padding(horizontal = 10.dp, vertical = 5.dp)
                                ) {
                                    Text(
                                        "${radius.roundToInt()} km",
                                        color = if (radiusKm == radius) GpsCyan else GpsTextSecondary,
                                        fontSize = 10.sp
                                    )
                                }
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                        Text("Detail (max zoom)", color = GpsTextSecondary, fontSize = 10.sp)
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            items(listOf(13 to "Streets", 15 to "Detailed", 16 to "Buildings", 17 to "Max"), key = { it.first }) { pair ->
                                Box(
                                    Modifier
                                        .clip(RoundedCornerShape(7.dp))
                                        .background(if (maxZoom == pair.first) GpsCyan.copy(alpha = 0.2f) else GpsBackground)
                                        .border(
                                            1.dp,
                                            if (maxZoom == pair.first) GpsCyan else GpsBorder,
                                            RoundedCornerShape(7.dp)
                                        )
                                        .clickable {
                                            maxZoom = pair.first
                                            minZoom = (pair.first - 4).coerceAtLeast(8)
                                        }
                                        .padding(horizontal = 10.dp, vertical = 5.dp)
                                ) {
                                    Text(
                                        "z${pair.first} ${pair.second}",
                                        color = if (maxZoom == pair.first) GpsCyan else GpsTextSecondary,
                                        fontSize = 10.sp
                                    )
                                }
                            }
                        }
                        if (bounds != null) {
                            Spacer(Modifier.height(10.dp))
                            val plan = state.offlinePlan
                            if (plan != null) {
                                GpsKeyValue("Area", "%.0f km²".format(bounds.approximateAreaKm2))
                                GpsKeyValue("Zoom range", "z${plan.minZoom} – z${plan.maxZoom}")
                                GpsKeyValue("Tiles", "%,d".format(plan.tileCount))
                                GpsKeyValue("Estimated size", "%.1f MB".format(plan.estimatedBytes / (1024.0 * 1024.0)))
                                GpsKeyValue(
                                    "Within free limits",
                                    if (plan.withinLimits) "yes" else "no",
                                    valueColor = if (plan.withinLimits) GpsGreen else GpsRed
                                )
                                if (!plan.withinLimits && plan.limitReason != null) {
                                    Spacer(Modifier.height(6.dp))
                                    GpsInlineNotice(plan.limitReason, GpsRed)
                                    Spacer(Modifier.height(6.dp))
                                    Button(
                                        onClick = { onAutoFit(bounds) },
                                        colors = ButtonDefaults.buttonColors(
                                            containerColor = GpsBackground,
                                            contentColor = GpsCyan
                                        ),
                                        shape = RoundedCornerShape(8.dp)
                                    ) {
                                        Text("Auto-fit to the tile budget", fontSize = 11.sp)
                                    }
                                }
                            }
                            Spacer(Modifier.height(10.dp))
                            Button(
                                onClick = {
                                    onDownload(regionName.ifBlank { "Region ${radiusKm.roundToInt()}km" }, bounds, minZoom, maxZoom)
                                },
                                enabled = online && (state.offlinePlan?.withinLimits == true),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = GpsCyan,
                                    contentColor = GpsBackground,
                                    disabledContainerColor = GpsBorder,
                                    disabledContentColor = GpsTextDim
                                ),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Icon(Icons.Default.CloudDownload, null, modifier = Modifier.size(15.dp))
                                Spacer(Modifier.width(7.dp))
                                Text(
                                    if (online) "Download region" else "Offline — cannot download tiles",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        OfflinePlanner.policyLine(),
                        color = GpsTextDim,
                        fontSize = 9.sp,
                        lineHeight = 13.sp
                    )
                }
            }
        }

        if (state.offlineMessage != null) {
            item(key = "offline-message") {
                Column {
                    GpsInlineNotice(
                        state.offlineMessage,
                        if (state.offlineError) GpsRed else GpsGreen
                    )
                    Text(
                        "dismiss",
                        color = GpsTextDim,
                        fontSize = 9.sp,
                        modifier = Modifier.clickable { onClearMessage() }.padding(top = 4.dp)
                    )
                }
            }
        }

        item(key = "offline-import") {
            GpsPanel {
                Column(Modifier.padding(12.dp)) {
                    GpsSectionTitle("Routing graph (offline navigation)", accent = GpsCyan)
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Offline routing needs an .adg.gz graph built from an OpenStreetMap extract with " +
                            "tools/osm_graph_builder.py. It is a real road graph: intersections, road " +
                            "lengths and speed limits. Import once per area; routing then needs no network.",
                        color = GpsTextDim,
                        fontSize = 9.sp,
                        lineHeight = 13.sp
                    )
                    Spacer(Modifier.height(8.dp))
                    if (state.offlinePacks.isEmpty()) {
                        GpsInlineNotice("Download a region first, then attach a routing graph to it.", GpsAmber)
                    } else {
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            items(state.offlinePacks, key = { it.id }) { pack ->
                                Box(
                                    Modifier
                                        .clip(RoundedCornerShape(7.dp))
                                        .background(
                                            if (importTarget == pack.id) GpsCyan.copy(alpha = 0.2f) else GpsBackground
                                        )
                                        .border(
                                            1.dp,
                                            if (importTarget == pack.id) GpsCyan else GpsBorder,
                                            RoundedCornerShape(7.dp)
                                        )
                                        .clickable { importTarget = pack.id }
                                        .padding(horizontal = 10.dp, vertical = 5.dp)
                                ) {
                                    Text(
                                        pack.name,
                                        color = if (importTarget == pack.id) GpsCyan else GpsTextSecondary,
                                        fontSize = 10.sp,
                                        maxLines = 1
                                    )
                                }
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                        Button(
                            onClick = { graphLauncher.launch(arrayOf("*/*")) },
                            enabled = importTarget != null,
                            colors = ButtonDefaults.buttonColors(
                                containerColor = GpsBackground,
                                contentColor = GpsCyan,
                                disabledContentColor = GpsTextDim
                            ),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Icon(Icons.Default.UploadFile, null, modifier = Modifier.size(15.dp))
                            Spacer(Modifier.width(7.dp))
                            Text("Import .adg.gz graph", fontSize = 11.sp)
                        }
                    }
                }
            }
        }

        if (state.offlinePacks.isEmpty()) {
            item(key = "offline-empty") {
                GpsEmptyState(
                    title = "No offline regions",
                    detail = "Nothing is downloaded yet. Map tiles, road rendering and offline search all " +
                        "work from a downloaded region; offline routing additionally needs a graph.",
                    icon = Icons.Default.Map,
                    accent = GpsGrey
                )
            }
        } else {
            item(key = "offline-packs-header") {
                GpsSectionTitle("Downloaded regions (${state.offlinePacks.size})", accent = GpsCyan)
            }
            items(state.offlinePacks, key = { it.id }, contentType = { "pack" }) { pack ->
                OfflinePackRow(
                    pack = pack,
                    online = online,
                    confirmingDelete = showDeleteConfirm == pack.id,
                    onUpdate = { onUpdatePack(pack) },
                    onDeleteRequest = { showDeleteConfirm = pack.id },
                    onDeleteConfirm = {
                        showDeleteConfirm = null
                        onDeletePack(pack)
                    },
                    onLoadGraph = { onLoadGraph(pack) }
                )
            }
        }

        item(key = "offline-footer") {
            Column(Modifier.padding(vertical = 16.dp)) {
                GpsKeyValue("Map engine", "MapLibre Native (BSD-2), OpenGL ES backend")
                GpsKeyValue("Tile data", "OpenStreetMap via OpenFreeMap, OpenMapTiles schema")
                GpsKeyValue("Routing", "on-device A* over the imported graph")
                GpsKeyValue("Evidence for buildings", "source layer 'building' with render_height")
                Spacer(Modifier.height(8.dp))
                Text(
                    "Map data updates when you refresh a pack (MapLibre invalidate). There is no silent " +
                        "background tile download: every megabyte is a user action.",
                    color = GpsTextDim,
                    fontSize = 9.sp,
                    lineHeight = 13.sp
                )
            }
        }
    }
}

@Composable
private fun OfflinePackRow(
    pack: OfflinePackUi,
    online: Boolean,
    confirmingDelete: Boolean,
    onUpdate: () -> Unit,
    onDeleteRequest: () -> Unit,
    onDeleteConfirm: () -> Unit,
    onLoadGraph: () -> Unit
) {
    val stateColor = when (pack.state) {
        OfflinePackState.READY -> GpsGreen
        OfflinePackState.DOWNLOADING -> GpsCyan
        OfflinePackState.QUEUED -> GpsAmber
        OfflinePackState.PAUSED -> GpsAmber
        OfflinePackState.FAILED -> GpsRed
    }
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(GpsBackground)
            .border(1.dp, GpsBorder.copy(alpha = 0.7f), RoundedCornerShape(10.dp))
            .padding(11.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Map, null, tint = stateColor, modifier = Modifier.size(15.dp))
            Spacer(Modifier.width(8.dp))
            Text(
                pack.name,
                color = GpsTextPrimary,
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium,
                modifier = Modifier.weight(1f),
                maxLines = 1
            )
            GpsChip(text = pack.state.name, color = stateColor)
        }
        Spacer(Modifier.height(6.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .weight(1f)
                    .height(5.dp)
                    .clip(RoundedCornerShape(3.dp))
                    .background(GpsBorder.copy(alpha = 0.5f))
            ) {
                Box(
                    Modifier
                        .fillMaxWidth(if (pack.state == OfflinePackState.READY) 1f else pack.progress)
                        .height(5.dp)
                        .background(stateColor, RoundedCornerShape(3.dp))
                )
            }
            Spacer(Modifier.width(8.dp))
            Text(
                if (pack.state == OfflinePackState.READY) "complete" else "${(pack.progress * 100).roundToInt()}%",
                color = GpsTextSecondary,
                fontSize = 9.sp,
                fontFamily = FontFamily.Monospace
            )
        }
        Spacer(Modifier.height(6.dp))
        Text(
            "z${pack.minZoom}–z${pack.maxZoom} · %.1f MB · %,d/%,d resources".format(
                pack.bytesDownloaded / (1024.0 * 1024.0),
                pack.completedResources,
                pack.requiredResources
            ),
            color = GpsTextSecondary,
            fontSize = 9.sp
        )
        Text(
            "area %.0f km² · style %s".format(
                pack.bounds.approximateAreaKm2,
                pack.styleUrl.substringAfterLast('/').ifBlank { "custom" }
            ),
            color = GpsTextDim,
            fontSize = 9.sp
        )
        if (pack.error != null) {
            Spacer(Modifier.height(4.dp))
            Text(pack.error, color = GpsRed, fontSize = 9.sp)
        }
        Spacer(Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Default.Route,
                null,
                tint = if (pack.hasRoutingGraph) GpsGreen else GpsGrey,
                modifier = Modifier.size(12.dp)
            )
            Spacer(Modifier.width(5.dp))
            Text(
                if (pack.hasRoutingGraph) {
                    "routing graph %.1f MB".format(pack.graphBytes / (1024.0 * 1024.0))
                } else {
                    "no routing graph (online routing only)"
                },
                color = if (pack.hasRoutingGraph) GpsGreen else GpsTextDim,
                fontSize = 9.sp,
                modifier = Modifier.weight(1f)
            )
            if (pack.hasRoutingGraph) {
                Text(
                    "load",
                    color = GpsCyan,
                    fontSize = 9.sp,
                    modifier = Modifier.clickable(onClick = onLoadGraph).padding(4.dp)
                )
            }
        }
        Spacer(Modifier.height(6.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = onUpdate,
                enabled = online && pack.mapLibreRegionId != null,
                colors = ButtonDefaults.buttonColors(
                    containerColor = GpsBackground,
                    contentColor = GpsCyan,
                    disabledContentColor = GpsTextDim
                ),
                shape = RoundedCornerShape(8.dp)
            ) {
                Icon(Icons.Default.Refresh, null, modifier = Modifier.size(13.dp))
                Spacer(Modifier.width(5.dp))
                Text("Refresh", fontSize = 10.sp)
            }
            if (!confirmingDelete) {
                Button(
                    onClick = onDeleteRequest,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = GpsRed.copy(alpha = 0.14f),
                        contentColor = GpsRed
                    ),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Icon(Icons.Default.Delete, null, modifier = Modifier.size(13.dp))
                    Spacer(Modifier.width(5.dp))
                    Text("Delete", fontSize = 10.sp)
                }
            } else {
                Button(
                    onClick = onDeleteConfirm,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = GpsRed,
                        contentColor = GpsBackground
                    ),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("Confirm delete", fontSize = 10.sp)
                }
            }
        }
    }
}

/** Exposed for the host screen so the tile budget is visible before a download is queued. */
fun tileBudgetLabel(): String =
    "%,d tiles / %d MB per pack".format(
        GpsPreferences.MAX_OFFLINE_TILES_PER_PACK,
        GpsPreferences.MAX_OFFLINE_BYTES_PER_PACK / (1024 * 1024)
    )
