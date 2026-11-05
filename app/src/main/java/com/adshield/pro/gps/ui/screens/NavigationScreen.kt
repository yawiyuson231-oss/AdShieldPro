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
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AltRoute
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Directions
import androidx.compose.material.icons.filled.Flag
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.VolumeUp
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.gps.engine.GpsFrame
import com.adshield.pro.gps.geo.Geodesy
import com.adshield.pro.gps.nav.NavigationPhase
import com.adshield.pro.gps.nav.NavigationState
import com.adshield.pro.gps.routing.ManeuverType
import com.adshield.pro.gps.routing.RouteProgress
import com.adshield.pro.gps.ui.GpsAmber
import com.adshield.pro.gps.ui.GpsBackground
import com.adshield.pro.gps.ui.GpsBorder
import com.adshield.pro.gps.ui.GpsChip
import com.adshield.pro.gps.ui.GpsCyan
import com.adshield.pro.gps.ui.GpsDivider
import com.adshield.pro.gps.ui.GpsEmptyState
import com.adshield.pro.gps.ui.GpsGreen
import com.adshield.pro.gps.ui.GpsInlineNotice
import com.adshield.pro.gps.ui.GpsKeyValue
import com.adshield.pro.gps.ui.GpsPanel
import com.adshield.pro.gps.ui.GpsRed
import com.adshield.pro.gps.ui.GpsSectionTitle
import com.adshield.pro.gps.ui.GpsTextDim
import com.adshield.pro.gps.ui.GpsTextPrimary
import com.adshield.pro.gps.ui.GpsTextSecondary
import com.adshield.pro.gps.ui.GpsUiState
import com.adshield.pro.gps.ui.PlaceResult
import com.adshield.pro.gps.ui.OfflinePackUi
import kotlin.math.roundToInt

/**
 * NAVIGATION — destination search, route summary and the live turn-by-turn banner.
 *
 * The banner shows the *next maneuver computed from the real route geometry* and the remaining
 * distance/ETA from the tracker, not a countdown timer. When nothing is being navigated, the screen
 * explains what is missing (fix, route, offline graph) instead of showing an empty dashboard.
 */
@Composable
fun NavigationScreen(
    state: GpsUiState,
    frame: GpsFrame,
    navigation: NavigationState,
    progress: RouteProgress?,
    offlinePacks: List<OfflinePackUi>,
    online: Boolean,
    onSearch: (String) -> Unit,
    onClearSearch: () -> Unit,
    onPickDestination: (PlaceResult) -> Unit,
    onStop: () -> Unit,
    onReroute: () -> Unit,
    onToggleVoice: (Boolean) -> Unit,
    onTestVoice: () -> Unit,
    onLoadOfflineGraph: (OfflinePackUi) -> Unit,
    onStartBackgroundNavigation: () -> Unit,
    modifier: Modifier = Modifier
) {
    var query by rememberSaveable { mutableStateOf("") }
    val fix = frame.fix

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(GpsBackground)
            .padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item(key = "nav-search") {
            Spacer(Modifier.height(10.dp))
            GpsPanel {
                Column(Modifier.padding(12.dp)) {
                    GpsSectionTitle("Destination", accent = GpsCyan)
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = query,
                        onValueChange = { query = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("Street, city or landmark", color = GpsTextDim, fontSize = 12.sp) },
                        leadingIcon = { Icon(Icons.Default.Search, null, tint = GpsTextSecondary, modifier = Modifier.size(18.dp)) },
                        trailingIcon = {
                            if (query.isNotBlank()) {
                                IconButton(onClick = { query = ""; onClearSearch() }) {
                                    Icon(Icons.Default.Close, null, tint = GpsTextSecondary, modifier = Modifier.size(16.dp))
                                }
                            }
                        },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                        keyboardActions = KeyboardActions(onSearch = { if (query.isNotBlank()) onSearch(query) }),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = GpsTextPrimary,
                            unfocusedTextColor = GpsTextPrimary,
                            focusedBorderColor = GpsCyan,
                            unfocusedBorderColor = GpsBorder,
                            cursorColor = GpsCyan
                        )
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Button(
                            onClick = { if (query.isNotBlank()) onSearch(query) },
                            enabled = query.isNotBlank() && !state.searching,
                            colors = ButtonDefaults.buttonColors(
                                containerColor = GpsCyan,
                                contentColor = GpsBackground,
                                disabledContainerColor = GpsBorder,
                                disabledContentColor = GpsTextDim
                            ),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            if (state.searching) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(14.dp),
                                    strokeWidth = 2.dp,
                                    color = GpsBackground
                                )
                                Spacer(Modifier.width(6.dp))
                            }
                            Text("Search", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                        }
                        Spacer(Modifier.width(8.dp))
                        Text(
                            if (online) "Nominatim · OpenStreetMap · free & keyless"
                            else "Offline — search downloaded regions instead",
                            color = GpsTextDim,
                            fontSize = 9.sp
                        )
                    }
                    if (state.searchError != null) {
                        Spacer(Modifier.height(6.dp))
                        GpsInlineNotice(state.searchError, GpsAmber)
                    }
                    if (!online) {
                        Spacer(Modifier.height(6.dp))
                        GpsInlineNotice(
                            "No connection: geocoding is unavailable. Routing still works if you import an " +
                                "offline graph for this area.",
                            GpsAmber
                        )
                    }
                }
            }
        }

        if (state.searchResults.isNotEmpty()) {
            item(key = "nav-results-header") {
                GpsSectionTitle("Results (${state.searchResults.size})", accent = GpsCyan)
            }
            items(state.searchResults, key = { "${it.position.latitude}-${it.position.longitude}-${it.shortName}" }) { place ->
                DestinationRow(place = place, onClick = { onPickDestination(place) })
            }
        }

        if (state.savedPlaces.isNotEmpty() && navigation.phase == NavigationPhase.IDLE) {
            item(key = "nav-saved-header") {
                GpsSectionTitle("Saved places", accent = GpsCyan)
            }
            items(state.savedPlaces, key = { "saved-${it.id}" }) { saved ->
                DestinationRow(
                    place = PlaceResult(saved.label, saved.label, saved.position),
                    onClick = { onPickDestination(PlaceResult(saved.label, saved.label, saved.position)) }
                )
            }
        }

        item(key = "nav-banner") {
            when (navigation.phase) {
                NavigationPhase.CALCULATING, NavigationPhase.REROUTING -> GpsPanel {
                    Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = GpsCyan)
                        Spacer(Modifier.width(12.dp))
                        Text(navigation.message, color = GpsTextPrimary, fontSize = 13.sp)
                    }
                }

                NavigationPhase.FAILED -> GpsEmptyState(
                    title = "Route not available",
                    detail = state.routeError ?: navigation.message,
                    icon = Icons.Default.AltRoute,
                    accent = GpsRed,
                    action = {
                        Text(
                            navigation.failureReason?.label ?: "",
                            color = GpsAmber,
                            fontSize = 10.sp
                        )
                    }
                )

                NavigationPhase.IDLE -> GpsEmptyState(
                    title = "No active route",
                    detail = when {
                        fix == null -> "Waiting for a GPS fix. A route needs a real starting position."
                        offlinePacks.none { it.hasRoutingGraph } && !online ->
                            "Online routing needs a connection. Import an offline routing graph to navigate without one."
                        else -> "Search for a destination, or pick a saved place, to calculate a route."
                    },
                    icon = Icons.Default.Directions,
                    accent = GpsTextDim
                )

                else -> {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        TurnBanner(navigation = navigation, progress = progress, frame = frame)
                        RouteSummaryPanel(navigation = navigation, progress = progress)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = onReroute,
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = GpsBackground,
                                    contentColor = GpsCyan
                                ),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.AltRoute, null, modifier = Modifier.size(14.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Reroute", fontSize = 11.sp)
                            }
                            Button(
                                onClick = onTestVoice,
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = GpsBackground,
                                    contentColor = GpsCyan
                                ),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.VolumeUp, null, modifier = Modifier.size(14.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Test voice", fontSize = 11.sp)
                            }
                        }
                        Button(
                            onClick = onStop,
                            colors = ButtonDefaults.buttonColors(
                                containerColor = GpsRed.copy(alpha = 0.18f),
                                contentColor = GpsRed
                            ),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.Stop, null, modifier = Modifier.size(14.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("End navigation", fontSize = 12.sp)
                        }
                    }
                }
            }
        }

        item(key = "nav-flags") {
            GpsPanel {
                Column(Modifier.padding(12.dp)) {
                    GpsSectionTitle("Guidance", accent = GpsCyan)
                    Spacer(Modifier.height(6.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        GpsChip(
                            text = if (state.policy.voiceGuidance) "Voice on" else "Voice off",
                            color = if (state.policy.voiceGuidance) GpsGreen else GpsTextDim,
                            filled = state.policy.voiceGuidance
                        )
                        GpsChip(
                            text = if (state.policy.backgroundNavigation) "Background GPS" else "Foreground only",
                            color = if (state.policy.backgroundNavigation) GpsCyan else GpsTextDim
                        )
                        GpsChip(
                            text = if (navigation.isOffline) "Offline route" else navigation.providerLabel.ifBlank { "No route" },
                            color = GpsCyan
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    if (state.voiceMessage != null) {
                        GpsInlineNotice(state.voiceMessage, GpsCyan)
                        Spacer(Modifier.height(6.dp))
                    }
                    GpsKeyValue(
                        "Routing provider",
                        navigation.providerLabel.ifBlank { "—" }
                    )
                    GpsKeyValue(
                        "Offline graph",
                        offlinePacks.firstOrNull { it.hasRoutingGraph }?.name ?: "none imported"
                    )
                    GpsKeyValue(
                        "Distance to destination",
                        progress?.remainingDistanceMeters?.let { Geodesy.formatDistance(it) } ?: "—"
                    )
                }
            }
        }

        item(key = "nav-offline") {
            GpsPanel {
                Column(Modifier.padding(12.dp)) {
                    GpsSectionTitle("Offline routing", accent = GpsCyan)
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Import an .adg.gz graph built from an OpenStreetMap extract with " +
                            "tools/osm_graph_builder.py. Routing then works with no network at all.",
                        color = GpsTextDim,
                        fontSize = 10.sp,
                        lineHeight = 14.sp
                    )
                    Spacer(Modifier.height(8.dp))
                    val graphs = offlinePacks.filter { it.hasRoutingGraph }
                    if (graphs.isEmpty()) {
                        GpsInlineNotice(
                            "No routing graph imported yet. Online routing works, offline routing does not.",
                            GpsAmber
                        )
                    } else {
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            items(graphs, key = { it.id }) { pack ->
                                Button(
                                    onClick = { onLoadOfflineGraph(pack) },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = GpsBackground,
                                        contentColor = GpsCyan
                                    ),
                                    shape = RoundedCornerShape(8.dp)
                                ) {
                                    Text(pack.name, fontSize = 10.sp)
                                }
                            }
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    Button(
                        onClick = onStartBackgroundNavigation,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = GpsCyan.copy(alpha = 0.15f),
                            contentColor = GpsCyan
                        ),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Keep GPS running with the screen off", fontSize = 11.sp)
                    }
                }
            }
        }

        item(key = "nav-footer") {
            Column(Modifier.padding(vertical = 16.dp)) {
                GpsDivider()
                Spacer(Modifier.height(8.dp))
                Text(
                    "Routing: OSRM / Valhalla public instances or your own endpoint · " +
                        "Search: Nominatim · Data © OpenStreetMap contributors",
                    color = GpsTextDim,
                    fontSize = 9.sp,
                    lineHeight = 13.sp
                )
            }
        }
    }
}

@Composable
private fun DestinationRow(place: PlaceResult, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(GpsPanel.copy(alpha = 0.7f))
            .border(1.dp, GpsBorder.copy(alpha = 0.5f), RoundedCornerShape(10.dp))
            .clickable(onClick = onClick)
            .padding(11.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(Icons.Default.Flag, null, tint = GpsCyan, modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(place.shortName, color = GpsTextPrimary, fontSize = 12.sp, fontWeight = FontWeight.Medium, maxLines = 1)
            Text(place.fullName, color = GpsTextDim, fontSize = 9.sp, maxLines = 2)
        }
        Text(
            "${place.position.latitude.roundToInt()}°N",
            color = GpsTextSecondary,
            fontSize = 9.sp,
            fontFamily = FontFamily.Monospace
        )
    }
}

@Composable
private fun TurnBanner(navigation: NavigationState, progress: RouteProgress?, frame: GpsFrame) {
    val maneuver = progress?.nextManeuver ?: ManeuverType.CONTINUE
    val distance = progress?.distanceToNextManeuverMeters
    GpsPanel(accent = if (navigation.phase == NavigationPhase.OFF_ROUTE) GpsAmber else GpsCyan) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier
                        .size(46.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(GpsCyan.copy(alpha = 0.14f)),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        maneuverGlyph(maneuver),
                        color = GpsCyan,
                        fontSize = 22.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        distance?.let { Geodesy.formatDistance(it) } ?: "—",
                        color = GpsTextPrimary,
                        fontSize = 22.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        progress?.nextInstruction ?: navigation.message,
                        color = GpsTextSecondary,
                        fontSize = 12.sp,
                        maxLines = 2,
                        lineHeight = 16.sp
                    )
                }
            }
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                BannerStat("ETA", navigation.totalDurationSeconds.let { seconds ->
                    progress?.remainingSeconds?.let { Geodesy.formatDuration(it) }
                        ?: Geodesy.formatDuration(seconds)
                })
                BannerStat("Left", progress?.remainingDistanceMeters?.let { Geodesy.formatDistance(it) } ?: "—")
                BannerStat("Speed", frame.speedKmh?.let { "${it.roundToInt()} km/h" } ?: "—")
                BannerStat("To dest.", navigation.destinationLabel.take(14))
            }
            if (navigation.phase == NavigationPhase.OFF_ROUTE) {
                Spacer(Modifier.height(8.dp))
                GpsInlineNotice(navigation.message, GpsAmber)
            }
        }
    }
}

@Composable
private fun BannerStat(label: String, value: String) {
    Column {
        Text(label.uppercase(), color = GpsTextDim, fontSize = 8.sp, letterSpacing = 1.sp)
        Text(value, color = GpsTextPrimary, fontSize = 12.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun RouteSummaryPanel(navigation: NavigationState, progress: RouteProgress?) {
    GpsPanel {
        Column(Modifier.padding(12.dp)) {
            GpsSectionTitle("Route", accent = GpsCyan)
            Spacer(Modifier.height(4.dp))
            GpsKeyValue("Total distance", Geodesy.formatDistance(navigation.totalDistanceMeters))
            GpsKeyValue("Total time", Geodesy.formatDuration(navigation.totalDurationSeconds))
            GpsKeyValue(
                "Progress",
                progress?.let { "%.0f%%".format(it.fractionComplete * 100) } ?: "—"
            )
            GpsKeyValue("Provider", navigation.providerLabel.ifBlank { "—" })
            GpsKeyValue(
                "Live traffic applied",
                if (navigation.advisories.any { it.contains("traffic", ignoreCase = true) }) "yes" else "no"
            )
            if (navigation.advisories.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                navigation.advisories.take(3).forEach { advisory ->
                    Text("• $advisory", color = GpsTextDim, fontSize = 9.sp, lineHeight = 13.sp)
                }
            }
        }
    }
}

/** Plain-text arrows: readable in every font, no icon set dependency in the banner. */
private fun maneuverGlyph(maneuver: ManeuverType): String = when (maneuver) {
    ManeuverType.TURN_LEFT -> "←"
    ManeuverType.TURN_RIGHT -> "→"
    ManeuverType.TURN_SHARP_LEFT -> "⬅"
    ManeuverType.TURN_SHARP_RIGHT -> "➡"
    ManeuverType.TURN_SLIGHT_LEFT, ManeuverType.FORK_LEFT -> "↖"
    ManeuverType.TURN_SLIGHT_RIGHT, ManeuverType.FORK_RIGHT -> "↗"
    ManeuverType.UTURN -> "↺"
    ManeuverType.ROUNDABOUT, ManeuverType.EXIT_ROUNDABOUT -> "⟳"
    ManeuverType.MERGE -> "⇧"
    ManeuverType.RAMP, ManeuverType.HIGHWAY_ENTRY, ManeuverType.HIGHWAY_EXIT -> "⇗"
    ManeuverType.FERRY -> "⛴"
    ManeuverType.ARRIVE -> "⚑"
    ManeuverType.DEPART -> "▲"
    else -> "↑"
}
