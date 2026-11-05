package com.adshield.pro.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.engine.intel.FeedFetchStatus
import com.adshield.pro.engine.intel.IntelIndicator
import com.adshield.pro.engine.intel.IntelSource
import com.adshield.pro.ui.components.CyberPanel
import com.adshield.pro.ui.components.ScrollToTopButton
import com.adshield.pro.ui.components.StatusPill
import com.adshield.pro.ui.cybershield.WorldMapData
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.NavyBorder
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber
import com.adshield.pro.ui.viewmodel.CyberShieldViewModel
import com.adshield.pro.ui.viewmodel.IntelMapFilter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Threat intelligence console: feed health, sync control and the raw indicator list.
 * Every row is a real indicator downloaded from abuse.ch, with its source, status and
 * first/last-seen timestamps. Indicators without geolocation are listed here and never
 * invented onto the map.
 */
@Composable
fun IntelligenceScreen(cyberViewModel: CyberShieldViewModel) {
    val intelState by cyberViewModel.intelState.collectAsStateWithLifecycle()
    val indicators by cyberViewModel.filteredIndicators.collectAsStateWithLifecycle()
    val mapFilter by cyberViewModel.mapFilter.collectAsStateWithLifecycle()
    var query by rememberSaveable { mutableStateOf("") }
    val listState = rememberLazyListState()
    val timeFormat = remember { SimpleDateFormat("MMM d, HH:mm", Locale.US) }

    val visible = remember(indicators, query) {
        val needle = query.trim().lowercase()
        if (needle.isEmpty()) indicators
        else indicators.filter {
            it.value.lowercase().contains(needle) ||
                it.host.lowercase().contains(needle) ||
                (it.malwareFamily?.lowercase()?.contains(needle) == true) ||
                (it.country?.lowercase()?.contains(needle) == true)
        }
    }

    Box(Modifier.fillMaxSize()) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item(key = "intel-feeds", contentType = "panel") {
                CyberPanel(
                    title = "Intelligence feeds",
                    subtitle = "Public abuse.ch sources · cached for offline use",
                    trailing = {
                        if (intelState.isRefreshing) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = CyberCyan)
                        else StatusPill("${intelState.indicators.size} indicators", if (intelState.hasAnyData) EmeraldPrimary else WarningAmber)
                    }
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        IntelSource.entries.forEach { source ->
                            val feed = intelState.feedState(source)
                            val color = when (feed.status) {
                                FeedFetchStatus.OK -> if (feed.isStale) WarningAmber else EmeraldPrimary
                                FeedFetchStatus.ERROR -> AlertRed
                                FeedFetchStatus.NOT_FETCHED -> MaterialTheme.colorScheme.onSurfaceVariant
                            }
                            Column(
                                Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(Color(0xFF08182B))
                                    .border(1.dp, NavyBorder.copy(alpha = 0.6f), RoundedCornerShape(10.dp))
                                    .padding(12.dp)
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.Public, contentDescription = null, tint = color, modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.width(8.dp))
                                    Text(source.displayName, color = Color.White, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                                    Text(
                                        when (feed.status) {
                                            FeedFetchStatus.OK -> if (feed.isStale) "Stale" else "Live"
                                            FeedFetchStatus.ERROR -> "Error"
                                            FeedFetchStatus.NOT_FETCHED -> "Not fetched"
                                        },
                                        color = color, fontSize = 10.sp, fontWeight = FontWeight.Bold
                                    )
                                }
                                Text(source.description, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp)
                                Text(
                                    buildString {
                                        append("${feed.itemCount} indicator(s)")
                                        if (feed.lastFetchEpochMs > 0L) append(" · synced ${timeFormat.format(Date(feed.lastFetchEpochMs))}")
                                        if (!source.hasGeoData) append(" · no geolocation published")
                                    },
                                    color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp
                                )
                                feed.lastError?.let { error ->
                                    Text("Last error: $error", color = AlertRed, fontSize = 10.sp)
                                }
                            }
                        }
                    }
                    Spacer(Modifier.height(10.dp))
                    Button(onClick = cyberViewModel::refreshIntel, enabled = !intelState.isRefreshing, modifier = Modifier.fillMaxWidth()) {
                        Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(if (intelState.isRefreshing) "Syncing feeds…" else "Sync intelligence now")
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Feeds refresh automatically every 6 hours in the background (WorkManager, network required). " +
                            "A failed sync keeps the cached data and shows the real error above.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp
                    )
                }
            }

            item(key = "intel-filters", contentType = "controls") {
                CyberPanel(title = "Indicator browser", subtitle = "${visible.size} of ${indicators.size} shown") {
                    OutlinedTextField(
                        value = query,
                        onValueChange = { query = it },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = SkyBlueGlow) },
                        placeholder = { Text("IP, host, family or country…", fontSize = 13.sp) },
                        label = { Text("Search indicators") }
                    )
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        IntelMapFilter.entries.forEach { filter ->
                            FilterChip(
                                selected = mapFilter == filter,
                                onClick = { cyberViewModel.setMapFilter(filter) },
                                label = { Text(filter.label, fontSize = 11.sp) },
                                colors = FilterChipDefaults.filterChipColors(selectedContainerColor = ElectricBlue.copy(alpha = 0.25f), selectedLabelColor = SkyBlueGlow)
                            )
                        }
                    }
                }
            }

            if (visible.isEmpty()) {
                item(key = "intel-empty", contentType = "empty") {
                    CyberPanel(title = "No indicators", subtitle = "Real data only") {
                        Text(
                            if (!intelState.hasAnyData) "No intelligence has been downloaded yet. Tap sync above. Until real data arrives, no indicators or map markers are shown."
                            else "No indicators match the current search and filter.",
                            color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp
                        )
                    }
                }
            } else {
                items(visible, key = { it.key }, contentType = { "indicator" }) { indicator ->
                    IndicatorRow(indicator)
                }
            }
        }
        ScrollToTopButton(state = listState, modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp))
    }
}

@Composable
private fun IndicatorRow(indicator: IntelIndicator) {
    val online = indicator.status.equals("online", ignoreCase = true)
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(Color(0xFF071526))
            .border(1.dp, NavyBorder.copy(alpha = 0.6f), RoundedCornerShape(10.dp))
            .padding(12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(8.dp).clip(CircleShape).background(if (online) AlertRed else WarningAmber))
            Spacer(Modifier.width(8.dp))
            Text(indicator.host, color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(indicator.kind.label, color = CyberCyan, fontSize = 9.sp, fontWeight = FontWeight.Bold)
        }
        Text(indicator.value, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
        Spacer(Modifier.height(4.dp))
        Text(
            buildString {
                append(indicator.country?.let { "${WorldMapData.displayName(it)} ($it)" } ?: "No location data")
                indicator.malwareFamily?.let { append(" · $it") }
                indicator.port?.let { append(" · port $it") }
                indicator.status?.let { append(" · $it") }
            },
            color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp
        )
        Text(
            buildString {
                indicator.firstSeenUtc?.let { append("First seen $it") }
                indicator.lastOnlineUtc?.let { append(" · last online $it") }
            },
            color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 9.sp
        )
    }
}
