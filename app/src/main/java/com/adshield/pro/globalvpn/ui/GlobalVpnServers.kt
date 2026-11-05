package com.adshield.pro.globalvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.globalvpn.engine.ServerScorer
import com.adshield.pro.globalvpn.model.GlobalVpnSettings
import com.adshield.pro.globalvpn.model.ProviderId
import com.adshield.pro.globalvpn.model.VpnServer
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber

@Composable
fun GlobalVpnServers(
    servers: List<VpnServer>,
    scored: List<ServerScorer.ScoredServer>,
    settings: GlobalVpnSettings,
    isRefreshing: Boolean,
    providerErrors: Map<ProviderId, String>,
    onRefresh: () -> Unit,
    onSelect: (String) -> Unit,
    onConnect: (String) -> Unit,
    onExport: (String) -> Unit
) {
    var query by remember { mutableStateOf("") }
    var countryFilter by remember { mutableStateOf<String?>(null) }

    val countries = servers.map { it.countryCode to it.countryName }.distinctBy { it.first }.sortedBy { it.second }
    val visible = scored.filter { scoredServer ->
        val server = scoredServer.server
        (countryFilter == null || server.countryCode == countryFilter) &&
            (query.isBlank() ||
                server.displayName.contains(query, true) ||
                server.countryName.contains(query, true) ||
                (server.city?.contains(query, true) == true))
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item(key = "header") {
            Column {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text("Server explorer", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    OutlinedButton(onClick = onRefresh, enabled = !isRefreshing) {
                        Text(if (isRefreshing) "Refreshing…" else "Refresh")
                    }
                }
                Text(
                    "${servers.size} real servers · ${servers.count { it.isConnectable }} connectable in-app",
                    color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp
                )
                providerErrors.forEach { (provider, error) ->
                    Text("${provider.label}: $error", color = WarningAmber, fontSize = 11.sp)
                }
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Search country, city or server") },
                    singleLine = true
                )
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.fillMaxWidth()) {
                    FilterChip(selected = countryFilter == null, onClick = { countryFilter = null }, label = { Text("All") })
                    countries.take(6).forEach { (code, name) ->
                        FilterChip(
                            selected = countryFilter == code,
                            onClick = { countryFilter = if (countryFilter == code) null else code },
                            label = { Text(name, maxLines = 1) }
                        )
                    }
                }
            }
        }

        if (visible.isEmpty()) {
            item(key = "empty") { EmptyState("No servers match. Import a WireGuard config or refresh discovery.") }
        }

        items(visible, key = { it.server.id }) { scoredServer ->
            ServerRow(
                scored = scoredServer,
                selected = settings.selectedServerId == scoredServer.server.id,
                onSelect = { onSelect(scoredServer.server.id) },
                onConnect = { onConnect(scoredServer.server.id) },
                onExport = { onExport(scoredServer.server.id) }
            )
        }

        item(key = "footer") { Spacer(Modifier.height(24.dp)) }
    }
}

@Composable
private fun ServerRow(
    scored: ServerScorer.ScoredServer,
    selected: Boolean,
    onSelect: () -> Unit,
    onConnect: () -> Unit,
    onExport: () -> Unit
) {
    val server = scored.server
    GlassPanel(
        title = server.displayName,
        subtitle = "${server.countryName}${server.city?.let { " · $it" } ?: ""} · ${server.provider.label} · ${server.protocol.label}",
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("Score ${scored.score}", color = SkyBlueGlow, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                server.measuredLatencyMs?.let { Text("${it} ms", color = EmeraldPrimary, fontSize = 12.sp) }
                    ?: server.reportedPingMs?.let { Text("$it ms (reported)", color = EmeraldPrimary, fontSize = 12.sp) }
                server.loadPercent?.let { Text("load $it%", color = WarningAmber, fontSize = 12.sp) }
                if (scored.trend == ServerScorer.CongestionTrend.RISING) {
                    Text("congestion ↑", color = WarningAmber, fontSize = 11.sp)
                }
            }
            if (!server.isConnectable) {
                Text(
                    server.unavailableReason ?: "Not connectable in-app.",
                    color = WarningAmber, fontSize = 11.sp
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onSelect, modifier = Modifier.weight(1f)) {
                    Text(if (selected) "Selected" else "Select")
                }
                if (server.isConnectable) {
                    Button(onClick = onConnect, modifier = Modifier.weight(1f)) { Text("Connect") }
                } else if (server.configRef != null) {
                    OutlinedButton(onClick = onExport, modifier = Modifier.weight(1f)) { Text("Export .ovpn") }
                }
            }
        }
    }
}
