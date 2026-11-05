package com.adshield.pro.globalvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.globalvpn.model.GlobalVpnSettings
import com.adshield.pro.globalvpn.model.SplitTunnelMode

@Composable
fun GlobalVpnSplitTunnel(
    settings: GlobalVpnSettings,
    apps: List<SplitApp>,
    onLoadApps: () -> Unit,
    onSetMode: (SplitTunnelMode) -> Unit,
    onToggleApp: (String) -> Unit
) {
    var showSystem by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { onLoadApps() }

    val visibleApps = apps.filter { showSystem || !it.isSystem }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item(key = "mode") {
            GlassPanel(title = "Per-app routing", subtitle = "Applied to the WireGuard tunnel on next connect") {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        SplitTunnelMode.entries.forEach { mode ->
                            FilterChip(
                                selected = settings.splitTunnelMode == mode,
                                onClick = { onSetMode(mode) },
                                label = { Text(mode.label, fontSize = 11.sp, maxLines = 1) }
                            )
                        }
                    }
                    Text(
                        when (settings.splitTunnelMode) {
                            SplitTunnelMode.OFF -> "All apps use the tunnel."
                            SplitTunnelMode.EXCLUDE_SELECTED -> "Selected apps bypass the tunnel."
                            SplitTunnelMode.INCLUDE_SELECTED -> "Only selected apps use the tunnel."
                        },
                        color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = showSystem, onCheckedChange = { showSystem = it })
                        Text("Show system apps", fontSize = 12.sp)
                    }
                }
            }
        }

        if (settings.splitTunnelMode == SplitTunnelMode.OFF) {
            item(key = "off-hint") { EmptyState("Choose Exclude or Include to pick apps.") }
        } else {
            items(visibleApps, key = { it.packageName }) { app ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(app.label, fontSize = 13.sp, maxLines = 1)
                        Text(app.packageName, fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
                    }
                    Checkbox(
                        checked = settings.splitTunnelPackages.contains(app.packageName),
                        onCheckedChange = { onToggleApp(app.packageName) }
                    )
                }
            }
        }

        item(key = "footer") { Spacer(Modifier.height(24.dp)) }
    }
}
