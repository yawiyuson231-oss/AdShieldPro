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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.globalvpn.model.ConnectionHistoryEntry
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun GlobalVpnHistory(
    history: List<ConnectionHistoryEntry>,
    onClear: () -> Unit
) {
    val formatter = remember { SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()) }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item(key = "header") {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text("Connection history", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                OutlinedButton(onClick = onClear, enabled = history.isNotEmpty()) { Text("Clear") }
            }
        }

        if (history.isEmpty()) {
            item(key = "empty") { EmptyState("No connections recorded yet.") }
        }

        items(history, key = { it.id }) { entry ->
            GlassPanel(title = entry.serverName, subtitle = "${entry.provider.label} · ${entry.protocol.label} · ${entry.countryCode}") {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        "Started ${formatter.format(Date(entry.startedAtEpochMs))}" +
                            (entry.endedAtEpochMs?.let { " · ended ${formatter.format(Date(it))}" } ?: " · ongoing"),
                        fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "↓ ${formatBytes(entry.rxBytes)} · ↑ ${formatBytes(entry.txBytes)} · ${entry.outcome}",
                        fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        item(key = "footer") { Spacer(Modifier.height(24.dp)) }
    }
}
