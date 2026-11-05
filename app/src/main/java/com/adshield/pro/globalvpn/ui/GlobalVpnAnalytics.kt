package com.adshield.pro.globalvpn.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.globalvpn.model.ConnectionHistoryEntry
import com.adshield.pro.globalvpn.model.GlobalVpnState
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.SkyBlueGlow
import kotlinx.coroutines.delay

@Composable
fun GlobalVpnAnalytics(
    state: GlobalVpnState,
    history: List<ConnectionHistoryEntry>
) {
    val rxSamples = remember { mutableStateListOf<Long>() }
    val txSamples = remember { mutableStateListOf<Long>() }

    LaunchedEffect(state.isConnected) {
        while (state.isConnected) {
            rxSamples.add(state.rxBytesPerSec)
            txSamples.add(state.txBytesPerSec)
            if (rxSamples.size > 60) rxSamples.removeAt(0)
            if (txSamples.size > 60) txSamples.removeAt(0)
            delay(1000)
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item(key = "throughput") {
            GlassPanel(title = "Throughput (live)", subtitle = "Bytes/sec sampled from the real tunnel") {
                Column {
                    Sparkline(samples = rxSamples, color = EmeraldPrimary, modifier = Modifier.fillMaxWidth().height(70.dp))
                    Spacer(Modifier.height(6.dp))
                    Sparkline(samples = txSamples, color = SkyBlueGlow, modifier = Modifier.fillMaxWidth().height(70.dp))
                    Spacer(Modifier.height(6.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("↓ ${formatRate(state.rxBytesPerSec)}", color = EmeraldPrimary, fontSize = 12.sp)
                        Text("↑ ${formatRate(state.txBytesPerSec)}", color = SkyBlueGlow, fontSize = 12.sp)
                    }
                }
            }
        }

        item(key = "quality") {
            GlassPanel(title = "Connection quality") {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Health score: ${state.healthScore}%", fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                    Text("Handshake age: ${state.handshakeAgeMs?.let { "${it / 1000}s" } ?: "n/a"}", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(
                        "Quality estimate: " + when {
                            state.healthScore >= 80 -> "stable"
                            state.healthScore >= 50 -> "degrading"
                            state.phase.name == "CONNECTED" -> "weak"
                            else -> "offline"
                        },
                        fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text("Total received: ${formatBytes(state.rxBytes)} · sent: ${formatBytes(state.txBytes)}", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }

        item(key = "sessions") {
            GlassPanel(title = "Recent sessions", subtitle = "${history.size} recorded on-device") {
                if (history.isEmpty()) {
                    EmptyState("No sessions yet.")
                } else {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        history.take(10).forEach { entry ->
                            Text(
                                "${entry.serverName} · ${entry.provider.label} · ${formatBytes(entry.rxBytes + entry.txBytes)} · ${entry.outcome}",
                                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }

        item(key = "footer") { Spacer(Modifier.height(24.dp)) }
    }
}

@Composable
private fun Sparkline(samples: List<Long>, color: androidx.compose.ui.graphics.Color, modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        if (samples.size < 2) return@Canvas
        val max = (samples.maxOrNull() ?: 1L).coerceAtLeast(1L)
        val stepX = size.width / (samples.size - 1).toFloat()
        val path = Path()
        samples.forEachIndexed { index, value ->
            val x = index * stepX
            val y = size.height - (value.toFloat() / max.toFloat()) * size.height
            if (index == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        drawPath(path, color, style = Stroke(2f))
    }
}
