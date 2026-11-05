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
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.globalvpn.engine.ServerScorer
import com.adshield.pro.globalvpn.model.GlobalVpnSettings
import com.adshield.pro.globalvpn.model.GlobalVpnState
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber
import kotlinx.coroutines.delay

@Composable
fun GlobalVpnDashboard(
    state: GlobalVpnState,
    settings: GlobalVpnSettings,
    scored: List<ServerScorer.ScoredServer>,
    onConnect: () -> Unit,
    onConnectFastest: () -> Unit,
    onOpenServers: () -> Unit,
    onOpenProviders: () -> Unit
) {
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(state.isConnected) {
        while (state.isConnected) {
            now = System.currentTimeMillis()
            delay(1000)
        }
    }

    val countryCodes = scored.map { it.server.countryCode }.distinct()
    val accent = phaseColor(state.phase)

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item(key = "globe") {
            GlassPanel(
                title = "Global tunnel",
                subtitle = state.server?.let { "${it.displayName} · ${it.provider.label}" }
                    ?: "No server selected — choose one or use Fastest"
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                    GlobalGlobe(
                        phase = state.phase,
                        serverCountryCodes = countryCodes,
                        connectedCountryCode = state.server?.countryCode,
                        modifier = Modifier.fillMaxWidth().height(220.dp)
                    )
                    Spacer(Modifier.height(8.dp))
                    ConnectButton(phase = state.phase, onClick = onConnect)
                    Spacer(Modifier.height(10.dp))
                    Text(phaseLabel(state.phase), color = accent, fontWeight = FontWeight.Bold, letterSpacing = 1.sp, fontSize = 14.sp)
                    Text(
                        text = state.errorMessage ?: state.statusNote ?: "Tap connect to start a real WireGuard tunnel.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 12.sp,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }
        }

        item(key = "stats") {
            GlassPanel(title = "Live connection", subtitle = "Real counters from the WireGuard engine") {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        StatTile("Public IP", state.tunnelPublicIp ?: state.baselinePublicIp ?: "—", Modifier.weight(1f))
                        StatTile("Ping", state.latencyMs?.let { "$it ms" } ?: "—", Modifier.weight(1f))
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        StatTile("Download", formatRate(state.rxBytesPerSec), Modifier.weight(1f), EmeraldPrimary)
                        StatTile("Upload", formatRate(state.txBytesPerSec), Modifier.weight(1f), SkyBlueGlow)
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        StatTile("Duration", formatDuration(state.connectedSinceEpochMs), Modifier.weight(1f))
                        StatTile(
                            "Health", "${state.healthScore}%", Modifier.weight(1f),
                            if (state.healthScore >= 70) EmeraldPrimary else WarningAmber
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        StatTile("Data down", formatBytes(state.rxBytes), Modifier.weight(1f))
                        StatTile("Data up", formatBytes(state.txBytes), Modifier.weight(1f))
                    }
                    if (state.ipChangeVerified) {
                        Text("Exit IP change verified against baseline.", color = EmeraldPrimary, fontSize = 11.sp)
                    }
                }
            }
        }

        item(key = "actions") {
            GlassPanel(title = "Quick actions") {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = onConnectFastest,
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = ElectricBlue)
                    ) { Text("Connect to fastest server") }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = onOpenServers, modifier = Modifier.weight(1f)) { Text("Browse servers") }
                        OutlinedButton(onClick = onOpenProviders, modifier = Modifier.weight(1f)) { Text("Add provider") }
                    }
                    if (!settings.killSwitch) {
                        Text(
                            "Kill switch is off. Enable it in Security for leak-free failover.",
                            color = WarningAmber, fontSize = 11.sp
                        )
                    }
                }
            }
        }

        item(key = "handoff-note") {
            Text(
                "Android allows one active VPN. Connecting Global VPN hands off from the local DNS " +
                    "filter for this session; your DNS system and its settings are not modified.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 11.sp,
                modifier = Modifier.padding(bottom = 24.dp)
            )
        }
    }
}
