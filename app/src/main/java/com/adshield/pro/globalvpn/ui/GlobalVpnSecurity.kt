package com.adshield.pro.globalvpn.ui

import android.content.Intent
import android.provider.Settings
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
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.globalvpn.model.FeatureAvailability
import com.adshield.pro.globalvpn.model.GlobalVpnSettings
import com.adshield.pro.globalvpn.model.GlobalVpnState
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.WarningAmber

@Composable
fun GlobalVpnSecurity(
    state: GlobalVpnState,
    settings: GlobalVpnSettings,
    featureMatrix: List<FeatureAvailability>,
    onToggleKillSwitch: (Boolean) -> Unit,
    onToggleLeakProtection: (Boolean) -> Unit,
    diagnostics: () -> String
) {
    val context = LocalContext.current

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item(key = "killswitch") {
            GlassPanel(title = "Kill switch", subtitle = "Block traffic if the tunnel drops") {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Text("Request kill switch", fontSize = 13.sp)
                        Switch(checked = settings.killSwitch, onCheckedChange = onToggleKillSwitch)
                    }
                    Text(
                        if (state.killSwitchActive)
                            "Active: Android Always-on VPN + lockdown is enabled."
                        else
                            "WireGuard blocking mode is on while connected, but a device-wide kill switch " +
                                "needs Android Always-on VPN with “Block connections without VPN”. Tap below to enable it.",
                        color = if (state.killSwitchActive) EmeraldPrimary else WarningAmber,
                        fontSize = 12.sp
                    )
                    OutlinedButton(
                        onClick = {
                            runCatching {
                                context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("Open Android VPN settings") }
                }
            }
        }

        item(key = "leak") {
            GlassPanel(title = "Leak protection") {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Text("Force DNS + full-tunnel routing", fontSize = 13.sp)
                        Switch(checked = settings.leakProtection, onCheckedChange = onToggleLeakProtection)
                    }
                    SecurityRow("DNS leak protection", state.dnsLeakProtected)
                    SecurityRow("IPv6 leak protection", state.ipv6LeakProtected)
                    SecurityRow("Exit IP change verified", state.ipChangeVerified)
                    Text(
                        "Baseline IP: ${state.baselinePublicIp ?: "—"} · Tunnel IP: ${state.tunnelPublicIp ?: "—"}",
                        color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp
                    )
                }
            }
        }

        item(key = "matrix-header") {
            Text("Capability honesty matrix", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        }

        items(featureMatrix, key = { it.feature }) { feature ->
            GlassPanel(title = feature.feature) {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    AvailabilityBadge(feature.status)
                    Text(feature.detail, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                }
            }
        }

        item(key = "diagnostics") {
            GlassPanel(title = "Connection diagnostics") {
                Text(
                    diagnostics(),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 11.sp,
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                )
            }
        }

        item(key = "footer") { Spacer(Modifier.height(24.dp)) }
    }
}

@Composable
private fun SecurityRow(label: String, active: Boolean) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
        Text(label, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(if (active) "On" else "Off", color = if (active) EmeraldPrimary else WarningAmber, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
    }
}
