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
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.globalvpn.model.GlobalVpnSettings
import com.adshield.pro.globalvpn.model.ProviderId
import com.adshield.pro.globalvpn.model.VpnProtocol
import com.adshield.pro.ui.theme.WarningAmber

@Composable
fun GlobalVpnSettings(
    settings: GlobalVpnSettings,
    onUpdate: ((GlobalVpnSettings) -> GlobalVpnSettings) -> Unit,
    onSetProtocol: (VpnProtocol) -> Unit,
    onSetProvider: (ProviderId?) -> Unit,
    onSetCountry: (String?) -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item(key = "protocol") {
            GlassPanel(title = "VPN protocol", subtitle = "Only protocols with a real engine are connectable") {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(
                            selected = settings.protocolPreference == VpnProtocol.WIREGUARD,
                            onClick = { onSetProtocol(VpnProtocol.WIREGUARD) },
                            label = { Text("WireGuard") }
                        )
                        FilterChip(
                            selected = settings.protocolPreference == VpnProtocol.OPENVPN,
                            onClick = { onSetProtocol(VpnProtocol.OPENVPN) },
                            label = { Text("OpenVPN") }
                        )
                    }
                    if (settings.protocolPreference == VpnProtocol.OPENVPN) {
                        Text(
                            "The in-app OpenVPN engine is not bundled. OpenVPN configs from VPN Gate / " +
                                "Riseup can be exported to an OpenVPN client.",
                            color = WarningAmber, fontSize = 12.sp
                        )
                    } else {
                        Text(
                            "WireGuard via the open-source wireguard-go engine. Fast, modern, audited.",
                            color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp
                        )
                    }
                }
            }
        }

        item(key = "behavior") {
            GlassPanel(title = "Connection behavior") {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    SettingSwitch("Automatic reconnection", settings.autoReconnect) { v -> onUpdate { it.copy(autoReconnect = v) } }
                    SettingSwitch("Automatic server failover", settings.autoFailover) { v -> onUpdate { it.copy(autoFailover = v) } }
                    SettingSwitch("Block IPv6 when unsupported", settings.blockIpv6WhenUnsupported) { v -> onUpdate { it.copy(blockIpv6WhenUnsupported = v) } }
                    SettingSwitch("Battery saver (slower polling)", settings.batterySaver) { v -> onUpdate { it.copy(batterySaver = v) } }
                    SettingSwitch("Prefer fastest server automatically", settings.autoSelectFastest) { v -> onUpdate { it.copy(autoSelectFastest = v) } }
                }
            }
        }

        item(key = "preference") {
            GlassPanel(title = "Routing preference", subtitle = "Used by the adaptive scorer") {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Preferred provider", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        FilterChip(
                            selected = settings.preferredProvider == null,
                            onClick = { onSetProvider(null) },
                            label = { Text("Any") }
                        )
                        ProviderId.entries.take(3).forEach { provider ->
                            FilterChip(
                                selected = settings.preferredProvider == provider,
                                onClick = { onSetProvider(provider) },
                                label = { Text(provider.label, fontSize = 11.sp, maxLines = 1) }
                            )
                        }
                    }
                    OutlinedTextField(
                        value = settings.preferredCountryCode ?: "",
                        onValueChange = { onSetCountry(it.ifBlank { null }) },
                        label = { Text("Preferred country code (e.g. US)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }

        item(key = "footer") { Spacer(Modifier.height(24.dp)) }
    }
}

@Composable
private fun SettingSwitch(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
        Text(label, fontSize = 13.sp, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}
