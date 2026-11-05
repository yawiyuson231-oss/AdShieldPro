package com.adshield.pro.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.FavoriteBorder
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.ui.components.CyberPanel
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.EmeraldGlow
import com.adshield.pro.ui.theme.NavyBorder
import com.adshield.pro.ui.theme.TextSecondaryDark
import com.adshield.pro.ui.theme.WarningAmber
import com.adshield.pro.ui.viewmodel.VpnViewModel
import com.adshield.pro.vpn.CountryList
import com.adshield.pro.vpn.FeatureStatus
import com.adshield.pro.vpn.VpnConnectionState
import com.adshield.pro.vpn.VpnServer
import com.adshield.pro.vpn.VpnServerSelection
import com.adshield.pro.vpn.VpnThreatEvent
import java.util.UUID

/**
 * CyberShield AI — Global VPN dashboard, styled after the reference console
 * (docs/images/cybershield-vpn-reference.jpg): dark navy, glowing blue shield core,
 * severity colors, live panels. Every number shown is real or explicitly empty.
 */
@Composable
fun VpnScreen(viewModel: VpnViewModel) {
    val connectionState by viewModel.connectionState.collectAsStateWithLifecycle()
    val activeServer by viewModel.activeServer.collectAsStateWithLifecycle()
    val stats by viewModel.stats.collectAsStateWithLifecycle()
    val status by viewModel.lastFeatureStatus.collectAsStateWithLifecycle()
    val servers by viewModel.displayServers.collectAsStateWithLifecycle()
    val threats by viewModel.threats.collectAsStateWithLifecycle()

    var showAdd by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item { VpnControlCenter(connectionState, activeServer, stats, status, servers, viewModel) }
        item { VpnMapPanel(servers, activeServer, viewModel) }
        item { VpnIntelligencePanel(servers, viewModel) }
        item { VpnThreatCenter(threats, viewModel) }
        item { VpnPrivacyPanel(stats, viewModel) }
        item { VpnFeatureStatusPanel() }
        item { Spacer(Modifier.height(8.dp)) }
    }

    if (showAdd) AddServerDialog(onDismiss = { showAdd = false }, onAdd = { server ->
        viewModel.addServer(server); showAdd = false
    })
    if (showImport) ImportConfigDialog(
        onDismiss = { showImport = false },
        onImport = { text ->
            val error = viewModel.importWireGuardConfig(text)
            if (error == null) showImport = false
            error
        }
    )
}

@Composable
private fun StatusBadge(state: VpnConnectionState) {
    val (label, color) = when (state) {
        VpnConnectionState.CONNECTED -> "CONNECTED" to EmeraldGlow
        VpnConnectionState.CONNECTING -> "CONNECTING…" to CyberCyan
        VpnConnectionState.FAILED -> "FAILED" to AlertRed
        VpnConnectionState.DISCONNECTED -> "DISCONNECTED" to TextSecondaryDark
    }
    Text(label, color = color, fontSize = 11.sp, fontWeight = FontWeight.Bold,
        modifier = Modifier.background(color.copy(alpha = 0.15f), RoundedCornerShape(8.dp)).padding(horizontal = 8.dp, vertical = 4.dp))
}

@Composable
private fun VpnControlCenter(
    state: VpnConnectionState, server: VpnServer?, stats: com.adshield.pro.vpn.VpnStats,
    status: FeatureStatus?, servers: List<VpnServer>, viewModel: VpnViewModel
) {
    CyberPanel(title = "Global VPN Control Center", subtitle = "Single shared VPNService — coordinated with DNS, never competing") {
        Row(verticalAlignment = Alignment.CenterVertically) {
            GlowingShield(connected = state == VpnConnectionState.CONNECTED)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                StatusBadge(state)
                Spacer(Modifier.height(4.dp))
                Text(
                    server?.let { "${it.city}, ${it.country} — ${it.host}:${it.port}" } ?: "No server selected",
                    fontSize = 12.sp, color = TextSecondaryDark, maxLines = 1
                )
                Text(
                    "Public IP: ${stats.publicIp ?: "not verified"}",
                    fontSize = 11.sp, color = if (stats.publicIp != null) CyberCyan else WarningAmber, maxLines = 1
                )
                Text(
                    "Kill switch: ${if (stats.killSwitchActive) "ACTIVE (blocking mode)" else "OFF"} • ${if (state == VpnConnectionState.CONNECTED) "tunnel up — encrypted forwarding active only with a configured server profile" else "no tunnel"}",
                    fontSize = 10.sp, color = TextSecondaryDark, maxLines = 1
                )
            }
        }
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (state == VpnConnectionState.CONNECTED) {
                OutlinedButton(onClick = { viewModel.disconnect() }) { Text("DISCONNECT", fontSize = 11.sp, color = AlertRed) }
            } else {
                OutlinedButton(onClick = { servers.firstOrNull()?.let { viewModel.connect(it) } }, enabled = servers.isNotEmpty()) {
                    Text("CONNECT", fontSize = 11.sp, color = EmeraldGlow)
                }
            }
            OutlinedButton(onClick = { viewModel.fastest() }, enabled = servers.isNotEmpty()) {
                Icon(Icons.Default.Speed, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(14.dp))
                Spacer(Modifier.width(4.dp)); Text("FASTEST", fontSize = 11.sp)
            }
            OutlinedButton(onClick = { viewModel.probeServers() }) {
                Icon(Icons.Default.Refresh, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(14.dp))
                Spacer(Modifier.width(4.dp)); Text("PING ALL", fontSize = 11.sp)
            }
            OutlinedButton(onClick = { viewModel.checkIp() }) { Text("VERIFY IP", fontSize = 11.sp) }
        }
        if (status != null && status != FeatureStatus.WORKING) {
            Spacer(Modifier.height(6.dp))
            Text("Last operation status: ${status.label}", color = WarningAmber, fontSize = 11.sp)
        }
        if (servers.isEmpty()) {
            Spacer(Modifier.height(6.dp))
            Text("No VPN servers configured — add a real endpoint below. Nothing is simulated.", color = WarningAmber, fontSize = 11.sp)
        }
    }
}

/**
 * Interactive globe: pinch to zoom, drag to pan, tap a pin to connect.
 * Pins are real configured servers at deterministic positions — zoom never invents data.
 */
@Composable
private fun ZoomableGlobe(
    servers: List<VpnServer>,
    activeId: String?,
    onPinTap: (VpnServer) -> Unit,
    modifier: Modifier = Modifier
) {
    var scale by remember { mutableFloatStateOf(1f) }
    var offsetX by remember { mutableFloatStateOf(0f) }
    var offsetY by remember { mutableFloatStateOf(0f) }
    Box(modifier = modifier) {
        Canvas(
            Modifier.fillMaxSize().pointerInput(Unit) {
                detectTransformGestures { _, pan, zoom, _ ->
                    scale = (scale * zoom).coerceIn(1f, 5f)
                    if (scale > 1f) {
                        offsetX += pan.x; offsetY += pan.y
                    } else {
                        offsetX = 0f; offsetY = 0f
                    }
                }
            }.pointerInput(Unit) {
                detectTapGestures { tap ->
                    val gx = (tap.x - offsetX - size.width / 2f) / (size.width / 2f * scale) + 0.5f
                    val gy = (tap.y - offsetY - size.height / 2f) / (size.height / 2f * scale) + 0.5f
                    val hit = VpnServerSelection.nearestPin(servers, gx.coerceIn(0f, 1f), gy.coerceIn(0f, 1f))
                    if (hit != null) onPinTap(hit)
                }
            }
        ) {
            val cx = size.width / 2f; val cy = size.height / 2f
            val step = 26.dp.toPx() * scale
            var gy = offsetY % step
            while (gy < size.height) {
                var gx = offsetX % step
                while (gx < size.width) {
                    drawCircle(Color(0xFF12365A), 1.2.dp.toPx() * scale, Offset(gx, gy))
                    gx += step
                }
                gy += step
            }
            drawArc(
                color = NavyBorder, startAngle = 0f, sweepAngle = 360f,
                useCenter = false, style = Stroke(1.dp.toPx()),
                size = androidx.compose.ui.geometry.Size(size.width * scale, size.height * scale),
                topLeft = Offset(cx - size.width * scale / 2f + offsetX, cy - size.height * scale / 2f + offsetY)
            )
            servers.forEach { s ->
                val (nx, ny) = VpnServerSelection.globePin(s.id)
                val px = cx + (nx - 0.5f) * size.width * scale + offsetX
                val py = cy + (ny - 0.5f) * size.height * scale + offsetY
                val isActive = s.id == activeId
                if (isActive) drawCircle(EmeraldGlow.copy(alpha = 0.3f), 14.dp.toPx() * scale, Offset(px, py))
                drawCircle(
                    if (isActive) EmeraldGlow else CyberCyan,
                    (if (isActive) 6f else 4f).dp.toPx() * scale, Offset(px, py)
                )
            }
        }
        if (servers.isEmpty()) {
            Text("No servers yet — tap + to add a real VPN endpoint.",
                color = TextSecondaryDark, fontSize = 11.sp, modifier = Modifier.align(Alignment.Center).padding(8.dp))
        }
        Text(
            "pinch to zoom • tap a pin to connect",
            color = TextSecondaryDark, fontSize = 9.sp,
            modifier = Modifier.align(Alignment.BottomEnd).padding(6.dp)
        )
    }
}

/** Glowing shield core in the reference style — animates only while connected. */
@Composable
private fun GlowingShield(connected: Boolean) {
    val color = if (connected) CyberCyan else TextSecondaryDark
    Canvas(modifier = Modifier.size(84.dp)) {
        val cx = size.width / 2
        val cy = size.height / 2
        drawCircle(
            brush = Brush.radialGradient(listOf(color.copy(alpha = 0.35f), Color.Transparent)),
            radius = size.width / 2
        )
        drawCircle(color = color.copy(alpha = 0.9f), radius = size.width / 2.4f, style = Stroke(2.dp.toPx()))
        val shield = Path().apply {
            moveTo(cx, cy - 22f)
            lineTo(cx + 16f, cy - 14f)
            lineTo(cx + 16f, cy + 4f)
            lineTo(cx, cy + 20f)
            lineTo(cx - 16f, cy + 4f)
            lineTo(cx - 16f, cy - 14f)
            close()
        }
        drawPath(shield, color = color, style = Stroke(2.5.dp.toPx(), cap = StrokeCap.Round))
    }
}

/** Stylized world panel: server pins by region + real measured latency. No fake attack map. */
@Composable
private fun VpnMapPanel(servers: List<VpnServer>, active: VpnServer?, viewModel: VpnViewModel) {
    var showAdd by remember { mutableStateOf(false) }
    var showImport by remember { mutableStateOf(false) }
    CyberPanel(
        title = "Global Network Map", subtitle = "Real server endpoints you configured — tap a pin to connect",
        trailing = {
            IconButton(onClick = { showImport = true }) { Icon(Icons.Default.VpnKey, contentDescription = "Import WireGuard config", tint = CyberCyan) }
            IconButton(onClick = { showAdd = true }) { Icon(Icons.Default.Add, contentDescription = "Add server", tint = CyberCyan) }
        }
    ) {
        ZoomableGlobe(
            servers = servers,
            activeId = active?.id,
            onPinTap = { server -> viewModel.connect(server) },
            modifier = Modifier.fillMaxWidth().height(180.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(Color(0xFF040C17))
                .border(1.dp, NavyBorder, RoundedCornerShape(12.dp))
        )
        Spacer(Modifier.height(8.dp))
        servers.forEach { server ->
            Row(
                modifier = Modifier.fillMaxWidth().clickable { viewModel.connect(server) }.padding(vertical = 5.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Default.Public, contentDescription = null,
                    tint = if (server.id == active?.id) EmeraldGlow else CyberCyan, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(8.dp))
                Column(Modifier.weight(1f)) {
                    Text("${server.city}, ${server.country} — ${server.name}", fontSize = 12.sp, maxLines = 1)
                    Text(
                        "${server.protocol} • ${server.host}:${server.port} • latency ${server.measuredLatencyMs?.let { "$it ms" } ?: "not measured"}" +
                            (server.loadPercent?.let { " • load $it%" } ?: ""),
                        fontSize = 10.sp, color = TextSecondaryDark, maxLines = 1
                    )
                }
                IconButton(onClick = { viewModel.toggleFavorite(server.id) }) {
                    Icon(if (server.isFavorite) Icons.Default.Favorite else Icons.Default.FavoriteBorder,
                        contentDescription = "Favorite", tint = WarningAmber, modifier = Modifier.size(16.dp))
                }
            }
        }
    }
}

/** Global country browser: every country present in the catalog, each with its real fastest node. */
@Composable
private fun VpnCountryPanel(servers: List<VpnServer>, viewModel: VpnViewModel) {
    val countries = com.adshield.pro.vpn.VpnServerSelection.countriesOf(servers)
    CyberPanel(title = "All Countries", subtitle = "${CountryList.ALL.size} countries supported in the picker • ${countries.size} with your servers") {
        if (countries.isEmpty()) {
            Text("Add servers from any of the ${CountryList.ALL.size} countries via the + button on the map.",
                color = TextSecondaryDark, fontSize = 11.sp)
        }
        countries.forEach { country ->
            val best = com.adshield.pro.vpn.VpnServerSelection.fastestInCountry(servers, country)
            Row(
                modifier = Modifier.fillMaxWidth().clickable {
                    best?.let { viewModel.connect(it) }
                }.padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Default.Public, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(14.dp))
                Spacer(Modifier.width(8.dp))
                Text(country, fontSize = 12.sp, modifier = Modifier.weight(1f))
                Text(
                    best?.let { "fastest ${it.city} ${it.measuredLatencyMs} ms" } ?: "no measured node",
                    fontSize = 10.sp, color = if (best != null) EmeraldGlow else TextSecondaryDark
                )
            }
        }
    }
}

@Composable
private fun VpnIntelligencePanel(servers: List<VpnServer>, viewModel: VpnViewModel) {
    val fastest = com.adshield.pro.vpn.VpnServerSelection.fastest(servers)
    CyberPanel(title = "VPN Intelligence", subtitle = "Latency-based routing from real probes") {
        Text(
            fastest?.let { "Fastest measured: ${it.city}, ${it.country} (${it.measuredLatencyMs} ms)" }
                ?: "Fastest server: unknown until a probe succeeds",
            fontSize = 12.sp, color = if (fastest != null) EmeraldGlow else TextSecondaryDark
        )
        Spacer(Modifier.height(4.dp))
        Text(
            "Auto failover / reconnection: the shared VpnService is START_STICKY and blocks traffic while down (kill switch). Multi-hop, QUIC/MASQUE and obfuscation: NOT IMPLEMENTED on this build.",
            fontSize = 10.sp, color = TextSecondaryDark
        )
    }
}

@Composable
private fun VpnThreatCenter(threats: List<VpnThreatEvent>, viewModel: VpnViewModel) {
    CyberPanel(title = "AI Threat Detection Center", subtitle = "Only real detected events — nothing invented",
        trailing = { if (threats.isNotEmpty()) TextButton(onClick = { viewModel.clearThreats() }) { Text("Clear", fontSize = 10.sp) } }) {
        if (threats.isEmpty()) {
            Text("No threats detected. The feed stays empty until a real event occurs — it is never pre-filled.",
                color = EmeraldGlow, fontSize = 11.sp)
        }
        threats.forEach { event ->
            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.Top) {
                val color = when (event.severity) {
                    VpnThreatEvent.Severity.CRITICAL -> AlertRed
                    VpnThreatEvent.Severity.HIGH -> AlertRed.copy(alpha = 0.8f)
                    VpnThreatEvent.Severity.MEDIUM -> WarningAmber
                    VpnThreatEvent.Severity.LOW -> EmeraldGlow
                }
                Icon(Icons.Default.Warning, contentDescription = null, tint = color, modifier = Modifier.size(14.dp))
                Spacer(Modifier.width(8.dp))
                Column {
                    Text("${event.severity.name} — ${event.title}", fontSize = 11.sp, color = color, fontWeight = FontWeight.Bold)
                    Text(event.detail, fontSize = 10.sp, color = TextSecondaryDark, maxLines = 2)
                }
            }
        }
    }
}

@Composable
private fun VpnPrivacyPanel(stats: com.adshield.pro.vpn.VpnStats, viewModel: VpnViewModel) {
    CyberPanel(title = "Privacy Protection", subtitle = "Leak checks run against the live connection") {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { viewModel.checkIp() }) { Text("IPv4 leak test", fontSize = 11.sp) }
            OutlinedButton(onClick = { viewModel.dnsLeakProbe() }) { Text("DNS leak test", fontSize = 11.sp) }
        }
        Spacer(Modifier.height(6.dp))
        Text("Public IP: ${stats.publicIp ?: "not verified"}", fontSize = 11.sp, color = TextSecondaryDark)
        Text("DNS probe: ${stats.dnsLeakTestResult ?: "not run"}", fontSize = 11.sp, color = TextSecondaryDark)
        Text("IPv6/WebRTC leak tests: not run — the DNS engine is untouched, as required.", fontSize = 10.sp, color = TextSecondaryDark)
    }
}

@Composable
private fun VpnFeatureStatusPanel() {
    CyberPanel(title = "Honest Feature Status", subtitle = "What this build actually does") {
        val rows = listOf(
            "Shared single VPNService (DNS + VPN coordinated)" to FeatureStatus.WORKING,
            "Full-tunnel routing + kill switch (blocking mode)" to FeatureStatus.WORKING,
            "Per-app split tunneling" to FeatureStatus.WORKING,
            "Real server latency probing & fastest selection" to FeatureStatus.WORKING,
            "Public IP / DNS leak verification" to FeatureStatus.WORKING,
            "WireGuard handshake to a server" to FeatureStatus.SERVER_REQUIRED,
            "OpenVPN handshake" to FeatureStatus.SERVER_REQUIRED,
            "Multi-hop / QUIC / MASQUE / obfuscation" to FeatureStatus.NOT_IMPLEMENTED,
            "Second simultaneous VPNService" to FeatureStatus.ANDROID_LIMITATION
        )
        rows.forEach { (name, status) ->
            Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Security, contentDescription = null,
                    tint = when (status) {
                        FeatureStatus.WORKING -> EmeraldGlow
                        FeatureStatus.PARTIAL -> CyberCyan
                        FeatureStatus.SERVER_REQUIRED, FeatureStatus.PERMISSION_REQUIRED -> WarningAmber
                        else -> AlertRed
                    }, modifier = Modifier.size(13.dp))
                Spacer(Modifier.width(8.dp))
                Text(name, fontSize = 11.sp, modifier = Modifier.weight(1f), color = TextSecondaryDark)
                Text(status.label, fontSize = 10.sp, fontWeight = FontWeight.Bold,
                    color = if (status == FeatureStatus.WORKING) EmeraldGlow else WarningAmber)
            }
        }
    }
}

@Composable
private fun ImportConfigDialog(onDismiss: () -> Unit, onImport: (String) -> String?) {
    var text by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = { error = onImport(text) }) { Text("Import") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
        title = { Text("Import WireGuard .conf", fontSize = 14.sp) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                OutlinedTextField(
                    text, { text = it }, singleLine = false, minLines = 5,
                    placeholder = { Text("[Interface]\nPrivateKey = …\n[Peer]\nEndpoint = host:51820 …", fontSize = 10.sp) },
                    modifier = Modifier.fillMaxWidth()
                )
                if (error != null) Text(error!!, color = AlertRed, fontSize = 11.sp)
            }
        }
    )
}

@Composable
private fun AddServerDialog(onDismiss: () -> Unit, onAdd: (VpnServer) -> Unit) {
    var name by remember { mutableStateOf("") }
    var country by remember { mutableStateOf("") }
    var countryExpanded by remember { mutableStateOf(false) }
    var city by remember { mutableStateOf("") }
    var host by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("51820") }
    val countryMatches = remember(country) {
        if (country.isBlank()) CountryList.ALL
        else CountryList.ALL.filter { it.contains(country, ignoreCase = true) }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = {
                val portNum = port.toIntOrNull() ?: 51820
                if (host.isNotBlank()) {
                    onAdd(
                        VpnServer(
                            id = UUID.randomUUID().toString(),
                            name = name.ifBlank { "My server" },
                            country = country.ifBlank { "Unknown" },
                            city = city.ifBlank { "Unknown" },
                            host = host.trim(), port = portNum,
                            protocol = com.adshield.pro.vpn.VpnProtocol.WIREGUARD
                        )
                    )
                }
            }) { Text("Add") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
        title = { Text("Add VPN server", fontSize = 14.sp) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                OutlinedTextField(name, { name = it }, singleLine = true, placeholder = { Text("Name", fontSize = 11.sp) })
                Box {
                    OutlinedTextField(
                        country, { country = it; countryExpanded = true }, singleLine = true,
                        placeholder = { Text("Country (${CountryList.ALL.size} available)", fontSize = 11.sp) },
                        modifier = Modifier.fillMaxWidth().clickable { countryExpanded = true }
                    )
                    DropdownMenu(
                        expanded = countryExpanded && countryMatches.isNotEmpty(),
                        onDismissRequest = { countryExpanded = false },
                        modifier = Modifier.fillMaxWidth(0.9f)
                    ) {
                        countryMatches.take(30).forEach { c ->
                            DropdownMenuItem(
                                text = { Text(c, fontSize = 12.sp) },
                                onClick = { country = c; countryExpanded = false }
                            )
                        }
                    }
                }
                OutlinedTextField(city, { city = it }, singleLine = true, placeholder = { Text("City", fontSize = 11.sp) })
                OutlinedTextField(host, { host = it }, singleLine = true, placeholder = { Text("Host / IP (real endpoint)", fontSize = 11.sp) })
                OutlinedTextField(port, { port = it }, singleLine = true, placeholder = { Text("Port", fontSize = 11.sp) })
            }
        }
    )
}
