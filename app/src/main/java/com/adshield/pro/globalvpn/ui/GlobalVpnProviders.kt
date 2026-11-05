package com.adshield.pro.globalvpn.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.globalvpn.model.ProviderId
import com.adshield.pro.globalvpn.model.ProviderIntegration
import com.adshield.pro.globalvpn.model.VpnServer
import com.adshield.pro.globalvpn.provider.VpnProviderAdapter
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.WarningAmber

@Composable
fun GlobalVpnProviders(
    providers: List<VpnProviderAdapter>,
    providerErrors: Map<ProviderId, String>,
    servers: List<VpnServer>,
    onImport: (String, ProviderId, String, String?, String?) -> Unit,
    onDelete: (String) -> Unit
) {
    var importProvider by remember { mutableStateOf<ProviderId?>(null) }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item(key = "intro") {
            Text(
                "Five free sources, integrated honestly. A source is only shown as connectable when a " +
                    "real tunnel can be dialed; otherwise its real limitation is stated.",
                color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp
            )
        }

        items(providers, key = { it.id.name }) { provider ->
            val imported = servers.filter { it.provider == provider.id && it.configRef != null && it.isConnectable }
            ProviderCard(
                provider = provider,
                error = providerErrors[provider.id],
                imported = imported,
                onImport = { importProvider = provider.id },
                onDelete = onDelete
            )
        }

        item(key = "footer") { Spacer(Modifier.height(24.dp)) }
    }

    val target = importProvider
    if (target != null) {
        ImportConfigDialog(
            provider = target,
            onDismiss = { importProvider = null },
            onImport = { name, config, code, country ->
                onImport(name, target, config, code, country)
                importProvider = null
            }
        )
    }
}

@Composable
private fun ProviderCard(
    provider: VpnProviderAdapter,
    error: String?,
    imported: List<VpnServer>,
    onImport: () -> Unit,
    onDelete: (String) -> Unit
) {
    val canImport = provider.integration == ProviderIntegration.REAL_WIREGUARD_IMPORT
    GlassPanel(title = provider.id.label, subtitle = provider.integration.label) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(provider.integration.detail, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
            Text(provider.freePlanNotes, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp)
            if (error != null) {
                Text("Discovery: $error", color = WarningAmber, fontSize = 11.sp)
            }
            provider.setupInstructions.forEachIndexed { index, step ->
                Text("${index + 1}. $step", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp)
            }
            if (canImport) {
                Button(onClick = onImport, modifier = Modifier.fillMaxWidth()) { Text("Import WireGuard config") }
            }
            imported.forEach { server ->
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(server.displayName, color = EmeraldPrimary, fontSize = 12.sp, modifier = Modifier.weight(1f))
                    TextButton(onClick = { onDelete(server.id) }) { Text("Remove") }
                }
            }
        }
    }
}

@Composable
private fun ImportConfigDialog(
    provider: ProviderId,
    onDismiss: () -> Unit,
    onImport: (String, String, String?, String?) -> Unit
) {
    val context = LocalContext.current
    var name by remember { mutableStateOf("") }
    var configText by remember { mutableStateOf("") }
    var countryCode by remember { mutableStateOf("") }

    val fileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            runCatching {
                context.contentResolver.openInputStream(uri)?.use { stream ->
                    configText = stream.readBytes().toString(Charsets.UTF_8)
                }
            }
            if (name.isBlank()) {
                name = uri.lastPathSegment?.substringAfterLast('/') ?: "Imported tunnel"
            }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Import ${provider.label} config") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Paste a WireGuard .conf or pick a file. The private key is encrypted with an " +
                        "Android Keystore key and never leaves this device.",
                    fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                OutlinedButton(onClick = { fileLauncher.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth()) {
                    Text("Choose .conf file")
                }
                OutlinedTextField(
                    value = name, onValueChange = { name = it },
                    label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = countryCode, onValueChange = { countryCode = it },
                    label = { Text("Country code (optional, e.g. US)") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = configText, onValueChange = { configText = it },
                    label = { Text("WireGuard configuration") },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 120.dp, max = 220.dp)
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onImport(name, configText, countryCode.ifBlank { null }, null) },
                enabled = configText.contains("[Interface]") && configText.contains("[Peer]")
            ) { Text("Import") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}
