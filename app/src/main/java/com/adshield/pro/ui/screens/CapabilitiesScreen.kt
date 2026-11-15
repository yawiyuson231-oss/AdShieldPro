package com.adshield.pro.ui.screens

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.TextButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.engine.platform.Capability
import com.adshield.pro.engine.platform.CapabilityRegistry
import com.adshield.pro.engine.platform.CapabilityStatus
import com.adshield.pro.engine.platform.DeviceProfile
import com.adshield.pro.ui.components.CompactStatusChip
import com.adshield.pro.ui.model.ProtectionPipelineStatus
import com.adshield.pro.ui.model.CapabilityStatusFilter
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.WarningAmber

private val CardSurface = Color(0xFF101C2C)
private val MutedText = Color(0xFF9FB6B8)
private val StatusBlue = Color(0xFF2E7DFF)

/** The catalogue describes what this build supports, not a live test of each feature. */
@Composable
fun CapabilitiesScreen(
    deviceProfile: DeviceProfile? = null,
    protectionStatus: ProtectionPipelineStatus? = null
) {
    var query by rememberSaveable { mutableStateOf("") }
    var selectedStatus by rememberSaveable { mutableStateOf("ALL") }
    val filter = CapabilityStatus.entries.firstOrNull { it.name == selectedStatus }
    val results = CapabilityStatusFilter.filter(CapabilityRegistry.capabilities, query, filter)

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        item {
            Text("Status", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        }
        if (protectionStatus != null) {
            item {
                Surface(color = CardSurface, shape = RoundedCornerShape(16.dp)) {
                    Column(Modifier.fillMaxWidth().padding(16.dp)) {
                        Text("Protection now", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(8.dp))
                        CompactStatusChip(protectionStatus)
                        Spacer(Modifier.height(8.dp))
                        Text(protectionStatus.summary, fontSize = 13.sp, color = MutedText)
                    }
                }
            }
        }
        if (deviceProfile != null) {
            item { DeviceProfileCard(deviceProfile) }
        }
        item {
            Text("Features in this app", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp))
            Text(
                "Browse what is available and its limits. These labels describe the build, not a live check of your device.",
                fontSize = 13.sp, color = MutedText
            )
        }
        item {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Search features") },
                singleLine = true
            )
        }
        item {
            Row(
                modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilterChip(selected = filter == null, onClick = { selectedStatus = "ALL" },
                    label = { Text("All (${CapabilityRegistry.capabilities.size})") })
                CapabilityStatus.entries.forEach { status ->
                    FilterChip(selected = filter == status, onClick = { selectedStatus = status.name },
                        label = { Text("${statusLabel(status)} (${CapabilityRegistry.count(status)})") })
                }
            }
        }
        item {
            Text("${results.size} feature${if (results.size == 1) "" else "s"} shown · Use Show details for more information", fontSize = 12.sp, color = MutedText)
        }
        if (results.isEmpty()) {
            item { Text("No features match. Try another search or choose All.", modifier = Modifier.padding(vertical = 16.dp), color = MutedText) }
        }
        results.groupBy { it.area }.forEach { (area, caps) ->
            item(key = "header-${area.name}") {
                Text(area.label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
            }
            items(caps, key = { it.id }, contentType = { "capability" }) { capability ->
                CapabilityCard(capability)
            }
        }
    }
}

private fun statusLabel(status: CapabilityStatus): String = when (status) {
    CapabilityStatus.IMPLEMENTED -> "Available"
    CapabilityStatus.PARTIAL -> "Limited"
    CapabilityStatus.PLANNED -> "Planned"
    CapabilityStatus.UNAVAILABLE -> "Unavailable"
}

@Composable
private fun CapabilityCard(capability: Capability) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    val statusColor = when (capability.status) {
        CapabilityStatus.IMPLEMENTED -> EmeraldPrimary
        CapabilityStatus.PARTIAL -> WarningAmber
        CapabilityStatus.PLANNED -> StatusBlue
        CapabilityStatus.UNAVAILABLE -> MutedText
    }
    Card(colors = CardDefaults.cardColors(containerColor = CardSurface), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text(capability.name, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Text(statusLabel(capability.status), fontSize = 12.sp, color = statusColor, fontWeight = FontWeight.Bold)
            TextButton(onClick = { expanded = !expanded }) {
                Text(if (expanded) "Hide details" else "Show details")
            }
            if (expanded) {
                if (capability.limitations.isNotEmpty()) {
                    Text("What to know", fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                    capability.limitations.forEach { Text("• $it", fontSize = 12.sp, color = MutedText) }
                }
                if (capability.permissions.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    Text("Permissions: " + capability.permissions.joinToString { it.substringAfterLast('.') }, fontSize = 11.sp, color = MutedText)
                }
                if (capability.dataSources.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    Text("Data sources: " + capability.dataSources.joinToString(), fontSize = 11.sp, color = MutedText)
                }
                if (capability.code.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    Text("Code: ${capability.code}", fontSize = 11.sp, color = MutedText)
                }
                if (capability.verification.isNotBlank()) {
                    Spacer(Modifier.height(6.dp))
                    Text("Verification: ${capability.verification}", fontSize = 11.sp, color = MutedText)
                }
            }
        }
    }
}

/** Everything this particular phone/tablet reports about itself, at a glance. */
@Composable
private fun DeviceProfileCard(profile: DeviceProfile) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    Card(colors = CardDefaults.cardColors(containerColor = CardSurface), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("This device", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(6.dp))
            Text(
                "${profile.manufacturer} ${profile.model} · Android ${profile.androidRelease} · ${profile.formFactor.name.lowercase().replace('_', ' ')}",
                fontSize = 13.sp,
                color = Color.White
            )
            Text(
                "Platform support: ${if (profile.supportedPlatform) "within the tested range" else "outside the tested range (API ${profile.sdkInt})"}",
                fontSize = 11.sp,
                color = if (profile.supportedPlatform) EmeraldPrimary else WarningAmber
            )
            TextButton(onClick = { expanded = !expanded }) {
                Text(if (expanded) "Hide device details" else "Show device details")
            }
            if (expanded) {
                Text(
                    "CPU: ${profile.cpuArchitectures.joinToString(", ").ifEmpty { "not reported" }}",
                    fontSize = 11.sp,
                    color = MutedText
                )
                val radios = buildList {
                    if (profile.hasWifi) add("Wi-Fi")
                    if (profile.hasTelephony) add("Mobile data")
                    if (profile.hasBluetooth) add("Bluetooth")
                    if (profile.hasNfc) add("NFC")
                    if (profile.hasGps) add("GPS")
                    if (profile.hasTouchscreen) add("Touch")
                }
                if (radios.isNotEmpty()) {
                    Text("Hardware: ${radios.joinToString(", ")}", fontSize = 11.sp, color = MutedText)
                }
                Text("Notifications: ${profile.notificationPermission}", fontSize = 11.sp, color = MutedText)

                Spacer(Modifier.height(10.dp))
                Text("Battery hardware on this device", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(4.dp))
                profile.batteryChecks.forEach { row ->
                    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                        Text(
                            if (row.supported) "✓" else "—",
                            color = if (row.supported) EmeraldPrimary else MutedText,
                            fontSize = 11.sp,
                            modifier = Modifier.width(18.dp)
                        )
                        Text(row.label, fontSize = 11.sp, color = Color.White, modifier = Modifier.weight(1f))
                        Text(row.value, fontSize = 11.sp, color = if (row.supported) Color.White else MutedText)
                    }
                }
                Spacer(Modifier.height(6.dp))
                Text(
                    "Rows marked — are values this device's firmware does not publish to apps. They are shown as " +
                        "unavailable in the app rather than estimated.",
                    fontSize = 10.sp,
                    color = MutedText
                )
            }
        }
    }
}
