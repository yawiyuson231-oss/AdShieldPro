package com.adshield.pro.ui.screens.connectors

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.domain.connectors.ConnectorSnapshot
import com.adshield.pro.domain.connectors.ConnectorStatus
import com.adshield.pro.domain.connectors.VerificationClass
import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.ui.model.ConnectorUiState
import com.adshield.pro.ui.screens.intelligence.GlassPanel
import com.adshield.pro.ui.screens.intelligence.formatRelative
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.DeepNavyBackground
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber

/**
 * Connector registry — the honest control surface for every integration.
 *
 * It deliberately reuses the app's existing dark command-centre styling; the layout of the live
 * map is untouched. This screen is opened from the map's command panel or a node's detail sheet.
 */
@Composable
fun ConnectorRegistryScreen(
    state: ConnectorUiState,
    onBack: () -> Unit,
    onSetModuleFilter: (IntelligenceModule?) -> Unit,
    onSetQuery: (String) -> Unit,
    onSync: (String) -> Unit,
    onSyncModule: (IntelligenceModule) -> Unit,
    onToggleEnabled: (ConnectorSnapshot) -> Unit,
    onCheckValue: (String) -> Unit,
    onClearCheck: () -> Unit,
    onDismissMessage: () -> Unit,
    modifier: Modifier = Modifier
) {
    var detail by remember { mutableStateOf<ConnectorSnapshot?>(null) }
    var checkInput by remember { mutableStateOf("") }

    Column(modifier = modifier.fillMaxSize().background(DeepNavyBackground)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = SkyBlueGlow)
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    "CONNECTOR REGISTRY",
                    color = Color(0xFFF8FAFC),
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp
                )
                Text(
                    "${state.implementedCount} implemented · ${state.connectedCount} connected · " +
                        "${state.totalIndicators} cached indicators",
                    color = Color(0xFF7C93AF),
                    fontSize = 9.sp
                )
            }
            IconButton(onClick = { onSyncModule(state.moduleFilter ?: IntelligenceModule.CYBER_DEFENSE) }) {
                Icon(Icons.Default.Refresh, contentDescription = "Sync module", tint = CyberCyan)
            }
        }

        LazyRow(
            contentPadding = PaddingValues(horizontal = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            item(key = "all") {
                FilterChip(
                    selected = state.moduleFilter == null,
                    onClick = { onSetModuleFilter(null) },
                    label = { Text("ALL", fontSize = 9.sp) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = CyberCyan.copy(alpha = 0.22f),
                        selectedLabelColor = CyberCyan
                    )
                )
            }
            itemsIndexed(IntelligenceModule.nodes, key = { _, m -> m.id }, contentType = { _, _ -> "module-chip" }) { _, module ->
                FilterChip(
                    selected = state.moduleFilter == module,
                    onClick = { onSetModuleFilter(if (state.moduleFilter == module) null else module) },
                    label = { Text(module.shortLabel, fontSize = 9.sp) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = CyberCyan.copy(alpha = 0.22f),
                        selectedLabelColor = CyberCyan
                    )
                )
            }
        }

        OutlinedTextField(
            value = state.query,
            onValueChange = onSetQuery,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 6.dp),
            singleLine = true,
            label = { Text("Search connectors", fontSize = 10.sp) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = Color(0xFF7C93AF)) },
            trailingIcon = {
                if (state.query.isNotEmpty()) {
                    IconButton(onClick = { onSetQuery("") }) {
                        Icon(Icons.Default.Close, contentDescription = "Clear search", tint = Color(0xFF7C93AF))
                    }
                }
            }
        )

        IndicatorCheckCard(
            input = checkInput,
            onInputChange = { checkInput = it },
            checking = state.checking,
            check = state.check,
            onCheck = { onCheckValue(checkInput) },
            onClear = { checkInput = ""; onClearCheck() }
        )

        state.message?.let { message ->
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(message, color = Color(0xFFB6C6DA), fontSize = 9.sp, modifier = Modifier.weight(1f), maxLines = 2)
                TextButton(onClick = onDismissMessage) { Text("OK", fontSize = 9.sp, color = CyberCyan) }
            }
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 10.dp, end = 10.dp, top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            items(
                items = state.visible,
                key = { snapshot -> snapshot.spec.id },
                contentType = { "connector-row" }
            ) { snapshot ->
                ConnectorRow(
                    snapshot = snapshot,
                    busy = state.syncingId == snapshot.spec.id,
                    onClick = { detail = snapshot },
                    onSync = { onSync(snapshot.spec.id) }
                )
            }
            if (state.visible.isEmpty()) {
                item(key = "empty") {
                    Text(
                        "No connector matches this filter.",
                        color = Color(0xFF64748B),
                        fontSize = 10.sp,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }
        }
    }

    detail?.let { snapshot ->
        ConnectorDetailSheet(
            snapshot = snapshot,
            syncing = state.syncingId == snapshot.spec.id,
            onDismiss = { detail = null },
            onSync = { onSync(snapshot.spec.id) },
            onToggleEnabled = { onToggleEnabled(snapshot) }
        )
    }
}

@Composable
private fun ConnectorRow(
    snapshot: ConnectorSnapshot,
    busy: Boolean,
    onClick: () -> Unit,
    onSync: () -> Unit
) {
    val status = snapshot.effectiveStatus
    GlassPanel(modifier = Modifier.fillMaxWidth().clickable { onClick() }) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    snapshot.spec.name,
                    color = Color(0xFFF1F5F9),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    "${snapshot.spec.provider} · ${snapshot.spec.module.shortLabel}",
                    color = Color(0xFF7C93AF),
                    fontSize = 8.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    "${snapshot.freshnessLabel} · ${snapshot.runtime.indicatorCount} indicator(s)",
                    color = Color(0xFF5B7089),
                    fontSize = 8.sp
                )
            }
            Spacer(Modifier.width(6.dp))
            ConnectorStatusPill(status)
            Spacer(Modifier.width(4.dp))
            IconButton(onClick = onSync, modifier = Modifier.size(30.dp), enabled = !busy) {
                Icon(
                    Icons.Default.Refresh,
                    contentDescription = "Sync",
                    tint = if (busy) Color(0xFF475569) else CyberCyan,
                    modifier = Modifier.size(15.dp)
                )
            }
        }
    }
}

@Composable
fun ConnectorStatusPill(status: ConnectorStatus, modifier: Modifier = Modifier) {
    val color = when (status) {
        ConnectorStatus.CONNECTED -> EmeraldPrimary
        ConnectorStatus.SYNCING -> SkyBlueGlow
        ConnectorStatus.OFFLINE -> Color(0xFF64748B)
        ConnectorStatus.DEGRADED -> WarningAmber
        ConnectorStatus.RATE_LIMITED -> WarningAmber
        ConnectorStatus.ERROR -> AlertRed
        ConnectorStatus.DISABLED -> Color(0xFF475569)
        ConnectorStatus.NOT_CONFIGURED -> SkyBlueGlow
        ConnectorStatus.NOT_IMPLEMENTED -> Color(0xFF475569)
    }
    Box(
        modifier = modifier
            .background(color.copy(alpha = 0.14f), RoundedCornerShape(4.dp))
            .border(1.dp, color.copy(alpha = 0.55f), RoundedCornerShape(4.dp))
            .padding(horizontal = 5.dp, vertical = 2.dp)
    ) {
        Text(
            status.label,
            color = color,
            fontSize = 7.sp,
            fontWeight = FontWeight.Bold,
            maxLines = 1
        )
    }
}

@Composable
private fun IndicatorCheckCard(
    input: String,
    onInputChange: (String) -> Unit,
    checking: Boolean,
    check: com.adshield.pro.ui.model.IndicatorCheckResult?,
    onCheck: () -> Unit,
    onClear: () -> Unit
) {
    GlassPanel(modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp)) {
        Column(modifier = Modifier.padding(10.dp)) {
            Text(
                "CHECK AGAINST CACHED INTELLIGENCE",
                color = Color(0xFF7C93AF),
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.6.sp
            )
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                OutlinedTextField(
                    value = input,
                    onValueChange = onInputChange,
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    label = { Text("domain, URL, IP or SHA-256", fontSize = 9.sp) }
                )
                Spacer(Modifier.width(6.dp))
                OutlinedButton(onClick = onCheck, enabled = !checking) {
                    Text(if (checking) "…" else "CHECK", fontSize = 9.sp, color = CyberCyan)
                }
            }
            check?.let { result ->
                Spacer(Modifier.height(6.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "${result.verdict} · ${result.score}/100",
                        color = if (result.score >= 60) AlertRed else if (result.score > 0) WarningAmber else EmeraldPrimary,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.weight(1f))
                    TextButton(onClick = onClear) { Text("Clear", fontSize = 9.sp, color = Color(0xFF7C93AF)) }
                }
                result.reasons.take(6).forEach { reason ->
                    Text("• $reason", color = Color(0xFF94A3B8), fontSize = 8.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
                }
                Text(
                    "Offline check against indicators cached on this device. Not a malware verdict.",
                    color = Color(0xFF5B7089),
                    fontSize = 7.sp
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConnectorDetailSheet(
    snapshot: ConnectorSnapshot,
    syncing: Boolean,
    onDismiss: () -> Unit,
    onSync: () -> Unit,
    onToggleEnabled: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = Color(0xFF04101D),
        contentColor = Color(0xFFE2E8F0)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().heightIn(max = 560.dp).padding(horizontal = 16.dp)
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxWidth().heightIn(max = 480.dp),
                contentPadding = PaddingValues(bottom = 16.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                item(key = "title") {
                    Column {
                        Text(snapshot.spec.name, color = Color(0xFFF8FAFC), fontSize = 16.sp, fontWeight = FontWeight.Bold)
                        Text(
                            "${snapshot.spec.provider} · ${snapshot.spec.module.displayName}",
                            color = Color(0xFF7C93AF),
                            fontSize = 10.sp
                        )
                    }
                }
                item(key = "status") {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        ConnectorStatusPill(snapshot.effectiveStatus)
                        Spacer(Modifier.width(8.dp))
                        Text(snapshot.freshnessLabel, color = Color(0xFF94A3B8), fontSize = 9.sp)
                    }
                }
                item(key = "meta") {
                    GlassPanel(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(10.dp)) {
                            MetaRow("Connector ID", snapshot.spec.id)
                            MetaRow("Endpoint / API", snapshot.spec.endpoint, maxLines = 3)
                            MetaRow("Method", snapshot.spec.method)
                            MetaRow("Response format", snapshot.spec.format.name)
                            MetaRow("Authentication", snapshot.spec.auth.name)
                            MetaRow("Free use", snapshot.spec.freeUse, maxLines = 3)
                            MetaRow("Restrictions", snapshot.spec.restrictions, maxLines = 4)
                            MetaRow("Rate limits", snapshot.spec.rateLimit, maxLines = 3)
                            MetaRow("Cache TTL", "${snapshot.spec.cacheTtlMs / 60_000L} min")
                            MetaRow("Timeout", "${snapshot.spec.timeoutMs / 1000}s")
                            MetaRow("Verification", verificationLabel(snapshot.spec.verification))
                            MetaRow("Last success", snapshot.runtime.lastSuccessEpochMs?.let { formatRelative(it) } ?: "never")
                            snapshot.runtime.lastError?.let { MetaRow("Last error", it, maxLines = 4, valueColor = WarningAmber) }
                            snapshot.runtime.lastSummary?.let { MetaRow("Last result", it, maxLines = 3) }
                            snapshot.runtime.httpCode?.let { MetaRow("HTTP status", it.toString()) }
                            snapshot.runtime.indicatorCount.takeIf { it > 0 }?.let {
                                MetaRow("Cached indicators", it.toString())
                            }
                        }
                    }
                }
                item(key = "controls") {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedButton(onClick = onSync, enabled = !syncing) {
                            Text(if (syncing) "WORKING…" else if (snapshot.spec.isFeed) "SYNC NOW" else "RUN PROBE",
                                fontSize = 9.sp, color = CyberCyan)
                        }
                        Spacer(Modifier.weight(1f))
                        Text("Enabled", color = Color(0xFF94A3B8), fontSize = 9.sp)
                        Switch(
                            checked = snapshot.runtime.enabled,
                            onCheckedChange = { onToggleEnabled() },
                            enabled = snapshot.spec.implemented && !snapshot.spec.requiresKey
                        )
                    }
                }
                item(key = "honesty") {
                    Text(
                        "Status comes from real attempts only. " +
                            if (snapshot.spec.requiresKey) {
                                "This provider requires credentials that are not bundled, so it can never turn green here."
                            } else if (!snapshot.spec.implemented) {
                                "This source has no public machine interface; it is listed instead of being faked."
                            } else {
                                "A successful sync or probe is required before this connector reports CONNECTED."
                            },
                        color = Color(0xFF5B7089),
                        fontSize = 8.sp
                    )
                }
            }
        }
    }
}

@Composable
private fun MetaRow(
    label: String,
    value: String,
    maxLines: Int = 1,
    valueColor: Color = Color(0xFFB6C6DA)
) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 1.dp)) {
        Text(label, color = Color(0xFF64748B), fontSize = 8.sp, modifier = Modifier.width(96.dp))
        Text(value, color = valueColor, fontSize = 8.sp, maxLines = maxLines, overflow = TextOverflow.Ellipsis)
    }
}

private fun verificationLabel(clazz: VerificationClass): String = when (clazz) {
    VerificationClass.IMPLEMENTED_AND_TESTED -> "implemented and tested (JVM)"
    VerificationClass.IMPLEMENTED_NOT_FULLY_VERIFIED -> "implemented, needs on-device verification"
    VerificationClass.FREE_WITH_RESTRICTIONS -> "free with provider restrictions"
    VerificationClass.ANDROID_LIMITED -> "Android-limited API"
    VerificationClass.SOURCE_UNAVAILABLE -> "source unavailable"
    VerificationClass.NOT_IMPLEMENTED -> "not implemented"
}
