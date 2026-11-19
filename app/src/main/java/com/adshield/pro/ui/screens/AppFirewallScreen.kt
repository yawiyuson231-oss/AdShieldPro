package com.adshield.pro.ui.screens

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.RestartAlt
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.domain.model.AppDnsActivity
import com.adshield.pro.domain.model.AppDnsPolicy
import com.adshield.pro.domain.model.AppExclusionInfo
import com.adshield.pro.engine.platform.ProtectionSnoozeEngine
import com.adshield.pro.engine.platform.ProtectionSnoozeEngine.AppFirewallFilter
import com.adshield.pro.ui.components.StatusPill
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber
import com.adshield.pro.ui.theme.formatInteger

/**
 * Full-screen Per-App Firewall & Split-Tunnel Manager.
 *
 * Lets users control each installed application individually across four deterministic modes:
 *  - **Filtered** (routes DNS through AdShield VPN with blocklists and DNS Alias Shield)
 *  - **Allow DNS** (routes DNS through encrypted upstream while bypassing domain blocklists)
 *  - **Block DNS** (blocks all DNS lookups originating from the app's UID)
 *  - **Bypass VPN** (excludes the app from the VPN tunnel via `addDisallowedApplication`)
 */
@Composable
fun AppFirewallScreen(
    apps: List<AppExclusionInfo>,
    liveTopApps: List<AppDnsActivity>,
    onBack: () -> Unit,
    onRefreshApps: () -> Unit,
    onToggleAppExclusion: (String, Boolean) -> Unit,
    onSetAppDnsPolicy: (String, AppDnsPolicy) -> Unit,
    onResetAllOverrides: () -> Unit
) {
    LaunchedEffect(Unit) {
        if (apps.isEmpty()) onRefreshApps()
    }

    var searchQuery by rememberSaveable { mutableStateOf("") }
    var activeFilter by rememberSaveable { mutableStateOf(AppFirewallFilter.ALL) }
    var showSystemApps by rememberSaveable { mutableStateOf(false) }
    var showResetConfirm by remember { mutableStateOf(false) }

    val activityByPackage = remember(liveTopApps) {
        liveTopApps.mapNotNull { entry ->
            entry.packageName?.takeIf { it.isNotBlank() }?.let { pkg -> pkg to entry }
        }.toMap()
    }

    val summary = remember(apps, activityByPackage) {
        ProtectionSnoozeEngine.summarizeFirewall(apps, activityByPackage)
    }

    val visibleApps = remember(apps, activityByPackage, searchQuery, activeFilter, showSystemApps) {
        ProtectionSnoozeEngine.filterFirewallApps(
            apps = apps,
            activityByPackage = activityByPackage,
            searchQuery = searchQuery,
            filter = activeFilter,
            includeSystemApps = showSystemApps
        )
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 56.dp)
                .padding(start = 4.dp, end = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back to settings")
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Per-App Firewall & Split-Tunnel",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "${summary.bypassedCount} bypassed · ${summary.dnsBlockedCount} DNS-blocked · ${summary.dnsAllowAllCount} unfiltered",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            if (summary.customRuleCount > 0) {
                IconButton(onClick = { showResetConfirm = true }) {
                    Icon(
                        Icons.Default.RestartAlt,
                        contentDescription = "Reset all per-app overrides",
                        tint = WarningAmber
                    )
                }
            }
            IconButton(onClick = onRefreshApps) {
                Icon(Icons.Default.Refresh, contentDescription = "Refresh installed apps")
            }
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 4.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Search app name or package…") },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                AppFirewallFilter.entries.forEach { filter ->
                    val countSuffix = when (filter) {
                        AppFirewallFilter.ALL -> ""
                        AppFirewallFilter.CONFIGURED -> " (${summary.customRuleCount})"
                        AppFirewallFilter.BYPASSED -> " (${summary.bypassedCount})"
                        AppFirewallFilter.DNS_BLOCKED -> " (${summary.dnsBlockedCount})"
                        AppFirewallFilter.ACTIVE_TRAFFIC -> " (${summary.activeTrafficCount})"
                    }
                    FilterChip(
                        selected = activeFilter == filter,
                        onClick = { activeFilter = filter },
                        label = { Text("${filter.label}$countSuffix", style = MaterialTheme.typography.labelSmall) }
                    )
                }
                FilterChip(
                    selected = showSystemApps,
                    onClick = { showSystemApps = !showSystemApps },
                    label = { Text("System apps", style = MaterialTheme.typography.labelSmall) }
                )
            }

            Text(
                text = "Bypass VPN excludes apps (banking, Android Auto, casting) from the tunnel. DNS modes govern DNS queries only; direct raw-IP sockets bypass the DNS-only tunnel.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        LazyColumn(
            modifier = Modifier.weight(1f),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            if (visibleApps.isEmpty()) {
                item(key = "empty-state", contentType = "empty") {
                    Surface(
                        color = MaterialTheme.colorScheme.surface,
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = if (apps.isEmpty()) {
                                "Loading installed apps…"
                            } else {
                                "No apps match the current filter. Enable 'System apps' or clear the search box to see all ${apps.size} packages."
                            },
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(16.dp)
                        )
                    }
                }
            }
            items(visibleApps, key = { it.packageName }, contentType = { "firewall-app-row" }) { app ->
                AppFirewallRowCard(
                    app = app,
                    activity = activityByPackage[app.packageName],
                    onSelectFiltered = {
                        if (app.isExcludedFromVpn) onToggleAppExclusion(app.packageName, false)
                        if (app.dnsPolicy != AppDnsPolicy.DEFAULT) onSetAppDnsPolicy(app.packageName, AppDnsPolicy.DEFAULT)
                    },
                    onSelectAllowDns = {
                        onSetAppDnsPolicy(app.packageName, AppDnsPolicy.ALLOW_ALL)
                    },
                    onSelectBlockDns = {
                        onSetAppDnsPolicy(app.packageName, AppDnsPolicy.BLOCK_ALL)
                    },
                    onSelectBlockWifi = {
                        onSetAppDnsPolicy(app.packageName, AppDnsPolicy.BLOCK_WIFI)
                    },
                    onSelectBlockCellular = {
                        onSetAppDnsPolicy(app.packageName, AppDnsPolicy.BLOCK_CELLULAR)
                    },
                    onSelectBlockScreenOff = {
                        onSetAppDnsPolicy(app.packageName, AppDnsPolicy.BLOCK_SCREEN_OFF)
                    },
                    onSelectBypassVpn = {
                        if (!app.isExcludedFromVpn) onToggleAppExclusion(app.packageName, true)
                    }
                )
            }
        }
    }

    if (showResetConfirm) {
        AlertDialog(
            onDismissRequest = { showResetConfirm = false },
            title = { Text("Reset all per-app rules?") },
            text = {
                Text(
                    "Clears ${summary.bypassedCount} split-tunnel exclusion(s) and " +
                        "${summary.dnsBlockedCount + summary.dnsAllowAllCount} per-app DNS override(s), " +
                        "returning every app to standard filtered protection."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showResetConfirm = false
                    onResetAllOverrides()
                }) {
                    Text("Reset all", color = AlertRed)
                }
            },
            dismissButton = {
                TextButton(onClick = { showResetConfirm = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@Composable
private fun AppFirewallRowCard(
    app: AppExclusionInfo,
    activity: AppDnsActivity?,
    onSelectFiltered: () -> Unit,
    onSelectAllowDns: () -> Unit,
    onSelectBlockDns: () -> Unit,
    onSelectBlockWifi: () -> Unit,
    onSelectBlockCellular: () -> Unit,
    onSelectBlockScreenOff: () -> Unit,
    onSelectBypassVpn: () -> Unit
) {
    val (statusText, statusColor) = when {
        app.isExcludedFromVpn -> "BYPASS VPN" to WarningAmber
        app.dnsPolicy == AppDnsPolicy.BLOCK_ALL -> "DNS BLOCKED" to AlertRed
        app.dnsPolicy == AppDnsPolicy.BLOCK_WIFI -> "NO WI-FI DNS" to AlertRed
        app.dnsPolicy == AppDnsPolicy.BLOCK_CELLULAR -> "NO CELL DNS" to AlertRed
        app.dnsPolicy == AppDnsPolicy.BLOCK_SCREEN_OFF -> "SCREEN-OFF BLOCK" to WarningAmber
        app.dnsPolicy == AppDnsPolicy.ALLOW_ALL -> "UNFILTERED" to CyberCyan
        else -> "FILTERED" to EmeraldPrimary
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = app.appName,
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false)
                        )
                        if (app.isSystemApp) {
                            Text(
                                text = "SYS",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    Text(
                        text = app.packageName,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                StatusPill(text = statusText, color = statusColor)
            }

            if (activity != null && activity.totalQueries > 0L) {
                val allowed = (activity.totalQueries - activity.blockedQueries).coerceAtLeast(0L)
                Text(
                    text = "Session DNS: ${formatInteger(activity.totalQueries)} queries · " +
                        "${formatInteger(activity.blockedQueries)} blocked · ${formatInteger(allowed)} allowed",
                    style = MaterialTheme.typography.labelSmall,
                    color = SkyBlueGlow
                )
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                FilterChip(
                    selected = !app.isExcludedFromVpn && app.dnsPolicy == AppDnsPolicy.DEFAULT,
                    onClick = onSelectFiltered,
                    label = { Text("Filtered", style = MaterialTheme.typography.labelSmall) }
                )
                FilterChip(
                    selected = !app.isExcludedFromVpn && app.dnsPolicy == AppDnsPolicy.ALLOW_ALL,
                    onClick = onSelectAllowDns,
                    label = { Text("Allow DNS", style = MaterialTheme.typography.labelSmall) }
                )
                FilterChip(
                    selected = !app.isExcludedFromVpn && app.dnsPolicy == AppDnsPolicy.BLOCK_ALL,
                    onClick = onSelectBlockDns,
                    label = { Text("Block DNS", style = MaterialTheme.typography.labelSmall) }
                )
                FilterChip(
                    selected = !app.isExcludedFromVpn && app.dnsPolicy == AppDnsPolicy.BLOCK_WIFI,
                    onClick = onSelectBlockWifi,
                    label = { Text("No Wi-Fi", style = MaterialTheme.typography.labelSmall) }
                )
                FilterChip(
                    selected = !app.isExcludedFromVpn && app.dnsPolicy == AppDnsPolicy.BLOCK_CELLULAR,
                    onClick = onSelectBlockCellular,
                    label = { Text("No Cell", style = MaterialTheme.typography.labelSmall) }
                )
                FilterChip(
                    selected = !app.isExcludedFromVpn && app.dnsPolicy == AppDnsPolicy.BLOCK_SCREEN_OFF,
                    onClick = onSelectBlockScreenOff,
                    label = { Text("Screen-Off Block", style = MaterialTheme.typography.labelSmall) }
                )
                FilterChip(
                    selected = app.isExcludedFromVpn,
                    onClick = onSelectBypassVpn,
                    label = { Text("Bypass VPN", style = MaterialTheme.typography.labelSmall) }
                )
            }

            if (app.compatibilityNote != null) {
                Row(verticalAlignment = Alignment.Top) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = null,
                        tint = WarningAmber,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = app.compatibilityNote,
                        style = MaterialTheme.typography.labelSmall,
                        color = WarningAmber
                    )
                }
            }
        }
    }
}
