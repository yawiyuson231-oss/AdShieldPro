package com.adshield.pro.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.engine.cloud.CloudConnection
import com.adshield.pro.engine.cloud.CloudServiceStatus
import com.adshield.pro.engine.cloud.ServiceIndicator
import com.adshield.pro.ui.components.CyberPanel
import com.adshield.pro.ui.components.ScrollToTopButton
import com.adshield.pro.ui.components.StatusPill
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.NavyBorder
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber
import com.adshield.pro.ui.viewmodel.CyberShieldViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Cloud systems monitor. Each card is one provider's official public status page — real
 * operational data, fetched on demand. Providers that were never checked render as
 * "Not connected". Account-level cloud security (AWS/GCP/Azure tenant posture) requires
 * credentials and an external integration that this build does not ship; the screen states
 * that plainly rather than pretending to monitor a tenant.
 */
@Composable
fun CloudScreen(cyberViewModel: CyberShieldViewModel) {
    val state by cyberViewModel.cloudStatuses.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()
    val timeFormat = rememberTimeFormat()

    Box(Modifier.fillMaxSize()) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item(key = "cloud-header", contentType = "panel") {
                CyberPanel(
                    title = "Cloud systems",
                    subtitle = "Official service status · ${state.connectedCount}/${state.services.size} connected",
                    trailing = {
                        if (state.isRefreshing) {
                            CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = CyberCyan)
                        } else {
                            IconButton(onClick = { cyberViewModel.refreshCloud() }, modifier = Modifier.size(28.dp)) {
                                Icon(Icons.Default.Refresh, contentDescription = "Refresh all cloud status", tint = SkyBlueGlow, modifier = Modifier.size(18.dp))
                            }
                        }
                    }
                ) {
                    Row(verticalAlignment = Alignment.Top) {
                        Icon(Icons.Default.Cloud, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "Status is read from each provider's public Statuspage API — incidents and component health, " +
                                "no credentials and no account access. Account-level cloud security posture (AWS, GCP, Azure " +
                                "tenant configuration) requires an external integration and is not connected in this build.",
                            color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    Button(onClick = { cyberViewModel.refreshCloud() }, enabled = !state.isRefreshing, modifier = Modifier.fillMaxWidth()) {
                        Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(if (state.isRefreshing) "Checking providers…" else "Check all providers")
                    }
                }
            }

            items(state.services, key = { it.provider.id }, contentType = { "provider" }) { service ->
                CloudProviderCard(service, timeFormat, onRefresh = { cyberViewModel.refreshCloud(service.provider) })
            }
        }
        ScrollToTopButton(state = listState, modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp))
    }
}

@Composable
private fun rememberTimeFormat(): SimpleDateFormat =
    androidx.compose.runtime.remember { SimpleDateFormat("MMM d, HH:mm", Locale.US) }

@Composable
private fun CloudProviderCard(
    service: CloudServiceStatus,
    timeFormat: SimpleDateFormat,
    onRefresh: () -> Unit
) {
    val indicatorColor = when {
        service.connection != CloudConnection.CONNECTED -> MaterialTheme.colorScheme.onSurfaceVariant
        service.indicator.operational -> EmeraldPrimary
        service.indicator == ServiceIndicator.MAINTENANCE -> CyberCyan
        service.indicator == ServiceIndicator.MINOR -> WarningAmber
        else -> AlertRed
    }
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(Color(0xFF071526))
            .border(1.dp, NavyBorder.copy(alpha = 0.85f), RoundedCornerShape(12.dp))
            .padding(14.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                if (service.connection == CloudConnection.CONNECTED) Icons.Default.Cloud else Icons.Default.CloudOff,
                contentDescription = null,
                tint = indicatorColor,
                modifier = Modifier.size(24.dp)
            )
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(service.provider.displayName, color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                Text(service.provider.role, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp)
            }
            StatusPill(
                when (service.connection) {
                    CloudConnection.NOT_CHECKED -> "Not connected"
                    CloudConnection.ERROR -> "Error"
                    CloudConnection.CONNECTED -> service.indicator.label
                },
                indicatorColor
            )
        }
        Spacer(Modifier.height(10.dp))
        when (service.connection) {
            CloudConnection.NOT_CHECKED -> Text(
                "This provider has not been checked yet. Tap refresh to read its public status page. " +
                    "Until then no security or availability claim is made.",
                color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp
            )
            CloudConnection.ERROR -> Text(
                "Could not reach the status page: ${service.error ?: "unknown error"}. " +
                    "Last attempt ${timeFormat.format(Date(service.fetchedAtEpochMs))}.",
                color = AlertRed, fontSize = 11.sp
            )
            CloudConnection.CONNECTED -> {
                Text(service.description ?: service.indicator.label, color = indicatorColor, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                val degraded = service.components.filter { !it.healthy }
                if (degraded.isEmpty()) {
                    Text("${service.components.size} component(s) operational.", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp)
                } else {
                    degraded.take(4).forEach { component ->
                        Text("• ${component.name}: ${component.status.replace('_', ' ')}", color = WarningAmber, fontSize = 11.sp)
                    }
                }
                Text(
                    "Fetched ${timeFormat.format(Date(service.fetchedAtEpochMs))}" +
                        (service.providerUpdatedAt?.let { " · provider updated $it" } ?: ""),
                    color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp, maxLines = 2, overflow = TextOverflow.Ellipsis
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            IconButton(onClick = onRefresh, modifier = Modifier.size(28.dp)) {
                Icon(Icons.Default.Refresh, contentDescription = "Refresh ${service.provider.displayName}", tint = SkyBlueGlow, modifier = Modifier.size(16.dp))
            }
        }
    }
}
