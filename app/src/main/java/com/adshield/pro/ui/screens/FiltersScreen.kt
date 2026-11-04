package com.adshield.pro.ui.screens

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CloudSync
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.domain.model.FilterListSource
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.WarningAmber
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun FiltersScreen(
    sources: List<FilterListSource>,
    settings: AppSettingsState,
    isUpdating: Boolean,
    onToggleSource: (FilterListSource, Boolean) -> Unit,
    onSyncAllNow: () -> Unit,
    onAddCustomSource: (String, String, RuleCategory) -> Unit,
    onDeleteCustomSource: (String) -> Unit,
    onUpdateAutoSyncSchedule: (Boolean, Int) -> Unit
) {
    var showAddDialog by remember { mutableStateOf(false) }

    val totalActiveRules = sources.filter { it.isEnabled }.sumOf { it.ruleCount }
    val totalDuplicatesStripped = sources.filter { it.isEnabled }.sumOf { it.duplicateCount }
    val dateFormat = remember { SimpleDateFormat("MMM dd, HH:mm", Locale.US) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Filter Lists & Blocklists",
                        style = MaterialTheme.typography.headlineMedium
                    )
                    Text(
                        text = "$totalActiveRules compiled rules • $totalDuplicatesStripped duplicates removed",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                Button(
                    onClick = onSyncAllNow,
                    enabled = !isUpdating,
                    colors = ButtonDefaults.buttonColors(containerColor = ElectricBlue)
                ) {
                    Icon(
                        imageVector = Icons.Default.CloudSync,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Evolve Now")
                }
            }
        }

        if (isUpdating) {
            item {
                Column {
                    Text(
                        text = "Checking enabled filter lists and saving a verified update…",
                        style = MaterialTheme.typography.labelMedium,
                        color = ElectricBlue
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    LinearProgressIndicator(
                        modifier = Modifier.fillMaxWidth(),
                        color = ElectricBlue
                    )
                }
            }
        }

        // Automatic Update Schedule Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(
                            modifier = Modifier
                                .weight(1f)
                                .padding(end = 12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Default.Schedule,
                                contentDescription = null,
                                tint = CyberCyan
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text(
                                    text = "AETHER Protection Evolution",
                                    style = MaterialTheme.typography.titleMedium
                                )
                                Text(
                                    text = "Validated rules, source-health learning and signed update discovery. Reversible by design.",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }

                        Switch(
                            checked = settings.autoUpdateFiltersEnabled,
                            onCheckedChange = {
                                onUpdateAutoSyncSchedule(it, settings.updateIntervalHours)
                            }
                        )
                    }

                    if (settings.autoUpdateFiltersEnabled) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "Sync Frequency:",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            listOf(6 to "Every 6h", 12 to "Every 12h", 24 to "Daily").forEach { (hours, label) ->
                                FilterChip(
                                    selected = settings.updateIntervalHours == hours,
                                    onClick = { onUpdateAutoSyncSchedule(true, hours) },
                                    label = {
                                        Text(
                                            text = label,
                                            style = MaterialTheme.typography.labelMedium,
                                            maxLines = 1
                                        )
                                    },
                                    modifier = Modifier.weight(1f)
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))
                    val evolutionColor = when (settings.lastEvolutionStatus) {
                        "SUCCESS" -> Color(0xFF22D3A6)
                        "COMPLETED_WITH_WARNINGS" -> WarningAmber
                        "FAILED" -> AlertRed
                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                    }
                    Text(
                        text = settings.lastEvolutionStatus.replace('_', ' '),
                        color = evolutionColor,
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = settings.lastEvolutionMessage,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (settings.lastEvolutionRunEpochMs > 0L) {
                        Text(
                            text = "Last run ${dateFormat.format(Date(settings.lastEvolutionRunEpochMs))} • " +
                                "${settings.evolutionRunCount} recorded run(s) • ${settings.lastEvolutionRuleCount} rules",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Text(
                        text = if (settings.availableAppVersion != null) {
                            "Signed app update available: ${settings.availableAppVersion}. Review it from Settings → Check for updates."
                        } else if (settings.lastAppUpdateCheckEpochMs > 0L) {
                            "App update channel checked ${dateFormat.format(Date(settings.lastAppUpdateCheckEpochMs))}; no newer verified release recorded."
                        } else {
                            "Signed app releases are checked daily. Android always asks before installation."
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = if (settings.availableAppVersion != null) CyberCyan else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "Protection data evolves automatically; executable code never rewrites or installs itself.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        // Add Custom Source Button
        item {
            OutlinedButton(
                onClick = { showAddDialog = true },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(imageVector = Icons.Default.Add, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Add Custom HTTPS Filter List URL")
            }
        }

        // Filter List Cards
        items(sources, key = { it.id }) { source ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.Top
                    ) {
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .padding(end = 12.dp)
                        ) {
                            Text(
                                text = source.name,
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Surface(
                                color = Color(source.category.badgeColorHex).copy(alpha = 0.2f),
                                shape = RoundedCornerShape(6.dp)
                            ) {
                                Text(
                                    text = source.category.displayName,
                                    style = MaterialTheme.typography.labelMedium,
                                    color = Color(source.category.badgeColorHex),
                                    maxLines = 1,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                                )
                            }

                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = source.description,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        Switch(
                            checked = source.isEnabled,
                            onCheckedChange = { onToggleSource(source, it) }
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "License: ${source.licenseName} • ${source.lastStatusMessage}",
                                style = MaterialTheme.typography.labelMedium,
                                color = ElectricBlue
                            )
                            val updatedText = if (source.lastUpdatedEpochMs > 0L) {
                                "Updated ${dateFormat.format(Date(source.lastUpdatedEpochMs))}"
                            } else {
                                "Not yet downloaded"
                            }
                            Text(
                                text = "$updatedText • ${source.ruleCount} rules (${source.duplicateCount} duplicates skipped)",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        if (!source.isBuiltIn) {
                            IconButton(onClick = { onDeleteCustomSource(source.id) }) {
                                Icon(
                                    imageVector = Icons.Default.Delete,
                                    contentDescription = "Delete Custom List",
                                    tint = AlertRed
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (showAddDialog) {
        var customName by remember { mutableStateOf("") }
        var customUrl by remember { mutableStateOf("https://") }
        var selectedCategory by remember { mutableStateOf(RuleCategory.ADS) }

        AlertDialog(
            onDismissRequest = { showAddDialog = false },
            title = { Text("Add Custom Filter List") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(
                        value = customName,
                        onValueChange = { customName = it },
                        label = { Text("List Name") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = customUrl,
                        onValueChange = { customUrl = it },
                        label = { Text("HTTPS Filter List URL (Hosts or Adblock DNS)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text(
                        text = "Category:",
                        style = MaterialTheme.typography.labelMedium
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        listOf(RuleCategory.ADS, RuleCategory.TRACKERS, RuleCategory.MALWARE).forEach { cat ->
                            FilterChip(
                                selected = selectedCategory == cat,
                                onClick = { selectedCategory = cat },
                                label = { Text(cat.displayName, style = MaterialTheme.typography.labelMedium) }
                            )
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        onAddCustomSource(customName, customUrl, selectedCategory)
                        showAddDialog = false
                    }
                ) {
                    Text("Add & Validate")
                }
            },
            dismissButton = {
                TextButton(onClick = { showAddDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}
