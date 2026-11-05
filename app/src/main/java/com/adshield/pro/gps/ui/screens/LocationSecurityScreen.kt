package com.adshield.pro.gps.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.gps.engine.GpsFrame
import com.adshield.pro.gps.security.HistoryGuard
import com.adshield.pro.gps.ui.GpsAmber
import com.adshield.pro.gps.ui.GpsBackground
import com.adshield.pro.gps.ui.GpsBorder
import com.adshield.pro.gps.ui.GpsChip
import com.adshield.pro.gps.ui.GpsCyan
import com.adshield.pro.gps.ui.GpsGreen
import com.adshield.pro.gps.ui.GpsGrey
import com.adshield.pro.gps.ui.GpsInlineNotice
import com.adshield.pro.gps.ui.GpsKeyValue
import com.adshield.pro.gps.ui.GpsPanel
import com.adshield.pro.gps.ui.GpsRed
import com.adshield.pro.gps.ui.GpsSectionTitle
import com.adshield.pro.gps.ui.GpsTextDim
import com.adshield.pro.gps.ui.GpsTextPrimary
import com.adshield.pro.gps.ui.GpsTextSecondary
import com.adshield.pro.gps.ui.GpsToggleRow
import com.adshield.pro.gps.ui.GpsUiState
import com.adshield.pro.gps.ui.integrityColor

@Composable
private fun PermissionRow(permission: String, granted: Boolean, detail: String) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.Top
    ) {
        Box(
            Modifier
                .padding(top = 5.dp)
                .size(6.dp)
                .clip(RoundedCornerShape(50))
                .background(if (granted) GpsGreen else GpsGrey)
        )
        Spacer(Modifier.width(8.dp))
        Column(Modifier.weight(1f)) {
            Text(permission, color = GpsTextPrimary, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
            Text(detail, color = GpsTextDim, fontSize = 9.sp, lineHeight = 12.sp)
        }
        Text(
            if (granted) "granted" else "off",
            color = if (granted) GpsGreen else GpsGrey,
            fontSize = 9.sp
        )
    }
}

/**
 * LOCATION SECURITY — privacy switches and the integrity verdict.
 *
 * Two things this screen does NOT do: it does not claim to block a system-level spoofer, and it does
 * not hide the fact that the VPN/DNS module is unaffected by anything here. Every switch shows the
 * concrete consequence ("nothing is written to disk", "one average speed per segment"), because a
 * privacy toggle the user cannot reason about is not a privacy control.
 */
@Composable
fun LocationSecurityScreen(
    state: GpsUiState,
    frame: GpsFrame,
    onSetContributeTraffic: (Boolean) -> Unit,
    onSetRecordHistory: (Boolean) -> Unit,
    onSetCoarseHistory: (Boolean) -> Unit,
    onSetRetentionDays: (Int) -> Unit,
    onSetEmergencySharing: (Boolean) -> Unit,
    onSetEmergencyKillSwitch: (Boolean) -> Unit,
    onSetIncidentReporting: (Boolean) -> Unit,
    onSetVoiceGuidance: (Boolean) -> Unit,
    onSetBackgroundNavigation: (Boolean) -> Unit,
    onRegenerateToken: () -> Unit,
    onDeleteAll: () -> Unit,
    onRefreshPermissions: () -> Unit,
    onEmergencyShare: () -> Result<String>,
    modifier: Modifier = Modifier
) {
    val policy = state.policy
    val clipboard = LocalClipboardManager.current
    var shareText by remember { mutableStateOf<String?>(null) }
    var shareError by remember { mutableStateOf<String?>(null) }
    var confirmDelete by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(GpsBackground)
            .padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item(key = "security-verdict") {
            Spacer(Modifier.height(10.dp))
            GpsPanel(accent = integrityColor(frame.integrity.verdict)) {
                Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        GpsSectionTitle("Integrity", accent = GpsCyan, modifier = Modifier.weight(1f))
                        GpsChip(
                            text = frame.integrity.verdict.label.uppercase(),
                            color = integrityColor(frame.integrity.verdict),
                            filled = true,
                            icon = Icons.Default.Security
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    val audit = state.permissionAudit
                    GpsKeyValue("Fine location", if (audit?.fineLocationGranted == true) "granted" else "not granted")
                    GpsKeyValue("Coarse location", if (audit?.coarseLocationGranted == true) "granted" else "not granted")
                    GpsKeyValue("Background location", "never requested by this module")
                    GpsKeyValue("System location", if (audit?.locationEnabled == true) "on" else "off")
                    GpsKeyValue("Mock provider", if (frame.fix?.mockProviderFlag == true) "DETECTED" else "not detected")
                    GpsKeyValue(
                        "Mock app-op",
                        audit?.mockSettingApp ?: "not enabled",
                        valueColor = if (audit?.mockSettingApp != null) GpsAmber else GpsTextPrimary
                    )
                    Spacer(Modifier.height(8.dp))
                    audit?.findings()?.forEach { finding ->
                        Text(
                            "• $finding",
                            color = if (finding.startsWith("No anomalies")) GpsGreen else GpsAmber,
                            fontSize = 9.sp,
                            lineHeight = 13.sp
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "What this cannot do: an app cannot switch off Android's mock-location setting, and " +
                            "a rooted device with a system-level spoofing module can defeat every app-side " +
                            "check. The verdict above is a heuristic, and it is reported as one.",
                        color = GpsTextDim,
                        fontSize = 9.sp,
                        lineHeight = 13.sp
                    )
                }
            }
        }

        item(key = "security-permissions") {
            GpsPanel {
                Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        GpsSectionTitle("Permissions in use", accent = GpsCyan, modifier = Modifier.weight(1f))
                        Text(
                            "refresh",
                            color = GpsCyan,
                            fontSize = 9.sp,
                            modifier = Modifier.clickable(onClick = onRefreshPermissions).padding(4.dp)
                        )
                    }
                    Spacer(Modifier.height(6.dp))
                    val audit = state.permissionAudit
                    PermissionRow(
                        "ACCESS_FINE_LOCATION",
                        audit?.fineLocationGranted == true,
                        "Required for GNSS. Without it only network positioning is possible."
                    )
                    PermissionRow(
                        "ACCESS_COARSE_LOCATION",
                        audit?.coarseLocationGranted == true,
                        "Approximate positioning and map centring."
                    )
                    PermissionRow(
                        "FOREGROUND_SERVICE_LOCATION",
                        true,
                        "Keeps GNSS alive during navigation with the screen off. Declared in the manifest."
                    )
                    PermissionRow(
                        "ACCESS_BACKGROUND_LOCATION",
                        false,
                        "Deliberately not requested: this module never tracks you in the background."
                    )
                    PermissionRow(
                        "POST_NOTIFICATIONS",
                        audit?.notificationPermissionGranted == true,
                        "Needed to show the navigation foreground-service notification on Android 13+."
                    )
                    Spacer(Modifier.height(8.dp))
                    GpsInlineNotice(
                        "The DNS/VPN protection module does not read location and is unaffected by every " +
                            "switch on this screen.",
                        GpsCyan
                    )
                }
            }
        }

        item(key = "security-privacy") {
            GpsPanel {
                Column(Modifier.padding(12.dp)) {
                    GpsSectionTitle("Privacy controls", accent = GpsCyan)
                    Spacer(Modifier.height(4.dp))
                    GpsToggleRow(
                        title = "Contribute anonymous traffic",
                        detail = if (policy.contributeTraffic) {
                            "One average speed per road segment is queued. No coordinates, no route."
                        } else {
                            "Off. Nothing leaves the device; traffic shows only others' data."
                        },
                        checked = policy.contributeTraffic,
                        onCheckedChange = onSetContributeTraffic
                    )
                    GpsToggleRow(
                        title = "Report incidents",
                        detail = "Lets you submit accidents and hazards. Off by default.",
                        checked = policy.allowIncidentReporting,
                        onCheckedChange = onSetIncidentReporting
                    )
                    GpsToggleRow(
                        title = "Record trip history",
                        detail = if (policy.recordTripHistory) {
                            "Stored on this device, AES-256-GCM encrypted, ${HistoryGuard.retentionLabel(policy)}."
                        } else {
                            "Off. No trip, no track, no distance is written to disk."
                        },
                        checked = policy.recordTripHistory,
                        onCheckedChange = onSetRecordHistory
                    )
                    GpsToggleRow(
                        title = "Coarse history only",
                        detail = if (policy.coarseHistoryOnly) {
                            "Coordinates rounded to ~1 km — neighbourhoods, not addresses."
                        } else {
                            "Full precision stored in the encrypted track file."
                        },
                        checked = policy.coarseHistoryOnly,
                        onCheckedChange = onSetCoarseHistory,
                        enabled = policy.recordTripHistory
                    )
                    GpsToggleRow(
                        title = "Voice guidance",
                        detail = "Speaks turns using the installed Android TTS voice. Works offline.",
                        checked = policy.voiceGuidance,
                        onCheckedChange = onSetVoiceGuidance
                    )
                    GpsToggleRow(
                        title = "Background navigation",
                        detail = "Runs a foreground location service while navigating. Stops when navigation ends.",
                        checked = policy.backgroundNavigation,
                        onCheckedChange = onSetBackgroundNavigation
                    )
                    if (policy.recordTripHistory) {
                        Spacer(Modifier.height(6.dp))
                        Text("Retention", color = GpsTextSecondary, fontSize = 10.sp)
                        Spacer(Modifier.height(4.dp))
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            items(listOf(7, 14, 30, 90, 180, 365), key = { it }) { days ->
                                Box(
                                    Modifier
                                        .clip(RoundedCornerShape(7.dp))
                                        .background(
                                            if (policy.historyRetentionDays == days) GpsCyan.copy(alpha = 0.2f)
                                            else GpsBackground
                                        )
                                        .border(
                                            1.dp,
                                            if (policy.historyRetentionDays == days) GpsCyan else GpsBorder,
                                            RoundedCornerShape(7.dp)
                                        )
                                        .clickable { onSetRetentionDays(days) }
                                        .padding(horizontal = 10.dp, vertical = 5.dp)
                                ) {
                                    Text(
                                        "$days d",
                                        color = if (policy.historyRetentionDays == days) GpsCyan else GpsTextSecondary,
                                        fontSize = 10.sp
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        item(key = "security-emergency") {
            GpsPanel(accent = if (policy.emergencySharingDisabled) GpsRed else GpsBorder) {
                Column(Modifier.padding(12.dp)) {
                    GpsSectionTitle("Emergency location sharing", accent = GpsCyan)
                    Spacer(Modifier.height(4.dp))
                    GpsToggleRow(
                        title = "Allow emergency sharing",
                        detail = "Generates a text you copy yourself — the app never uploads it.",
                        checked = policy.allowEmergencySharing,
                        onCheckedChange = onSetEmergencySharing,
                        enabled = !policy.emergencySharingDisabled
                    )
                    GpsToggleRow(
                        title = "Kill switch",
                        detail = "Disables every sharing path, including the emergency one. Overrides the switch above.",
                        checked = policy.emergencySharingDisabled,
                        onCheckedChange = onSetEmergencyKillSwitch,
                        accent = GpsRed
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = {
                                val result = onEmergencyShare()
                                result.fold(
                                    onSuccess = { shareText = it; shareError = null },
                                    onFailure = { shareError = it.message; shareText = null }
                                )
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (policy.canShareEmergencyLocation) GpsCyan.copy(alpha = 0.16f) else GpsBackground,
                                contentColor = if (policy.canShareEmergencyLocation) GpsCyan else GpsTextDim
                            ),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Text("Generate location text", fontSize = 11.sp)
                        }
                        if (shareText != null) {
                            Button(
                                onClick = { clipboard.setText(AnnotatedString(shareText ?: "")) },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = GpsBackground,
                                    contentColor = GpsCyan
                                ),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Text("Copy", fontSize = 11.sp)
                            }
                        }
                    }
                    if (shareText != null) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            shareText ?: "",
                            color = GpsTextPrimary,
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            lineHeight = 14.sp
                        )
                    }
                    if (shareError != null) {
                        Spacer(Modifier.height(6.dp))
                        GpsInlineNotice(shareError ?: "", GpsAmber)
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Link target: openstreetmap.org — free, no account, no tracking. Full precision is " +
                            "used only here because an emergency is exactly the case that needs it.",
                        color = GpsTextDim,
                        fontSize = 9.sp,
                        lineHeight = 13.sp
                    )
                }
            }
        }

        item(key = "security-storage") {
            GpsPanel {
                Column(Modifier.padding(12.dp)) {
                    GpsSectionTitle("Local data", accent = GpsCyan)
                    Spacer(Modifier.height(6.dp))
                    GpsKeyValue("Storage", "AES-256-GCM, key in Android Keystore")
                    GpsKeyValue("Precision kept", HistoryGuard.precisionLabel(policy))
                    GpsKeyValue("Retention", HistoryGuard.retentionLabel(policy))
                    GpsKeyValue("Trips stored", state.trips.size.toString())
                    Spacer(Modifier.height(8.dp))
                    Button(
                        onClick = onRegenerateToken,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = GpsBackground,
                            contentColor = GpsCyan
                        ),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text("Regenerate anonymous token", fontSize = 11.sp)
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "The token only lets the traffic server ignore duplicate submissions. It is not " +
                            "derived from any device identifier.",
                        color = GpsTextDim,
                        fontSize = 9.sp,
                        lineHeight = 13.sp
                    )
                    Spacer(Modifier.height(12.dp))
                    if (!confirmDelete) {
                        Button(
                            onClick = { confirmDelete = true },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = GpsRed.copy(alpha = 0.15f),
                                contentColor = GpsRed
                            ),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Text("Delete all location data", fontSize = 11.sp)
                        }
                    } else {
                        GpsInlineNotice(
                            "This deletes trip history, encrypted tracks, traffic samples, your reports and " +
                                "the encryption key. It cannot be undone.",
                            GpsRed
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { onDeleteAll(); confirmDelete = false },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = GpsRed,
                                    contentColor = GpsBackground
                                ),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Text("Confirm delete", fontSize = 11.sp)
                            }
                            Button(
                                onClick = { confirmDelete = false },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = GpsBackground,
                                    contentColor = GpsTextSecondary
                                ),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Text("Cancel", fontSize = 11.sp)
                            }
                        }
                    }
                }
            }
        }

        item(key = "security-footer") {
            Column(Modifier.padding(vertical = 16.dp)) {
                Text(
                    "Location is read only while a GPS screen is open or navigation is active. " +
                        "The DNS/VPN engine is a separate service and never touches these APIs.",
                    color = GpsTextDim,
                    fontSize = 9.sp,
                    lineHeight = 13.sp
                )
            }
        }
    }
}
