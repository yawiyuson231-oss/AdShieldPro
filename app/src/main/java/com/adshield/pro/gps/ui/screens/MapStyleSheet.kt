package com.adshield.pro.gps.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.gps.data.GpsPreferences
import com.adshield.pro.gps.ui.GpsAmber
import com.adshield.pro.gps.ui.GpsBackground
import com.adshield.pro.gps.ui.GpsBorder
import com.adshield.pro.gps.ui.GpsCyan
import com.adshield.pro.gps.ui.GpsPanel
import com.adshield.pro.gps.ui.GpsRed
import com.adshield.pro.gps.ui.GpsSectionTitle
import com.adshield.pro.gps.ui.GpsTextDim
import com.adshield.pro.gps.ui.GpsTextPrimary
import com.adshield.pro.gps.ui.GpsTextSecondary
import com.adshield.pro.gps.ui.GpsUiState

/**
 * MAP STYLE sheet — the real style/layer switcher behind the map's "Map style" button.
 *
 * Before this existed the button navigated to the Offline Maps tab, so the four published styles in
 * `GpsPreferences.STYLE_PRESETS` were unreachable and the only way to change the map's look was to
 * edit preferences. Everything here is a real MapLibre style URL: the presets are keyless and free
 * (OpenFreeMap, MIT), and the custom field accepts any self-hosted style — MapTiler, a tilemaker or
 * OpenMapTiles deployment, or a style served from the user's own machine.
 *
 * Changing the style re-creates MapLibre's sources and layers, which is why the engine re-applies
 * the route, trail, traffic and incidents after every style load.
 */
@Composable
fun MapStyleSheet(
    state: GpsUiState,
    onSelectStyle: (String) -> Unit,
    onToggleTraffic: () -> Unit,
    onToggleTerrainTilt: (Boolean) -> Unit,
    onRecentre: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    val current = state.mapStyleUrl
    var customUrl by remember { mutableStateOf("") }

    Column(
        modifier
            .fillMaxWidth()
            .padding(14.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            GpsSectionTitle("Map style", modifier = Modifier.weight(1f))
            IconButton(onClick = onDismiss, modifier = Modifier.size(28.dp)) {
                Icon(Icons.Default.Close, contentDescription = "Close", tint = GpsTextSecondary, modifier = Modifier.size(16.dp))
            }
        }

        Text(
            "Every style below is a free, keyless vector style over OpenStreetMap data. " +
                "The one in use is highlighted; switching re-draws your route and traffic overlay.",
            color = GpsTextDim,
            fontSize = 10.sp,
            lineHeight = 14.sp
        )

        GpsPreferences.STYLE_PRESETS.forEach { (label, url) ->
            StyleRow(
                label = label,
                subtitle = url.substringAfter("://").substringBefore("/styles"),
                selected = url == current,
                onClick = { onSelectStyle(url) }
            )
        }

        Spacer(Modifier.height(2.dp))
        GpsSectionTitle("Self-hosted or custom style", accent = GpsAmber)
        OutlinedTextField(
            value = customUrl,
            onValueChange = { customUrl = it },
            modifier = Modifier.fillMaxWidth(),
            placeholder = {
                Text("https://tiles.example.org/styles/yourstyle", color = GpsTextDim, fontSize = 11.sp)
            },
            singleLine = true,
            colors = OutlinedTextFieldDefaults.colors(
                focusedTextColor = GpsTextPrimary,
                unfocusedTextColor = GpsTextPrimary,
                focusedBorderColor = GpsCyan,
                unfocusedBorderColor = GpsBorder
            )
        )
        val trimmed = customUrl.trim()
        val valid = trimmed.startsWith("https://")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Box(
                Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(if (valid) GpsCyan else GpsBorder)
                    .clickable(enabled = valid) { onSelectStyle(trimmed) }
                    .padding(horizontal = 12.dp, vertical = 6.dp)
            ) {
                Text(
                    "Use this style",
                    color = if (valid) GpsBackground else GpsTextDim,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }
        if (trimmed.isNotEmpty() && !valid) {
            Text(
                "Only https:// style URLs are accepted. A plain-http style would be modified in transit " +
                    "and its tiles are not trusted.",
                color = GpsRed,
                fontSize = 9.sp,
                lineHeight = 12.sp
            )
        }

        Spacer(Modifier.height(2.dp))
        GpsSectionTitle("Layers")
        ToggleRow(
            label = "Traffic overlay",
            detail = "Community speed colours on the roads of the current route. Roads with no " +
                "observations stay grey — that is the honest state, not \"clear\".",
            enabled = state.trafficVisible,
            onToggle = { onToggleTraffic() }
        )
        ToggleRow(
            label = "3D buildings and tilt",
            detail = "Fill-extrusion buildings where the tile schema carries render_height, and the " +
                "camera tilt used in follow mode.",
            enabled = state.mapTerrainTilt,
            onToggle = { onToggleTerrainTilt(!state.mapTerrainTilt) }
        )
        Text(
            "Terrain (hills and valleys) is drawn only when the style's own source publishes a DEM. " +
                "No elevation tiles are bundled with the app.",
            color = GpsTextDim,
            fontSize = 9.sp,
            lineHeight = 12.sp
        )

        Spacer(Modifier.height(2.dp))
        GpsPanel {
            Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "Style loading failed? A first launch needs one connection to fetch the style " +
                        "document. After that the downloaded regions and the cached style keep working.",
                    color = GpsTextSecondary,
                    fontSize = 9.sp,
                    lineHeight = 12.sp,
                    modifier = Modifier.weight(1f)
                )
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Box(
                Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(GpsBackground)
                    .border(1.dp, GpsBorder, RoundedCornerShape(8.dp))
                    .clickable(onClick = onRecentre)
                    .padding(horizontal = 12.dp, vertical = 6.dp)
            ) {
                Text("Recentre on my position", color = GpsTextSecondary, fontSize = 10.sp)
            }
        }
        state.mapStyleError?.let { error ->
            Text(error, color = GpsRed, fontSize = 9.sp, lineHeight = 12.sp)
        }
    }
}

@Composable
private fun StyleRow(
    label: String,
    subtitle: String,
    selected: Boolean,
    onClick: () -> Unit
) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(9.dp))
            .background(if (selected) GpsCyan.copy(alpha = 0.12f) else GpsPanel)
            .border(
                1.dp,
                if (selected) GpsCyan else GpsBorder,
                RoundedCornerShape(9.dp)
            )
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, color = if (selected) GpsCyan else GpsTextPrimary, fontSize = 11.sp)
            Text(subtitle, color = GpsTextDim, fontSize = 8.sp, fontFamily = FontFamily.Monospace)
        }
        if (selected) {
            Icon(Icons.Default.Check, contentDescription = "In use", tint = GpsCyan, modifier = Modifier.size(15.dp))
        }
    }
}

@Composable
private fun ToggleRow(
    label: String,
    detail: String,
    enabled: Boolean,
    onToggle: () -> Unit
) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(9.dp))
            .background(GpsPanel)
            .border(1.dp, GpsBorder, RoundedCornerShape(9.dp))
            .clickable(onClick = onToggle)
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, color = toggleLabelColor(enabled), fontSize = 11.sp)
            Text(detail, color = GpsTextDim, fontSize = 9.sp, lineHeight = 12.sp)
        }
        Spacer(Modifier.width(8.dp))
        Box(
            Modifier
                .width(34.dp)
                .height(18.dp)
                .clip(RoundedCornerShape(9.dp))
                .background(if (enabled) GpsCyan.copy(alpha = 0.35f) else GpsBorder)
        ) {
            Box(
                Modifier
                    .padding(2.dp)
                    .size(14.dp)
                    .clip(RoundedCornerShape(7.dp))
                    .background(if (enabled) GpsCyan else GpsTextDim)
                    .align(if (enabled) Alignment.CenterEnd else Alignment.CenterStart)
            )
        }
    }
}

private fun toggleLabelColor(enabled: Boolean) = if (enabled) GpsTextPrimary else GpsTextSecondary
