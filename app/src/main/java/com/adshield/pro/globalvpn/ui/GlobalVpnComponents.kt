package com.adshield.pro.globalvpn.ui

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.globalvpn.model.AvailabilityStatus
import com.adshield.pro.globalvpn.model.TunnelPhase
import com.adshield.pro.ui.components.rememberAnimationsEnabled
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.NavyBorder
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber
import kotlin.math.cos
import kotlin.math.sin

fun phaseColor(phase: TunnelPhase): Color = when (phase) {
    TunnelPhase.CONNECTED -> EmeraldPrimary
    TunnelPhase.CONNECTING, TunnelPhase.RECONNECTING, TunnelPhase.PREPARING -> CyberCyan
    TunnelPhase.ERROR -> AlertRed
    TunnelPhase.DISCONNECTING -> WarningAmber
    TunnelPhase.IDLE -> Color(0xFF5B718C)
}

fun phaseLabel(phase: TunnelPhase): String = when (phase) {
    TunnelPhase.CONNECTED -> "CONNECTED"
    TunnelPhase.CONNECTING -> "CONNECTING"
    TunnelPhase.RECONNECTING -> "RECONNECTING"
    TunnelPhase.PREPARING -> "PREPARING"
    TunnelPhase.DISCONNECTING -> "DISCONNECTING"
    TunnelPhase.ERROR -> "ERROR"
    TunnelPhase.IDLE -> "DISCONNECTED"
}

fun formatBytes(bytes: Long): String {
    val kb = bytes / 1024.0
    val mb = kb / 1024.0
    val gb = mb / 1024.0
    return when {
        gb >= 1 -> String.format("%.2f GB", gb)
        mb >= 1 -> String.format("%.1f MB", mb)
        else -> String.format("%.0f KB", kb)
    }
}

fun formatRate(bytesPerSec: Long): String {
    val kb = bytesPerSec / 1024.0
    return if (kb >= 1024) String.format("%.1f MB/s", kb / 1024.0) else String.format("%.0f KB/s", kb)
}

fun formatDuration(sinceEpochMs: Long?): String {
    if (sinceEpochMs == null) return "00:00"
    val seconds = ((System.currentTimeMillis() - sinceEpochMs) / 1000).coerceAtLeast(0)
    val h = seconds / 3600
    val m = (seconds % 3600) / 60
    val s = seconds % 60
    return if (h > 0) String.format("%d:%02d:%02d", h, m, s) else String.format("%02d:%02d", m, s)
}

/** Approximate schematic coordinates for real servers; decorative, not a location claim. */
private fun countryLatLng(code: String): Pair<Float, Float>? = when (code.uppercase()) {
    "US", "USA" -> 39f to -98f
    "CA" -> 56f to -106f
    "GB", "UK" -> 54f to -2f
    "DE" -> 51f to 10f
    "FR" -> 46f to 2f
    "NL" -> 52f to 5f
    "CH" -> 47f to 8f
    "SE" -> 62f to 15f
    "NO" -> 61f to 9f
    "IS" -> 65f to -18f
    "JP" -> 36f to 138f
    "SG" -> 1f to 104f
    "AU" -> -25f to 134f
    "PH" -> 13f to 122f
    "IN" -> 21f to 78f
    "BR" -> -10f to -52f
    "IT" -> 42f to 12f
    "ES" -> 40f to -4f
    "PL" -> 52f to 19f
    "RO" -> 46f to 25f
    else -> null
}

/**
 * Schematic "3D-style" globe. Animation is confined to Canvas draw state, runs only while connected
 * and only when system animations are enabled, so it is battery-efficient and idle-safe.
 */
@Composable
fun GlobalGlobe(
    phase: TunnelPhase,
    serverCountryCodes: List<String>,
    connectedCountryCode: String?,
    modifier: Modifier = Modifier
) {
    val connected = phase == TunnelPhase.CONNECTED
    val animate = rememberAnimationsEnabled() && connected
    val accent = phaseColor(phase)
    val rotation = if (animate) {
        val transition = rememberInfiniteTransition(label = "globe")
        val value by transition.animateFloat(
            initialValue = 0f, targetValue = 360f,
            animationSpec = infiniteRepeatable(tween(40000, easing = LinearEasing), RepeatMode.Restart),
            label = "globe-rotation"
        )
        value
    } else {
        0f
    }
    val pulse = if (animate) {
        val transition = rememberInfiniteTransition(label = "globe-pulse")
        val value by transition.animateFloat(
            initialValue = 0.3f, targetValue = 1f,
            animationSpec = infiniteRepeatable(tween(1600, easing = LinearEasing), RepeatMode.Reverse),
            label = "globe-pulse"
        )
        value
    } else {
        0.5f
    }

    Canvas(modifier = modifier) {
        val cx = size.width / 2f
        val cy = size.height / 2f
        val r = size.minDimension * 0.42f

        drawCircle(
            brush = Brush.radialGradient(
                listOf(accent.copy(alpha = 0.16f), Color.Transparent),
                center = Offset(cx, cy), radius = r * 1.4f
            ),
            radius = r * 1.4f, center = Offset(cx, cy)
        )
        drawCircle(color = Color(0xFF071526), radius = r, center = Offset(cx, cy))
        drawCircle(color = NavyBorder.copy(alpha = 0.9f), radius = r, center = Offset(cx, cy), style = Stroke(1.5f))

        // Graticule
        for (i in 1..3) {
            val rr = r * i / 4f
            drawCircle(color = NavyBorder.copy(alpha = 0.35f), radius = rr, center = Offset(cx, cy), style = Stroke(0.7f))
        }
        drawLine(NavyBorder.copy(alpha = 0.35f), Offset(cx - r, cy), Offset(cx + r, cy), 0.7f)
        drawLine(NavyBorder.copy(alpha = 0.35f), Offset(cx, cy - r), Offset(cx, cy + r), 0.7f)

        fun project(lat: Float, lon: Float): Offset? {
            val lambda = Math.toRadians((lon + rotation).toDouble())
            val phi = Math.toRadians(lat.toDouble())
            val x = cos(phi) * sin(lambda)
            val y = sin(phi)
            val z = cos(phi) * cos(lambda)
            if (z < -0.05) return null
            return Offset(cx + (r * x).toFloat(), cy - (r * y).toFloat())
        }

        for (code in serverCountryCodes) {
            val ll = countryLatLng(code) ?: continue
            val p = project(ll.first, ll.second) ?: continue
            val isConnected = connected && code.equals(connectedCountryCode, ignoreCase = true)
            val dotColor = if (isConnected) accent else SkyBlueGlow.copy(alpha = 0.7f)
            val dotRadius = if (isConnected) 5f + 3f * pulse else 3f
            if (isConnected) {
                drawCircle(color = accent.copy(alpha = 0.25f * pulse), radius = dotRadius * 3, center = p)
            }
            drawCircle(color = dotColor, radius = dotRadius, center = p)
        }
    }
}

@Composable
fun ConnectButton(
    phase: TunnelPhase,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val connected = phase == TunnelPhase.CONNECTED
    val busy = phase == TunnelPhase.CONNECTING || phase == TunnelPhase.RECONNECTING || phase == TunnelPhase.PREPARING
    val color = phaseColor(phase)
    val label = when {
        connected -> "DISCONNECT"
        busy -> "CONNECTING…"
        phase == TunnelPhase.ERROR -> "RETRY"
        else -> "CONNECT"
    }
    Box(
        modifier = modifier
            .size(150.dp)
            .clip(CircleShape)
            .background(
                Brush.radialGradient(
                    listOf(color.copy(alpha = 0.28f), color.copy(alpha = 0.06f))
                )
            )
            .border(2.dp, color.copy(alpha = 0.8f), CircleShape)
            .clickable(enabled = !busy, onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(label, color = color, fontWeight = FontWeight.Bold, fontSize = 16.sp, letterSpacing = 1.sp)
        }
    }
}

@Composable
fun StatTile(label: String, value: String, modifier: Modifier = Modifier, accent: Color = SkyBlueGlow) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(Color(0xFF08182B))
            .border(1.dp, NavyBorder.copy(alpha = 0.6f), RoundedCornerShape(12.dp))
            .padding(12.dp)
    ) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp, letterSpacing = 0.6.sp, maxLines = 1)
        Spacer(Modifier.height(4.dp))
        Text(value, color = accent, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
    }
}

@Composable
fun AvailabilityBadge(status: AvailabilityStatus, modifier: Modifier = Modifier) {
    val color = when (status) {
        AvailabilityStatus.IMPLEMENTED -> EmeraldPrimary
        AvailabilityStatus.PARTIAL -> WarningAmber
        AvailabilityStatus.UNAVAILABLE -> AlertRed
    }
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(50))
            .background(color.copy(alpha = 0.14f))
            .border(1.dp, color.copy(alpha = 0.5f), RoundedCornerShape(50))
            .padding(horizontal = 8.dp, vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.size(6.dp).clip(CircleShape).background(color))
        Spacer(Modifier.width(6.dp))
        Text(status.label, color = color, fontSize = 10.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
    }
}

@Composable
fun GlassPanel(
    title: String,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
    content: @Composable () -> Unit
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(
                Brush.verticalGradient(listOf(Color(0xFF0A1B30).copy(alpha = 0.9f), Color(0xFF040C17).copy(alpha = 0.95f)))
            )
            .border(1.dp, NavyBorder.copy(alpha = 0.7f), RoundedCornerShape(16.dp))
            .padding(16.dp)
    ) {
        Text(title.uppercase(), color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.8.sp)
        if (subtitle != null) {
            Text(subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp)
        }
        Spacer(Modifier.height(10.dp))
        content()
    }
}

@Composable
fun EmptyState(text: String, modifier: Modifier = Modifier) {
    Box(modifier = modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
        Text(text, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
    }
}
