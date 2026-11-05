package com.adshield.pro.ui.cybershield

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.cybershield.CsDataSource
import com.adshield.pro.cybershield.CsLoadState
import com.adshield.pro.cybershield.CsSeverity

/**
 * CyberShield AI visual identity — dark navy SOC console with electric
 * blue/cyan neon lighting. Scoped to the dashboard; the rest of the app keeps
 * its existing Material 3 theme.
 */
object Cs {
    val Background = Color(0xFF040B18)
    val BackgroundDeep = Color(0xFF02060F)
    val Surface = Color(0xFF081426)
    val SurfaceAlt = Color(0xFF0B1D36)
    val SurfaceRaised = Color(0xFF0F2440)
    val Border = Color(0xFF13365C)
    val BorderBright = Color(0xFF1E4E82)

    val NeonBlue = Color(0xFF2E7CFF)
    val Cyan = Color(0xFF00E5FF)
    val CyanDim = Color(0xFF0E7490)
    val Green = Color(0xFF22F2A6)
    val Amber = Color(0xFFFFB020)
    val Red = Color(0xFFFF3B5C)
    val Purple = Color(0xFF9D6BFF)
    val Steel = Color(0xFF5E7BA6)

    val Text = Color(0xFFE6F1FF)
    val TextDim = Color(0xFF7C93B5)
    val TextFaint = Color(0xFF4A6285)

    val CardShape = RoundedCornerShape(14.dp)
    val ChipShape = RoundedCornerShape(6.dp)

    val mono = FontFamily.Monospace

    fun severityColor(severity: CsSeverity): Color = when (severity) {
        CsSeverity.CRITICAL -> Red
        CsSeverity.HIGH -> Color(0xFFFF7A45)
        CsSeverity.MEDIUM -> Amber
        CsSeverity.LOW -> Cyan
        CsSeverity.INFO -> Steel
    }

    fun categoryColor(category: String): Color = when (category) {
        "MALWARE" -> Red
        "TRACKERS" -> Amber
        "ADS" -> NeonBlue
        "STRICT_TELEMETRY" -> Purple
        "CUSTOM" -> Green
        else -> Steel
    }

    fun categoryLabel(category: String): String = when (category) {
        "MALWARE" -> "Malware / Phishing"
        "TRACKERS" -> "Tracking & Analytics"
        "ADS" -> "Advertising"
        "STRICT_TELEMETRY" -> "Telemetry"
        "CUSTOM" -> "Custom rules"
        else -> "Other"
    }
}

/** Futuristic bordered card with a subtle neon edge gradient. */
@Composable
fun NeonCard(
    modifier: Modifier = Modifier,
    glowColor: Color = Cs.Cyan,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        modifier = modifier
            .clip(Cs.CardShape)
            .background(
                Brush.verticalGradient(listOf(Cs.SurfaceAlt, Cs.Surface))
            )
            .border(
                width = 1.dp,
                brush = Brush.linearGradient(
                    listOf(glowColor.copy(alpha = 0.45f), Cs.Border, glowColor.copy(alpha = 0.18f))
                ),
                shape = Cs.CardShape
            )
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        content = content
    )
}

@Composable
fun CardHeader(
    title: String,
    accent: Color = Cs.Cyan,
    trailing: (@Composable () -> Unit)? = null
) {
    Row(
        modifier = Modifier.padding(bottom = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Box(
            Modifier
                .size(7.dp)
                .clip(CircleShape)
                .background(accent)
        )
        Text(
            text = title.uppercase(),
            color = Cs.Text,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.6.sp,
            fontFamily = Cs.mono,
            modifier = Modifier.weight(1f)
        )
        trailing?.invoke()
    }
}

@Composable
fun StatusChip(
    text: String,
    color: Color,
    modifier: Modifier = Modifier,
    filled: Boolean = false
) {
    Text(
        text = text.uppercase(),
        color = if (filled) Cs.BackgroundDeep else color,
        fontSize = 9.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = 0.8.sp,
        fontFamily = Cs.mono,
        modifier = modifier
            .clip(Cs.ChipShape)
            .background(if (filled) color else color.copy(alpha = 0.12f))
            .border(1.dp, color.copy(alpha = if (filled) 0f else 0.5f), Cs.ChipShape)
            .padding(horizontal = 6.dp, vertical = 3.dp)
    )
}

@Composable
fun SourceChip(source: CsDataSource) {
    val color = when (source) {
        CsDataSource.ON_DEVICE -> Cs.Cyan
        CsDataSource.LOCAL_CHECK -> Cs.Green
        CsDataSource.EXTERNAL_INTEL -> Cs.Purple
        CsDataSource.DEMO -> Cs.Amber
    }
    StatusChip(text = source.label, color = color)
}

@Composable
fun LoadStateChip(state: CsLoadState) {
    when (state) {
        CsLoadState.LIVE -> StatusChip("Live", Cs.Green)
        CsLoadState.CACHED -> StatusChip("Cached", Cs.Amber)
        CsLoadState.LOADING -> StatusChip("Loading", Cs.Cyan)
        CsLoadState.ERROR -> StatusChip("Offline", Cs.Red)
        CsLoadState.DISABLED -> StatusChip("Disabled", Cs.Steel)
        CsLoadState.NEVER_LOADED -> StatusChip("Not loaded", Cs.Steel)
    }
}

@Composable
fun SeverityChip(severity: CsSeverity) {
    StatusChip(text = severity.name, color = Cs.severityColor(severity))
}

@Composable
fun KeyValueLine(key: String, value: String, valueColor: Color = Cs.Text) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(key, color = Cs.TextDim, fontSize = 12.sp, modifier = Modifier.weight(1f))
        Text(value, color = valueColor, fontSize = 12.sp, fontFamily = Cs.mono, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
fun EmptyState(message: String, icon: String = "◇") {
    Column(
        modifier = Modifier
            .padding(vertical = 14.dp)
            .background(Color.Transparent),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Text(icon, color = Cs.CyanDim, fontSize = 22.sp)
        Text(message, color = Cs.TextDim, fontSize = 12.sp, lineHeight = 17.sp)
    }
}

@Composable
fun HonestNote(text: String) {
    Text(
        text = text,
        color = Cs.TextFaint,
        fontSize = 10.sp,
        lineHeight = 14.sp,
        modifier = Modifier
            .clip(Cs.ChipShape)
            .background(Cs.BackgroundDeep.copy(alpha = 0.5f))
            .padding(horizontal = 8.dp, vertical = 6.dp)
    )
}

fun relativeTime(epochMs: Long, nowMs: Long): String {
    val delta = (nowMs - epochMs).coerceAtLeast(0L)
    return when {
        delta < 60_000 -> "${delta / 1000}s ago"
        delta < 3_600_000 -> "${delta / 60_000}m ago"
        delta < 86_400_000 -> "${delta / 3_600_000}h ago"
        else -> "${delta / 86_400_000}d ago"
    }
}

fun clockTime(epochMs: Long): String {
    val sdf = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
    return sdf.format(java.util.Date(epochMs))
}
