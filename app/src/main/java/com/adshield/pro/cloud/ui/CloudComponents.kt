package com.adshield.pro.cloud.ui

import androidx.compose.animation.core.animateFloatAsState
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
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Movie
import androidx.compose.material.icons.filled.MusicNote
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.cloud.data.CloudNodeDto
import com.adshield.pro.cloud.util.ByteFormat
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.EmeraldGlow
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.PurpleAccent
import com.adshield.pro.ui.theme.WarningAmber
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Shared visual language for the cloud module: glass panels, neon accents, live gauges. */
val CloudPanel = Color(0xFF0B1728)
val CloudPanelBorder = Color(0xFF1B3355)

@Composable
fun GlassPanel(
    modifier: Modifier = Modifier,
    accent: Color = EmeraldPrimary,
    content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(
                Brush.verticalGradient(listOf(CloudPanel, CloudPanel.copy(alpha = 0.82f))),
                RoundedCornerShape(20.dp)
            )
            .border(
                1.dp,
                Brush.linearGradient(listOf(accent.copy(alpha = 0.55f), CloudPanelBorder)),
                RoundedCornerShape(20.dp)
            )
            .padding(16.dp),
        content = content
    )
}

@Composable
fun SectionHeader(title: String, subtitle: String? = null, accent: Color = EmeraldPrimary) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .size(width = 4.dp, height = 22.dp)
                .background(accent, RoundedCornerShape(2.dp))
        )
        Spacer(Modifier.width(10.dp))
        Column {
            Text(
                text = title.uppercase(),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.2.sp,
                color = Color.White
            )
            if (subtitle != null) {
                Text(subtitle, style = MaterialTheme.typography.labelMedium, color = Color(0xFF8FA6C4))
            }
        }
    }
}

@Composable
fun StatTile(
    label: String,
    value: String,
    caption: String? = null,
    accent: Color = EmeraldPrimary,
    icon: ImageVector? = null,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .background(CloudPanel.copy(alpha = 0.9f), RoundedCornerShape(16.dp))
            .border(1.dp, accent.copy(alpha = 0.35f), RoundedCornerShape(16.dp))
            .padding(12.dp)
    ) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (icon != null) {
                    Icon(icon, contentDescription = null, tint = accent, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                }
                Text(label, style = MaterialTheme.typography.labelMedium, color = Color(0xFF8FA6C4), maxLines = 1)
            }
            Spacer(Modifier.height(6.dp))
            Text(value, style = MaterialTheme.typography.titleLarge, color = Color.White, maxLines = 1)
            if (caption != null) {
                Text(caption, style = MaterialTheme.typography.labelMedium, color = accent.copy(alpha = 0.8f), maxLines = 1)
            }
        }
    }
}

/**
 * Circular storage gauge. Values come straight from the API quota response —
 * nothing is synthesised, so an empty account reads 0 B of a real quota.
 */
@Composable
fun StorageGauge(
    usedBytes: Long,
    totalBytes: Long,
    modifier: Modifier = Modifier,
    label: String = "Cloud storage"
) {
    val fraction = if (totalBytes <= 0) 0f else (usedBytes.toFloat() / totalBytes.toFloat()).coerceIn(0f, 1f)
    val animated by animateFloatAsState(targetValue = fraction, animationSpec = tween(700), label = "storageArc")
    val ringColor = when {
        fraction >= 0.95f -> AlertRed
        fraction >= 0.8f -> WarningAmber
        else -> EmeraldGlow
    }

    Column(modifier = modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Box(contentAlignment = Alignment.Center) {
            Canvas(Modifier.size(168.dp)) {
                val stroke = Stroke(width = 16f, cap = StrokeCap.Round)
                drawArc(
                    color = Color(0xFF16263F),
                    startAngle = 135f,
                    sweepAngle = 270f,
                    useCenter = false,
                    style = stroke,
                    topLeft = Offset(8f, 8f),
                    size = Size(size.width - 16f, size.height - 16f)
                )
                drawArc(
                    brush = Brush.sweepGradient(listOf(ringColor, CyberCyan, ringColor)),
                    startAngle = 135f,
                    sweepAngle = 270f * animated,
                    useCenter = false,
                    style = stroke,
                    topLeft = Offset(8f, 8f),
                    size = Size(size.width - 16f, size.height - 16f)
                )
            }
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    text = "${(fraction * 100).toInt()}%",
                    style = MaterialTheme.typography.headlineLarge,
                    color = Color.White,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = ByteFormat.human(usedBytes),
                    style = MaterialTheme.typography.labelMedium,
                    color = Color(0xFF8FA6C4)
                )
            }
        }
        Spacer(Modifier.height(6.dp))
        Text(
            text = "${ByteFormat.human(usedBytes)} of ${ByteFormat.human(totalBytes)}",
            style = MaterialTheme.typography.bodyMedium,
            color = Color(0xFFB9CBDF)
        )
        Text(label, style = MaterialTheme.typography.labelMedium, color = Color(0xFF7D93B1))
    }
}

@Composable
fun StatusPill(text: String, color: Color, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier
            .background(color.copy(alpha = 0.16f), RoundedCornerShape(50))
            .border(1.dp, color.copy(alpha = 0.5f), RoundedCornerShape(50))
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.size(7.dp).background(color, RoundedCornerShape(50)))
        Spacer(Modifier.width(6.dp))
        Text(text, style = MaterialTheme.typography.labelMedium, color = color, maxLines = 1)
    }
}

@Composable
fun MetricBar(label: String, value: String, fraction: Float, accent: Color = EmeraldPrimary) {
    Column(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = Color(0xFF9BB0CB))
            Text(value, style = MaterialTheme.typography.labelMedium, color = accent)
        }
        Spacer(Modifier.height(4.dp))
        Box(
            Modifier
                .fillMaxWidth()
                .height(7.dp)
                .background(Color(0xFF15253C), RoundedCornerShape(50))
        ) {
            Box(
                Modifier
                    .fillMaxWidth(fraction.coerceIn(0f, 1f))
                    .height(7.dp)
                    .background(Brush.horizontalGradient(listOf(accent, CyberCyan)), RoundedCornerShape(50))
            )
        }
    }
}

fun nodeIcon(node: CloudNodeDto): ImageVector = when {
    node.isFolder -> Icons.Default.Folder
    node.isImage -> Icons.Default.Image
    node.isVideo -> Icons.Default.Movie
    node.isAudio -> Icons.Default.MusicNote
    node.mime?.contains("pdf") == true || node.mime?.startsWith("text/") == true -> Icons.Default.Description
    node.mime?.startsWith("application/") == true -> Icons.Default.Description
    else -> Icons.Default.InsertDriveFile
}

fun nodeAccent(node: CloudNodeDto): Color = when {
    node.isQuarantined -> AlertRed
    node.isFolder -> CyberCyan
    node.isImage -> EmeraldGlow
    node.isVideo -> PurpleAccent
    node.isAudio -> WarningAmber
    else -> Color(0xFF7FB2FF)
}

@Composable
fun FileRow(
    node: CloudNodeDto,
    onClick: () -> Unit,
    trailing: @Composable (() -> Unit)? = null
) {
    val accent = nodeAccent(node)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .background(Color(0xFF0E1C30).copy(alpha = 0.75f), RoundedCornerShape(14.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier
                .size(40.dp)
                .background(accent.copy(alpha = 0.14f), RoundedCornerShape(12.dp)),
            contentAlignment = Alignment.Center
        ) {
            Icon(nodeIcon(node), contentDescription = null, tint = accent, modifier = Modifier.size(20.dp))
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(
                node.name,
                style = MaterialTheme.typography.titleMedium,
                color = Color.White,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            val meta = buildString {
                if (node.isFolder) append("Folder") else append(ByteFormat.human(node.size))
                if (node.version > 1) append(" • v${node.version}")
                if (node.encrypted) append(" • encrypted")
                if (node.scanStatus == "infected") append(" • QUARANTINED")
                append(" • ").append(formatRelative(node.updatedAt))
            }
            Text(meta, style = MaterialTheme.typography.labelMedium, color = Color(0xFF8195B0), maxLines = 1)
        }
        if (trailing != null) trailing()
    }
}

@Composable
fun EmptyState(title: String, message: String, icon: ImageVector = Icons.Default.Cloud) {
    Column(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(icon, contentDescription = null, tint = Color(0xFF2C4468), modifier = Modifier.size(44.dp))
        Spacer(Modifier.height(8.dp))
        Text(title, style = MaterialTheme.typography.titleMedium, color = Color(0xFFB9CBDF))
        Text(
            message,
            style = MaterialTheme.typography.bodyMedium,
            color = Color(0xFF7D93B1),
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 4.dp)
        )
    }
}

private val relativeFormatter = SimpleDateFormat("dd MMM, HH:mm", Locale.US)

fun formatRelative(epochMs: Long): String {
    if (epochMs <= 0) return "—"
    val delta = System.currentTimeMillis() - epochMs
    return when {
        delta < 60_000 -> "just now"
        delta < 3_600_000 -> "${delta / 60_000} min ago"
        delta < 86_400_000 -> "${delta / 3_600_000} h ago"
        else -> relativeFormatter.format(Date(epochMs))
    }
}

fun formatTimestamp(epochMs: Long): String =
    if (epochMs <= 0) "—" else relativeFormatter.format(Date(epochMs))
