package com.adshield.pro.ui.components

import android.provider.Settings
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SmallFloatingActionButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.NavyBorder
import kotlinx.coroutines.launch

/** Shared visual language for the cyber-console dashboard. */
val CyberPanelShape = RoundedCornerShape(14.dp)

@Composable
fun rememberAnimationsEnabled(): Boolean {
    val context = LocalContext.current
    return remember(context) {
        runCatching {
            Settings.Global.getFloat(context.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) > 0f &&
                Settings.Global.getFloat(context.contentResolver, Settings.Global.TRANSITION_ANIMATION_SCALE, 1f) > 0f
        }.getOrDefault(true)
    }
}

@Composable
fun CyberPanel(
    title: String,
    subtitle: String,
    modifier: Modifier = Modifier,
    trailing: @Composable (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(CyberPanelShape)
            .background(
                Brush.verticalGradient(
                    listOf(Color(0xFF071526), Color(0xFF040C17))
                )
            )
            .border(1.dp, NavyBorder.copy(alpha = 0.85f), CyberPanelShape)
            .padding(14.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title.uppercase(),
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 0.8.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = subtitle,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 11.sp,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
            if (trailing != null) {
                Spacer(Modifier.width(8.dp))
                trailing()
            }
        }
        Spacer(Modifier.height(12.dp))
        content()
    }
}

@Composable
fun StatusPill(text: String, color: Color, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(50))
            .background(color.copy(alpha = 0.14f))
            .border(1.dp, color.copy(alpha = 0.45f), RoundedCornerShape(50))
            .padding(horizontal = 10.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.size(7.dp).clip(CircleShape).background(color))
        Spacer(Modifier.width(7.dp))
        Text(text, color = color, fontSize = 11.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
    }
}

data class MetricSpec(
    val label: String,
    val value: String,
    val caption: String,
    val color: Color
)

@Composable
fun ResponsiveMetrics(metrics: List<MetricSpec>, columns: Int, modifier: Modifier = Modifier) {
    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        metrics.chunked(columns.coerceAtLeast(1)).forEach { row ->
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                row.forEach { metric ->
                    MetricTile(metric, modifier = Modifier.weight(1f))
                }
                repeat(columns - row.size) { Spacer(Modifier.weight(1f)) }
            }
        }
    }
}

@Composable
private fun MetricTile(metric: MetricSpec, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .background(Color(0xFF08182B))
            .border(1.dp, NavyBorder.copy(alpha = 0.55f), RoundedCornerShape(10.dp))
            .padding(10.dp)
    ) {
        Text(metric.label.uppercase(), color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 9.sp, letterSpacing = 0.6.sp, maxLines = 1)
        Spacer(Modifier.height(4.dp))
        Text(metric.value, color = metric.color, fontSize = 20.sp, fontWeight = FontWeight.Bold, maxLines = 1)
        Text(metric.caption, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
    }
}

data class DonutSegment(val label: String, val value: Long, val color: Color)

@Composable
fun DonutChart(
    segments: List<DonutSegment>,
    centerValue: String,
    centerLabel: String,
    modifier: Modifier = Modifier
) {
    val total = segments.sumOf { it.value.coerceAtLeast(0L) }
    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val stroke = 16.dp.toPx()
            val diameter = size.minDimension - stroke
            val topLeft = Offset((size.width - diameter) / 2f, (size.height - diameter) / 2f)
            val arcSize = androidx.compose.ui.geometry.Size(diameter, diameter)
            if (total <= 0L) {
                drawArc(
                    color = NavyBorder.copy(alpha = 0.6f), startAngle = -90f, sweepAngle = 360f,
                    useCenter = false, topLeft = topLeft, size = arcSize,
                    style = Stroke(stroke, cap = StrokeCap.Round)
                )
            } else {
                var start = -90f
                segments.filter { it.value > 0 }.forEach { segment ->
                    val sweep = (segment.value.toFloat() / total.toFloat()) * 360f
                    drawArc(
                        color = segment.color, startAngle = start + 1.2f, sweepAngle = (sweep - 2.4f).coerceAtLeast(0.5f),
                        useCenter = false, topLeft = topLeft, size = arcSize,
                        style = Stroke(stroke, cap = StrokeCap.Round)
                    )
                    start += sweep
                }
            }
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(centerValue, color = MaterialTheme.colorScheme.onSurface, fontSize = 20.sp, fontWeight = FontWeight.Bold, maxLines = 1)
            Text(centerLabel, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 9.sp, letterSpacing = 0.8.sp, maxLines = 1)
        }
    }
}

@Composable
fun Sparkline(
    values: List<Long>,
    lineColor: Color,
    modifier: Modifier = Modifier,
    secondaryValues: List<Long> = emptyList(),
    secondaryColor: Color = ElectricBlue
) {
    Canvas(modifier = modifier) {
        if (values.isEmpty()) {
            drawLine(NavyBorder, Offset(0f, size.height - 1f), Offset(size.width, size.height - 1f), 1.dp.toPx())
            return@Canvas
        }
        val maxValue = (values + secondaryValues).maxOrNull()?.coerceAtLeast(1L) ?: 1L
        fun pathFor(data: List<Long>): Path {
            val path = Path()
            val step = if (data.size == 1) size.width else size.width / (data.size - 1).coerceAtLeast(1)
            data.forEachIndexed { index, value ->
                val x = if (data.size == 1) size.width / 2f else index * step
                val y = size.height - (value.toFloat() / maxValue.toFloat()) * (size.height - 6.dp.toPx()) - 3.dp.toPx()
                if (index == 0) path.moveTo(x, y) else path.lineTo(x, y)
            }
            return path
        }
        val primary = pathFor(values)
        val fill = Path().apply {
            addPath(primary)
            lineTo(size.width, size.height)
            lineTo(0f, size.height)
            close()
        }
        drawPath(fill, Brush.verticalGradient(listOf(lineColor.copy(alpha = 0.30f), Color.Transparent)))
        if (secondaryValues.isNotEmpty()) {
            drawPath(pathFor(secondaryValues), secondaryColor.copy(alpha = 0.75f), style = Stroke(1.6.dp.toPx(), cap = StrokeCap.Round))
        }
        drawPath(primary, lineColor, style = Stroke(2.dp.toPx(), cap = StrokeCap.Round))
    }
}

@Composable
fun BarRow(label: String, valueLabel: String, percent: Float, color: Color, modifier: Modifier = Modifier) {
    Column(modifier = modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(label, color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
            Text(valueLabel, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp, maxLines = 1)
        }
        Spacer(Modifier.height(5.dp))
        Box(
            Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(50))
                .background(Color(0xFF10233B))
        ) {
            Box(
                Modifier.fillMaxWidth((percent / 100f).coerceIn(0f, 1f)).height(6.dp)
                    .clip(RoundedCornerShape(50)).background(color)
            )
        }
    }
}

@Composable
fun PrivacyBadge(label: String, icon: ImageVector, active: Boolean, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        val tint = if (active) CyberCyan else MaterialTheme.colorScheme.onSurfaceVariant
        Box(
            Modifier.size(42.dp).clip(CircleShape)
                .background(tint.copy(alpha = 0.10f))
                .border(1.dp, tint.copy(alpha = 0.55f), CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(20.dp))
        }
        Spacer(Modifier.height(5.dp))
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 9.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
fun ScrollToTopButton(state: LazyListState, modifier: Modifier = Modifier) {
    val visible by remember(state) { derivedStateOf { state.firstVisibleItemIndex > 2 } }
    val scope = rememberCoroutineScope()
    AnimatedVisibility(visible = visible, enter = fadeIn(), exit = fadeOut(), modifier = modifier) {
        SmallFloatingActionButton(
            onClick = { scope.launch { state.animateScrollToItem(0) } },
            containerColor = ElectricBlue,
            contentColor = Color.White
        ) {
            Icon(Icons.Default.KeyboardArrowUp, contentDescription = "Scroll to top")
        }
    }
}
