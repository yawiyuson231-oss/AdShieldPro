package com.adshield.pro.ui.cybershield

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.cybershield.CategoryCount
import com.adshield.pro.cybershield.CsSeverity
import com.adshield.pro.cybershield.HourBucket
import com.adshield.pro.cybershield.ThreatStats
import com.adshield.pro.domain.model.TimeBucketStat

/** Severity distribution donut — real counts from persisted events. */
@Composable
fun SeverityDonut(stats: ThreatStats, modifier: Modifier = Modifier) {
    val segments = remember(stats.bySeverity) {
        CsSeverity.entries.filter { (stats.bySeverity[it] ?: 0L) > 0L }
            .map { it to (stats.bySeverity[it] ?: 0L) }
    }
    val total = segments.sumOf { it.second }
    Row(
        modifier = modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Box(contentAlignment = Alignment.Center) {
            Canvas(Modifier.size(110.dp)) {
                val stroke = 13.dp.toPx()
                val inset = stroke / 2 + 2.dp.toPx()
                val arcSize = Size(size.width - inset * 2, size.height - inset * 2)
                if (total == 0L) {
                    drawArc(
                        color = Cs.Border, startAngle = 0f, sweepAngle = 360f, useCenter = false,
                        topLeft = Offset(inset, inset), size = arcSize, style = Stroke(stroke)
                    )
                } else {
                    var start = -90f
                    for ((severity, count) in segments) {
                        val sweep = (count.toFloat() / total) * 360f
                        drawArc(
                            color = Cs.severityColor(severity),
                            startAngle = start + 1.5f, sweepAngle = (sweep - 3f).coerceAtLeast(0.5f),
                            useCenter = false,
                            topLeft = Offset(inset, inset), size = arcSize,
                            style = Stroke(stroke, cap = StrokeCap.Butt)
                        )
                        start += sweep
                    }
                }
            }
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    total.toString(), color = Cs.Text, fontSize = 20.sp,
                    fontWeight = FontWeight.Bold, fontFamily = Cs.mono
                )
                Text("EVENTS", color = Cs.TextFaint, fontSize = 8.sp, letterSpacing = 1.2.sp, fontFamily = Cs.mono)
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(5.dp), modifier = Modifier.weight(1f)) {
            for (severity in CsSeverity.entries) {
                val count = stats.bySeverity[severity] ?: 0L
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                    Canvas(Modifier.size(8.dp)) { drawCircle(Cs.severityColor(severity)) }
                    Text(
                        severity.name, color = Cs.TextDim, fontSize = 10.sp,
                        fontFamily = Cs.mono, modifier = Modifier.weight(1f)
                    )
                    Text(count.toString(), color = Cs.Text, fontSize = 11.sp, fontFamily = Cs.mono, fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }
}

/** 24-hour stacked activity bars (blocked over allowed), real hourly counts. */
@Composable
fun HourlyActivityBars(buckets: List<HourBucket>, modifier: Modifier = Modifier) {
    val maxVal = remember(buckets) { (buckets.maxOfOrNull { it.blocked + it.allowed } ?: 0L).coerceAtLeast(1L) }
    Column(modifier = modifier.fillMaxWidth()) {
        Canvas(
            Modifier
                .fillMaxWidth()
                .height(96.dp)
        ) {
            if (buckets.isEmpty()) return@Canvas
            val n = buckets.size
            val gap = 2.dp.toPx()
            val barW = (size.width - gap * (n - 1)) / n
            val radius = CornerRadius(2.dp.toPx(), 2.dp.toPx())
            for (i in buckets.indices) {
                val b = buckets[i]
                val x = i * (barW + gap)
                val allowedH = (b.allowed.toFloat() / maxVal) * size.height
                val blockedH = (b.blocked.toFloat() / maxVal) * size.height
                if (b.allowed > 0) {
                    drawRoundRect(
                        color = Cs.CyanDim.copy(alpha = 0.55f),
                        topLeft = Offset(x, size.height - allowedH),
                        size = Size(barW, allowedH), cornerRadius = radius
                    )
                }
                if (b.blocked > 0) {
                    drawRoundRect(
                        brush = Brush.verticalGradient(listOf(Cs.Red, Cs.Red.copy(alpha = 0.6f))),
                        topLeft = Offset(x, size.height - allowedH - blockedH),
                        size = Size(barW, blockedH), cornerRadius = radius
                    )
                }
                if (b.allowed == 0L && b.blocked == 0L) {
                    drawRoundRect(
                        color = Cs.Border.copy(alpha = 0.5f),
                        topLeft = Offset(x, size.height - 1.5.dp.toPx()),
                        size = Size(barW, 1.5.dp.toPx()), cornerRadius = radius
                    )
                }
            }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("24h ago", color = Cs.TextFaint, fontSize = 9.sp, fontFamily = Cs.mono)
            Text("12h", color = Cs.TextFaint, fontSize = 9.sp, fontFamily = Cs.mono)
            Text("now", color = Cs.TextFaint, fontSize = 9.sp, fontFamily = Cs.mono)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.padding(top = 4.dp)) {
            LegendDot(Cs.Red, "Blocked")
            LegendDot(Cs.CyanDim.copy(alpha = 0.7f), "Allowed")
        }
    }
}

@Composable
private fun LegendDot(color: Color, label: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(5.dp)) {
        Canvas(Modifier.size(7.dp)) { drawCircle(color) }
        Text(label, color = Cs.TextDim, fontSize = 9.sp, fontFamily = Cs.mono)
    }
}

/** 7-day blocked-query trend sparkline from real daily aggregates. */
@Composable
fun TrendSparkline(daily: List<TimeBucketStat>, modifier: Modifier = Modifier) {
    val values = remember(daily) { daily.map { it.blockedQueries.toFloat() } }
    val maxV = remember(values) { (values.maxOrNull() ?: 0f).coerceAtLeast(1f) }
    Column(modifier = modifier.fillMaxWidth()) {
        Canvas(
            Modifier
                .fillMaxWidth()
                .height(64.dp)
        ) {
            if (values.size < 2) return@Canvas
            val stepX = size.width / (values.size - 1)
            val line = Path()
            val fill = Path()
            for (i in values.indices) {
                val x = i * stepX
                val y = size.height - (values[i] / maxV) * (size.height - 6.dp.toPx()) - 3.dp.toPx()
                if (i == 0) {
                    line.moveTo(x, y); fill.moveTo(x, size.height); fill.lineTo(x, y)
                } else {
                    line.lineTo(x, y); fill.lineTo(x, y)
                }
            }
            fill.lineTo(size.width, size.height)
            fill.close()
            drawPath(fill, Brush.verticalGradient(listOf(Cs.NeonBlue.copy(alpha = 0.30f), Color.Transparent)))
            drawPath(line, Cs.Cyan, style = Stroke(2.dp.toPx(), cap = StrokeCap.Round))
            val lastX = (values.size - 1) * stepX
            val lastY = size.height - (values.last() / maxV) * (size.height - 6.dp.toPx()) - 3.dp.toPx()
            drawCircle(Cs.Cyan, radius = 3.dp.toPx(), center = Offset(lastX.coerceAtMost(size.width - 3.dp.toPx()), lastY))
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            daily.forEach { Text(it.label, color = Cs.TextFaint, fontSize = 8.sp, fontFamily = Cs.mono) }
        }
    }
}

/** Horizontal attack-vector bars by real blocked category. */
@Composable
fun VectorBars(vectors: List<CategoryCount>, modifier: Modifier = Modifier) {
    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        for (v in vectors) {
            Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Row {
                    Text(
                        Cs.categoryLabel(v.category), color = Cs.TextDim, fontSize = 11.sp,
                        modifier = Modifier.weight(1f)
                    )
                    Text(
                        "${v.count} · ${String.format(java.util.Locale.US, "%.0f", v.share * 100)}%",
                        color = Cs.Text, fontSize = 10.sp, fontFamily = Cs.mono
                    )
                }
                Canvas(
                    Modifier
                        .fillMaxWidth()
                        .height(6.dp)
                ) {
                    drawRoundRect(
                        color = Cs.Border.copy(alpha = 0.5f),
                        cornerRadius = CornerRadius(3.dp.toPx())
                    )
                    drawRoundRect(
                        brush = Brush.horizontalGradient(
                            listOf(Cs.categoryColor(v.category).copy(alpha = 0.55f), Cs.categoryColor(v.category))
                        ),
                        size = Size(size.width * v.share.coerceIn(0.02f, 1f), size.height),
                        cornerRadius = CornerRadius(3.dp.toPx())
                    )
                }
            }
        }
    }
}

/** Compliance score ring. */
@Composable
fun ScoreRing(score: Int, modifier: Modifier = Modifier) {
    val color = when {
        score >= 80 -> Cs.Green
        score >= 55 -> Cs.Amber
        else -> Cs.Red
    }
    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        Canvas(Modifier.size(74.dp)) {
            val stroke = 7.dp.toPx()
            val inset = stroke / 2 + 1.dp.toPx()
            val arcSize = Size(size.width - inset * 2, size.height - inset * 2)
            drawArc(
                Cs.Border, 0f, 360f, false, Offset(inset, inset), arcSize, style = Stroke(stroke)
            )
            drawArc(
                color, -90f, 360f * (score / 100f), false, Offset(inset, inset), arcSize,
                style = Stroke(stroke, cap = StrokeCap.Round)
            )
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text("$score", color = color, fontSize = 19.sp, fontWeight = FontWeight.Bold, fontFamily = Cs.mono)
            Text("SCORE", color = Cs.TextFaint, fontSize = 7.sp, letterSpacing = 1.sp, fontFamily = Cs.mono)
        }
    }
}
