package com.adshield.pro.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import kotlin.math.cos
import kotlin.math.sin

/**
 * Decorative-only visuals for the cyber command-center theme.
 *
 * Everything here draws on [Canvas] from animated *draw state*, so a scanning sweep or a pulse
 * costs one GPU draw per frame and never recomposes the surrounding panel. Each animation is also
 * switchable-off: the callers pass `animate = false` when the app is not live (or the user turned
 * system animations off), and the canvas then renders a static frame.
 *
 * No data is produced or altered by anything in this file — these are pixels, not measurements.
 */

/** Sweeping radar line used behind the live-monitoring header. */
@Composable
fun scanningSweep(animate: Boolean, color: Color): State<Float> =
    if (!animate) {
        remember { mutableFloatStateOf(0f) }
    } else {
        val transition = rememberInfiniteTransition(label = "scan-sweep")
        transition.animateFloat(
            initialValue = 0f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(tween(2600, easing = LinearEasing), RepeatMode.Restart),
            label = "scan-progress"
        )
    }

/** Slow breathing alpha for "live" indicators. */
@Composable
fun livePulse(animate: Boolean): State<Float> =
    if (!animate) {
        remember { mutableFloatStateOf(0.6f) }
    } else {
        val transition = rememberInfiniteTransition(label = "live-pulse-transition")
        transition.animateFloat(
            initialValue = 0.25f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(tween(1400, easing = LinearEasing), RepeatMode.Reverse),
            label = "live-pulse"
        )
    }

/**
 * A thin horizontal scanning line that sweeps vertically across its bounds — the "sensor sweep"
 * behind glass panels.
 */
@Composable
fun ScanlineOverlay(
    progress: Float,
    color: Color,
    modifier: Modifier = Modifier,
    lineHeightFraction: Float = 0.10f
) {
    Canvas(modifier) {
        val height = (size.height * lineHeightFraction).coerceAtLeast(1f)
        val centre = size.height * progress
        val top = (centre - height / 2f).coerceIn(-height, size.height)
        drawRect(
            brush = Brush.verticalGradient(
                listOf(Color.Transparent, color.copy(alpha = 0.16f), Color.Transparent),
                startY = top,
                endY = top + height
            ),
            topLeft = Offset(0f, top),
            size = Size(size.width, height)
        )
    }
}

/**
 * Circular power gauge: an arc scaled to the measured fraction, with a soft inner glow.
 * [value] is 0..1 and is clamped; a null/out-of-range value draws the empty track only, so the
 * gauge can never imply a reading that does not exist.
 */
@Composable
fun PowerGauge(
    value: Float?,
    accent: Color,
    modifier: Modifier = Modifier,
    trackColor: Color = Color(0xFF10233B)
) {
    Box(modifier) {
        Canvas(Modifier.fillMaxSize()) {
            val stroke = size.minDimension * 0.085f
            val inset = stroke / 2f + 1f
            val arcSize = Size(size.width - inset * 2f, size.height - inset * 2f)
            val topLeft = Offset(inset, inset)
            drawArc(
                color = trackColor,
                startAngle = 135f,
                sweepAngle = 270f,
                useCenter = false,
                topLeft = topLeft,
                size = arcSize,
                style = Stroke(stroke, cap = StrokeCap.Round)
            )
            val fraction = value?.coerceIn(0f, 1f)
            if (fraction != null && fraction > 0f) {
                drawArc(
                    brush = Brush.sweepGradient(
                        listOf(accent.copy(alpha = 0.35f), accent, accent.copy(alpha = 0.55f)),
                        center = Offset(size.width / 2f, size.height / 2f)
                    ),
                    startAngle = 135f,
                    sweepAngle = 270f * fraction,
                    useCenter = false,
                    topLeft = topLeft,
                    size = arcSize,
                    style = Stroke(stroke, cap = StrokeCap.Round)
                )
            }
        }
    }
}

/**
 * Filled area chart for a real series. Values are drawn in order; gaps (nulls) break the line so a
 * missing measurement is visibly missing instead of being interpolated across.
 */
@Composable
fun RealSeriesChart(
    values: List<Float?>,
    accent: Color,
    modifier: Modifier = Modifier,
    secondaryValues: List<Float?> = emptyList(),
    secondaryColor: Color = accent,
    zeroBaseline: Boolean = false
) {
    Canvas(modifier) {
        val usable = values.filterNotNull()
        if (usable.isEmpty()) {
            drawLine(
                color = Color(0xFF16324F),
                start = Offset(0f, size.height - 1f),
                end = Offset(size.width, size.height - 1f),
                strokeWidth = 1.5f
            )
            return@Canvas
        }
        val all = usable + secondaryValues.filterNotNull()
        val maxValue = all.max().takeIf { it > 0f } ?: 1f
        val minValue = if (zeroBaseline) 0f else all.min()
        val range = (maxValue - minValue).takeIf { it > 0.0001f } ?: 1f
        val pad = 3f

        fun toPoint(index: Int, value: Float, count: Int): Offset {
            val step = if (count <= 1) size.width else size.width / (count - 1)
            val x = if (count <= 1) size.width / 2f else index * step
            val y = size.height - pad - ((value - minValue) / range) * (size.height - pad * 2f)
            return Offset(x, y)
        }

        fun buildPath(data: List<Float?>): Pair<Path, Path> {
            val line = Path()
            val fill = Path()
            var started = false
            data.forEachIndexed { index, value ->
                if (value == null) {
                    started = false
                    return@forEachIndexed
                }
                val point = toPoint(index, value, data.size)
                if (!started) {
                    line.moveTo(point.x, point.y)
                    fill.moveTo(point.x, point.y)
                    started = true
                } else {
                    line.lineTo(point.x, point.y)
                    fill.lineTo(point.x, point.y)
                }
            }
            return line to fill
        }

        if (secondaryValues.isNotEmpty() && secondaryValues.any { it != null }) {
            val (line, _) = buildPath(secondaryValues)
            drawPath(line, secondaryColor.copy(alpha = 0.55f), style = Stroke(1.6f, cap = StrokeCap.Round))
        }
        val (line, _) = buildPath(values)
        // Soft fill under the primary series, anchored at the bottom of the plot area.
        val area = Path().apply {
            addPath(line)
            lineTo(size.width, size.height)
            lineTo(0f, size.height)
            close()
        }
        drawPath(area, Brush.verticalGradient(listOf(accent.copy(alpha = 0.28f), Color.Transparent)))
        drawPath(line, accent, style = Stroke(2.2f, cap = StrokeCap.Round))
        values.lastOrNull { it != null }?.let { last ->
            val lastIndex = values.indexOfLast { it != null }
            val point = toPoint(lastIndex, last, values.size)
            drawCircle(accent, radius = 3.5f, center = point)
            drawCircle(accent.copy(alpha = 0.25f), radius = 8f, center = point)
        }
    }
}

/**
 * A decorative HUD ring used behind the headline percentage. Purely visual: the caller draws the
 * real number on top, and the ring never scales with a measurement, so it cannot misrepresent one.
 */
@Composable
fun HudRing(
    rotationDegrees: Float,
    color: Color,
    modifier: Modifier = Modifier,
    segmentCount: Int = 48,
    activeSegments: Int = 34
) {
    Canvas(modifier) {
        val radius = size.minDimension / 2f * 0.94f
        val centre = Offset(size.width / 2f, size.height / 2f)
        val segmentLength = 360f / segmentCount
        for (index in 0 until segmentCount) {
            val angle = rotationDegrees + index * segmentLength
            val active = index < activeSegments
            val radians = Math.toRadians(angle.toDouble())
            val inner = radius * 0.86f
            val outer = radius
            val start = Offset(
                centre.x + (inner * cos(radians)).toFloat(),
                centre.y + (inner * sin(radians)).toFloat()
            )
            val end = Offset(
                centre.x + (outer * cos(radians)).toFloat(),
                centre.y + (outer * sin(radians)).toFloat()
            )
            drawLine(
                color = if (active) color.copy(alpha = 0.75f) else color.copy(alpha = 0.18f),
                start = start,
                end = end,
                strokeWidth = if (active) 2.4f else 1.2f,
                cap = StrokeCap.Round
            )
        }
        drawCircle(
            color = color.copy(alpha = 0.10f),
            radius = radius * 0.78f,
            center = centre,
            style = Stroke(1.2f)
        )
    }
}

/** Rotates a decor HUD ring only when animation is allowed; returns 0 otherwise. */
@Composable
fun hudRotation(animate: Boolean): State<Float> =
    if (!animate) {
        remember { mutableFloatStateOf(0f) }
    } else {
        val transition = rememberInfiniteTransition(label = "hud-ring")
        transition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(tween(24_000, easing = LinearEasing), RepeatMode.Restart),
            label = "hud-rotation"
        )
    }

/** Small helper for drawing a dotted grid across a canvas (ambient console texture). */
fun DrawScope.drawDotGrid(color: Color, spacing: Float = 18f, dotRadius: Float = 1.1f) {
    var y = spacing
    while (y < size.height) {
        var x = spacing
        while (x < size.width) {
            drawCircle(color, radius = dotRadius, center = Offset(x, y))
            x += spacing
        }
        y += spacing
    }
}
