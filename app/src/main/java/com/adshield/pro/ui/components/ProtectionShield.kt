package com.adshield.pro.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.getValue
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
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber
import kotlin.math.cos
import kotlin.math.sin

/**
 * The reference console's central shield, rebuilt as a lightweight vector scene.
 *
 * The circuitry is decorative; every status light and counter around it is real. Animation is
 * confined to Canvas draw state (no per-frame recomposition), stops when the tunnel is idle or
 * protection is off, and is disabled when the user turns system animations off.
 */
@Composable
fun ProtectionShield(
    status: VpnStatus,
    hasTraffic: Boolean,
    threatSignals: Int,
    onClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val active = status == VpnStatus.CONNECTED
    val animate = rememberAnimationsEnabled() && active && hasTraffic
    val accent = when (status) {
        VpnStatus.CONNECTED -> SkyBlueGlow
        VpnStatus.PAUSED -> WarningAmber
        VpnStatus.STARTING, VpnStatus.RECONNECTING -> CyberCyan
        VpnStatus.ERROR -> AlertRed
        VpnStatus.DISCONNECTED -> Color(0xFF5B718C)
    }
    val pulse: State<Float>
    val rotation: State<Float>
    if (animate) {
        val transition = rememberInfiniteTransition(label = "protection-shield")
        pulse = transition.animateFloat(
            initialValue = 0.25f, targetValue = 1f,
            animationSpec = infiniteRepeatable(tween(1800, easing = LinearEasing), RepeatMode.Reverse),
            label = "shield-pulse"
        )
        rotation = transition.animateFloat(
            initialValue = 0f, targetValue = 360f,
            animationSpec = infiniteRepeatable(tween(9000, easing = LinearEasing), RepeatMode.Restart),
            label = "shield-ring"
        )
    } else {
        pulse = remember { mutableFloatStateOf(if (active) 0.55f else 0.15f) }
        rotation = remember { mutableFloatStateOf(0f) }
    }
    val shieldPath = remember {
        Path().apply {
            moveTo(50f, 4f)
            lineTo(91f, 20f)
            lineTo(91f, 52f)
            cubicTo(91f, 78f, 73f, 96f, 50f, 108f)
            cubicTo(27f, 96f, 9f, 78f, 9f, 52f)
            lineTo(9f, 20f)
            close()
        }
    }
    val label = when {
        onClick == null -> "Protection status: ${status.name.lowercase()}"
        active -> "Protection on. Tap to turn off."
        else -> "Protection off. Tap to turn on."
    }
    val baseModifier = modifier.semantics { contentDescription = label }
    Box(
        modifier = if (onClick != null) {
            baseModifier.clickable(onClickLabel = if (active) "Turn protection off" else "Turn protection on", onClick = onClick)
        } else {
            baseModifier
        }
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val center = Offset(size.width / 2f, size.height / 2f)
            val radius = (size.minDimension * 0.46f).coerceAtLeast(1f)
            val p = pulse.value
            drawCircle(
                brush = Brush.radialGradient(
                    listOf(accent.copy(alpha = if (active) 0.22f + 0.10f * p else 0.06f), Color.Transparent),
                    center = center, radius = radius
                ),
                radius = radius, center = center
            )
            drawCircuitry(center, radius, accent, active)
            // Rotating signal rings. Reading State inside Canvas invalidates drawing only.
            rotate(rotation.value, center) {
                drawArc(
                    color = accent.copy(alpha = 0.85f), startAngle = -20f, sweepAngle = 110f + 30f * p,
                    useCenter = false,
                    topLeft = Offset(center.x - radius * 0.86f, center.y - radius * 0.86f),
                    size = Size(radius * 1.72f, radius * 1.72f),
                    style = Stroke(3.dp.toPx(), cap = StrokeCap.Round)
                )
                drawArc(
                    color = ElectricBlue.copy(alpha = 0.55f), startAngle = 160f, sweepAngle = 90f,
                    useCenter = false,
                    topLeft = Offset(center.x - radius * 0.86f, center.y - radius * 0.86f),
                    size = Size(radius * 1.72f, radius * 1.72f),
                    style = Stroke(1.5.dp.toPx(), cap = StrokeCap.Round)
                )
            }
            drawCircle(accent.copy(alpha = 0.35f), radius * 0.68f, center, style = Stroke(1.dp.toPx()))
            // Shield body, scaled from a stable 100x112 design space.
            val shieldScale = radius * 1.05f / 112f
            scale(shieldScale, shieldScale, center) {
                translate(center.x - 50f, center.y - 56f) {
                    drawPath(shieldPath, Color(0xFF06182C))
                    drawPath(shieldPath, accent.copy(alpha = 0.25f), style = Stroke(10f))
                    drawPath(shieldPath, accent, style = Stroke(3.5f, cap = StrokeCap.Round))
                    // Lock shackle + body + keyhole.
                    drawArc(
                        color = accent, startAngle = 180f, sweepAngle = 180f, useCenter = false,
                        topLeft = Offset(36f, 34f), size = Size(28f, 30f), style = Stroke(4f, cap = StrokeCap.Round)
                    )
                    drawRoundRect(
                        color = accent, topLeft = Offset(32f, 48f), size = Size(36f, 30f),
                        cornerRadius = androidx.compose.ui.geometry.CornerRadius(5f, 5f)
                    )
                    drawCircle(Color(0xFF06182C), 4f, Offset(50f, 60f))
                    drawRect(Color(0xFF06182C), topLeft = Offset(48f, 60f), size = Size(4f, 9f))
                }
            }
            // Real threat signals get red markers; no markers are invented when count is zero.
            val markers = threatSignals.coerceIn(0, 6)
            repeat(markers) { index ->
                val angle = Math.toRadians((index * 61.0 + 18.0))
                val point = Offset(
                    center.x + (radius * 0.95f * cos(angle)).toFloat(),
                    center.y + (radius * 0.95f * sin(angle)).toFloat()
                )
                drawThreatMarker(point, 7.dp.toPx())
            }
        }
    }
}

private fun DrawScope.drawCircuitry(center: Offset, radius: Float, accent: Color, active: Boolean) {
    val alpha = if (active) 0.42f else 0.16f
    val stroke = 1.2.dp.toPx()
    val endpoints = listOf(
        Offset(0f, center.y - radius * 0.55f), Offset(0f, center.y + radius * 0.45f),
        Offset(size.width, center.y - radius * 0.50f), Offset(size.width, center.y + radius * 0.55f),
        Offset(center.x - radius * 0.55f, 0f), Offset(center.x + radius * 0.60f, size.height)
    )
    endpoints.forEachIndexed { index, end ->
        val horizontalFirst = index % 2 == 0
        val bend = if (horizontalFirst) Offset(end.x, center.y) else Offset(center.x, end.y)
        drawLine(accent.copy(alpha = alpha), center, bend, stroke)
        drawLine(accent.copy(alpha = alpha), bend, end, stroke)
        drawCircle(accent.copy(alpha = alpha + 0.15f), 2.2.dp.toPx(), end)
    }
}

private fun DrawScope.drawThreatMarker(center: Offset, radius: Float) {
    val path = Path().apply {
        moveTo(center.x, center.y - radius)
        lineTo(center.x + radius, center.y + radius)
        lineTo(center.x - radius, center.y + radius)
        close()
    }
    drawPath(path, AlertRed.copy(alpha = 0.20f))
    drawPath(path, AlertRed, style = Stroke(1.4.dp.toPx()))
    drawLine(AlertRed, Offset(center.x, center.y - radius * 0.35f), Offset(center.x, center.y + radius * 0.25f), 1.4.dp.toPx())
    drawCircle(AlertRed, 0.9.dp.toPx(), Offset(center.x, center.y + radius * 0.55f))
}
