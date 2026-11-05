package com.adshield.pro.ui.cybershield

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.cybershield.ShieldMode
import com.adshield.pro.cybershield.ShieldState
import com.adshield.pro.domain.model.VpnRuntimeState
import kotlin.math.min

/**
 * Central security shield. Its color, glow, rings and label are driven ONLY by
 * the real VPN runtime state — it never displays a permanent "protected" claim.
 * Animation is a single lightweight rotation + state-change pulse.
 */
@Composable
fun ShieldHero(
    shield: ShieldState,
    vpnState: VpnRuntimeState,
    onActivate: () -> Unit,
    onStop: () -> Unit,
    onPauseResume: () -> Unit,
    modifier: Modifier = Modifier
) {
    val accent = when (shield.mode) {
        ShieldMode.ACTIVE -> Cs.Green
        ShieldMode.STARTING -> Cs.Cyan
        ShieldMode.PAUSED -> Cs.Amber
        ShieldMode.ERROR -> Cs.Red
        ShieldMode.OFF -> Cs.Steel
    }
    val ringColor = when (shield.mode) {
        ShieldMode.ACTIVE -> Cs.Cyan
        ShieldMode.STARTING -> Cs.Cyan
        ShieldMode.PAUSED -> Cs.Amber
        ShieldMode.ERROR -> Cs.Red
        ShieldMode.OFF -> Cs.BorderBright
    }

    val transition = rememberInfiniteTransition(label = "shield")
    val sweepAngle by transition.animateFloat(
        initialValue = 0f, targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(4200, easing = LinearEasing), RepeatMode.Restart),
        label = "sweep"
    )
    val breathe by transition.animateFloat(
        initialValue = 0.86f, targetValue = 1.0f,
        animationSpec = infiniteRepeatable(tween(2200, easing = LinearEasing), RepeatMode.Reverse),
        label = "breathe"
    )
    val pulse by animateFloatAsState(
        targetValue = if (shield.recentBlocked > 0) 1.04f else 1f,
        animationSpec = tween(600), label = "pulse"
    )
    val animated = shield.mode == ShieldMode.ACTIVE || shield.mode == ShieldMode.STARTING

    NeonCard(modifier = modifier.fillMaxWidth(), glowColor = accent) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(230.dp),
            contentAlignment = Alignment.Center
        ) {
            Canvas(Modifier.size(230.dp)) {
                val c = Offset(size.width / 2f, size.height / 2f)
                val r = min(size.width, size.height) / 2f

                // Ambient radial glow
                drawCircle(
                    brush = Brush.radialGradient(
                        colors = listOf(accent.copy(alpha = if (animated) 0.22f * breathe else 0.10f), Color.Transparent),
                        center = c, radius = r
                    ),
                    radius = r, center = c
                )
                // Static concentric rings
                drawCircle(ringColor.copy(alpha = 0.16f), radius = r * 0.97f, center = c, style = Stroke(1.dp.toPx()))
                drawCircle(ringColor.copy(alpha = 0.28f), radius = r * 0.84f, center = c, style = Stroke(1.2.dp.toPx()))
                drawCircle(ringColor.copy(alpha = 0.10f), radius = r * 0.70f, center = c, style = Stroke(1.dp.toPx()))

                // Rotating neon sweep (only while protection is running/starting)
                if (animated) {
                    val sweepRadius = r * 0.84f
                    drawArc(
                        brush = Brush.sweepGradient(
                            0f to Color.Transparent,
                            0.72f to Color.Transparent,
                            0.92f to ringColor.copy(alpha = 0.85f),
                            1f to ringColor,
                            center = c
                        ),
                        startAngle = sweepAngle,
                        sweepAngle = 300f,
                        useCenter = false,
                        topLeft = Offset(c.x - sweepRadius, c.y - sweepRadius),
                        size = androidx.compose.ui.geometry.Size(sweepRadius * 2, sweepRadius * 2),
                        style = Stroke(2.4.dp.toPx(), cap = StrokeCap.Round)
                    )
                }

                // Shield body
                scale(pulse, c) {
                    drawShield(
                        center = c,
                        radius = r * 0.56f,
                        accent = accent,
                        mode = shield.mode,
                        glow = if (animated) breathe else 0.9f
                    )
                }
            }
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(4.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = shield.headline,
                color = accent,
                fontSize = 19.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 2.4.sp,
                fontFamily = Cs.mono
            )
            Text(
                text = shield.subtitle,
                color = Cs.TextDim,
                fontSize = 12.sp,
                lineHeight = 17.sp,
                modifier = Modifier.padding(horizontal = 8.dp)
            )
            shield.error?.let {
                Text(it, color = Cs.Red.copy(alpha = 0.85f), fontSize = 11.sp, lineHeight = 15.sp)
            }
        }

        Row(
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            when (shield.mode) {
                ShieldMode.OFF, ShieldMode.ERROR -> {
                    Button(
                        onClick = onActivate,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Cs.NeonBlue, contentColor = Color.White
                        )
                    ) { Text(if (shield.mode == ShieldMode.ERROR) "RETRY ACTIVATION" else "ACTIVATE PROTECTION", fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp) }
                }
                ShieldMode.STARTING -> {
                    OutlinedButton(
                        onClick = {}, enabled = false, modifier = Modifier.weight(1f)
                    ) { Text("STARTING…", fontSize = 12.sp, letterSpacing = 1.sp) }
                }
                ShieldMode.ACTIVE, ShieldMode.PAUSED -> {
                    OutlinedButton(
                        onClick = onPauseResume,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = accent)
                    ) {
                        Text(
                            if (shield.mode == ShieldMode.PAUSED) "RESUME FILTERING" else "PAUSE FILTERING",
                            fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp
                        )
                    }
                    OutlinedButton(
                        onClick = onStop,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = Cs.TextDim)
                    ) { Text("STOP", fontSize = 12.sp, letterSpacing = 1.sp) }
                }
            }
        }

        if (vpnState.status.name == "CONNECTED") {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                HeroStat("SESSION BLOCKED", vpnState.sessionBlockedQueries.toString(), Cs.Cyan)
                HeroStat("RULES LOADED", vpnState.loadedRuleCount.toString(), Cs.Text)
                HeroStat("AVG DNS", "${vpnState.averageLatencyMs} ms", Cs.Text)
            }
        }
    }
}

@Composable
private fun HeroStat(label: String, value: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, color = color, fontSize = 15.sp, fontWeight = FontWeight.Bold, fontFamily = Cs.mono)
        Text(label, color = Cs.TextFaint, fontSize = 8.sp, letterSpacing = 1.sp, fontFamily = Cs.mono)
    }
}

private fun DrawScope.drawShield(
    center: Offset,
    radius: Float,
    accent: Color,
    mode: ShieldMode,
    glow: Float
) {
    val w = radius * 1.55f
    val h = radius * 1.9f
    val top = center.y - h / 2f
    val left = center.x - w / 2f

    val path = Path().apply {
        moveTo(center.x, top)
        cubicTo(center.x + w * 0.28f, top + h * 0.06f, left + w * 0.82f, top + h * 0.10f, left + w, top + h * 0.14f)
        cubicTo(left + w, top + h * 0.46f, left + w * 0.94f, top + h * 0.66f, center.x, top + h)
        cubicTo(left + w * 0.06f, top + h * 0.66f, left, top + h * 0.46f, left, top + h * 0.14f)
        cubicTo(left + w * 0.18f, top + h * 0.10f, center.x - w * 0.28f, top + h * 0.06f, center.x, top)
        close()
    }

    // Outer glow
    drawPath(
        path = path,
        brush = Brush.radialGradient(
            listOf(accent.copy(alpha = 0.30f * glow), Color.Transparent),
            center = center, radius = radius * 1.5f
        )
    )
    // Body gradient — dark steel when OFF, deep blue otherwise
    val bodyTop = if (mode == ShieldMode.OFF) Color(0xFF22344E) else Color(0xFF123A6B)
    val bodyBottom = if (mode == ShieldMode.OFF) Color(0xFF101B2C) else Color(0xFF071E3D)
    drawPath(path, brush = Brush.verticalGradient(listOf(bodyTop, bodyBottom), startY = top, endY = top + h))
    // Neon rim
    drawPath(path, color = accent.copy(alpha = 0.95f), style = Stroke(2.6.dp.toPx()))
    // Inner rim highlight
    drawPath(path, color = Color.White.copy(alpha = 0.14f), style = Stroke(1.dp.toPx()))

    val iconColor = if (mode == ShieldMode.OFF) Cs.Steel else accent
    val cx = center.x
    val cy = center.y - h * 0.04f
    val s = radius * 0.42f
    when (mode) {
        ShieldMode.ACTIVE -> {
            // Check mark
            val check = Path().apply {
                moveTo(cx - s * 0.55f, cy)
                lineTo(cx - s * 0.12f, cy + s * 0.45f)
                lineTo(cx + s * 0.62f, cy - s * 0.42f)
            }
            drawPath(check, iconColor, style = Stroke(4.dp.toPx(), cap = StrokeCap.Round))
        }
        ShieldMode.PAUSED -> {
            drawLine(iconColor, Offset(cx - s * 0.28f, cy - s * 0.45f), Offset(cx - s * 0.28f, cy + s * 0.45f), strokeWidth = 4.dp.toPx(), cap = StrokeCap.Round)
            drawLine(iconColor, Offset(cx + s * 0.28f, cy - s * 0.45f), Offset(cx + s * 0.28f, cy + s * 0.45f), strokeWidth = 4.dp.toPx(), cap = StrokeCap.Round)
        }
        ShieldMode.ERROR -> {
            drawLine(iconColor, Offset(cx, cy - s * 0.5f), Offset(cx, cy + s * 0.15f), strokeWidth = 4.dp.toPx(), cap = StrokeCap.Round)
            drawCircle(iconColor, radius = 2.6.dp.toPx(), center = Offset(cx, cy + s * 0.45f))
        }
        ShieldMode.STARTING -> {
            drawCircle(iconColor.copy(alpha = 0.8f), radius = s * 0.4f, center = Offset(cx, cy), style = Stroke(3.dp.toPx()))
        }
        ShieldMode.OFF -> {
            // Power symbol
            drawArc(
                color = iconColor, startAngle = -60f, sweepAngle = 300f, useCenter = false,
                topLeft = Offset(cx - s * 0.45f, cy - s * 0.4f),
                size = androidx.compose.ui.geometry.Size(s * 0.9f, s * 0.9f),
                style = Stroke(3.4.dp.toPx(), cap = StrokeCap.Round)
            )
            drawLine(iconColor, Offset(cx, cy - s * 0.6f), Offset(cx, cy - s * 0.05f), strokeWidth = 3.4.dp.toPx(), cap = StrokeCap.Round)
        }
    }
}
