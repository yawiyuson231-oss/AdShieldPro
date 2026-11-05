package com.adshield.pro.gps.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.gps.engine.AccuracyBand
import com.adshield.pro.gps.engine.IntegrityVerdict
import com.adshield.pro.gps.engine.MovementState
import com.adshield.pro.gps.traffic.CongestionLevel
import com.adshield.pro.ui.components.rememberAnimationsEnabled
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldGlow
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

/**
 * AdShield Pro — GPS module UI kit.
 *
 * Everything here is a thin, stateless drawing layer: the cyber HUD language (hairline borders,
 * cyan glow, monospace numerals) reused by all seven GPS tabs so the console feels like one device.
 * No component invents data; each takes a value or an explicit "unknown" state.
 */

// ---------------------------------------------------------------- palette
val GpsBackground = Color(0xFF030A14)
val GpsPanel = Color(0xFF061426)
val GpsPanelRaised = Color(0xFF0A1F35)
val GpsBorder = Color(0xFF123B60)
val GpsBorderBright = Color(0xFF1E5B8A)
val GpsTextPrimary = Color(0xFFE6F3FF)
val GpsTextSecondary = Color(0xFF8FB3CE)
val GpsTextDim = Color(0xFF5A7A96)
val GpsCyan = Color(0xFF22D3EE)
val GpsBlue = Color(0xFF2E7DFF)
val GpsGreen = Color(0xFF22C55E)
val GpsAmber = Color(0xFFF59E0B)
val GpsRed = Color(0xFFEF4444)
val GpsGrey = Color(0xFF64748B)
val GpsMagenta = Color(0xFFC084FC)

fun accuracyColor(band: AccuracyBand): Color = when (band) {
    AccuracyBand.EXCELLENT -> GpsGreen
    AccuracyBand.GOOD -> GpsCyan
    AccuracyBand.FAIR -> GpsAmber
    AccuracyBand.POOR -> GpsRed
    AccuracyBand.UNUSABLE -> GpsGrey
}

fun integrityColor(verdict: IntegrityVerdict): Color = when (verdict) {
    IntegrityVerdict.TRUSTED -> GpsGreen
    IntegrityVerdict.DEGRADED -> GpsCyan
    IntegrityVerdict.SUSPICIOUS -> GpsAmber
    IntegrityVerdict.COMPROMISED -> GpsRed
}

fun congestionColor(level: CongestionLevel): Color = when (level) {
    CongestionLevel.FREE_FLOW, CongestionLevel.LIGHT -> GpsGreen
    CongestionLevel.MODERATE -> GpsAmber
    CongestionLevel.HEAVY -> GpsRed
    CongestionLevel.STANDSTILL -> Color(0xFFB91C1C)
    CongestionLevel.UNKNOWN -> GpsGrey
}

fun movementColor(state: MovementState): Color = when (state) {
    MovementState.DRIVING -> GpsCyan
    MovementState.MOVING -> GpsBlue
    MovementState.STATIONARY -> GpsTextDim
    MovementState.UNKNOWN -> GpsGrey
}

/** Constellation colours for the radar and the satellite table. */
fun constellationColor(constellation: String): Color = when (constellation) {
    "GPS" -> GpsCyan
    "Galileo" -> GpsGreen
    "GLONASS" -> GpsAmber
    "BeiDou" -> GpsMagenta
    "QZSS" -> GpsBlue
    "NavIC" -> Color(0xFFF472B6)
    "SBAS" -> GpsTextSecondary
    else -> GpsGrey
}

// --------------------------------------------------------------- surfaces

@Composable
fun GpsPanel(
    modifier: Modifier = Modifier,
    accent: Color = GpsBorder,
    content: @Composable () -> Unit
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(14.dp))
            .background(
                Brush.verticalGradient(
                    listOf(GpsPanel, GpsBackground)
                )
            )
            .border(1.dp, accent.copy(alpha = 0.55f), RoundedCornerShape(14.dp))
    ) {
        content()
    }
}

@Composable
fun GpsSectionTitle(text: String, modifier: Modifier = Modifier, accent: Color = GpsCyan) {
    Row(modifier = modifier, verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .size(width = 3.dp, height = 14.dp)
                .background(accent, RoundedCornerShape(2.dp))
        )
        Spacer(Modifier.width(8.dp))
        Text(
            text = text.uppercase(),
            color = GpsTextSecondary,
            fontSize = 11.sp,
            letterSpacing = 1.6.sp,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
fun GpsChip(
    text: String,
    color: Color,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    filled: Boolean = false
) {
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(20.dp))
            .background(if (filled) color.copy(alpha = 0.22f) else Color.Transparent)
            .border(1.dp, color.copy(alpha = 0.65f), RoundedCornerShape(20.dp))
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (icon != null) {
            Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(12.dp))
            Spacer(Modifier.width(5.dp))
        }
        Text(text, color = color, fontSize = 11.sp, fontWeight = FontWeight.Medium, maxLines = 1)
    }
}

/** Big monospace reading with a unit and a caption — the core of the telemetry HUD. */
@Composable
fun TelemetryReadout(
    label: String,
    value: String,
    unit: String,
    modifier: Modifier = Modifier,
    accent: Color = GpsCyan,
    caption: String? = null
) {
    Column(modifier = modifier) {
        Text(
            label.uppercase(),
            color = GpsTextDim,
            fontSize = 9.sp,
            letterSpacing = 1.2.sp,
            fontWeight = FontWeight.Medium
        )
        Row(verticalAlignment = Alignment.Bottom) {
            Text(
                value,
                color = accent,
                fontSize = 26.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                maxLines = 1
            )
            if (unit.isNotBlank()) {
                Spacer(Modifier.width(3.dp))
                Text(
                    unit,
                    color = GpsTextSecondary,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.padding(bottom = 5.dp)
                )
            }
        }
        if (caption != null) {
            Text(caption, color = GpsTextDim, fontSize = 9.sp, maxLines = 1)
        }
    }
}

// ----------------------------------------------------------------- gauge

/**
 * Speed gauge: an arc from 210° to -30° with ticks every 20 km/h. Scale adapts to the data so a
 * 4 km/h walk and a 120 km/h motorway run both read well, and an unknown speed shows an empty arc
 * with "—" rather than a zero needle.
 */
@Composable
fun SpeedGauge(
    speedKmh: Double?,
    modifier: Modifier = Modifier,
    maxScaleKmh: Double = 140.0
) {
    val animationsEnabled = rememberAnimationsEnabled()
    val target = ((speedKmh ?: 0.0) / maxScaleKmh).coerceIn(0.0, 1.0).toFloat()
    val progress by animateFloatAsState(
        targetValue = target,
        animationSpec = androidx.compose.animation.core.tween(if (animationsEnabled) 400 else 0),
        label = "speedGauge"
    )
    val color = when {
        speedKmh == null -> GpsGrey
        speedKmh > maxScaleKmh * 0.9 -> GpsRed
        else -> GpsCyan
    }
    Canvas(modifier = modifier) {
        val stroke = size.minDimension * 0.055f
        val inset = stroke / 2f
        val arcSize = Size(size.width - stroke, size.height - stroke)
        val startAngle = 150f
        val sweepTotal = 240f
        // track
        drawArc(
            color = GpsBorder.copy(alpha = 0.55f),
            startAngle = startAngle,
            sweepAngle = sweepTotal,
            useCenter = false,
            topLeft = Offset(inset, inset),
            size = arcSize,
            style = Stroke(width = stroke, cap = StrokeCap.Round)
        )
        // value
        if (speedKmh != null && progress > 0.001f) {
            drawArc(
                color = color,
                startAngle = startAngle,
                sweepAngle = sweepTotal * progress,
                useCenter = false,
                topLeft = Offset(inset, inset),
                size = arcSize,
                style = Stroke(width = stroke, cap = StrokeCap.Round)
            )
        }
        // ticks
        val radius = min(size.width, size.height) / 2f - stroke
        val centre = Offset(size.width / 2f, size.height / 2f)
        for (tick in 0..7) {
            val fraction = tick / 7f
            val angle = Math.toRadians((startAngle + sweepTotal * fraction).toDouble())
            val inner = 0.82f
            drawLine(
                color = GpsBorderBright.copy(alpha = 0.8f),
                start = Offset(
                    centre.x + radius * inner * cos(angle).toFloat(),
                    centre.y + radius * inner * sin(angle).toFloat()
                ),
                end = Offset(
                    centre.x + radius * 0.95f * cos(angle).toFloat(),
                    centre.y + radius * 0.95f * sin(angle).toFloat()
                ),
                strokeWidth = 2f
            )
        }
    }
}

/** Small compass rose. North is fixed at the top; the needle follows the fused heading. */
@Composable
fun CompassRose(
    headingDegrees: Double?,
    modifier: Modifier = Modifier,
    sourceLabel: String? = null
) {
    Canvas(modifier = modifier) {
        val stroke = size.minDimension * 0.03f
        val radius = min(size.width, size.height) / 2f - stroke
        val centre = Offset(size.width / 2f, size.height / 2f)
        drawCircle(
            color = GpsBorder.copy(alpha = 0.6f),
            radius = radius,
            center = centre,
            style = Stroke(width = stroke)
        )
        drawCircle(
            color = GpsCyan.copy(alpha = 0.18f),
            radius = radius * 0.62f,
            center = centre,
            style = Stroke(width = 1f)
        )
        // cardinal ticks
        for (index in 0 until 8) {
            val angle = Math.toRadians(index * 45.0 - 90.0)
            drawLine(
                color = GpsBorderBright,
                start = Offset(
                    centre.x + radius * 0.80f * cos(angle).toFloat(),
                    centre.y + radius * 0.80f * sin(angle).toFloat()
                ),
                end = Offset(
                    centre.x + radius * 0.95f * cos(angle).toFloat(),
                    centre.y + radius * 0.95f * sin(angle).toFloat()
                ),
                strokeWidth = if (index % 2 == 0) 3f else 1.5f
            )
        }
        if (headingDegrees != null) {
            val angle = Math.toRadians(headingDegrees - 90.0)
            val tip = Offset(
                centre.x + radius * 0.72f * cos(angle).toFloat(),
                centre.y + radius * 0.72f * sin(angle).toFloat()
            )
            val left = Math.toRadians(headingDegrees - 90.0 + 145.0)
            val right = Math.toRadians(headingDegrees - 90.0 - 145.0)
            val path = Path().apply {
                moveTo(tip.x, tip.y)
                lineTo(
                    centre.x + radius * 0.28f * cos(left).toFloat(),
                    centre.y + radius * 0.28f * sin(left).toFloat()
                )
                lineTo(
                    centre.x + radius * 0.28f * cos(right).toFloat(),
                    centre.y + radius * 0.28f * sin(right).toFloat()
                )
                close()
            }
            drawPath(path, GpsRed)
        }
    }
}

/** Horizontal accuracy bar with thresholds — readable at a glance while driving. */
@Composable
fun AccuracyBar(accuracyMeters: Float?, band: AccuracyBand, modifier: Modifier = Modifier) {
    val ratio = when {
        accuracyMeters == null -> 0f
        else -> (1f - (accuracyMeters / 60f)).coerceIn(0.03f, 1f)
    }
    Column(modifier = modifier) {
        Box(
            Modifier
                .fillMaxWidth()
                .height(6.dp)
                .clip(RoundedCornerShape(3.dp))
                .background(GpsBorder.copy(alpha = 0.4f))
        ) {
            Box(
                Modifier
                    .fillMaxWidth(ratio)
                    .height(6.dp)
                    .background(accuracyColor(band), RoundedCornerShape(3.dp))
            )
        }
        Spacer(Modifier.height(4.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("±5 m", color = GpsTextDim, fontSize = 8.sp)
            Text("±30 m", color = GpsTextDim, fontSize = 8.sp)
            Text("±60 m", color = GpsTextDim, fontSize = 8.sp)
        }
    }
}

/**
 * The GPS marker drawn on top of the map: a rotating chevron with an accuracy ring. The ring radius
 * is set by the caller from the real accuracy and the current zoom, so it always shows metres, not
 * pixels.
 */
@Composable
fun VehicleMarker(
    bearingDegrees: Double?,
    accuracyColor: Color,
    movement: MovementState,
    modifier: Modifier = Modifier,
    integrityCompromised: Boolean = false
) {
    val animationsEnabled = rememberAnimationsEnabled()
    val rotation by animateFloatAsState(
        targetValue = (bearingDegrees ?: 0.0).toFloat(),
        animationSpec = androidx.compose.animation.core.tween(if (animationsEnabled) 300 else 0),
        label = "markerBearing"
    )
    val bodyColor = if (integrityCompromised) GpsRed else when (movement) {
        MovementState.DRIVING -> GpsCyan
        MovementState.MOVING -> GpsBlue
        else -> SkyBlueGlow
    }
    Canvas(modifier = modifier) {
        val radius = size.minDimension / 2f
        val centre = Offset(size.width / 2f, size.height / 2f)
        drawCircle(color = accuracyColor.copy(alpha = 0.14f), radius = radius, center = centre)
        drawCircle(
            color = accuracyColor.copy(alpha = 0.55f),
            radius = radius * 0.92f,
            center = centre,
            style = Stroke(width = 2f)
        )
        rotate(rotation, centre) {
            val path = Path().apply {
                moveTo(centre.x, centre.y - radius * 0.62f)
                lineTo(centre.x - radius * 0.30f, centre.y + radius * 0.42f)
                lineTo(centre.x, centre.y + radius * 0.20f)
                lineTo(centre.x + radius * 0.30f, centre.y + radius * 0.42f)
                close()
            }
            drawPath(path, bodyColor)
            drawPath(path, Color.White.copy(alpha = 0.65f), style = Stroke(width = 1.6f))
        }
    }
}

/** Placeholder used whenever a screen has no data: says why, never fakes a value. */
@Composable
fun GpsEmptyState(
    title: String,
    detail: String,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    accent: Color = GpsTextDim,
    action: (@Composable () -> Unit)? = null
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(GpsPanel.copy(alpha = 0.6f))
            .border(1.dp, GpsBorder.copy(alpha = 0.5f), RoundedCornerShape(12.dp))
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        if (icon != null) {
            Icon(icon, contentDescription = null, tint = accent, modifier = Modifier.size(22.dp))
            Spacer(Modifier.height(8.dp))
        }
        Text(
            title,
            color = GpsTextPrimary,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(4.dp))
        Text(
            detail,
            color = GpsTextSecondary,
            fontSize = 11.sp,
            textAlign = TextAlign.Center,
            lineHeight = 15.sp
        )
        if (action != null) {
            Spacer(Modifier.height(10.dp))
            action()
        }
    }
}

/** Thin hairline divider. */
@Composable
fun GpsDivider(modifier: Modifier = Modifier, color: Color = GpsBorder) {
    Box(
        modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(color.copy(alpha = 0.5f))
    )
}

/** Key/value row used by the telemetry and security tables. */
@Composable
fun GpsKeyValue(
    key: String,
    value: String,
    modifier: Modifier = Modifier,
    valueColor: Color = GpsTextPrimary,
    monospace: Boolean = true
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(key, color = GpsTextSecondary, fontSize = 11.sp, modifier = Modifier.weight(1f))
        Text(
            value,
            color = valueColor,
            fontSize = 11.sp,
            fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
            fontWeight = FontWeight.Medium,
            textAlign = TextAlign.End
        )
    }
}

/** Status dot + label, used in every header to show the real module state. */
@Composable
fun StatusDot(color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier
            .size(7.dp)
            .clip(RoundedCornerShape(50))
            .background(color)
    )
}

/** Legend for the traffic colours, with the UNKNOWN entry always present. */
@Composable
fun TrafficLegend(modifier: Modifier = Modifier) {
    Row(modifier = modifier, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        listOf(
            "Free" to GpsGreen,
            "Slow" to GpsAmber,
            "Jam" to GpsRed,
            "No data" to GpsGrey
        ).forEach { (label, color) ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier
                        .size(width = 14.dp, height = 4.dp)
                        .background(color, RoundedCornerShape(2.dp))
                )
                Spacer(Modifier.width(4.dp))
                Text(label, color = GpsTextSecondary, fontSize = 9.sp)
            }
        }
    }
}

/** Simple on/off switch row with an explanation, used all over the privacy screen. */
@Composable
fun GpsToggleRow(
    title: String,
    detail: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    accent: Color = CyberCyan,
    enabled: Boolean = true
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                title,
                color = if (enabled) GpsTextPrimary else GpsTextDim,
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium
            )
            Text(detail, color = GpsTextDim, fontSize = 10.sp, lineHeight = 14.sp)
        }
        Spacer(Modifier.width(10.dp))
        androidx.compose.material3.Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            enabled = enabled,
            colors = androidx.compose.material3.SwitchDefaults.colors(
                checkedThumbColor = GpsBackground,
                checkedTrackColor = accent,
                uncheckedThumbColor = GpsTextDim,
                uncheckedTrackColor = GpsBorder
            )
        )
    }
}

/** Wrapper that keeps a consistent empty-state card for a whole tab section. */
@Composable
fun GpsInlineNotice(text: String, color: Color = GpsAmber, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(color.copy(alpha = 0.10f))
            .border(1.dp, color.copy(alpha = 0.35f), RoundedCornerShape(8.dp))
            .padding(horizontal = 10.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.size(6.dp).background(color, RoundedCornerShape(50)))
        Spacer(Modifier.width(8.dp))
        Text(text, color = color, fontSize = 10.sp, lineHeight = 14.sp)
    }
}

/** The header every GPS tab shares: live state, accuracy and privacy chips. */
@Composable
fun GpsStatusHeader(
    frame: com.adshield.pro.gps.engine.GpsFrame,
    statusLine: String,
    contributing: Boolean,
    online: Boolean,
    modifier: Modifier = Modifier,
    extra: @Composable () -> Unit = {}
) {
    Column(modifier = modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            StatusDot(if (frame.hasFix) accuracyColor(frame.accuracyBand) else GpsAmber)
            Spacer(Modifier.width(6.dp))
            Text(
                statusLine,
                color = GpsTextPrimary,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f)
            )
            GpsChip(
                text = if (online) "ONLINE" else "OFFLINE",
                color = if (online) GpsGreen else GpsAmber
            )
            Spacer(Modifier.width(6.dp))
            GpsChip(
                text = if (contributing) "SHARING" else "PRIVATE",
                color = if (contributing) GpsCyan else GpsTextSecondary
            )
        }
        Spacer(Modifier.height(6.dp))
        AccuracyBar(
            accuracyMeters = frame.fix?.accuracyMeters,
            band = frame.accuracyBand
        )
        Spacer(Modifier.height(6.dp))
        extra()
    }
}

/** Colour for the "live/offline" indicator used by the map overlay. */
fun onlineColor(online: Boolean): Color = if (online) GpsGreen else GpsAmber

/** Map overlay pill. */
@Composable
fun MapOverlayPill(text: String, color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(GpsBackground.copy(alpha = 0.82f))
            .border(1.dp, color.copy(alpha = 0.5f), RoundedCornerShape(8.dp))
            .padding(horizontal = 9.dp, vertical = 5.dp)
    ) {
        Text(text, color = color, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
fun GpsPanelTitleRow(
    title: String,
    subtitle: String?,
    accent: Color = ElectricBlue,
    modifier: Modifier = Modifier,
    trailing: @Composable (() -> Unit)? = null
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                title,
                color = GpsTextPrimary,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.4.sp
            )
            if (subtitle != null) {
                Text(subtitle, color = GpsTextDim, fontSize = 10.sp, lineHeight = 13.sp)
            }
        }
        trailing?.invoke()
    }
    Spacer(Modifier.height(2.dp))
    Box(
        Modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(
                Brush.horizontalGradient(
                    listOf(accent.copy(alpha = 0.7f), EmeraldGlow.copy(alpha = 0.05f), Color.Transparent)
                )
            )
    )
}

/** Compose helper so callers can build a Path without importing the graphics package. */
fun markerPath(centre: Offset, radius: Float): Path = Path().apply {
    moveTo(centre.x, centre.y - radius)
    lineTo(centre.x - radius * 0.6f, centre.y + radius * 0.7f)
    lineTo(centre.x, centre.y + radius * 0.35f)
    lineTo(centre.x + radius * 0.6f, centre.y + radius * 0.7f)
    close()
}

/** Text style shared by the monospace telemetry columns. */
@Composable
fun monospaceStyle(size: Int, color: Color = GpsTextPrimary) = MaterialTheme.typography.bodyMedium.copy(
    fontFamily = FontFamily.Monospace,
    fontSize = size.sp,
    color = color
)

/** Kept for symmetry with the rest of the app: colours are constants, not theme lookups. */
val gpsAccent: Color = CyberCyan
val gpsWarning: Color = WarningAmber
val gpsDanger: Color = AlertRed
