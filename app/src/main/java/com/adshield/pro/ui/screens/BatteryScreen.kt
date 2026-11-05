package com.adshield.pro.ui.screens

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BatteryChargingFull
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.DeviceThermostat
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Insights
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material.icons.filled.Thermostat
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.data.repository.BatteryIntelligenceRepository
import com.adshield.pro.engine.battery.BatteryConditionTone
import com.adshield.pro.engine.battery.BatteryDiagnostic
import com.adshield.pro.engine.battery.BatteryDiagnosticSeverity
import com.adshield.pro.engine.battery.BatteryDiagnostics
import com.adshield.pro.engine.battery.BatteryHealthStatus
import com.adshield.pro.engine.battery.BatteryMonitor
import com.adshield.pro.engine.battery.BatteryReading
import com.adshield.pro.engine.battery.BatteryReadingSource
import com.adshield.pro.engine.battery.BatterySession
import com.adshield.pro.engine.battery.DataFreshness
import com.adshield.pro.engine.battery.DisplayStateDrain
import com.adshield.pro.engine.battery.EngineState
import com.adshield.pro.engine.battery.MeasurementReliability
import com.adshield.pro.engine.battery.MonitoringState
import com.adshield.pro.engine.battery.MonitoringStatus
import com.adshield.pro.engine.battery.PowerTrend
import com.adshield.pro.engine.battery.SensorState
import com.adshield.pro.engine.battery.SensorStatus
import com.adshield.pro.ui.components.CyberPanel
import com.adshield.pro.ui.components.HudRing
import com.adshield.pro.ui.components.PowerGauge
import com.adshield.pro.ui.components.RealSeriesChart
import com.adshield.pro.ui.components.ResponsiveMetrics
import com.adshield.pro.ui.components.MetricSpec
import com.adshield.pro.ui.components.ScanlineOverlay
import com.adshield.pro.ui.components.StatusPill
import com.adshield.pro.ui.components.hudRotation
import com.adshield.pro.ui.components.livePulse
import com.adshield.pro.ui.components.rememberAnimationsEnabled
import com.adshield.pro.ui.components.scanningSweep
import com.adshield.pro.ui.theme.ElectricBlue
import java.text.DateFormat
import java.util.Date

// --- Cyber command-center palette (black / neon green / cyan) --------------------------------
private val ConsoleBlack = Color(0xFF04070A)
private val ConsolePanel = Color(0xFF070E14)
private val ConsolePanelHigh = Color(0xFF0A1520)
private val NeonGreen = Color(0xFF39FF88)
private val NeonGreenDim = Color(0xFF14B863)
private val NeonCyan = Color(0xFF22E4F0)
private val ConsoleBorder = Color(0xFF12343F)
private val ConsoleMuted = Color(0xFF7C9BA6)
private val ConsoleCritical = Color(0xFFFF4F74)
private val ConsoleAmber = Color(0xFFFFB020)

private val MonoFont = FontFamily.Monospace

/**
 * AdShield Pro — BATTERY COMMAND CENTER.
 *
 * Eight sections, all fed by [BatteryIntelligenceRepository.BatteryDashboardState], which is
 * derived from real `ACTION_BATTERY_CHANGED` broadcasts and `BatteryManager` properties:
 *
 *  1. Live Power Monitor        5. Temperature Monitor
 *  2. Battery Intelligence      6. Power Consumption History
 *  3. Charging Analytics        7. Sensor Diagnostics
 *  4. Battery Health            8. System Monitoring Status
 *
 * Every tile states where its number came from (measured / computed / estimated / unsupported), and
 * a tile with no reading renders "—" plus the reason instead of a plausible-looking value.
 */
@Composable
fun BatteryScreen(
    state: BatteryIntelligenceRepository.BatteryDashboardState,
    diagnostics: List<BatteryDiagnostic>,
    sessions: List<BatterySession>,
    history: List<BatteryDiagnostics.Sample>,
    isDiagnosing: Boolean,
    lastDiagnosticAtMs: Long,
    onDetect: () -> Unit,
    onRefresh: () -> Unit,
    onClearSessions: () -> Unit
) {
    val listState = rememberLazyListState()
    val animationsEnabled = rememberAnimationsEnabled()
    val live = state.freshness == DataFreshness.LIVE && state.engineState == EngineState.ACTIVE
    val animate = animationsEnabled && live
    val sweep = scanningSweep(animate, NeonCyan)
    val pulse = livePulse(animate)
    val hud = hudRotation(animate)
    val columns = if (LocalConfiguration.current.screenWidthDp >= 600) 4 else 2

    // A status change must be visible without hunting. Scroll back to the banner only when the
    // *condition* changes (plugged in, overheating, …) and the user has scrolled away — never on a
    // value tick, and never fighting a user who is reading a panel.
    val statusKey = state.status.primary.name + state.status.tone.name
    LaunchedEffect(statusKey) {
        if (listState.firstVisibleItemIndex > 2) listState.animateScrollToItem(0)
    }

    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize().background(ConsoleBlack),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 28.dp)
    ) {
        item(key = "battery-hero") {
            CommandCenterHero(
                state = state,
                sweep = sweep.value,
                pulse = pulse.value,
                hudRotation = hud.value,
                animate = animate,
                onDetect = onDetect,
                isDiagnosing = isDiagnosing
            )
        }
        item(key = "battery-live-power") {
            LivePowerMonitorSection(state = state)
        }
        item(key = "battery-intelligence") {
            BatteryIntelligenceSection(state = state, columns = columns)
        }
        item(key = "battery-charging-analytics") {
            ChargingAnalyticsSection(state = state)
        }
        item(key = "battery-health") {
            BatteryHealthSection(state = state)
        }
        item(key = "battery-temperature") {
            TemperatureMonitorSection(
                state = state,
                history = history,
                animate = animate
            )
        }
        item(key = "battery-power-history") {
            PowerHistorySection(state = state, history = history)
        }
        item(key = "battery-sensors") {
            SensorDiagnosticsSection(state = state)
        }
        item(key = "battery-monitoring-status") {
            SystemMonitoringSection(state = state)
        }
        item(key = "battery-diagnostics") {
            DiagnosticsSection(
                diagnostics = diagnostics,
                lastDiagnosticAtMs = lastDiagnosticAtMs,
                chargeRatePercentPerHour = state.chargeRatePercentPerHour,
                isDiagnosing = isDiagnosing
            )
        }
        item(key = "battery-sessions") {
            SessionsSection(sessions = sessions, onClearSessions = onClearSessions)
        }
        item(key = "battery-provenance") {
            ProvenanceFooter(onRefresh = onRefresh)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Hero / main dashboard
// ---------------------------------------------------------------------------------------------

@Composable
private fun CommandCenterHero(
    state: BatteryIntelligenceRepository.BatteryDashboardState,
    sweep: Float,
    pulse: Float,
    hudRotation: Float,
    animate: Boolean,
    onDetect: () -> Unit,
    isDiagnosing: Boolean
) {
    val telemetry = state.telemetry
    val toneColor = toneColor(state.status.tone)
    val level = telemetry.level
    val gaugeFraction by animateFloatAsState(
        targetValue = (level ?: 0) / 100f,
        animationSpec = tween(600),
        label = "level-gauge"
    )

    Surface(color = ConsoleBlack, modifier = Modifier.fillMaxWidth()) {
        Box {
            // Ambient console texture: dot grid + a scan sweep whose brightness follows the pulse.
            Canvas(Modifier.fillMaxSize()) {
                var y = 14f
                while (y < size.height) {
                    var x = 14f
                    while (x < size.width) {
                        drawCircle(Color(0xFF123241).copy(alpha = 0.5f), radius = 1.1f, center = Offset(x, y))
                        x += 22f
                    }
                    y += 22f
                }
            }
            ScanlineOverlay(
                progress = sweep,
                color = NeonCyan.copy(alpha = 0.35f + 0.35f * pulse),
                modifier = Modifier.matchParentSize()
            )
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 18.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "BATTERY COMMAND CENTER",
                        color = NeonCyan,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 2.2.sp,
                        fontFamily = MonoFont
                    )
                    Spacer(Modifier.weight(1f))
                    ReliabilityBadge(state.monitoring.reliability)
                    Spacer(Modifier.width(8.dp))
                    LiveIndicator(state = state, pulse = pulse)
                }
                Spacer(Modifier.height(2.dp))
                Text(
                    "${telemetry.manufacturer} ${telemetry.model} · ${telemetry.technology} · " +
                        "Android telemetry",
                    color = ConsoleMuted,
                    fontSize = 10.sp,
                    fontFamily = MonoFont
                )
                Spacer(Modifier.height(14.dp))

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier.size(150.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        PowerGauge(
                            value = gaugeFraction,
                            accent = toneColor,
                            modifier = Modifier.fillMaxSize()
                        )
                        HudRing(
                            rotationDegrees = hudRotation,
                            color = NeonCyan,
                            modifier = Modifier.fillMaxSize()
                        )
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                text = level?.let { "$it" } ?: "—",
                                color = Color.White,
                                fontSize = 46.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = MonoFont
                            )
                            Text(
                                text = if (level != null) "PERCENT" else "NO READING",
                                color = ConsoleMuted,
                                fontSize = 9.sp,
                                letterSpacing = 1.6.sp,
                                fontFamily = MonoFont
                            )
                        }
                    }
                    Spacer(Modifier.width(16.dp))
                    Column(Modifier.weight(1f)) {
                        StatusPill(
                            text = state.status.headline.uppercase(),
                            color = toneColor
                        )
                        Spacer(Modifier.height(8.dp))
                        HeroLine(
                            label = "CURRENT",
                            value = telemetry.current?.let { "$it mA" } ?: "—",
                            detail = telemetry.current?.let {
                                BatteryMonitor.currentDirectionLabel(
                                    it, telemetry.isCharging, telemetry.currentSignKnown
                                ) ?: ""
                            } ?: sourceHint(telemetry.currentMilliAmps),
                            color = NeonGreen
                        )
                        HeroLine(
                            label = "VOLTAGE",
                            value = telemetry.voltage?.let { "${BatteryMonitor.format1(it)} V" } ?: "—",
                            detail = telemetry.voltage?.let { "${(it * 1000).toInt()} mV" }
                                ?: sourceHint(telemetry.voltageVolts),
                            color = NeonCyan
                        )
                        HeroLine(
                            label = "POWER",
                            value = telemetry.power?.let { "${BatteryMonitor.format1(it)} W" } ?: "—",
                            detail = if (telemetry.power != null) "battery-side V × I"
                            else sourceHint(telemetry.powerWatts),
                            color = ElectricBlue
                        )
                    }
                }
                Spacer(Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    HeroChip(
                        label = "TEMP",
                        value = telemetry.temperature?.let { "${BatteryMonitor.format1(it)}°C" } ?: "—",
                        color = if ((telemetry.temperature ?: 0f) >= BatteryMonitor.WARM_TEMPERATURE_CELSIUS) {
                            ConsoleAmber
                        } else NeonGreen,
                        modifier = Modifier.weight(1f)
                    )
                    HeroChip(
                        label = "HEALTH",
                        value = telemetry.healthLabel.uppercase(),
                        color = if (telemetry.health == BatteryHealthStatus.GOOD) NeonGreen else ConsoleAmber,
                        modifier = Modifier.weight(1f)
                    )
                    HeroChip(
                        label = "MONITOR",
                        value = state.monitoring.overall.label.uppercase(),
                        color = monitoringColor(state.monitoring.overall),
                        modifier = Modifier.weight(1f)
                    )
                }
                Spacer(Modifier.height(10.dp))
                Text(
                    text = state.status.detail,
                    color = Color(0xFFB9CBD3),
                    fontSize = 11.sp,
                    lineHeight = 15.sp
                )
                Spacer(Modifier.height(10.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedAction(
                        label = if (isDiagnosing) "ANALYZING…" else "RUN DIAGNOSTICS",
                        icon = Icons.Default.Science,
                        enabled = !isDiagnosing,
                        onClick = onDetect
                    )
                    Spacer(Modifier.weight(1f))
                    Text(
                        text = if (state.freshness == DataFreshness.NO_DATA) "no reading yet"
                    else "last reading ${BatteryMonitor.describeAge(state.telemetry.ageMs(nowElapsed()))} ago",
                        color = ConsoleMuted,
                        fontSize = 9.sp,
                        fontFamily = MonoFont
                    )
                }
            }
        }
    }
}

/** Coarse trust level for the numbers shown, derived from freshness and sensor coverage. */
@Composable
private fun ReliabilityBadge(reliability: MeasurementReliability) {
    val color = when (reliability) {
        MeasurementReliability.HIGH -> NeonGreen
        MeasurementReliability.MEDIUM -> NeonCyan
        MeasurementReliability.LOW -> ConsoleAmber
        MeasurementReliability.NONE -> ConsoleMuted
    }
    Text(
        text = "REL ${reliability.label.uppercase()}",
        color = color,
        fontSize = 8.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = 1.sp,
        fontFamily = MonoFont,
        modifier = Modifier
            .clip(RoundedCornerShape(4.dp))
            .background(color.copy(alpha = 0.12f))
            .padding(horizontal = 5.dp, vertical = 2.dp)
    )
}

/** Live/delayed/stale indicator with a real, breathing dot (animation is draw-state only). */
@Composable
private fun LiveIndicator(
    state: BatteryIntelligenceRepository.BatteryDashboardState,
    pulse: Float
) {
    val color = when (state.freshness) {
        DataFreshness.LIVE -> NeonGreen
        DataFreshness.DELAYED -> ConsoleAmber
        DataFreshness.STALE -> ConsoleAmber
        DataFreshness.NO_DATA -> ConsoleMuted
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .size(8.dp)
                .clip(RoundedCornerShape(50))
                .background(color.copy(alpha = 0.35f + 0.65f * pulse))
        )
        Spacer(Modifier.width(6.dp))
        Text(
            text = state.freshness.label.uppercase(),
            color = color,
            fontSize = 9.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.2.sp,
            fontFamily = MonoFont
        )
        if (state.livePolling) {
            Spacer(Modifier.width(8.dp))
            Text(
                text = "1 Hz",
                color = NeonCyan,
                fontSize = 9.sp,
                fontFamily = MonoFont
            )
        }
    }
}

@Composable
private fun HeroLine(label: String, value: String, detail: String, color: Color) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            color = ConsoleMuted,
            fontSize = 9.sp,
            letterSpacing = 1.2.sp,
            fontFamily = MonoFont,
            modifier = Modifier.width(62.dp)
        )
        Text(
            text = value,
            color = color,
            fontSize = 17.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = MonoFont
        )
        Spacer(Modifier.width(6.dp))
        Text(
            text = detail,
            color = ConsoleMuted,
            fontSize = 9.sp,
            fontFamily = MonoFont,
            maxLines = 1
        )
    }
}

@Composable
private fun HeroChip(label: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(ConsolePanelHigh)
            .border(1.dp, ConsoleBorder, RoundedCornerShape(8.dp))
            .padding(horizontal = 8.dp, vertical = 7.dp)
    ) {
        Text(label, color = ConsoleMuted, fontSize = 8.sp, letterSpacing = 1.sp, fontFamily = MonoFont)
        Spacer(Modifier.height(2.dp))
        Text(
            value,
            color = color,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = MonoFont,
            maxLines = 1
        )
    }
}

// ---------------------------------------------------------------------------------------------
// 1. Live Power Monitor
// ---------------------------------------------------------------------------------------------

@Composable
private fun LivePowerMonitorSection(
    state: BatteryIntelligenceRepository.BatteryDashboardState
) {
    val telemetry = state.telemetry
    val intelligence = state.intelligence
    val chargingPower = BatteryMonitor.chargingPowerWatts(telemetry.voltage, telemetry.current, telemetry.isCharging)
    val dischargePower = BatteryMonitor.dischargePowerWatts(telemetry.voltage, telemetry.current, telemetry.isCharging)
    CyberPanel(
        title = "Live Power Monitor",
        subtitle = if (state.livePolling) {
            "Instantaneous current re-read ${BatteryMonitor.recommendedRefreshIntervalMs(
                state.freshness, true, state.engineState
            ) / 1000} Hz from BATTERY_PROPERTY_CURRENT_NOW"
        } else {
            "Event-driven updates from ACTION_BATTERY_CHANGED"
        },
        trailing = {
            StatusPill(
                text = if (state.livePolling) "POLLING" else "EVENT",
                color = if (state.livePolling) NeonGreen else NeonCyan
            )
        },
        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        MetricRow(
            metrics = listOf(
                MetricSpec(
                    label = "Live current",
                    value = telemetry.current?.let { "$it mA" } ?: "—",
                    caption = sourceCaption(telemetry.currentMilliAmps, "CURRENT_NOW"),
                    color = NeonGreen
                ),
                MetricSpec(
                    label = "Average current",
                    value = telemetry.averageCurrent?.let { "$it mA" } ?: "—",
                    caption = telemetry.averageCurrent?.let { "CURRENT_AVERAGE" }
                        ?: "not exposed — see computed average",
                    color = NeonCyan
                )
            )
        )
        Spacer(Modifier.height(8.dp))
        MetricRow(
            metrics = listOf(
                MetricSpec(
                    label = "Voltage",
                    value = telemetry.voltage?.let { "${BatteryMonitor.format1(it)} V" } ?: "—",
                    caption = telemetry.voltage?.let { "${(it * 1000).toInt()} mV · EXTRA_VOLTAGE" }
                        ?: "not reported",
                    color = NeonCyan
                ),
                MetricSpec(
                    label = "Actual power",
                    value = telemetry.power?.let { "${BatteryMonitor.format1(it)} W" } ?: "—",
                    caption = if (telemetry.power != null) "V × I on the battery side" else "needs V and I",
                    color = ElectricBlue
                )
            )
        )
        Spacer(Modifier.height(8.dp))
        MetricRow(
            metrics = listOf(
                MetricSpec(
                    label = "Charging power",
                    value = chargingPower?.let { "${BatteryMonitor.format1(it)} W" } ?: "—",
                    caption = if (telemetry.isCharging) "into the battery now" else "not charging",
                    color = NeonGreen
                ),
                MetricSpec(
                    label = "Discharge power",
                    value = dischargePower?.let { "${BatteryMonitor.format1(it)} W" } ?: "—",
                    caption = if (telemetry.isCharging) "not discharging" else "drawn from the battery",
                    color = ConsoleAmber
                )
            )
        )
        Spacer(Modifier.height(8.dp))
        MetricRow(
            metrics = listOf(
                MetricSpec(
                    label = "Avg power (observed)",
                    value = intelligence.averagePowerWatts?.let { "${BatteryMonitor.format1(it)} W" } ?: "—",
                    caption = if (intelligence.averagePowerWatts != null) {
                        "mean of ${intelligence.totalSamples} samples"
                    } else "needs samples",
                    color = ElectricBlue
                ),
                MetricSpec(
                    label = "Peak power (observed)",
                    value = intelligence.peakPowerWatts?.let { "${BatteryMonitor.format1(it)} W" } ?: "—",
                    caption = "highest sample this session",
                    color = NeonCyan
                )
            )
        )
        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Bolt, contentDescription = null, tint = NeonGreen, modifier = Modifier.size(14.dp))
            Spacer(Modifier.width(6.dp))
            Text(
                text = "Instantaneous = newest CURRENT_NOW sample. Average = CURRENT_AVERAGE when the device " +
                    "provides it, otherwise the mean of observed samples. They are never mixed.",
                color = ConsoleMuted,
                fontSize = 10.sp,
                lineHeight = 13.sp
            )
        }
    }
}

@Composable
private fun MetricRow(metrics: List<MetricSpec>) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        metrics.forEach { metric ->
            MetricTileCompact(metric, Modifier.weight(1f))
        }
    }
}

@Composable
private fun MetricTileCompact(metric: MetricSpec, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(ConsolePanelHigh)
            .border(1.dp, ConsoleBorder.copy(alpha = 0.8f), RoundedCornerShape(8.dp))
            .padding(9.dp)
    ) {
        Text(
            metric.label.uppercase(),
            color = ConsoleMuted,
            fontSize = 8.sp,
            letterSpacing = 0.8.sp,
            fontFamily = MonoFont,
            maxLines = 1
        )
        Spacer(Modifier.height(3.dp))
        Text(
            metric.value,
            color = metric.color,
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = MonoFont,
            maxLines = 1
        )
        Text(
            metric.caption,
            color = ConsoleMuted.copy(alpha = 0.85f),
            fontSize = 9.sp,
            maxLines = 2,
            lineHeight = 11.sp
        )
    }
}

// ---------------------------------------------------------------------------------------------
// 2. Battery Intelligence
// ---------------------------------------------------------------------------------------------

@Composable
private fun BatteryIntelligenceSection(
    state: BatteryIntelligenceRepository.BatteryDashboardState,
    columns: Int
) {
    val intelligence = state.intelligence
    val trendColor = when (intelligence.powerTrend) {
        PowerTrend.RISING -> ConsoleAmber
        PowerTrend.FALLING -> NeonGreen
        PowerTrend.STEADY -> NeonCyan
        PowerTrend.INSUFFICIENT_DATA -> ConsoleMuted
    }
    CyberPanel(
        title = "Battery Intelligence",
        subtitle = if (intelligence.totalSamples > 0) {
            "${intelligence.totalSamples} samples · ${intelligence.observationMinutes} min observed"
        } else {
            "Waiting for the first hardware sample"
        },
        trailing = {
            StatusPill(
                text = intelligence.powerTrend.label.uppercase(),
                color = trendColor
            )
        },
        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        ResponsiveMetrics(
            columns = columns,
            metrics = listOf(
                MetricSpec(
                    label = "Avg current",
                    value = intelligence.averageCurrentMilliAmps?.let { "${it.toInt()} mA" } ?: "—",
                    caption = "mean |I| of observed samples",
                    color = NeonGreen
                ),
                MetricSpec(
                    label = "Power trend",
                    value = intelligence.powerTrend.label,
                    caption = "first half vs second half of window",
                    color = trendColor
                ),
                MetricSpec(
                    label = "Drain rate",
                    value = intelligence.drainTrendPerHour?.let { "${BatteryMonitor.format1(it)} %/h" } ?: "—",
                    caption = if (intelligence.drainTrendPerHour != null) "measured from level change"
                    else "needs ≥5 min of samples",
                    color = ConsoleAmber
                ),
                MetricSpec(
                    label = "Charge rate",
                    value = intelligence.chargeTrendPerHour?.let { "${BatteryMonitor.format1(it)} %/h" } ?: "—",
                    caption = if (intelligence.chargeTrendPerHour != null) "measured while charging"
                    else "not charging / no samples",
                    color = NeonGreen
                )
            )
        )
        Spacer(Modifier.height(10.dp))
        ResourceLine(
            icon = Icons.Default.Memory,
            title = "Screen-on vs screen-off drain",
            body = displayDrainSummary(intelligence.displayDrain),
            color = if (intelligence.displayDrain.hasComparison) NeonCyan else ConsoleMuted
        )
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FlagChip(
                label = "Abnormal drain",
                active = intelligence.abnormalDrainDetected,
                modifier = Modifier.weight(1f)
            )
            FlagChip(
                label = "Overheating",
                active = intelligence.overheatingDetected,
                modifier = Modifier.weight(1f)
            )
        }
        Spacer(Modifier.height(8.dp))
        intelligence.notes.forEach { note ->
            Row(Modifier.padding(vertical = 2.dp)) {
                Text("›", color = NeonGreenDim, fontSize = 10.sp, fontFamily = MonoFont)
                Spacer(Modifier.width(5.dp))
                Text(note, color = ConsoleMuted, fontSize = 10.sp, lineHeight = 13.sp)
            }
        }
    }
}

private fun displayDrainSummary(drain: DisplayStateDrain): String {
    if (!drain.hasComparison) {
        val have = buildList {
            if (drain.screenOnAverageMilliAmps != null) add("screen-on ${drain.screenOnAverageMilliAmps.toInt()} mA")
            if (drain.screenOffAverageMilliAmps != null) add("screen-off ${drain.screenOffAverageMilliAmps.toInt()} mA")
        }
        return if (have.isEmpty()) {
            "Not enough samples yet: needs ${DisplayStateDrain.MIN_SAMPLES}+ samples with the screen on and " +
                "${DisplayStateDrain.MIN_SAMPLES}+ with it off while this app is observing."
        } else {
            have.joinToString(" · ") + " — needs both states to compare."
        }
    }
    val on = drain.screenOnAverageMilliAmps!!.toInt()
    val off = drain.screenOffAverageMilliAmps!!.toInt()
    val ratio = drain.ratio
    return "Screen on $on mA avg (${drain.screenOnMinutes} min, ${drain.screenOnSamples} samples) · " +
        "screen off $off mA avg (${drain.screenOffMinutes} min, ${drain.screenOffSamples} samples)" +
        (ratio?.let { " · ${BatteryMonitor.format1(it)}× more draw with the screen on" } ?: "")
}

@Composable
private fun FlagChip(label: String, active: Boolean, modifier: Modifier = Modifier) {
    val color = if (active) ConsoleCritical else NeonGreenDim
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(color.copy(alpha = 0.10f))
            .border(1.dp, color.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
            .padding(horizontal = 8.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = if (active) Icons.Default.WarningAmber else Icons.Default.CheckCircle,
            contentDescription = null,
            tint = color,
            modifier = Modifier.size(13.dp)
        )
        Spacer(Modifier.width(5.dp))
        Column {
            Text(label.uppercase(), color = ConsoleMuted, fontSize = 8.sp, fontFamily = MonoFont)
            Text(
                if (active) "DETECTED" else "NOT DETECTED",
                color = color,
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = MonoFont
            )
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 3. Charging Analytics
// ---------------------------------------------------------------------------------------------

@Composable
private fun ChargingAnalyticsSection(state: BatteryIntelligenceRepository.BatteryDashboardState) {
    val telemetry = state.telemetry
    val efficiency = state.intelligence.efficiency
    val sourceLabel = telemetry.chargingSource.label
    CyberPanel(
        title = "Charging Analytics",
        subtitle = "${sourceLabel} · ${telemetry.pluggedLabel}",
        trailing = {
            StatusPill(
                text = when {
                    telemetry.isFull -> "FULL"
                    telemetry.isCharging -> "CHARGING"
                    telemetry.chargingSource != com.adshield.pro.engine.battery.ChargingSource.NOT_PLUGGED -> "IDLE"
                    else -> "ON BATTERY"
                },
                color = if (telemetry.isCharging) NeonGreen else ConsoleMuted
            )
        },
        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        ResponsiveMetrics(
            columns = 2,
            metrics = listOf(
                MetricSpec(
                    label = "Charge rate",
                    value = state.chargeRatePercentPerHour?.let { "${BatteryMonitor.format1(it)} %/h" } ?: "—",
                    caption = if (state.chargeRatePercentPerHour != null) "measured level gain"
                    else "measuring (needs a few minutes)",
                    color = NeonGreen
                ),
                MetricSpec(
                    label = "Time to full",
                    value = state.minutesToFull?.let(::formatMinutes) ?: "—",
                    caption = when {
                        telemetry.isFull -> "already full"
                        state.minutesToFull != null -> "estimate from measured rate"
                        telemetry.chargerMinutes != null -> "Android estimate below"
                        else -> "not measurable yet"
                    },
                    color = NeonCyan
                )
            )
        )
        Spacer(Modifier.height(8.dp))
        ResponsiveMetrics(
            columns = 2,
            metrics = listOf(
                MetricSpec(
                    label = "Runtime left",
                    value = state.minutesToEmpty?.let(::formatMinutes) ?: "—",
                    caption = if (state.minutesToEmpty != null) "estimate from measured drain"
                    else "needs a measured drain rate",
                    color = ConsoleAmber
                ),
                MetricSpec(
                    label = "Android charge ETA",
                    value = telemetry.chargerMinutes?.let(::formatMinutes) ?: "—",
                    caption = if (telemetry.chargerMinutes != null)
                        "computeChargeTimeRemaining()"
                    else "not provided while not charging",
                    color = NeonCyan
                )
            )
        )
        Spacer(Modifier.height(10.dp))
        Text(
            "CHARGING EFFICIENCY (estimate)",
            color = ConsoleMuted,
            fontSize = 9.sp,
            letterSpacing = 1.sp,
            fontFamily = MonoFont
        )
        Spacer(Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = efficiency.efficiencyPercent?.let { "${BatteryMonitor.format1(it)}%" } ?: "—",
                color = if (efficiency.isMeasured) NeonGreen else ConsoleMuted,
                fontSize = 26.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = MonoFont
            )
            Spacer(Modifier.width(10.dp))
            BatteryIntelligenceBar(
                fraction = (efficiency.efficiencyPercent ?: 0f) / 100f,
                color = if (efficiency.isMeasured) NeonGreen else ConsoleMuted,
                modifier = Modifier.weight(1f)
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(
            efficiency.explanation,
            color = ConsoleMuted,
            fontSize = 10.sp,
            lineHeight = 13.sp
        )
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "CHARGING TECHNOLOGY",
                color = ConsoleMuted,
                fontSize = 9.sp,
                letterSpacing = 1.sp,
                fontFamily = MonoFont
            )
            Spacer(Modifier.width(8.dp))
            Text(
                text = listOfNotNull(
                    telemetry.technology.takeIf { it != "Not reported" }?.let { "cell: $it" },
                    state.status.fastChargeSource,
                    if (telemetry.chargingSource != com.adshield.pro.engine.battery.ChargingSource.NOT_PLUGGED) {
                        "source: ${telemetry.chargingSource.name.lowercase()}"
                    } else null
                ).joinToString(" · ").ifBlank { "not published by this device" },
                color = Color(0xFFCBDDE4),
                fontSize = 10.sp,
                maxLines = 2
            )
        }
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Default.Bolt,
                contentDescription = null,
                tint = if (state.status.fastChargeDetected) NeonGreen else ConsoleMuted,
                modifier = Modifier.size(13.dp)
            )
            Spacer(Modifier.width(6.dp))
            Text(
                text = if (state.status.fastChargeDetected) {
                    "Fast charging confirmed by a platform signal and the measured rate."
                } else {
                    "Fast charging is not claimed: this device publishes no fast-charge signal" +
                        (if (telemetry.isCharging) " and the measured rate has not exceeded " +
                            "${BatteryMonitor.FAST_CHARGE_RATE_PERCENT_PER_HOUR.toInt()} %/h." else ".")
                },
                color = ConsoleMuted,
                fontSize = 10.sp,
                lineHeight = 13.sp
            )
        }
    }
}

@Composable
private fun BatteryIntelligenceBar(fraction: Float, color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .height(6.dp)
            .clip(RoundedCornerShape(50))
            .background(Color(0xFF10233B))
    ) {
        Box(
            Modifier
                .fillMaxWidth(fraction.coerceIn(0f, 1f))
                .height(6.dp)
                .clip(RoundedCornerShape(50))
                .background(color)
        )
    }
}

// ---------------------------------------------------------------------------------------------
// 4. Battery Health
// ---------------------------------------------------------------------------------------------

@Composable
private fun BatteryHealthSection(state: BatteryIntelligenceRepository.BatteryDashboardState) {
    val telemetry = state.telemetry
    val score = state.healthScore
    val scoreColor = when {
        score >= 80 -> NeonGreen
        score >= 60 -> ConsoleAmber
        else -> ConsoleCritical
    }
    CyberPanel(
        title = "Battery Health",
        subtitle = "Android health flag plus measured capacity where the device exposes it",
        trailing = { StatusPill(text = BatteryDiagnostics.healthLabel(score).uppercase(), color = scoreColor) },
        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("HEALTH INDEX", color = ConsoleMuted, fontSize = 9.sp, letterSpacing = 1.sp, fontFamily = MonoFont)
                Row(verticalAlignment = Alignment.Bottom) {
                    Text(
                        "$score",
                        color = scoreColor,
                        fontSize = 34.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = MonoFont
                    )
                    Text(
                        " / 100",
                        color = ConsoleMuted,
                        fontSize = 12.sp,
                        fontFamily = MonoFont,
                        modifier = Modifier.padding(bottom = 6.dp)
                    )
                }
                Text(
                    "Composite of measured temperature, capacity and cycle count. Missing inputs are skipped, " +
                        "not assumed.",
                    color = ConsoleMuted,
                    fontSize = 9.sp,
                    lineHeight = 12.sp
                )
            }
            BatteryIntelligenceBar(
                fraction = score / 100f,
                color = scoreColor,
                modifier = Modifier.width(90.dp)
            )
        }
        Spacer(Modifier.height(10.dp))
        HealthRow(
            label = "Android health",
            reading = BatteryReading.measured(telemetry.healthLabel, ""),
            fallbackDetail = "BatteryManager.EXTRA_HEALTH = ${telemetry.health.name}"
        )
        val capacityPercent = telemetry.capacityHealthPercent
        HealthRow(
            label = "Measured capacity",
            valueOverride = capacityPercent?.let { "${BatteryMonitor.format1(it)}% of design" },
            reading = BatteryReading(capacityPercent, BatteryReadingSource.COMPUTED, "%"),
            fallbackDetail = "Full ${telemetry.fullChargeCapacity ?: "—"} µAh / " +
                "design ${telemetry.designCapacity ?: "—"} µAh"
        )
        HealthRow(
            label = "Cycle count",
            reading = telemetry.cycleCount,
            fallbackDetail = "BatteryManager.getCycleCount() needs Android 14+"
        )
        HealthRow(
            label = "Technology",
            reading = BatteryReading.measured(telemetry.technology, ""),
            fallbackDetail = "EXTRA_TECHNOLOGY"
        )
    }
}

@Composable
private fun HealthRow(
    label: String,
    reading: BatteryReading<*>,
    fallbackDetail: String,
    valueOverride: String? = null
) {
    val value = valueOverride ?: when (val raw = reading.rawValue) {
        null -> "—"
        is Float -> BatteryMonitor.format1(raw)
        else -> raw.toString()
    }
    val color = when (reading.source) {
        BatteryReadingSource.HARDWARE, BatteryReadingSource.COMPUTED -> Color.White
        BatteryReadingSource.ESTIMATED -> ConsoleAmber
        else -> ConsoleMuted
    }
    Column(Modifier.padding(vertical = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(label, color = ConsoleMuted, fontSize = 10.sp, modifier = Modifier.weight(1f))
            Text(value, color = color, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, fontFamily = MonoFont)
            Spacer(Modifier.width(8.dp))
            SourceBadge(reading.source)
        }
        Text(fallbackDetail, color = ConsoleMuted.copy(alpha = 0.7f), fontSize = 9.sp, lineHeight = 11.sp)
    }
}

// ---------------------------------------------------------------------------------------------
// 5. Temperature Monitor
// ---------------------------------------------------------------------------------------------

@Composable
private fun TemperatureMonitorSection(
    state: BatteryIntelligenceRepository.BatteryDashboardState,
    history: List<BatteryDiagnostics.Sample>,
    animate: Boolean
) {
    val telemetry = state.telemetry
    val temperature = telemetry.temperature
    val series = remember(history) {
        history.takeLast(120).map { it.temperatureCelsius }
    }
    val color = when {
        temperature == null -> ConsoleMuted
        temperature >= BatteryMonitor.CRITICAL_TEMPERATURE_CELSIUS -> ConsoleCritical
        temperature >= BatteryMonitor.WARM_TEMPERATURE_CELSIUS -> ConsoleAmber
        else -> NeonGreen
    }
    CyberPanel(
        title = "Temperature Monitor",
        subtitle = "EXTRA_TEMPERATURE, the same value Android reports in Settings",
        trailing = {
            StatusPill(
                text = when {
                    temperature == null -> "NO SENSOR"
                    temperature >= BatteryMonitor.WARM_TEMPERATURE_CELSIUS -> "HOT"
                    temperature <= 5f -> "COLD"
                    else -> "NORMAL"
                },
                color = color
            )
        },
        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Thermostat, contentDescription = null, tint = color, modifier = Modifier.size(30.dp))
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    temperature?.let { "${BatteryMonitor.format1(it)} °C" } ?: "—",
                    color = color,
                    fontSize = 30.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = MonoFont
                )
                Text(
                    telemetry.temperatureFahrenheit?.let { "= ${BatteryMonitor.format1(it)} °F" }
                        ?: temperature?.let { "" }
                        ?: "This device does not report battery temperature to apps",
                    color = ConsoleMuted,
                    fontSize = 10.sp,
                    fontFamily = MonoFont
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    "AVG ${state.intelligence.averageTemperatureCelsius?.let { BatteryMonitor.format1(it) + "°C" } ?: "—"}",
                    color = ConsoleMuted,
                    fontSize = 9.sp,
                    fontFamily = MonoFont
                )
                Text(
                    "WARN ≥ ${BatteryMonitor.WARM_TEMPERATURE_CELSIUS.toInt()}°C",
                    color = ConsoleMuted,
                    fontSize = 9.sp,
                    fontFamily = MonoFont
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        RealSeriesChart(
            values = series,
            accent = color,
            modifier = Modifier.fillMaxWidth().height(78.dp)
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = if (series.count { it != null } >= 2) {
                "History from samples recorded while AdShield was monitoring (min " +
                    BatteryMonitor.format1(series.filterNotNull().min()) + "°C, max " +
                    BatteryMonitor.format1(series.filterNotNull().max()) + "°C)."
            } else {
                "Temperature history appears once at least two readings have been recorded."
            },
            color = ConsoleMuted,
            fontSize = 9.sp,
            lineHeight = 12.sp
        )
    }
}

// ---------------------------------------------------------------------------------------------
// 6. Power Consumption History
// ---------------------------------------------------------------------------------------------

@Composable
private fun PowerHistorySection(
    state: BatteryIntelligenceRepository.BatteryDashboardState,
    history: List<BatteryDiagnostics.Sample>
) {
    val powerSeries = remember(history) { history.takeLast(180).map { it.powerWatts } }
    val levelSeries = remember(history) { history.takeLast(180).map { it.levelPercent?.toFloat() } }
    val currentSeries = remember(history) { history.takeLast(180).map { it.currentMilliAmps?.toFloat() } }
    CyberPanel(
        title = "Power Consumption History",
        subtitle = if (history.size >= 2) {
            "${history.size} samples · oldest ${ageLabel(history.first().timestampEpochMs)}"
        } else {
            "Collecting samples — a chart appears after the second reading"
        },
        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        ChartBlock(
            title = "Battery-side power (W)",
            color = ElectricBlue,
            values = powerSeries,
            unit = "W",
            formatter = { BatteryMonitor.format1(it) }
        )
        ChartBlock(
            title = "Current (mA)",
            color = NeonGreen,
            values = currentSeries,
            unit = "mA",
            formatter = { it.toInt().toString() }
        )
        ChartBlock(
            title = "Level (%)",
            color = NeonCyan,
            values = levelSeries,
            unit = "%",
            formatter = { it.toInt().toString() }
        )
        Spacer(Modifier.height(4.dp))
        Text(
            "Negative current gaps are missing sensor reads, not zero draw: the line breaks where no " +
                "measurement exists so dips are never invented.",
            color = ConsoleMuted,
            fontSize = 9.sp,
            lineHeight = 12.sp
        )
    }
}

@Composable
private fun ChartBlock(
    title: String,
    color: Color,
    values: List<Float?>,
    unit: String,
    formatter: (Float) -> String
) {
    val usable = values.filterNotNull()
    Column(Modifier.padding(vertical = 4.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(title, color = Color(0xFFCBDDE4), fontSize = 11.sp)
            Text(
                text = if (usable.isEmpty()) "no data" else "${formatter(usable.last())} $unit",
                color = if (usable.isEmpty()) ConsoleMuted else color,
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold,
                fontFamily = MonoFont
            )
        }
        Spacer(Modifier.height(4.dp))
        RealSeriesChart(
            values = values,
            accent = color,
            modifier = Modifier.fillMaxWidth().height(66.dp)
        )
        if (usable.size >= 2) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("min ${formatter(usable.min())} $unit", color = ConsoleMuted, fontSize = 8.sp, fontFamily = MonoFont)
                Text("max ${formatter(usable.max())} $unit", color = ConsoleMuted, fontSize = 8.sp, fontFamily = MonoFont)
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 7. Sensor Diagnostics
// ---------------------------------------------------------------------------------------------

@Composable
private fun SensorDiagnosticsSection(state: BatteryIntelligenceRepository.BatteryDashboardState) {
    val sensors = state.sensors
    val operational = sensors.count { it.isUsable }
    CyberPanel(
        title = "Sensor Diagnostics",
        subtitle = "$operational of ${sensors.size} hardware inputs usable on this device",
        trailing = {
            StatusPill(
                text = if (operational == sensors.size) "ALL PRESENT" else "PARTIAL",
                color = if (operational == sensors.size) NeonGreen else ConsoleAmber
            )
        },
        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        sensors.forEach { sensor ->
            SensorRow(sensor)
        }
        Spacer(Modifier.height(6.dp))
        Text(
            "Unsupported means the Android build does not expose the property to apps — not that the sensor " +
                "is broken. Nothing in this table is estimated.",
            color = ConsoleMuted,
            fontSize = 9.sp,
            lineHeight = 12.sp
        )
    }
}

@Composable
private fun SensorRow(sensor: SensorStatus) {
    val color = when (sensor.state) {
        SensorState.OPERATIONAL -> NeonGreen
        SensorState.DELAYED -> ConsoleAmber
        SensorState.INVALID -> ConsoleCritical
        SensorState.UNSUPPORTED -> ConsoleMuted
        SensorState.UNAVAILABLE -> ConsoleAmber
        SensorState.WAITING -> NeonCyan
    }
    Column(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(6.dp).clip(RoundedCornerShape(50)).background(color))
            Spacer(Modifier.width(7.dp))
            Text(sensor.name, color = Color(0xFFD5E4EA), fontSize = 11.sp, modifier = Modifier.weight(1f))
            Text(
                sensor.statusValue,
                color = color,
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold,
                fontFamily = MonoFont
            )
            Spacer(Modifier.width(8.dp))
            Text(
                sensor.state.label.uppercase(),
                color = color,
                fontSize = 8.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.6.sp,
                fontFamily = MonoFont
            )
        }
        Text(
            text = "${sensor.source} — ${sensor.detail}",
            color = ConsoleMuted.copy(alpha = 0.8f),
            fontSize = 9.sp,
            lineHeight = 11.sp,
            modifier = Modifier.padding(start = 13.dp, top = 1.dp)
        )
    }
}

// ---------------------------------------------------------------------------------------------
// 8. System Monitoring Status
// ---------------------------------------------------------------------------------------------

@Composable
private fun SystemMonitoringSection(state: BatteryIntelligenceRepository.BatteryDashboardState) {
    val monitoring = state.monitoring
    val overallColor = monitoringColor(monitoring.overall)
    CyberPanel(
        title = "System Monitoring Status",
        subtitle = "Engine ${state.engineState.label.lowercase()} · data ${state.freshness.label.lowercase()}",
        trailing = {
            StatusPill(
                text = "${monitoring.overall.label.uppercase()} ${monitoring.scorePercent}%",
                color = overallColor
            )
        },
        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        monitoring.components.forEach { component ->
            ComponentRow(component.component, component.state, component.value, component.detail)
        }
        Spacer(Modifier.height(8.dp))
        BatteryIntelligenceBar(
            fraction = monitoring.scorePercent / 100f,
            color = overallColor,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(6.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "RELIABILITY",
                color = ConsoleMuted,
                fontSize = 9.sp,
                letterSpacing = 1.sp,
                fontFamily = MonoFont
            )
            Spacer(Modifier.width(8.dp))
            ReliabilityBadge(monitoring.reliability)
            Spacer(Modifier.width(8.dp))
            Text(
                "CHARGING STABILITY ${stabilityLabel(state)}",
                color = ConsoleMuted,
                fontSize = 9.sp,
                letterSpacing = 0.6.sp,
                fontFamily = MonoFont
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(
            text = monitoring.reliabilityDetail,
            color = ConsoleMuted,
            fontSize = 9.sp,
            lineHeight = 12.sp
        )
        Spacer(Modifier.height(6.dp))
        Text(
            text = monitoringSummary(monitoring),
            color = ConsoleMuted,
            fontSize = 10.sp,
            lineHeight = 13.sp
        )
    }
}

private fun monitoringSummary(monitoring: MonitoringStatus): String = buildString {
    append(monitoring.overall.label)
    append(" — ")
    append(monitoring.components.count { it.state == MonitoringState.OPERATIONAL })
    append(" of ")
    append(monitoring.components.size)
    append(" components operational.")
    val missing = monitoring.components.filter { it.state == MonitoringState.UNSUPPORTED }
    if (missing.isNotEmpty()) {
        append(" Not exposed by this device: ")
        append(missing.joinToString(", ") { it.component })
        append(".")
    }
}

@Composable
private fun ComponentRow(name: String, state: MonitoringState, value: String, detail: String) {
    val color = monitoringColor(state)
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = when (state) {
                    MonitoringState.OPERATIONAL, MonitoringState.ACTIVE -> Icons.Default.CheckCircle
                    MonitoringState.ERROR -> Icons.Default.ErrorOutline
                    MonitoringState.UNSUPPORTED, MonitoringState.UNAVAILABLE -> Icons.Default.Info
                    else -> Icons.Default.Sensors
                },
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(12.dp)
            )
            Spacer(Modifier.width(6.dp))
            Text(name, color = Color(0xFFD5E4EA), fontSize = 11.sp, modifier = Modifier.weight(1f))
            if (value != "—") {
                Text(value, color = color, fontSize = 10.sp, fontFamily = MonoFont)
                Spacer(Modifier.width(8.dp))
            }
            Text(
                state.label.uppercase(),
                color = color,
                fontSize = 8.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = MonoFont
            )
        }
        Text(
            detail,
            color = ConsoleMuted.copy(alpha = 0.75f),
            fontSize = 9.sp,
            lineHeight = 11.sp,
            modifier = Modifier.padding(start = 18.dp)
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Diagnostics + sessions (preserved from the previous screen)
// ---------------------------------------------------------------------------------------------

@Composable
private fun DiagnosticsSection(
    diagnostics: List<BatteryDiagnostic>,
    lastDiagnosticAtMs: Long,
    chargeRatePercentPerHour: Float?,
    isDiagnosing: Boolean
) {
    CyberPanel(
        title = "Diagnostic Engine",
        subtitle = when {
            isDiagnosing -> "Analyzing live readings…"
            lastDiagnosticAtMs == 0L -> "Run the rule chain against the current readings"
            else -> "Last run ${DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(lastDiagnosticAtMs))}" +
                (chargeRatePercentPerHour?.let { " · measured ${BatteryMonitor.format1(it)} %/h" } ?: "")
        },
        trailing = {
            StatusPill(
                text = when {
                    isDiagnosing -> "RUNNING"
                    diagnostics.isEmpty() -> "IDLE"
                    diagnostics.any { it.severity == BatteryDiagnosticSeverity.CRITICAL } -> "ALERT"
                    diagnostics.any { it.severity == BatteryDiagnosticSeverity.WARNING } -> "ATTENTION"
                    else -> "CLEAR"
                },
                color = when {
                    diagnostics.any { it.severity == BatteryDiagnosticSeverity.CRITICAL } -> ConsoleCritical
                    diagnostics.any { it.severity == BatteryDiagnosticSeverity.WARNING } -> ConsoleAmber
                    diagnostics.isEmpty() -> ConsoleMuted
                    else -> NeonGreen
                }
            )
        },
        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        if (diagnostics.isEmpty()) {
            Text(
                "Diagnostics are rule-based and run entirely on-device. They explain only what the readings " +
                    "show — no faults are invented, and missing data is reported as missing.",
                color = ConsoleMuted,
                fontSize = 10.sp,
                lineHeight = 13.sp
            )
        }
        diagnostics.forEach { diagnostic -> DiagnosticCard(diagnostic) }
    }
}

@Composable
private fun DiagnosticCard(diagnostic: BatteryDiagnostic) {
    val (color, icon) = when (diagnostic.severity) {
        BatteryDiagnosticSeverity.CRITICAL -> ConsoleCritical to Icons.Default.WarningAmber
        BatteryDiagnosticSeverity.WARNING -> ConsoleAmber to Icons.Default.WarningAmber
        BatteryDiagnosticSeverity.NOTICE -> NeonCyan to Icons.Default.DeviceThermostat
        BatteryDiagnosticSeverity.INFO -> NeonGreenDim to Icons.Default.Info
    }
    Column(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(ConsolePanelHigh)
            .border(1.dp, color.copy(alpha = 0.35f), RoundedCornerShape(8.dp))
            .padding(10.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(15.dp))
            Spacer(Modifier.width(7.dp))
            Text(
                diagnostic.title,
                color = Color.White,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f)
            )
        }
        Spacer(Modifier.height(5.dp))
        Text(diagnostic.explanation, color = Color(0xFFC2D5DC), fontSize = 10.sp, lineHeight = 13.sp)
        Spacer(Modifier.height(4.dp))
        Text("→ ${diagnostic.recommendation}", color = color, fontSize = 10.sp, lineHeight = 13.sp)
        Spacer(Modifier.height(5.dp))
        AssistChip(
            onClick = {},
            label = {
                Text(
                    "${diagnostic.confidenceLabel} · ${diagnostic.confidencePercent}%",
                    fontSize = 9.sp
                )
            },
            colors = AssistChipDefaults.assistChipColors(labelColor = ConsoleMuted),
            modifier = Modifier.height(24.dp)
        )
        diagnostic.evidence.forEach {
            Text("• $it", fontSize = 9.sp, color = ConsoleMuted.copy(alpha = 0.85f), lineHeight = 11.sp)
        }
    }
}

@Composable
private fun SessionsSection(sessions: List<BatterySession>, onClearSessions: () -> Unit) {
    CyberPanel(
        title = "Charging Sessions",
        subtitle = "Recorded locally when you plug in or unplug",
        trailing = {
            if (sessions.isNotEmpty()) {
                TextButton(onClick = onClearSessions) { Text("CLEAR", fontSize = 10.sp, color = ConsoleMuted) }
            }
        },
        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        if (sessions.isEmpty()) {
            Text(
                "No sessions yet. History stays on this device and is never uploaded.",
                color = ConsoleMuted,
                fontSize = 10.sp
            )
            return@CyberPanel
        }
        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            items(sessions.take(20), key = { it.id }, contentType = { "battery-session" }) { session ->
                SessionCard(session)
            }
        }
    }
}

@Composable
private fun SessionCard(session: BatterySession) {
    Column(
        Modifier
            .width(168.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(ConsolePanelHigh)
            .border(1.dp, ConsoleBorder, RoundedCornerShape(8.dp))
            .padding(9.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Default.BatteryChargingFull,
                contentDescription = null,
                tint = if (session.wasCharging) NeonGreen else ConsoleMuted,
                modifier = Modifier.size(13.dp)
            )
            Spacer(Modifier.width(5.dp))
            Text(
                if (session.wasCharging) "CHARGE" else "DISCHARGE",
                color = if (session.wasCharging) NeonGreen else ConsoleMuted,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = MonoFont
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(
            "${session.startLevelPercent}% → ${session.endLevelPercent}%",
            color = Color.White,
            fontSize = 12.sp,
            fontFamily = MonoFont
        )
        Text(formatMinutes(session.durationMinutes), color = ConsoleMuted, fontSize = 9.sp, fontFamily = MonoFont)
        session.levelPercentPerHour?.let {
            Text("${BatteryMonitor.format1(it)} %/h", color = NeonCyan, fontSize = 9.sp, fontFamily = MonoFont)
        }
        session.peakPowerWatts?.let {
            Text("peak ${BatteryMonitor.format1(it)} W", color = ElectricBlue, fontSize = 9.sp, fontFamily = MonoFont)
        }
        session.peakTemperatureCelsius?.let {
            Text("peak ${BatteryMonitor.format1(it)} °C", color = ConsoleAmber, fontSize = 9.sp, fontFamily = MonoFont)
        }
        Text(session.pluggedLabel, color = ConsoleMuted.copy(alpha = 0.75f), fontSize = 8.sp)
    }
}

@Composable
private fun ProvenanceFooter(onRefresh: () -> Unit) {
    Column(Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Insights, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(15.dp))
            Spacer(Modifier.width(6.dp))
            Text(
                "WHERE THESE NUMBERS COME FROM",
                color = NeonCyan,
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp,
                fontFamily = MonoFont
            )
        }
        Spacer(Modifier.height(6.dp))
        Text(
            "Level, temperature, voltage, health, technology and charging source come straight from Android's " +
                "ACTION_BATTERY_CHANGED broadcast. Current, average current and charge counters come from " +
                "BatteryManager properties. Power is computed as V × I on the battery side: no app can read your " +
                "charger's output, so charger wattage is never shown. Charge and runtime projections are " +
                "extrapolated from measured level changes and are labelled as estimates. Anything this device " +
                "does not expose is shown as — with the reason, never as a plausible-looking number.",
            color = ConsoleMuted,
            fontSize = 10.sp,
            lineHeight = 14.sp
        )
        Spacer(Modifier.height(6.dp))
        Button(
            onClick = onRefresh,
            colors = ButtonDefaults.buttonColors(
                containerColor = ConsolePanelHigh,
                contentColor = NeonCyan
            ),
            shape = RoundedCornerShape(8.dp),
            modifier = Modifier.height(34.dp)
        ) {
            Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(14.dp))
            Spacer(Modifier.width(6.dp))
            Text("RE-READ HARDWARE", fontSize = 10.sp, fontFamily = MonoFont)
        }
        Spacer(Modifier.height(6.dp))
        Text(
            "Monitoring draws no wake locks. The 1 Hz current poll runs only while this screen is visible; " +
                "state changes arrive as system broadcasts. History is stored on this device only.",
            color = ConsoleMuted.copy(alpha = 0.75f),
            fontSize = 9.sp,
            lineHeight = 12.sp
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------------------------

@Composable
private fun OutlinedAction(
    label: String,
    icon: ImageVector,
    enabled: Boolean,
    onClick: () -> Unit
) {
    TextButton(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(ConsolePanelHigh.copy(alpha = 0.9f))
            .border(
                1.dp,
                (if (enabled) NeonCyan else ConsoleMuted).copy(alpha = 0.5f),
                RoundedCornerShape(8.dp)
            )
    ) {
        Icon(
            icon,
            contentDescription = null,
            tint = if (enabled) NeonCyan else ConsoleMuted,
            modifier = Modifier.size(13.dp)
        )
        Spacer(Modifier.width(6.dp))
        Text(
            label,
            color = if (enabled) NeonCyan else ConsoleMuted,
            fontSize = 10.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = MonoFont
        )
    }
}

@Composable
private fun ResourceLine(icon: ImageVector, title: String, body: String, color: Color) {
    Row(Modifier.fillMaxWidth()) {
        Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(15.dp))
        Spacer(Modifier.width(8.dp))
        Column(Modifier.weight(1f)) {
            Text(title, color = Color(0xFFD5E4EA), fontSize = 11.sp, fontWeight = FontWeight.Medium)
            Text(body, color = ConsoleMuted, fontSize = 9.sp, lineHeight = 12.sp)
        }
    }
}

@Composable
private fun SourceBadge(source: BatteryReadingSource) {
    val (text, color) = when (source) {
        BatteryReadingSource.HARDWARE -> "MEASURED" to NeonGreen
        BatteryReadingSource.COMPUTED -> "COMPUTED" to NeonCyan
        BatteryReadingSource.ESTIMATED -> "ESTIMATED" to ConsoleAmber
        BatteryReadingSource.UNSUPPORTED -> "NOT SUPPORTED" to ConsoleMuted
        BatteryReadingSource.UNAVAILABLE -> "UNAVAILABLE" to ConsoleMuted
    }
    Box(
        Modifier
            .clip(RoundedCornerShape(4.dp))
            .background(color.copy(alpha = 0.12f))
            .padding(horizontal = 4.dp, vertical = 1.dp)
    ) {
        Text(text, color = color, fontSize = 7.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.5.sp)
    }
}

private fun toneColor(tone: BatteryConditionTone): Color = when (tone) {
    BatteryConditionTone.POSITIVE -> NeonGreen
    BatteryConditionTone.NOMINAL -> NeonCyan
    BatteryConditionTone.CAUTION -> ConsoleAmber
    BatteryConditionTone.CRITICAL -> ConsoleCritical
    BatteryConditionTone.NEUTRAL -> ConsoleMuted
}

/**
 * Charging stability, judged only from measurements: voltage spread across the observed window,
 * and the number of charging dropouts the session tracker recorded. When the device exposes no
 * voltage there is nothing to judge, and the label says so.
 */
@Composable
private fun stabilityLabel(state: BatteryIntelligenceRepository.BatteryDashboardState): String {
    val spread = state.intelligence.stabilityPercent
    val dropouts = state.intelligence.chargingInterruptions
    if (spread == null && dropouts == 0) {
        return if (state.telemetry.isCharging) "NOT MEASURABLE" else "IDLE"
    }
    if (dropouts >= 2 || (spread != null && spread > 3f)) return "UNSTABLE"
    if (dropouts >= 1 || (spread != null && spread > 1.5f)) return "FLUCTUATING"
    return "STABLE"
}

private fun monitoringColor(state: MonitoringState): Color = when (state) {
    MonitoringState.OPERATIONAL, MonitoringState.ACTIVE -> NeonGreen
    MonitoringState.PARTIAL -> ConsoleAmber
    MonitoringState.WAITING, MonitoringState.PAUSED -> NeonCyan
    MonitoringState.ERROR -> ConsoleCritical
    MonitoringState.UNSUPPORTED, MonitoringState.UNAVAILABLE -> ConsoleMuted
}

private fun sourceHint(reading: BatteryReading<*>): String = when (reading.source) {
    BatteryReadingSource.UNSUPPORTED -> "not exposed"
    BatteryReadingSource.UNAVAILABLE -> "no value now"
    BatteryReadingSource.ESTIMATED -> "estimate"
    else -> ""
}

private fun sourceCaption(reading: BatteryReading<*>, api: String): String =
    if (reading.rawValue != null) "$api · measured" else "$api · ${reading.source.name.lowercase()}"

private fun formatMinutes(minutes: Int): String {
    if (minutes < 60) return "$minutes min"
    val hours = minutes / 60
    val rest = minutes % 60
    return if (rest == 0) "$hours h" else "$hours h $rest min"
}

private fun ageLabel(timestampEpochMs: Long): String {
    val ageMinutes = ((System.currentTimeMillis() - timestampEpochMs) / 60_000L).coerceAtLeast(0)
    return if (ageMinutes < 60) "${ageMinutes} min ago" else "${ageMinutes / 60} h ago"
}

private fun nowElapsed(): Long = android.os.SystemClock.elapsedRealtime()
