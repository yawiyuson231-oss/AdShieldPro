package com.adshield.pro.ui.screens.intelligence

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animate
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.TextMeasurer
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.domain.intelligence.IntelligenceEvent
import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.domain.intelligence.IntelligenceModuleState
import com.adshield.pro.domain.intelligence.IntelligenceSeverity
import com.adshield.pro.domain.intelligence.NodePosition
import com.adshield.pro.ui.model.IntelligenceMapUiState
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.DeepNavyBackground
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.PurpleAccent
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.WarningAmber
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlin.math.cos
import kotlin.math.sin

/** A short-lived pulse for one real event. */
data class MapPulse(
    val eventId: Long,
    val module: IntelligenceModule,
    val severity: IntelligenceSeverity,
    val startNanos: Long
)

/**
 * Hoisted, Compose-observable camera. Reads happen inside the Canvas draw phase, so a pan or a
 * pinch only invalidates drawing — it never recomposes the surrounding screen.
 */
@Stable
class IntelligenceCameraState {
    var camera by mutableStateOf(MapCamera())
        private set
    var viewport by mutableStateOf(Size.Zero)
        private set
    var hasUserMovedCamera by mutableStateOf(false)
        private set

    private var fitted = MapCamera()
    private var animation: Job? = null

    val fitScale: Float get() = fitted.scale

    fun onViewportChanged(size: Size) {
        if (size.width <= 0f || size.height <= 0f || size == viewport) return
        viewport = size
        fitted = MapCamera().fit(size)
        camera = if (hasUserMovedCamera) camera.clamped(size) else fitted
    }

    fun panBy(dx: Float, dy: Float) {
        animation?.cancel()
        camera = camera.panBy(dx, dy).clamped(viewport)
        hasUserMovedCamera = true
    }

    fun zoomBy(focal: Offset, factor: Float, animate: Boolean = false) {
        animation?.cancel()
        camera = camera.zoomAround(focal, factor, viewport)
        hasUserMovedCamera = true
    }

    fun reset() {
        animation?.cancel()
        camera = fitted
        hasUserMovedCamera = false
    }

    fun focusOnWorld(world: Offset) {
        animation?.cancel()
        val target = camera.centredOn(
            world = world,
            viewport = viewport,
            targetScale = (fitted.scale * FOCUS_ZOOM).coerceAtMost(MapGeometry.MAX_SCALE_ABS)
        )
        camera = target
        hasUserMovedCamera = true
    }

    suspend fun animateReset() {
        val target = fitted
        animateCameraTo(target)
        hasUserMovedCamera = false
    }

    suspend fun animateFocusOnWorld(world: Offset) {
        val targetScale = (fitted.scale * FOCUS_ZOOM).coerceAtMost(MapGeometry.MAX_SCALE_ABS)
        animateCameraTo(
            MapCamera(
                scale = targetScale,
                offsetX = viewport.width / 2f - world.x * targetScale,
                offsetY = viewport.height / 2f - world.y * targetScale
            ).clamped(viewport)
        )
        hasUserMovedCamera = true
    }

    private suspend fun animateCameraTo(target: MapCamera) {
        animation?.cancel()
        val start = camera
        coroutineScope {
            val job = launch {
                animate(
                    initialValue = 0f,
                    targetValue = 1f,
                    animationSpec = tween(durationMillis = CAMERA_ANIMATION_MS, easing = FastOutSlowInEasing)
                ) { fraction, _ ->
                    camera = start.lerpTo(target, fraction)
                }
            }
            animation = job
            job.join()
        }
    }

    companion object {
        const val FOCUS_ZOOM = 1.55f
        const val CAMERA_ANIMATION_MS = 340
    }
}

private val moduleAccents: Map<IntelligenceModule, Color> = mapOf(
    IntelligenceModule.CORE to CyberCyan,
    IntelligenceModule.CYBER_DEFENSE to ElectricBlue,
    IntelligenceModule.FINANCIAL_DEFENSE to Color(0xFF38BDF8),
    IntelligenceModule.PRIVACY_DEFENSE to PurpleAccent,
    IntelligenceModule.NETWORK_DEFENSE to CyberCyan,
    IntelligenceModule.DEVICE_INTELLIGENCE to EmeraldPrimary,
    IntelligenceModule.EMERGENCY_INTELLIGENCE to WarningAmber,
    IntelligenceModule.AUTOMATION_CORE to SkyBlueGlow
)

fun stateColor(state: IntelligenceModuleState): Color = when (state) {
    IntelligenceModuleState.NORMAL -> EmeraldPrimary
    IntelligenceModuleState.MONITORING -> CyberCyan
    IntelligenceModuleState.WARNING -> WarningAmber
    IntelligenceModuleState.CRITICAL -> AlertRed
    IntelligenceModuleState.OFFLINE -> Color(0xFF64748B)
    IntelligenceModuleState.DISABLED -> Color(0xFF475569)
}

fun severityColor(severity: IntelligenceSeverity): Color = when (severity) {
    IntelligenceSeverity.INFO -> SkyBlueGlow
    IntelligenceSeverity.NOTICE -> CyberCyan
    IntelligenceSeverity.WARNING -> WarningAmber
    IntelligenceSeverity.CRITICAL -> AlertRed
}

fun moduleAccent(module: IntelligenceModule): Color = moduleAccents[module] ?: CyberCyan

/**
 * The interactive map canvas. Everything drawn here comes from [uiState]; `frameNanos` only moves
 * pulses that were created for real stored events.
 */
@Composable
fun IntelligenceMapCanvas(
    uiState: IntelligenceMapUiState,
    cameraState: IntelligenceCameraState,
    pulses: List<MapPulse>,
    frameNanos: Long,
    modifier: Modifier = Modifier,
    onTapModule: (IntelligenceModule) -> Unit,
    onLongPressModule: (IntelligenceModule) -> Unit,
    onTapEventMarker: (IntelligenceEvent) -> Unit,
    onTapEmpty: () -> Unit,
    onMoveNode: (IntelligenceModule, NodePosition) -> Unit
) {
    val textMeasurer = rememberTextMeasurer(cacheSize = 48)
    var draggingModule by remember { mutableStateOf<IntelligenceModule?>(null) }
    var dragWorld by remember { mutableStateOf<Offset?>(null) }

    val effectivePositions = remember(uiState.nodePositions, draggingModule, dragWorld) {
        val dragged = draggingModule
        val world = dragWorld
        if (dragged != null && world != null) {
            uiState.nodePositions + (dragged to MapGeometry.clampNormalized(world))
        } else {
            uiState.nodePositions
        }
    }

    val latestMarkers = remember(uiState.allEvents, uiState.nodePositions) {
        buildMarkers(uiState.allEvents, uiState.nodePositions)
    }

    val drawModifier = modifier
        .pointerInput(uiState.isEditingLayout) {
            if (!uiState.isEditingLayout) return@pointerInput
            var active: IntelligenceModule? = null
            detectDragGestures(
                onDragStart = { start ->
                    val hit = MapGeometry.hitTest(cameraState.camera, size.toSize(), effectivePositions, start)
                    active = hit?.takeIf { it.isNode }
                    draggingModule = active
                    dragWorld = active?.let { cameraState.camera.screenToWorld(start) }
                },
                onDragEnd = {
                    val module = draggingModule
                    val world = dragWorld
                    if (module != null && world != null) {
                        onMoveNode(module, MapGeometry.clampNormalized(world))
                    }
                    draggingModule = null
                    dragWorld = null
                    active = null
                },
                onDragCancel = {
                    draggingModule = null
                    dragWorld = null
                    active = null
                },
                onDrag = { change, _ ->
                    if (active != null) {
                        dragWorld = cameraState.camera.screenToWorld(change.position)
                        change.consume()
                    }
                }
            )
        }
        .pointerInput(uiState.isEditingLayout) {
            detectTapGestures(
                onDoubleTap = { tap -> cameraState.zoomBy(tap, 2.1f) },
                onLongPress = { press ->
                    val hit = MapGeometry.hitTest(cameraState.camera, size.toSize(), effectivePositions, press)
                    if (hit != null) onLongPressModule(hit)
                },
                onTap = { tap ->
                    val marker = MapGeometry.hitTestMarker(cameraState.camera, latestMarkers, tap)
                    if (marker != null) {
                        uiState.allEvents.firstOrNull { it.id == marker.eventId }?.let(onTapEventMarker)
                        return@detectTapGestures
                    }
                    val hit = MapGeometry.hitTest(cameraState.camera, size.toSize(), effectivePositions, tap)
                    if (hit != null) onTapModule(hit) else onTapEmpty()
                }
            )
        }
        .pointerInput(Unit) {
            detectTransformGestures(panZoomLock = false) { centroid, pan, zoom, _ ->
                if (zoom != 1f) cameraState.zoomBy(centroid, zoom)
                if (pan != Offset.Zero) cameraState.panBy(pan.x, pan.y)
            }
        }

    Canvas(modifier = drawModifier) {
        cameraState.onViewportChanged(size)
        val camera = cameraState.camera
        val positions = effectivePositions
        val coreWorld = MapGeometry.coreWorldPosition
        val coreScreen = camera.worldToScreen(coreWorld)
        // Temporary event highlight: only real, still-running pulses light up their module.
        val pulseHighlights = mutableMapOf<IntelligenceModule, Float>()
        pulses.forEach { pulse ->
            val progress = MapGeometry.progress(frameNanos, pulse.startNanos, MapGeometry.PULSE_DURATION_NANOS)
            if (progress < 1f) {
                val strength = 1f - progress
                pulseHighlights[pulse.module] = maxOf(pulseHighlights[pulse.module] ?: 0f, strength)
            }
        }
        val context = DrawContext(
            camera = camera,
            fitScale = cameraState.fitScale,
            viewport = size,
            textMeasurer = textMeasurer,
            uiState = uiState,
            positions = positions,
            coreScreen = coreScreen,
            pulseHighlights = pulseHighlights
        )

        drawBackground(context)
        drawGrid(context)
        drawConnections(context)
        drawMarkers(context, latestMarkers)
        drawPulses(context, pulses, frameNanos)
        drawCore(context)
        drawModuleNodes(context)
    }
}

private class DrawContext(
    val camera: MapCamera,
    val fitScale: Float,
    val viewport: Size,
    val textMeasurer: TextMeasurer,
    val uiState: IntelligenceMapUiState,
    val positions: Map<IntelligenceModule, NodePosition>,
    val coreScreen: Offset,
    val pulseHighlights: Map<IntelligenceModule, Float>
)

private fun DrawScope.drawBackground(context: DrawContext) {
    drawRect(
        brush = Brush.verticalGradient(
            colors = listOf(Color(0xFF01060E), DeepNavyBackground, Color(0xFF01050B)),
            startY = 0f,
            endY = context.viewport.height
        ),
        size = context.viewport
    )
    // Depth: a single soft well behind the core, drawn with one radial gradient (no per-frame blur).
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(CyberCyan.copy(alpha = 0.10f), Color.Transparent),
            center = context.coreScreen,
            radius = (MapGeometry.WORLD_SIZE * 0.42f * context.camera.scale).coerceAtLeast(120f)
        ),
        radius = (MapGeometry.WORLD_SIZE * 0.42f * context.camera.scale).coerceAtLeast(120f),
        center = context.coreScreen
    )
}

private fun DrawScope.drawGrid(context: DrawContext) {
    val camera = context.camera
    val spacing = MapGeometry.gridSpacingWorld(camera.scale) * camera.scale
    if (spacing < 8f) return
    val origin = camera.worldToScreen(Offset.Zero)
    val line = Color(0xFF14304D).copy(alpha = 0.45f)
    val width = 1f
    var x = origin.x % spacing
    var guard = 0
    while (x < context.viewport.width && guard < MAX_GRID_LINES) {
        drawLine(line, Offset(x, 0f), Offset(x, context.viewport.height), strokeWidth = width)
        x += spacing
        guard++
    }
    var y = origin.y % spacing
    guard = 0
    while (y < context.viewport.height && guard < MAX_GRID_LINES) {
        drawLine(line, Offset(0f, y), Offset(context.viewport.width, y), strokeWidth = width)
        y += spacing
        guard++
    }
}

private fun DrawScope.drawConnections(context: DrawContext) {
    val camera = context.camera
    val selected = context.uiState.selectedModule
    context.positions.forEach { (module, position) ->
        val snapshot = context.uiState.system.snapshotFor(module)
        val state = snapshot?.state ?: IntelligenceModuleState.OFFLINE
        val base = stateColor(state)
        val isSelected = selected == module
        val nodeScreen = camera.worldToScreen(MapGeometry.worldPosition(position))
        val alpha = when {
            isSelected -> 0.85f
            state == IntelligenceModuleState.CRITICAL -> 0.65f
            state == IntelligenceModuleState.WARNING -> 0.5f
            state == IntelligenceModuleState.DISABLED || state == IntelligenceModuleState.OFFLINE -> 0.18f
            else -> 0.34f
        }
        // Glow pass + hair line: two strokes, no shader allocation per frame.
        drawLine(
            color = base.copy(alpha = alpha * 0.28f),
            start = context.coreScreen,
            end = nodeScreen,
            strokeWidth = 6.dp.toPx(),
            cap = StrokeCap.Round
        )
        drawLine(
            color = base.copy(alpha = alpha),
            start = context.coreScreen,
            end = nodeScreen,
            strokeWidth = if (isSelected) 1.8.dp.toPx() else 1.dp.toPx(),
            cap = StrokeCap.Round
        )
    }
}

private fun DrawScope.drawMarkers(context: DrawContext, markers: List<MarkerGeometry>) {
    markers.forEach { marker ->
        val screen = context.camera.worldToScreen(marker.world)
        val event = context.uiState.allEvents.firstOrNull { it.id == marker.eventId }
        val color = event?.let { severityColor(it.severity) } ?: CyberCyan
        val isSelected = context.uiState.selectedEvent?.id == marker.eventId
        val radius = (if (isSelected) 7.dp else 4.dp).toPx()
        drawCircle(color = color.copy(alpha = 0.20f), radius = radius * 2.6f, center = screen)
        drawCircle(color = color, radius = radius, center = screen)
        drawCircle(
            color = Color(0xFF02060D),
            radius = radius * 0.45f,
            center = screen
        )
    }
}

private fun DrawScope.drawPulses(context: DrawContext, pulses: List<MapPulse>, frameNanos: Long) {
    if (pulses.isEmpty() || frameNanos <= 0L) return
    val camera = context.camera
    pulses.forEach { pulse ->
        val progress = MapGeometry.progress(frameNanos, pulse.startNanos, MapGeometry.PULSE_DURATION_NANOS)
        if (progress >= 1f) return@forEach
        val position = context.positions[pulse.module] ?: return@forEach
        val from = camera.worldToScreen(MapGeometry.worldPosition(position))
        val to = context.coreScreen
        val head = MapGeometry.pulsePoint(from, to, progress)
        val color = severityColor(pulse.severity)
        val alpha = MapGeometry.pulseAlpha(progress)
        drawCircle(color = color.copy(alpha = alpha * 0.22f), radius = 10.dp.toPx(), center = head)
        drawCircle(color = color.copy(alpha = alpha), radius = 3.dp.toPx(), center = head)
        // Short comet trail, still only two path points.
        val tail = MapGeometry.pulsePoint(from, to, (progress - 0.08f).coerceAtLeast(0f))
        drawLine(
            color = color.copy(alpha = alpha * 0.55f),
            start = tail,
            end = head,
            strokeWidth = 2.dp.toPx(),
            cap = StrokeCap.Round
        )
    }
}

private fun DrawScope.drawCore(context: DrawContext) {
    val core = context.uiState.system.snapshotFor(IntelligenceModule.CORE)
    val state = core?.state ?: IntelligenceModuleState.NORMAL
    val color = stateColor(state)
    val center = context.coreScreen
    val baseRadius = MapGeometry.drawRadius(context.camera.scale) * 1.35f
    drawCircle(color = color.copy(alpha = 0.10f), radius = baseRadius * 2.1f, center = center)
    drawCircle(color = color.copy(alpha = 0.16f), radius = baseRadius * 1.55f, center = center)
    drawCircle(color = Color(0xFF04121F), radius = baseRadius, center = center)
    drawCircle(color = color.copy(alpha = 0.9f), radius = baseRadius, center = center, style = Stroke(width = 2.dp.toPx()))
    drawCircle(color = color.copy(alpha = 0.35f), radius = baseRadius * 0.82f, center = center, style = Stroke(width = 1.dp.toPx()))

    val labelAlpha = MapGeometry.labelAlpha(context.camera.scale, context.fitScale).coerceAtLeast(0.85f)
    val health = context.uiState.system.healthPercent
    drawCenteredText(
        context,
        text = "OMNISHIELD X",
        center = center + Offset(0f, -baseRadius * 0.22f),
        color = Color(0xFFF8FAFC),
        fontSizeSp = 12f,
        weight = FontWeight.Bold,
        alpha = labelAlpha
    )
    drawCenteredText(
        context,
        text = "$health% HEALTHY",
        center = center + Offset(0f, baseRadius * 0.42f),
        color = color,
        fontSizeSp = 10f,
        weight = FontWeight.SemiBold,
        alpha = labelAlpha
    )
}

private fun DrawScope.drawModuleNodes(context: DrawContext) {
    val camera = context.camera
    val selected = context.uiState.selectedModule
    context.positions.forEach { (module, position) ->
        val snapshot = context.uiState.system.snapshotFor(module)
        val state = snapshot?.state ?: IntelligenceModuleState.OFFLINE
        val color = stateColor(state)
        val accent = moduleAccent(module)
        val center = camera.worldToScreen(MapGeometry.worldPosition(position))
        val radius = MapGeometry.drawRadius(camera.scale)
        val isSelected = selected == module

        context.pulseHighlights[module]?.takeIf { it > 0f }?.let { strength ->
            drawCircle(
                color = accent.copy(alpha = 0.38f * strength),
                radius = radius * 1.55f,
                center = center,
                style = Stroke(width = 2.dp.toPx())
            )
        }
        if (state == IntelligenceModuleState.CRITICAL || state == IntelligenceModuleState.WARNING) {
            drawCircle(color = color.copy(alpha = 0.12f), radius = radius * 1.9f, center = center)
        }
        drawCircle(color = accent.copy(alpha = 0.14f), radius = radius * 1.35f, center = center)
        drawCircle(color = Color(0xFF05101D), radius = radius, center = center)
        drawCircle(
            color = color.copy(alpha = if (isSelected) 1f else 0.85f),
            radius = radius,
            center = center,
            style = Stroke(width = if (isSelected) 2.4.dp.toPx() else 1.4.dp.toPx())
        )

        // Segmented ring: one arc per active alert (cap 4) around the node.
        val alerts = snapshot?.activeAlerts ?: 0
        if (alerts > 0) {
            val segments = alerts.coerceAtMost(4)
            repeat(segments) { index ->
                val startAngle = -90f + index * (360f / segments.coerceAtLeast(1)) + 6f
                drawArc(
                    color = color,
                    startAngle = startAngle,
                    sweepAngle = (360f / segments) * 0.5f,
                    useCenter = false,
                    topLeft = Offset(center.x - radius * 1.18f, center.y - radius * 1.18f),
                    size = Size(radius * 2.36f, radius * 2.36f),
                    style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round)
                )
            }
        }

        val labelAlpha = MapGeometry.labelAlpha(camera.scale, context.fitScale)
        val showName = camera.scale >= 0.30f
        if (showName) {
            drawCenteredText(
                context,
                text = module.shortLabel,
                center = center + Offset(0f, if (camera.scale >= 0.45f) -radius * 0.10f else 0f),
                color = Color(0xFFF1F5F9),
                fontSizeSp = 10f,
                weight = FontWeight.Bold,
                alpha = 1f
            )
        }
        if (camera.scale >= 0.42f) {
            drawCenteredText(
                context,
                text = state.label,
                center = center + Offset(0f, radius + 11.dp.toPx()),
                color = color,
                fontSizeSp = 9f,
                weight = FontWeight.SemiBold,
                alpha = 1f
            )
            drawCenteredText(
                context,
                text = module.displayName,
                center = center + Offset(0f, radius + 23.dp.toPx()),
                color = Color(0xFF94A3B8),
                fontSizeSp = 9f,
                weight = FontWeight.Medium,
                alpha = labelAlpha.coerceAtLeast(0.75f)
            )
        }
        if (alerts > 0 && camera.scale >= 0.3f) {
            val badgeCenter = center + Offset(radius * 0.78f, -radius * 0.78f)
            drawCircle(color = color, radius = 7.dp.toPx(), center = badgeCenter)
            drawCenteredText(
                context,
                text = alerts.coerceAtMost(99).toString(),
                center = badgeCenter,
                color = Color(0xFF02060D),
                fontSizeSp = 8f,
                weight = FontWeight.Bold,
                alpha = 1f
            )
        }
    }
}

private fun DrawScope.drawCenteredText(
    context: DrawContext,
    text: String,
    center: Offset,
    color: Color,
    fontSizeSp: Float,
    weight: FontWeight,
    alpha: Float
) {
    if (alpha <= 0.02f) return
    val layout = context.textMeasurer.measure(
        text = text,
        style = TextStyle(
            color = color.copy(alpha = color.alpha * alpha),
            fontSize = fontSizeSp.sp,
            fontWeight = weight
        ),
        maxLines = 1
    )
    drawText(
        textLayoutResult = layout,
        topLeft = Offset(
            center.x - layout.size.width / 2f,
            center.y - layout.size.height / 2f
        )
    )
}

private fun buildMarkers(
    events: List<IntelligenceEvent>,
    positions: Map<IntelligenceModule, NodePosition>
): List<MarkerGeometry> {
    val markers = ArrayList<MarkerGeometry>(IntelligenceModule.nodes.size)
    IntelligenceModule.nodes.forEach { module ->
        val position = positions[module] ?: return@forEach
        val latest = events.firstOrNull { it.module == module } ?: return@forEach
        markers += MarkerGeometry(
            eventId = latest.id,
            module = module,
            world = MapGeometry.eventMarkerWorld(position, 0, 1)
        )
    }
    return markers
}

private const val MAX_GRID_LINES = 90

/** Small helper so pointer inputs can read the current canvas size. */
private fun androidx.compose.ui.unit.IntSize.toSize(): Size = Size(width.toFloat(), height.toFloat())

/** Compass tick used by the mini orientation indicator (kept here so canvas maths stays together). */
internal fun compassPoint(center: Offset, radius: Float, degrees: Float): Offset {
    val radians = Math.toRadians(degrees.toDouble())
    return Offset(center.x + radius * cos(radians).toFloat(), center.y + radius * sin(radians).toFloat())
}

/** Marker path used for a selected node halo (triangle notch). */
internal fun nodeHaloPath(center: Offset, radius: Float): Path = Path().apply {
    moveTo(center.x, center.y - radius)
    lineTo(center.x + radius, center.y)
    lineTo(center.x, center.y + radius)
    lineTo(center.x - radius, center.y)
    close()
}
