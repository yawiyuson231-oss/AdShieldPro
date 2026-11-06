package com.adshield.pro.ui.screens.intelligence

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.domain.intelligence.NodePosition
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.hypot
import kotlin.math.min
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Pure map geometry: camera maths, default layout, hit-testing and animation curves.
 *
 * Everything here is plain Kotlin so drag/pinch behaviour, hit radii and pulse timing are verified
 * by JVM tests instead of by hand on a phone. The Compose layer only calls these functions.
 */
object MapGeometry {

    /** The map's world is a square of this size in abstract units. */
    const val WORLD_SIZE = 1000f

    /** Minimum and maximum camera scale relative to the fitted scale. */
    const val MIN_SCALE_ABS = 180f / WORLD_SIZE
    const val MAX_SCALE_ABS = 6.0f

    /** World radius of a module node; the screen radius scales with the camera. */
    const val NODE_RADIUS_WORLD = 62f

    /** Hit target never shrinks below this many pixels (accessibility). */
    const val NODE_HIT_MIN_PX = 26f

    /** Ring radius of the seven module nodes, in normalised [0,1] space. */
    const val RING_RADIUS = 0.345f

    /** Tap movement above this cancels the tap so a drag never opens a panel. */
    const val TAP_SLOP_PX = 18f

    const val PULSE_DURATION_NANOS = 1_600_000_000L
    const val HIGHLIGHT_DURATION_NANOS = 3_200_000_000L

    fun defaultPositions(): Map<IntelligenceModule, NodePosition> {
        val nodes = IntelligenceModule.nodes
        val result = LinkedHashMap<IntelligenceModule, NodePosition>(nodes.size)
        nodes.forEachIndexed { index, module ->
            val angle = -PI / 2.0 + (2.0 * PI * index / nodes.size)
            result[module] = NodePosition(
                x = (0.5 + RING_RADIUS * cos(angle)).toFloat(),
                y = (0.5 + RING_RADIUS * sin(angle)).toFloat()
            )
        }
        return result
    }

    /** User layout overrides win; missing/invalid entries fall back to the generated ring. */
    fun resolvedPositions(
        overrides: Map<IntelligenceModule, NodePosition>
    ): Map<IntelligenceModule, NodePosition> {
        val base = defaultPositions()
        val merged = LinkedHashMap<IntelligenceModule, NodePosition>(base)
        overrides.forEach { (module, position) ->
            if (module.isNode) merged[module] = position.clamped()
        }
        return merged
    }

    fun worldPosition(position: NodePosition): Offset =
        Offset(position.x * WORLD_SIZE, position.y * WORLD_SIZE)

    val coreWorldPosition: Offset get() = Offset(WORLD_SIZE / 2f, WORLD_SIZE / 2f)

    /** Distance in world units from a point to a module node. */
    fun distanceToNode(position: NodePosition, worldPoint: Offset): Float {
        val node = worldPosition(position)
        return hypot(worldPoint.x - node.x, worldPoint.y - node.y)
    }

    fun nodeScreenRadius(scale: Float): Float = (NODE_RADIUS_WORLD * scale).coerceAtLeast(NODE_HIT_MIN_PX / 2f)

    fun hitRadiusPx(scale: Float): Float =
        (NODE_RADIUS_WORLD * scale).coerceAtLeast(NODE_HIT_MIN_PX)

    /**
     * Returns the module whose node contains [screenTap], or null.
     * Nodes are tested in stable module order so an overlap resolves deterministically.
     */
    fun hitTest(
        camera: MapCamera,
        viewport: Size,
        positions: Map<IntelligenceModule, NodePosition>,
        screenTap: Offset
    ): IntelligenceModule? {
        val world = camera.screenToWorld(screenTap)
        val radiusWorld = hitRadiusPx(camera.scale) / camera.scale
        var best: IntelligenceModule? = null
        var bestDistance = Float.MAX_VALUE
        IntelligenceModule.nodes.forEach { module ->
            val pos = positions[module] ?: return@forEach
            val distance = distanceToNode(pos, world)
            if (distance <= radiusWorld && distance < bestDistance) {
                bestDistance = distance
                best = module
            }
        }
        if (best == null) {
            val coreDistance = hypot(world.x - coreWorldPosition.x, world.y - coreWorldPosition.y)
            if (coreDistance <= radiusWorld * 1.15f) best = IntelligenceModule.CORE
        }
        return best
    }

    /** Position of an event marker along the connector from [module] to the core. */
    fun eventMarkerWorld(
        modulePosition: NodePosition,
        slotIndex: Int,
        slotCount: Int
    ): Offset {
        val from = worldPosition(modulePosition)
        val to = coreWorldPosition
        val slots = slotCount.coerceAtLeast(1)
        val t = 0.42f + (slotIndex.coerceIn(0, slots - 1).toFloat() / slots) * 0.34f
        return Offset(from.x + (to.x - from.x) * t, from.y + (to.y - from.y) * t)
    }

    /**
     * Hit test for event markers. [markers] is a small list (the newest slice of the feed), so a
     * linear scan is cheaper than maintaining a spatial index.
     */
    fun hitTestMarker(
        camera: MapCamera,
        markers: List<MarkerGeometry>,
        screenTap: Offset
    ): MarkerGeometry? {
        var best: MarkerGeometry? = null
        var bestDistance = Float.MAX_VALUE
        val radius = (MARKER_HIT_DP * camera.scale).coerceIn(14f, 44f)
        markers.forEach { marker ->
            val screen = camera.worldToScreen(marker.world)
            val distance = hypot(screen.x - screenTap.x, screen.y - screenTap.y)
            if (distance <= radius && distance < bestDistance) {
                bestDistance = distance
                best = marker
            }
        }
        return best
    }

    const val MARKER_HIT_DP = 44f

    /** Node drag target (edit mode): returns the node under a press, if any. */
    fun nodeUnderPress(
        camera: MapCamera,
        positions: Map<IntelligenceModule, NodePosition>,
        screenPress: Offset
    ): IntelligenceModule? = hitTest(camera, Size.Zero, positions, screenPress)

    fun clampNormalized(world: Offset): NodePosition = NodePosition(
        x = (world.x / WORLD_SIZE).coerceIn(0.06f, 0.94f),
        y = (world.y / WORLD_SIZE).coerceIn(0.06f, 0.94f)
    )

    /** Eased progress for a pulse, clamped to [0,1]. */
    fun progress(nowNanos: Long, startNanos: Long, durationNanos: Long): Float {
        if (durationNanos <= 0L) return 1f
        val raw = (nowNanos - startNanos).toFloat() / durationNanos.toFloat()
        return raw.coerceIn(0f, 1f)
    }

    /** Fast rise, slow fade — reads as a signal, not a strobe. */
    fun pulseAlpha(progress: Float): Float {
        val p = progress.coerceIn(0f, 1f)
        return if (p < 0.25f) p / 0.25f else 1f - ((p - 0.25f) / 0.75f)
    }

    /** Slight arc so several pulses on the same connector stay distinguishable. */
    fun pulsePoint(from: Offset, to: Offset, progress: Float, arc: Float = 22f): Offset {
        val t = progress.coerceIn(0f, 1f)
        val mid = Offset((from.x + to.x) / 2f, (from.y + to.y) / 2f)
        val dx = to.x - from.x
        val dy = to.y - from.y
        val length = sqrt(dx * dx + dy * dy).coerceAtLeast(0.001f)
        val normal = Offset(-dy / length, dx / length)
        val control = Offset(mid.x + normal.x * arc, mid.y + normal.y * arc)
        val oneMinus = 1f - t
        return Offset(
            oneMinus * oneMinus * from.x + 2f * oneMinus * t * control.x + t * t * to.x,
            oneMinus * oneMinus * from.y + 2f * oneMinus * t * control.y + t * t * to.y
        )
    }

    /** Label scale used to hide text before it becomes unreadable clutter. */
    fun labelAlpha(scale: Float, fitScale: Float): Float {
        val ratio = scale / fitScale.coerceAtLeast(0.0001f)
        return ((ratio - 0.55f) / 0.35f).coerceIn(0f, 1f)
    }

    /** Grid spacing in world units, chosen so lines stay 40-120 px apart on screen. */
    fun gridSpacingWorld(scale: Float): Float {
        val targetPx = 72f
        val raw = targetPx / scale.coerceAtLeast(0.0001f)
        val snapped = (raw / 50f).toInt() * 50f
        return snapped.coerceIn(50f, 300f)
    }

    fun screenDistance(a: Offset, b: Offset): Float = hypot(a.x - b.x, a.y - b.y)

    fun hasDragged(start: Offset, current: Offset, slop: Float = TAP_SLOP_PX): Boolean =
        screenDistance(start, current) > slop

    /** Node radius in screen pixels for drawing, scaled but bounded for low-zoom legibility. */
    fun drawRadius(scale: Float): Float = (NODE_RADIUS_WORLD * scale).coerceIn(14f, 96f)
}

/** Marker placed on a connector for one recent event. */
data class MarkerGeometry(
    val eventId: Long,
    val module: IntelligenceModule,
    val world: Offset
)

/**
 * Immutable camera. [offsetX]/[offsetY] are the screen coordinates of world origin; [scale] maps
 * world units to pixels. All methods return a new instance so state updates are atomic.
 */
data class MapCamera(
    val scale: Float = 1f,
    val offsetX: Float = 0f,
    val offsetY: Float = 0f
) {
    fun worldToScreen(world: Offset): Offset =
        Offset(world.x * scale + offsetX, world.y * scale + offsetY)

    fun screenToWorld(screen: Offset): Offset =
        Offset((screen.x - offsetX) / scale, (screen.y - offsetY) / scale)

    /**
     * Fits the whole world into [viewport] with [paddingFraction] breathing room.
     * Used for the initial view and the reset-camera control.
     */
    fun fit(
        viewport: Size,
        worldSize: Float = MapGeometry.WORLD_SIZE,
        paddingFraction: Float = 0.09f
    ): MapCamera {
        if (viewport.width <= 0f || viewport.height <= 0f) return this
        val usable = min(viewport.width, viewport.height) * (1f - 2f * paddingFraction)
        val fitted = (usable / worldSize).coerceIn(MapGeometry.MIN_SCALE_ABS, MapGeometry.MAX_SCALE_ABS)
        return MapCamera(
            scale = fitted,
            offsetX = (viewport.width - worldSize * fitted) / 2f,
            offsetY = (viewport.height - worldSize * fitted) / 2f
        )
    }

    fun panBy(dx: Float, dy: Float): MapCamera = copy(offsetX = offsetX + dx, offsetY = offsetY + dy)

    /** Zoom around a focal point so the world point under the fingers stays put. */
    fun zoomAround(
        focal: Offset,
        factor: Float,
        viewport: Size,
        minScale: Float = MapGeometry.MIN_SCALE_ABS,
        maxScale: Float = MapGeometry.MAX_SCALE_ABS
    ): MapCamera {
        if (!factor.isFinite() || factor <= 0f) return this
        val newScale = (scale * factor).coerceIn(minScale, maxScale)
        if (newScale == scale) return this
        val ratio = newScale / scale
        val newOffsetX = focal.x - (focal.x - offsetX) * ratio
        val newOffsetY = focal.y - (focal.y - offsetY) * ratio
        return MapCamera(newScale, newOffsetX, newOffsetY).clamped(viewport)
    }

    /** Keeps at least a slice of the world on screen so the map can never be lost. */
    fun clamped(viewport: Size): MapCamera {
        if (viewport.width <= 0f || viewport.height <= 0f) return this
        val contentW = MapGeometry.WORLD_SIZE * scale
        val contentH = MapGeometry.WORLD_SIZE * scale
        val minX = viewport.width * 0.25f - contentW
        val maxX = viewport.width * 0.75f
        val minY = viewport.height * 0.25f - contentH
        val maxY = viewport.height * 0.75f
        return copy(
            offsetX = offsetX.coerceIn(minX, maxX),
            offsetY = offsetY.coerceIn(minY, maxY)
        )
    }

    /** Camera that centres a world point in the viewport, optionally zooming in. */
    fun centredOn(
        world: Offset,
        viewport: Size,
        targetScale: Float = scale,
        minScale: Float = MapGeometry.MIN_SCALE_ABS,
        maxScale: Float = MapGeometry.MAX_SCALE_ABS
    ): MapCamera {
        val newScale = targetScale.coerceIn(minScale, maxScale)
        return MapCamera(
            scale = newScale,
            offsetX = viewport.width / 2f - world.x * newScale,
            offsetY = viewport.height / 2f - world.y * newScale
        ).clamped(viewport)
    }

    /** Linear interpolation used by the smooth animated transitions. */
    fun lerpTo(target: MapCamera, fraction: Float): MapCamera {
        val t = fraction.coerceIn(0f, 1f)
        return MapCamera(
            scale = scale + (target.scale - scale) * t,
            offsetX = offsetX + (target.offsetX - offsetX) * t,
            offsetY = offsetY + (target.offsetY - offsetY) * t
        )
    }

    val isAtFit: Boolean get() = scale <= MapGeometry.MIN_SCALE_ABS * 1.001f
}
