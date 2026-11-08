package com.adshield.pro.engine.worldmonitor

import android.webkit.JavascriptInterface
import com.adshield.pro.domain.worldmonitor.GlobeViewport
import com.adshield.pro.domain.worldmonitor.SatellitePassPrediction
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Validated JavaScript <-> Kotlin Bridge for the CesiumJS 3D Digital Earth WebView.
 *
 * Security invariants:
 *  - Every inbound JSON message is bounded in byte length (`MAX_INBOUND_CHARS`) before parsing.
 *  - Every numeric field is checked for finiteness and valid geographic bounds (`[-90, 90]`, `[-180, 180]`).
 *  - No raw HTML or script strings are ever reflected back into the DOM or Intent URIs.
 *  - Outbound Kotlin -> JS payloads are UTF-8 Base64 encoded so quotes, newlines, and Unicode can
 *    never cause JavaScript injection when evaluated via `window.WorldMonitorApp.receiveBase64(...)`.
 */
class WorldMonitorJsBridge(
    private val listener: Listener
) {
    interface Listener {
        fun onGlobeReady(webglSupported: Boolean, cesiumVersion: String)
        fun onGlobeError(errorMessage: String)
        fun onViewportChanged(viewport: GlobeViewport)
        fun onEntitySelected(entityId: String)
        fun onBuildingSelected(id: String, name: String, heightMeters: Double, levels: Int, lat: Double, lon: Double)
        fun onLocationSelected(lat: Double, lon: Double, terrainElevationMeters: Int)
        fun onSatellitePassesComputed(noradId: String, satName: String, passes: List<SatellitePassPrediction>)
    }

    @JavascriptInterface
    fun onGlobeReady(rawJson: String?) {
        val obj = parseSafeObject(rawJson) ?: return
        val webgl = obj["webgl"]?.jsonPrimitive?.booleanOrNull ?: true
        val ver = sanitizeText(obj["cesiumVersion"]?.jsonPrimitive?.content, 32).ifBlank { "1.147.0" }
        listener.onGlobeReady(webgl, ver)
    }

    @JavascriptInterface
    fun onGlobeError(rawJson: String?) {
        val obj = parseSafeObject(rawJson) ?: return
        val message = sanitizeText(obj["error"]?.jsonPrimitive?.content, 300)
        if (message.isNotBlank()) {
            listener.onGlobeError(message)
        }
    }

    @JavascriptInterface
    fun onViewportChanged(rawJson: String?) {
        val obj = parseSafeObject(rawJson) ?: return
        val lat = obj["lat"]?.jsonPrimitive?.doubleOrNull ?: return
        val lon = obj["lon"]?.jsonPrimitive?.doubleOrNull ?: return
        if (!GeoSpatialIndex.isValidCoordinate(lat, lon)) return

        val alt = (obj["altitudeMeters"]?.jsonPrimitive?.doubleOrNull ?: 15_000_000.0)
            .takeIf { it.isFinite() }?.coerceIn(10.0, 60_000_000.0) ?: 15_000_000.0
        val heading = (obj["headingDeg"]?.jsonPrimitive?.doubleOrNull ?: 0.0)
            .takeIf { it.isFinite() }?.coerceIn(0.0, 360.0) ?: 0.0
        val pitch = (obj["pitchDeg"]?.jsonPrimitive?.doubleOrNull ?: -90.0)
            .takeIf { it.isFinite() }?.coerceIn(-90.0, 90.0) ?: -90.0
        val west = (obj["west"]?.jsonPrimitive?.doubleOrNull ?: -180.0).takeIf { it.isFinite() }?.coerceIn(-180.0, 180.0) ?: -180.0
        val south = (obj["south"]?.jsonPrimitive?.doubleOrNull ?: -85.0).takeIf { it.isFinite() }?.coerceIn(-90.0, 90.0) ?: -85.0
        val east = (obj["east"]?.jsonPrimitive?.doubleOrNull ?: 180.0).takeIf { it.isFinite() }?.coerceIn(-180.0, 180.0) ?: 180.0
        val north = (obj["north"]?.jsonPrimitive?.doubleOrNull ?: 85.0).takeIf { it.isFinite() }?.coerceIn(-90.0, 90.0) ?: 85.0
        val fps = (obj["fps"]?.jsonPrimitive?.intOrNull ?: 60).coerceIn(0, 240)

        listener.onViewportChanged(
            GlobeViewport(
                latitude = lat,
                longitude = lon,
                altitudeMeters = alt,
                headingDeg = heading,
                pitchDeg = pitch,
                west = west,
                south = south,
                east = east,
                north = north,
                fps = fps
            )
        )
    }

    @JavascriptInterface
    fun onEntitySelected(rawJson: String?) {
        val obj = parseSafeObject(rawJson) ?: return
        val id = sanitizeId(obj["entityId"]?.jsonPrimitive?.content)
        if (id.isNotBlank()) {
            listener.onEntitySelected(id)
        }
    }

    @JavascriptInterface
    fun onBuildingSelected(rawJson: String?) {
        val obj = parseSafeObject(rawJson) ?: return
        val id = sanitizeId(obj["id"]?.jsonPrimitive?.content)
        val name = sanitizeText(obj["name"]?.jsonPrimitive?.content, 120).ifBlank { "OSM 3D Building" }
        val height = (obj["height"]?.jsonPrimitive?.doubleOrNull ?: 12.0).takeIf { it.isFinite() }?.coerceIn(3.0, 1000.0) ?: 12.0
        val levels = (obj["levels"]?.jsonPrimitive?.intOrNull ?: 0).coerceIn(0, 250)
        val lat = obj["lat"]?.jsonPrimitive?.doubleOrNull ?: return
        val lon = obj["lon"]?.jsonPrimitive?.doubleOrNull ?: return
        if (!GeoSpatialIndex.isValidCoordinate(lat, lon)) return
        listener.onBuildingSelected(id, name, height, levels, lat, lon)
    }

    @JavascriptInterface
    fun onLocationSelected(rawJson: String?) {
        val obj = parseSafeObject(rawJson) ?: return
        val lat = obj["lat"]?.jsonPrimitive?.doubleOrNull ?: return
        val lon = obj["lon"]?.jsonPrimitive?.doubleOrNull ?: return
        if (!GeoSpatialIndex.isValidCoordinate(lat, lon)) return
        val elev = (obj["elevationMeters"]?.jsonPrimitive?.intOrNull ?: 0).coerceIn(-11_500, 9_500)
        listener.onLocationSelected(lat, lon, elev)
    }

    @JavascriptInterface
    fun onSatellitePassesComputed(rawJson: String?) {
        val obj = parseSafeObject(rawJson) ?: return
        val noradId = sanitizeId(obj["noradId"]?.jsonPrimitive?.content)
        val name = sanitizeText(obj["name"]?.jsonPrimitive?.content, 100)
        val passesArr = obj["passes"]?.jsonArray ?: return
        val passes = passesArr.take(16).mapNotNull { el ->
            val p = el as? JsonObject ?: return@mapNotNull null
            val start = p["startEpochMs"]?.jsonPrimitive?.longOrNull ?: return@mapNotNull null
            val end = p["endEpochMs"]?.jsonPrimitive?.longOrNull ?: return@mapNotNull null
            val maxEl = p["maxElevationDeg"]?.jsonPrimitive?.doubleOrNull ?: return@mapNotNull null
            if (!maxEl.isFinite() || end < start) return@mapNotNull null
            SatellitePassPrediction(
                noradId = noradId,
                name = name,
                startEpochMs = start,
                endEpochMs = end,
                maxElevationDeg = maxEl.coerceIn(0.0, 90.0),
                durationSec = (p["durationSec"]?.jsonPrimitive?.intOrNull ?: ((end - start) / 1000L).toInt()).coerceAtLeast(0)
            )
        }
        listener.onSatellitePassesComputed(noradId, name, passes)
    }

    companion object {
        const val BRIDGE_NAME = "WorldMonitorBridge"
        private const val MAX_INBOUND_CHARS = 16_384
        private val SAFE_ID_REGEX = Regex("^[A-Za-z0-9:_./+=-]{1,180}$")

        private val bridgeJson = Json {
            ignoreUnknownKeys = true
            isLenient = false
        }

        internal fun parseSafeObject(rawJson: String?): JsonObject? {
            if (rawJson.isNullOrBlank() || rawJson.length > MAX_INBOUND_CHARS) return null
            return runCatching {
                bridgeJson.parseToJsonElement(rawJson).jsonObject
            }.getOrNull()
        }

        internal fun sanitizeId(raw: String?): String {
            val trimmed = raw?.trim().orEmpty()
            return if (SAFE_ID_REGEX.matches(trimmed)) trimmed else ""
        }

        internal fun sanitizeText(raw: String?, maxLen: Int): String {
            if (raw.isNullOrBlank()) return ""
            return raw.replace(Regex("[\\u0000-\\u001F<>]"), " ")
                .trim()
                .take(maxLen)
        }

        fun isAllowedHttpsSourceUrl(url: String?): Boolean {
            if (url.isNullOrBlank() || url.length > 1024) return false
            return url.startsWith("https://", ignoreCase = true)
        }

        /**
         * Encodes a command envelope `{ "type": ..., "payload": ... }` into a JavaScript expression
         * invoking `window.WorldMonitorApp.receiveBase64('<base64>')`.
         */
        fun buildJsDispatchExpression(type: String, payloadJsonObject: String): String {
            val envelope = """{"type":"$type","payload":$payloadJsonObject}"""
            val base64 = Base64.getEncoder().encodeToString(envelope.toByteArray(StandardCharsets.UTF_8))
            return "window.WorldMonitorApp && window.WorldMonitorApp.receiveBase64('$base64');"
        }
    }
}
