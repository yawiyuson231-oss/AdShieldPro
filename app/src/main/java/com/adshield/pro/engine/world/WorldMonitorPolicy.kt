package com.adshield.pro.engine.world

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import java.net.URI

/** Pure host policy, shared by native export and background scheduling; covered by JVM tests. */
object WorldMonitorPolicy {
    const val HOST = "appassets.androidplatform.net"
    const val ORIGIN = "https://appassets.androidplatform.net"
    const val ENTRY_URL = "$ORIGIN/assets/world-monitor/world/embed.html"
    const val MAX_EXPORT_BYTES = 8_000_000
    const val MAX_FEED_BYTES = 6_000_000
    const val MAX_SNAPSHOT_BYTES = 30_000_000
    private val fileName = Regex("^omnishield-world-[a-z0-9.-]+$")
    private val exportTypes = setOf("application/json", "text/csv", "text/markdown", "text/plain")
    private val privateHost = Regex("^(127\\.|10\\.|192\\.168\\.|169\\.254\\.|0\\.|172\\.(1[6-9]|2\\d|3[01])\\.)")

    data class ExportRequest(val filename: String, val content: String, val mime: String)

    fun trustedOrigin(raw: String, isMainFrame: Boolean): Boolean = isMainFrame && runCatching {
        val uri = URI(raw)
        uri.scheme == "https" && uri.host == HOST && (uri.port == -1 || uri.port == 443) &&
            uri.rawUserInfo == null && (uri.path.isNullOrEmpty() || uri.path == "/") && uri.query == null && uri.fragment == null
    }.getOrDefault(false)

    fun publicHttps(raw: String): Boolean = runCatching {
        val uri = URI(raw)
        val host = uri.host?.lowercase() ?: return false
        raw.length <= 2048 && uri.scheme == "https" && uri.rawUserInfo == null &&
            host.contains('.') && !host.contains(':') && host != HOST && host != "localhost" &&
            !host.endsWith(".localhost") && !host.endsWith(".local") && !host.endsWith(".internal") &&
            !privateHost.containsMatchIn(host)
    }.getOrDefault(false)

    fun exportRequest(raw: String): ExportRequest? = runCatching {
        require(raw.length <= MAX_EXPORT_BYTES * 2)
        val value = Json.parseToJsonElement(raw).jsonObject
        val filename = value.string("filename") ?: return null
        val content = value.string("content") ?: return null
        val mime = value.string("mime") ?: return null
        require(filename.length <= 100 && fileName.matches(filename) && ".." !in filename)
        require(mime in exportTypes && content.toByteArray(Charsets.UTF_8).size <= MAX_EXPORT_BYTES)
        ExportRequest(filename, content, mime)
    }.getOrNull()

    fun scheduledSources(value: JsonObject, allowed: Set<String>): Set<String> =
        (value["sources"] as? JsonArray).orEmpty()
            .mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            .filter { it in allowed }.toSet()

    fun JsonObject.string(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull

    /** Top-level shape only. The shared JavaScript adapter validates individual records on open. */
    fun validFeedShape(format: String, payload: String): Boolean = runCatching {
        when (format) {
            "advisories", "noaa" -> Json.parseToJsonElement(payload) is JsonArray
            else -> {
                val root = Json.parseToJsonElement(payload).jsonObject
                when (format) {
                    "usgs", "geonet", "emsc", "gdacs", "nws" -> root.string("type") == "FeatureCollection" && root["features"] is JsonArray
                    "eonet" -> root["events"] is JsonArray
                    "kev" -> root["vulnerabilities"] is JsonArray
                    "gdelt" -> root["articles"] is JsonArray
                    "github-status", "cloudflare-status" -> root["incidents"] is JsonArray
                    else -> false
                }
            }
        }
    }.getOrDefault(false)
}
