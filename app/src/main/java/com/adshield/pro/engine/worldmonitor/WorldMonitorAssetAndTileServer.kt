package com.adshield.pro.engine.worldmonitor

import android.content.Context
import android.net.Uri
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import androidx.webkit.WebViewAssetLoader
import okhttp3.Cache
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayInputStream
import java.io.File
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * Local Asset + Persistent Tile Cache Interceptor for CesiumJS WebView.
 *
 * Responsibilities:
 *  1. Serves bundled `/assets/worldmonitor/` files under `https://appassets.androidplatform.net/`
 *     with normalized MIME types for `.js`, `.wasm`, `.json`, `.css`, `.png`, `.jpg` across all Android versions.
 *  2. Proxies allowlisted HTTPS map/terrain/weather tile requests through an OkHttp 120 MB disk cache
 *     so visited satellite imagery, OpenStreetMap tiles, NASA GIBS layers, RainViewer radar, and
 *     AWS Terrarium 3D elevation tiles persist across sessions and render offline when cached.
 *  3. Blocks any non-HTTPS or non-allowlisted WebView network request.
 */
class WorldMonitorAssetAndTileServer(
    context: Context
) {
    private val appContext = context.applicationContext

    private val assetLoader: WebViewAssetLoader = WebViewAssetLoader.Builder()
        .setDomain(ASSET_HOST)
        .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(appContext))
        .build()

    private val tileClient: OkHttpClient by lazy {
        val cacheDir = File(appContext.cacheDir, "worldmonitor_tiles_v1")
        OkHttpClient.Builder()
            .cache(Cache(cacheDir, 120L * 1024L * 1024L))
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .followRedirects(true)
            .followSslRedirects(true)
            .build()
    }

    fun intercept(request: WebResourceRequest): WebResourceResponse? {
        val uri = request.url ?: return blockedResponse("Invalid URI")
        val scheme = uri.scheme?.lowercase(Locale.US) ?: return blockedResponse("Missing scheme")
        if (scheme != "https") {
            return blockedResponse("Non-HTTPS scheme blocked")
        }

        val host = uri.host?.lowercase(Locale.US) ?: return blockedResponse("Missing host")

        // 1. Local bundled CesiumJS + worldmonitor assets
        if (host == ASSET_HOST) {
            val res = assetLoader.shouldInterceptRequest(uri) ?: return null
            val normalizedMime = resolveMimeType(uri.path.orEmpty(), res.mimeType)
            res.mimeType = normalizedMime
            res.responseHeaders = (res.responseHeaders ?: emptyMap()) + mapOf(
                "Access-Control-Allow-Origin" to "https://$ASSET_HOST",
                "Cache-Control" to "public, max-age=31536000, immutable"
            )
            return res
        }

        // 2. Allowlisted public imagery / elevation / weather tile hosts with disk caching
        if (isAllowedTileHost(host)) {
            return proxyCachedTile(uri)
        }

        // 3. Reject unexpected third-party hosts from inside the globe WebView
        return blockedResponse("Host not allowlisted: $host")
    }

    private fun proxyCachedTile(uri: Uri): WebResourceResponse {
        return try {
            val req = Request.Builder()
                .url(uri.toString())
                .header("User-Agent", "OmniShieldX-WorldMonitor/2035.1 (Android; TileCache)")
                .get()
                .build()
            val response = tileClient.newCall(req).execute()
            if (!response.isSuccessful) {
                response.close()
                return WebResourceResponse(
                    "text/plain",
                    "UTF-8",
                    response.code,
                    response.message.ifBlank { "Upstream Error" },
                    mapOf("Access-Control-Allow-Origin" to "*"),
                    ByteArrayInputStream(ByteArray(0))
                )
            }
            val body = response.body
            val contentType = response.header("Content-Type")
                ?.substringBefore(';')
                ?.trim()
                ?.ifBlank { null }
                ?: resolveMimeType(uri.path.orEmpty(), "application/octet-stream")

            WebResourceResponse(
                contentType,
                null,
                200,
                "OK",
                mapOf(
                    "Access-Control-Allow-Origin" to "*",
                    "Cache-Control" to "public, max-age=86400"
                ),
                body.byteStream()
            )
        } catch (_: Exception) {
            // Offline or transient timeout: return clean 504 so Cesium gracefully falls back to parent/offline level
            WebResourceResponse(
                "text/plain",
                "UTF-8",
                504,
                "Offline",
                mapOf("Access-Control-Allow-Origin" to "*"),
                ByteArrayInputStream(ByteArray(0))
            )
        }
    }

    companion object {
        const val ASSET_HOST = "appassets.androidplatform.net"
        const val ENTRY_URL = "https://appassets.androidplatform.net/assets/worldmonitor/index.html"

        private val ALLOWED_TILE_SUFFIXES = listOf(
            "arcgisonline.com",
            "openstreetmap.org",
            "basemaps.cartocdn.com",
            "earthdata.nasa.gov",
            "rainviewer.com",
            "s3.amazonaws.com"
        )

        internal fun isAllowedTileHost(host: String): Boolean {
            val h = host.lowercase(Locale.US)
            return ALLOWED_TILE_SUFFIXES.any { suffix -> h == suffix || h.endsWith(".$suffix") }
        }

        internal fun resolveMimeType(path: String, fallback: String?): String {
            val lower = path.lowercase(Locale.US)
            return when {
                lower.endsWith(".js") || lower.endsWith(".mjs") -> "text/javascript"
                lower.endsWith(".wasm") -> "application/wasm"
                lower.endsWith(".json") || lower.endsWith(".geojson") || lower.endsWith(".czml") || lower.endsWith(".topojson") -> "application/json"
                lower.endsWith(".css") -> "text/css"
                lower.endsWith(".html") -> "text/html"
                lower.endsWith(".png") -> "image/png"
                lower.endsWith(".jpg") || lower.endsWith(".jpeg") -> "image/jpeg"
                lower.endsWith(".svg") -> "image/svg+xml"
                lower.endsWith(".xml") -> "application/xml"
                !fallback.isNullOrBlank() -> fallback
                else -> "application/octet-stream"
            }
        }

        private fun blockedResponse(reason: String): WebResourceResponse =
            WebResourceResponse(
                "text/plain",
                "UTF-8",
                403,
                "Blocked",
                mapOf("Access-Control-Allow-Origin" to "null"),
                ByteArrayInputStream(reason.toByteArray(Charsets.UTF_8))
            )
    }
}
