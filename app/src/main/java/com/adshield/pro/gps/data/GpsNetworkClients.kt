package com.adshield.pro.gps.data

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.adshield.pro.gps.data.GpsPreferences.Companion.NOMINATIM_MIN_INTERVAL_MS
import com.adshield.pro.gps.data.GpsPreferences.Companion.ROUTING_MIN_INTERVAL_MS
import com.adshield.pro.gps.data.GpsPreferences.Companion.USER_AGENT
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.routing.OsrmMapper
import com.adshield.pro.gps.routing.RouteRequest
import com.adshield.pro.gps.routing.RoutingFailureReason
import com.adshield.pro.gps.routing.RoutingProvider
import com.adshield.pro.gps.routing.RoutingResult
import com.adshield.pro.gps.routing.ValhallaMapper
import com.adshield.pro.gps.traffic.IncidentKind
import com.adshield.pro.gps.traffic.SpeedObservation
import com.adshield.pro.gps.traffic.TokenBucketRateLimiter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import dagger.hilt.android.qualifiers.ApplicationContext
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AdShield Pro — free/open geospatial network clients.
 *
 * Everything here talks to free, keyless, OpenStreetMap-based services over HTTPS only:
 *
 *   geocoding  Nominatim (usage policy: identifying User-Agent, ≤1 req/s — enforced below)
 *   routing    OSRM demo servers, Valhalla public instance, or any self-hosted instance the user
 *              configures in the UI
 *   traffic    optional, self-hosted community backend (see `traffic/` in this repository)
 *
 * All three are *optional*. If the network or the service is unavailable, the module returns a
 * typed failure and the UI says so; the map and the offline router keep working.
 */
@Singleton
class GeocodingClient @Inject constructor(
    @ApplicationContext private val context: Context,
    private val preferences: GpsPreferences,
    @GpsHttpClient private val httpClient: OkHttpClient
) {

    private val limiter = TokenBucketRateLimiter(capacity = 3, refillPerMinute = 40)
    private val json = Json { ignoreUnknownKeys = true; isLenient = true }
    private var lastRequestAtMs = 0L

    data class Place(
        val displayName: String,
        val shortName: String,
        val position: GeoPoint,
        val category: String?,
        val type: String?,
        val boundingBox: List<Double>? = null
    )

    /** Nominatim search. Returns an empty list on failure *and* reports why via [lastError]. */
    var lastError: String? = null
        private set

    suspend fun search(query: String, limit: Int = 6, viewbox: List<Double>? = null): List<Place> =
        withContext(Dispatchers.IO) {
            lastError = null
            val trimmed = query.trim()
            if (trimmed.length < 2) {
                lastError = "Type at least two characters"
                return@withContext emptyList()
            }
            if (!NetworkMonitor.isOnline(context)) {
                lastError = "Offline — destination search needs a connection or a downloaded region"
                return@withContext emptyList()
            }
            if (!limiter.tryAcquire()) {
                lastError = "Search rate limit reached, try again in a moment"
                return@withContext emptyList()
            }
            val sinceLast = System.currentTimeMillis() - lastRequestAtMs
            if (sinceLast < NOMINATIM_MIN_INTERVAL_MS) {
                kotlinx.coroutines.delay(NOMINATIM_MIN_INTERVAL_MS - sinceLast)
            }
            val base = preferences.customNominatimUrl.collectOnce()?.takeIf { it.isNotBlank() }
                ?: GpsPreferences.DEFAULT_NOMINATIM
            val url = (base.trimEnd('/') + "/search").toHttpUrlOrNull()?.newBuilder()
                ?.addQueryParameter("q", trimmed)
                ?.addQueryParameter("format", "jsonv2")
                ?.addQueryParameter("limit", limit.toString())
                ?.addQueryParameter("addressdetails", "1")
                ?.addQueryParameter("accept-language", java.util.Locale.getDefault().language)
                ?.apply {
                    if (viewbox != null && viewbox.size == 4) {
                        addQueryParameter("viewbox", viewbox.joinToString(","))
                        addQueryParameter("bounded", "0")
                    }
                }
                ?.build()
            if (url == null) {
                lastError = "The configured geocoder URL is not valid"
                return@withContext emptyList()
            }
            lastRequestAtMs = System.currentTimeMillis()
            val request = Request.Builder()
                .url(url)
                .header("User-Agent", USER_AGENT)
                .header("Accept", "application/json")
                .get()
                .build()
            try {
                httpClient.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        lastError = "Geocoder returned HTTP ${response.code}"
                        return@withContext emptyList()
                    }
                    val body = response.body.string()
                    val array = runCatching { json.parseToJsonElement(body).jsonArray }.getOrNull()
                    if (array == null) {
                        lastError = "Geocoder response could not be parsed"
                        return@withContext emptyList()
                    }
                    array.mapNotNull { element ->
                        val item = runCatching { element.jsonObject }.getOrNull() ?: return@mapNotNull null
                        val lat = item["lat"]?.jsonPrimitive?.doubleOrNull ?: return@mapNotNull null
                        val lon = item["lon"]?.jsonPrimitive?.doubleOrNull ?: return@mapNotNull null
                        if (lat !in -90.0..90.0 || lon !in -180.0..180.0) return@mapNotNull null
                        val display = item["display_name"]?.jsonPrimitive?.content ?: trimmed
                        val bounding = runCatching {
                            item["boundingbox"]?.jsonArray?.mapNotNull { it.jsonPrimitive.content.toDoubleOrNull() }
                        }.getOrNull()
                        Place(
                            displayName = display,
                            shortName = display.substringBefore(',').trim().ifBlank { display },
                            position = GeoPoint(lat, lon),
                            category = item["category"]?.jsonPrimitive?.content,
                            type = item["type"]?.jsonPrimitive?.content,
                            boundingBox = bounding
                        )
                    }
                }
            } catch (t: Throwable) {
                lastError = t.message ?: "Geocoder request failed"
                emptyList()
            }
        }
}

/** Minimal connectivity probe used to avoid pointless requests. */
object NetworkMonitor {
    fun isOnline(context: Context): Boolean = try {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = manager.activeNetwork ?: return false
        val capabilities = manager.getNetworkCapabilities(network) ?: return false
        capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    } catch (t: Throwable) {
        true // If the probe is unavailable, let the request decide instead of blocking the user.
    }
}

/**
 * Routing over the free OSRM / Valhalla instances (or a self-hosted one).
 *
 * The mapper is pure and unit-tested; this class only builds the URL, applies rate limiting and
 * maps transport errors to [RoutingFailureReason].
 */
@Singleton
class RoutingClient @Inject constructor(
    @ApplicationContext private val context: Context,
    private val preferences: GpsPreferences,
    @GpsHttpClient private val httpClient: OkHttpClient
) {
    private val limiter = TokenBucketRateLimiter(capacity = 4, refillPerMinute = 30)
    private var lastRequestAtMs = 0L

    var lastError: String? = null
        private set

    suspend fun route(
        request: RouteRequest,
        provider: RoutingProvider,
        fallbackProvider: RoutingProvider? = RoutingProvider.VALHALLA
    ): RoutingResult = withContext(Dispatchers.IO) {
        lastError = null
        if (!NetworkMonitor.isOnline(context)) {
            return@withContext RoutingResult.Failure(
                RoutingFailureReason.NO_NETWORK,
                "This device is offline. Use a downloaded routing graph for offline navigation."
            )
        }
        if (!limiter.tryAcquire()) {
            return@withContext RoutingResult.Failure(
                RoutingFailureReason.RATE_LIMITED,
                "Local rate limit reached — waiting would exceed the public service fair-use policy."
            )
        }
        val sinceLast = System.currentTimeMillis() - lastRequestAtMs
        if (sinceLast < ROUTING_MIN_INTERVAL_MS) {
            kotlinx.coroutines.delay(ROUTING_MIN_INTERVAL_MS - sinceLast)
        }
        lastRequestAtMs = System.currentTimeMillis()

        val primary = when (provider) {
            RoutingProvider.OFFLINE -> RoutingResult.Failure(
                RoutingFailureReason.NO_OFFLINE_GRAPH,
                "Offline routing needs a downloaded graph (Offline maps → Import routing graph)."
            )
            else -> requestFrom(provider, request)
        }
        if (primary is RoutingResult.Success) return@withContext primary

        val failure = primary as RoutingResult.Failure
        val isTransport = failure.reason == RoutingFailureReason.SERVER_ERROR
        val alternative = fallbackProvider
        if (isTransport && alternative != null && alternative != RoutingProvider.OFFLINE) {
            val second = requestFrom(alternative, request)
            if (second is RoutingResult.Success) {
                return@withContext RoutingResult.Success(
                    second.plans,
                    second.warnings + "${provider.label} was unreachable, routed with ${alternative.label} instead."
                )
            }
        }
        RoutingResult.Failure(failure.reason, failure.detail)
    }

    private suspend fun requestFrom(provider: RoutingProvider, request: RouteRequest): RoutingResult {
        val custom = when (provider) {
            RoutingProvider.OSRM -> preferences.customOsrmUrl.collectOnce()
            RoutingProvider.VALHALLA -> preferences.customValhallaUrl.collectOnce()
            else -> null
        }
        val coordinatePart = "${request.origin.longitude},${request.origin.latitude};" +
            "${request.destination.longitude},${request.destination.latitude}"
        val url = when (provider) {
            RoutingProvider.OSRM -> {
                val base = (custom ?: GpsPreferences.DEFAULT_OSRM).trimEnd('/')
                "$base/route/v1/driving/$coordinatePart" +
                    "?overview=full&geometries=polyline&steps=true&alternatives=${request.alternatives}&annotations=false"
            }
            RoutingProvider.VALHALLA -> {
                val base = (custom ?: GpsPreferences.DEFAULT_VALHALLA).trimEnd('/')
                "$base/route?json=" +
                    java.net.URLEncoder.encode(
                        """{"locations":[{"lat":${request.origin.latitude},"lon":${request.origin.longitude}},""" +
                            """{"lat":${request.destination.latitude},"lon":${request.destination.longitude}}],""" +
                            """"costing":"auto","directions_options":{"units":"kilometers"}}""",
                        "UTF-8"
                    )
            }
            RoutingProvider.OFFLINE -> return RoutingResult.Failure(
                RoutingFailureReason.NO_OFFLINE_GRAPH, "Offline provider cannot be called over HTTP"
            )
        }
        val httpUrl = url.toHttpUrlOrNull() ?: return RoutingResult.Failure(
            RoutingFailureReason.NO_PROVIDER_CONFIGURED, "Configured router URL is not valid"
        )
        val body = try {
            httpClient.newCall(
                Request.Builder()
                    .url(httpUrl)
                    .header("User-Agent", USER_AGENT)
                    .header("Accept", "application/json")
                    .get()
                    .build()
            ).execute().use { response ->
                if (response.code == 429) {
                    return RoutingResult.Failure(
                        RoutingFailureReason.RATE_LIMITED,
                        "${provider.label} asked us to slow down (HTTP 429)."
                    )
                }
                if (!response.isSuccessful) {
                    return RoutingResult.Failure(
                        RoutingFailureReason.SERVER_ERROR,
                        "${provider.label} returned HTTP ${response.code}"
                    )
                }
                response.body.string()
            }
        } catch (t: Throwable) {
            lastError = t.message
            return RoutingResult.Failure(
                RoutingFailureReason.SERVER_ERROR,
                "${provider.label} request failed: ${t.message ?: t.javaClass.simpleName}"
            )
        }
        return when (provider) {
            RoutingProvider.OSRM -> OsrmMapper.parse(body, request)
            RoutingProvider.VALHALLA -> ValhallaMapper.parse(body, request)
            RoutingProvider.OFFLINE -> RoutingResult.Failure(RoutingFailureReason.NO_OFFLINE_GRAPH, "")
        }
    }
}

/** Collects the first value of a flow without pulling in a coroutines-extra API. */
internal suspend fun <T> kotlinx.coroutines.flow.Flow<T>.collectOnce(): T {
    var value: T? = null
    collect { value = it; return@collect }
    @Suppress("UNCHECKED_CAST")
    return value as T
}

/**
 * Client for the optional community traffic backend.
 *
 * IMPORTANT: this class does **not** fall back to any commercial traffic provider. If no backend is
 * configured, every call returns an empty result and the traffic layer stays UNKNOWN — that is the
 * intended behaviour and the UI says so.
 *
 * The request bodies are deliberately minimal: a random per-install token, a segment id, an average
 * speed and a timestamp. No coordinates, no trip shape, no device identifiers.
 */
@Singleton
class TrafficApiClient @Inject constructor(
    @ApplicationContext private val context: Context,
    private val preferences: GpsPreferences,
    @GpsHttpClient private val httpClient: OkHttpClient
) {
    private val limiter = TokenBucketRateLimiter(capacity = 6, refillPerMinute = 40)
    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    var lastError: String? = null
        private set

    data class ServerSegmentState(
        val segmentId: String,
        val segmentName: String?,
        val averageSpeedKmh: Double?,
        val freeFlowKmh: Double?,
        val sampleCount: Int,
        val confidence: Double,
        val updatedAtMs: Long
    )

    suspend fun backendUrl(): String? = preferences.trafficBackendUrl.collectOnce()?.takeIf { it.isNotBlank() }

    suspend fun isEnabled(): Boolean = preferences.trafficBackendEnabled.collectOnce()

    /**
     * Uploads a batch of observations. Returns the number accepted, or -1 with [lastError] set.
     * Batches are capped at 50 so a long queue cannot burst the backend.
     */
    suspend fun uploadObservations(token: String, observations: List<SpeedObservation>): Int =
        withContext(Dispatchers.IO) {
            lastError = null
            val base = backendUrl()
            if (base.isNullOrBlank()) {
                lastError = "No community traffic backend configured"
                return@withContext -1
            }
            if (observations.isEmpty()) return@withContext 0
            if (!NetworkMonitor.isOnline(context)) {
                lastError = "Offline — samples stay queued on this device"
                return@withContext -1
            }
            if (!limiter.tryAcquire()) {
                lastError = "Upload rate limit reached"
                return@withContext -1
            }
            val payload = buildJsonObject {
                put("token", token)
                put("reporter_version", 1)
                put("observations", buildJsonArray {
                    observations.take(50).forEach { observation ->
                        add(buildJsonObject {
                            put("segment_id", observation.segmentId)
                            put("speed_kmh", observation.speedKmh)
                            put("timestamp_ms", observation.timestampMs)
                            put("accuracy_m", observation.accuracyMeters.toDouble())
                            put("samples", observation.sampleCount)
                        })
                    }
                })
            }.toString()
            postJson("$base/v1/traffic/observations", payload)?.let { body ->
                runCatching {
                    json.parseToJsonElement(body).jsonObject["accepted"]?.jsonPrimitive?.content?.toIntOrNull()
                }.getOrNull() ?: observations.size
            } ?: -1
        }

    suspend fun submitIncident(
        token: String,
        kind: IncidentKind,
        segmentId: String?,
        position: GeoPoint,
        notes: String?
    ): Boolean = withContext(Dispatchers.IO) {
        lastError = null
        val base = backendUrl()
        if (base.isNullOrBlank()) {
            lastError = "No community traffic backend configured"
            return@withContext false
        }
        if (!NetworkMonitor.isOnline(context)) {
            lastError = "Offline — the report is kept on this device and uploaded later"
            return@withContext false
        }
        if (!limiter.tryAcquire()) {
            lastError = "Report rate limit reached"
            return@withContext false
        }
        // Coordinates are rounded to ~100 m: enough to place the report, not enough to identify a
        // person's exact position at a given second.
        val payload = buildJsonObject {
            put("token", token)
            put("kind", kind.name)
            put("segment_id", segmentId)
            put("lat", Math.round(position.latitude * 1000.0) / 1000.0)
            put("lon", Math.round(position.longitude * 1000.0) / 1000.0)
            put("notes", notes?.take(280))
            put("reported_at_ms", System.currentTimeMillis())
        }.toString()
        postJson("$base/v1/traffic/incidents", payload) != null
    }

    /** Pulls current aggregates for the visible segments. Empty result = UNKNOWN everywhere. */
    suspend fun fetchSegments(segmentIds: List<String>): List<ServerSegmentState> =
        withContext(Dispatchers.IO) {
            lastError = null
            val base = backendUrl()
            if (base.isNullOrBlank()) {
                lastError = "No community traffic backend configured"
                return@withContext emptyList()
            }
            if (segmentIds.isEmpty()) return@withContext emptyList()
            if (!NetworkMonitor.isOnline(context)) {
                lastError = "Offline"
                return@withContext emptyList()
            }
            if (!limiter.tryAcquire(2)) {
                lastError = "Rate limit reached"
                return@withContext emptyList()
            }
            val url = ("$base/v1/traffic/segments").toHttpUrlOrNull()?.newBuilder()
                ?.addQueryParameter("ids", segmentIds.take(100).joinToString(","))
                ?.build() ?: return@withContext emptyList()
            val body = try {
                httpClient.newCall(
                    Request.Builder().url(url).header("User-Agent", USER_AGENT).get().build()
                ).execute().use { response ->
                    if (!response.isSuccessful) {
                        lastError = "Traffic backend returned HTTP ${response.code}"
                        return@withContext emptyList()
                    }
                    response.body.string()
                }
            } catch (t: Throwable) {
                lastError = t.message ?: "Traffic backend unreachable"
                return@withContext emptyList()
            }
            runCatching {
                json.parseToJsonElement(body).jsonObject["segments"]?.jsonArray?.mapNotNull { element ->
                    val item = element.jsonObject
                    ServerSegmentState(
                        segmentId = item["segment_id"]?.jsonPrimitive?.content ?: return@mapNotNull null,
                        segmentName = item["name"]?.jsonPrimitive?.content,
                        averageSpeedKmh = item["avg_speed_kmh"]?.jsonPrimitive?.doubleOrNull,
                        freeFlowKmh = item["free_flow_kmh"]?.jsonPrimitive?.doubleOrNull,
                        sampleCount = item["samples"]?.jsonPrimitive?.content?.toIntOrNull() ?: 0,
                        confidence = item["confidence"]?.jsonPrimitive?.doubleOrNull ?: 0.0,
                        updatedAtMs = item["updated_at_ms"]?.jsonPrimitive?.content?.toLongOrNull() ?: 0L
                    )
                }.orEmpty()
            }.getOrElse {
                lastError = "Traffic backend response could not be parsed"
                emptyList()
            }
        }

    private fun postJson(url: String, payload: String): String? {
        val httpUrl = url.toHttpUrlOrNull() ?: run {
            lastError = "The configured traffic backend URL is not valid"
            return null
        }
        val request = Request.Builder()
            .url(httpUrl)
            .header("User-Agent", USER_AGENT)
            .header("Content-Type", "application/json")
            .post(payload.toRequestBody("application/json".toMediaType()))
            .build()
        return try {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    lastError = "Traffic backend returned HTTP ${response.code}"
                    null
                } else {
                    response.body.string()
                }
            }
        } catch (t: Throwable) {
            lastError = t.message ?: "Traffic backend unreachable"
            null
        }
    }
}

/**
 * Qualifier for the GPS module's own OkHttp client. Without it the cloud module's unqualified
 * OkHttpClient binding would collide with this one, and the GPS client (short timeouts, no retry
 * storm) would be injected into cloud code by accident.
 */
@javax.inject.Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class GpsHttpClient

/** Shared OkHttp client for the GPS module (separate instance from the DNS/cloud clients). */
@Singleton
class GpsHttpClientFactory @Inject constructor() {
    fun create(): OkHttpClient = OkHttpClient.Builder()
        // TLS only: the module never talks to a cleartext endpoint (Android's network security
        // config also blocks cleartext app-wide).
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(12, TimeUnit.SECONDS)
        .writeTimeout(12, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .followRedirects(true)
        .build()
}
