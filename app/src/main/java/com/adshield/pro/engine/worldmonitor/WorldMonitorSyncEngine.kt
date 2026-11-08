package com.adshield.pro.engine.worldmonitor

import com.adshield.pro.data.repository.ProviderCredentialStore
import com.adshield.pro.data.worldmonitor.WorldMonitorDao
import com.adshield.pro.data.worldmonitor.WorldProviderStateEntity
import com.adshield.pro.domain.worldmonitor.BuildingFootprint3D
import com.adshield.pro.domain.worldmonitor.GeoSearchResult
import com.adshield.pro.domain.worldmonitor.GlobeViewport
import com.adshield.pro.domain.worldmonitor.ProviderAuthRequirement
import com.adshield.pro.domain.worldmonitor.ProviderSyncStatus
import com.adshield.pro.domain.worldmonitor.WorldEntity
import com.adshield.pro.domain.worldmonitor.WorldProviderSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import okhttp3.Credentials
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Locale
import com.adshield.pro.di.WorldMonitorHttpClient
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Rate-limit-disciplined, HTTPS-only, ETag/Last-Modified-aware HTTP sync & geocoding engine
 * for World Monitor 2035.
 */
@Singleton
class WorldMonitorSyncEngine @Inject constructor(
    @WorldMonitorHttpClient private val httpClient: OkHttpClient,
    private val dao: WorldMonitorDao,
    private val credentialStore: ProviderCredentialStore
) {
    private val nominatimMutex = Mutex()
    private var lastNominatimCallMs: Long = 0L

    data class ProviderFetchOutcome(
        val providerId: String,
        val status: ProviderSyncStatus,
        val entities: List<WorldEntity> = emptyList(),
        val rainViewerFrames: List<WorldMonitorNormalizers.RainViewerFrame> = emptyList(),
        val buildings3D: List<BuildingFootprint3D> = emptyList(),
        val errorMessage: String? = null
    )

    suspend fun syncProvider(
        spec: WorldProviderSpec,
        viewport: GlobeViewport? = null,
        force: Boolean = false,
        nowEpochMs: Long = System.currentTimeMillis()
    ): ProviderFetchOutcome = withContext(Dispatchers.IO) {
        val existingState = dao.getProviderState(spec.id)
        if (existingState != null && !existingState.enabled) {
            return@withContext ProviderFetchOutcome(spec.id, ProviderSyncStatus.DISABLED)
        }

        // 1. Offline / Bundled Baseline Catalog
        if (spec.id == "wm.infra.baseline") {
            val items = BaselineReferenceStore.buildBaselineEntities(nowEpochMs)
            saveProviderState(spec.id, existingState, ProviderSyncStatus.HEALTHY, 200, items.size, null, nowEpochMs)
            return@withContext ProviderFetchOutcome(spec.id, ProviderSyncStatus.HEALTHY, entities = items)
        }

        // 2. Unimplemented / Backend-proxy-gated feeds (e.g. AISStream WebSocket)
        if (!spec.implemented) {
            val hasCred = spec.credentialSlot?.let { !credentialStore.get(it).isNullOrBlank() } == true
            val status = if (hasCred) ProviderSyncStatus.ERROR else ProviderSyncStatus.REQUIRES_KEY
            val note = spec.limitationNote ?: "Requires external WebSocket stream proxy or API credentials."
            saveProviderState(spec.id, existingState, status, null, 0, note, nowEpochMs)
            return@withContext ProviderFetchOutcome(spec.id, status, errorMessage = note)
        }

        // 3. Required API key check (e.g. NASA FIRMS MAP_KEY)
        val secret = spec.credentialSlot?.let { credentialStore.get(it) }
        if (spec.authRequirement == ProviderAuthRequirement.REQUIRED_USER_API_KEY && secret.isNullOrBlank()) {
            val note = spec.limitationNote ?: "Add your free API key in World Monitor Settings to enable this feed."
            saveProviderState(spec.id, existingState, ProviderSyncStatus.REQUIRES_KEY, null, 0, note, nowEpochMs)
            return@withContext ProviderFetchOutcome(spec.id, ProviderSyncStatus.REQUIRES_KEY, errorMessage = note)
        }

        // 4. Respect backoff & minimum provider gap (e.g. CelesTrak 2-hour policy!)
        if (existingState != null) {
            if (nowEpochMs < existingState.nextEligibleEpochMs) {
                return@withContext ProviderFetchOutcome(
                    spec.id,
                    ProviderSyncStatus.RATE_LIMITED,
                    errorMessage = "Cooling down until rate-limit window expires"
                )
            }
            val minGap = if (spec.id.startsWith("wm.space.celestrak.")) {
                spec.minGapMs // Always enforce CelesTrak 2h rule even on manual tap if already cached!
            } else if (force) {
                10_000L
            } else {
                spec.refreshIntervalMs
            }
            val lastOk = existingState.lastSuccessEpochMs ?: 0L
            if (lastOk > 0L && (nowEpochMs - lastOk) < minGap) {
                return@withContext ProviderFetchOutcome(spec.id, existingStateStatus(existingState))
            }
        }

        // 5. Special handling for Overpass 3D Buildings & Local Infra (POST with bbox < 0.6 deg)
        if (spec.id == "wm.infra.overpass") {
            return@withContext fetchOverpassViewport(spec, existingState, viewport, nowEpochMs)
        }

        // 6. Build HTTPS request URL
        val resolvedUrl = resolveEndpointUrl(spec, secret, viewport)
        if (!resolvedUrl.startsWith("https://", ignoreCase = true)) {
            saveProviderState(spec.id, existingState, ProviderSyncStatus.ERROR, null, 0, "Blocked non-HTTPS URL", nowEpochMs)
            return@withContext ProviderFetchOutcome(spec.id, ProviderSyncStatus.ERROR, errorMessage = "Non-HTTPS endpoint")
        }

        val reqBuilder = Request.Builder()
            .url(resolvedUrl)
            .header("User-Agent", USER_AGENT)
            .header("Accept", "application/json, application/xml, text/csv, text/plain, */*")
            .get()

        // Optional OpenSky credentials (`username:password` or Bearer token)
        if (spec.id == "wm.aviation.opensky" && !secret.isNullOrBlank()) {
            if (secret.contains(':')) {
                val user = secret.substringBefore(':')
                val pass = secret.substringAfter(':')
                reqBuilder.header("Authorization", Credentials.basic(user, pass))
            } else {
                reqBuilder.header("Authorization", "Bearer $secret")
            }
        }

        existingState?.etag?.takeIf { it.isNotBlank() }?.let { reqBuilder.header("If-None-Match", it) }
        existingState?.lastModifiedHeader?.takeIf { it.isNotBlank() }?.let { reqBuilder.header("If-Modified-Since", it) }

        return@withContext executeFeedRequest(spec, reqBuilder.build(), existingState, nowEpochMs)
    }

    private suspend fun fetchOverpassViewport(
        spec: WorldProviderSpec,
        existingState: WorldProviderStateEntity?,
        viewport: GlobeViewport?,
        nowEpochMs: Long
    ): ProviderFetchOutcome {
        val vp = viewport ?: return ProviderFetchOutcome(spec.id, ProviderSyncStatus.IDLE)
        val latSpan = kotlin.math.abs(vp.north - vp.south)
        val lonSpan = kotlin.math.abs(vp.east - vp.west)
        if (latSpan > 0.65 || lonSpan > 0.65 || vp.altitudeMeters > 35_000.0) {
            return ProviderFetchOutcome(
                spec.id,
                ProviderSyncStatus.IDLE,
                errorMessage = "Zoom closer (< 35 km altitude) to stream live OSM 3D buildings & street infrastructure."
            )
        }
        val s = "%.5f".format(Locale.US, vp.south)
        val w = "%.5f".format(Locale.US, vp.west)
        val n = "%.5f".format(Locale.US, vp.north)
        val e = "%.5f".format(Locale.US, vp.east)

        val ql = """
            [out:json][timeout:12];
            (
              way["building"]($s,$w,$n,$e);
              node["railway"="station"]($s,$w,$n,$e);
              node["power"="substation"]($s,$w,$n,$e);
              node["man_made"="mast"]($s,$w,$n,$e);
            );
            out body center 180;
        """.trimIndent()
        val formBody = ("data=" + URLEncoder.encode(ql, "UTF-8"))
            .toRequestBody("application/x-www-form-urlencoded".toMediaType())

        val req = Request.Builder()
            .url(spec.endpointDescription)
            .header("User-Agent", USER_AGENT)
            .post(formBody)
            .build()

        return try {
            httpClient.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) {
                    val status = if (resp.code == 429) ProviderSyncStatus.RATE_LIMITED else ProviderSyncStatus.ERROR
                    saveProviderState(spec.id, existingState, status, resp.code, 0, "HTTP ${resp.code}", nowEpochMs)
                    return ProviderFetchOutcome(spec.id, status, errorMessage = "HTTP ${resp.code}")
                }
                val raw = readBoundedUtf8(resp.body.byteStream(), MAX_BODY_BYTES)
                val parsed = WorldMonitorNormalizers.parseOverpass(raw, nowEpochMs)
                saveProviderState(
                    spec.id,
                    existingState,
                    ProviderSyncStatus.HEALTHY,
                    200,
                    parsed.infrastructureEntities.size + parsed.buildings3D.size,
                    null,
                    nowEpochMs
                )
                ProviderFetchOutcome(
                    providerId = spec.id,
                    status = ProviderSyncStatus.HEALTHY,
                    entities = parsed.infrastructureEntities,
                    buildings3D = parsed.buildings3D
                )
            }
        } catch (e: Exception) {
            saveProviderState(spec.id, existingState, ProviderSyncStatus.OFFLINE, null, 0, e.message, nowEpochMs)
            ProviderFetchOutcome(spec.id, ProviderSyncStatus.OFFLINE, errorMessage = e.message)
        }
    }

    private suspend fun executeFeedRequest(
        spec: WorldProviderSpec,
        request: Request,
        existingState: WorldProviderStateEntity?,
        nowEpochMs: Long
    ): ProviderFetchOutcome {
        return try {
            httpClient.newCall(request).execute().use { response ->
                val code = response.code
                if (code == 304) {
                    saveProviderState(
                        spec.id,
                        existingState,
                        ProviderSyncStatus.HEALTHY,
                        304,
                        existingState?.cachedItemCount ?: 0,
                        null,
                        nowEpochMs,
                        etag = response.header("ETag") ?: existingState?.etag,
                        lastMod = response.header("Last-Modified") ?: existingState?.lastModifiedHeader
                    )
                    return ProviderFetchOutcome(spec.id, ProviderSyncStatus.HEALTHY)
                }

                if (code == 429) {
                    val retrySec = response.header("Retry-After")?.trim()?.toLongOrNull()?.coerceIn(30L, 7_200L) ?: 300L
                    saveProviderState(
                        spec.id,
                        existingState,
                        ProviderSyncStatus.RATE_LIMITED,
                        429,
                        existingState?.cachedItemCount ?: 0,
                        "Rate limited (retry in ${retrySec}s)",
                        nowEpochMs,
                        backoffMs = retrySec * 1000L
                    )
                    return ProviderFetchOutcome(spec.id, ProviderSyncStatus.RATE_LIMITED, errorMessage = "HTTP 429")
                }

                if (!response.isSuccessful) {
                    val failures = (existingState?.consecutiveFailures ?: 0) + 1
                    val backoff = (30_000L * (1L shl failures.coerceAtMost(6))).coerceAtMost(1_800_000L)
                    saveProviderState(
                        spec.id,
                        existingState,
                        ProviderSyncStatus.ERROR,
                        code,
                        existingState?.cachedItemCount ?: 0,
                        "HTTP $code",
                        nowEpochMs,
                        consecutiveFailures = failures,
                        backoffMs = backoff
                    )
                    return ProviderFetchOutcome(spec.id, ProviderSyncStatus.ERROR, errorMessage = "HTTP $code")
                }

                val bodyText = readBoundedUtf8(response.body.byteStream(), MAX_BODY_BYTES)
                val rainFrames = if (spec.id == "wm.weather.rainviewer") {
                    WorldMonitorNormalizers.parseRainViewerFrames(bodyText)
                } else emptyList()

                val entities = if (spec.id == "wm.weather.rainviewer") {
                    emptyList()
                } else {
                    WorldMonitorNormalizers.normalize(spec.id, bodyText, nowEpochMs)
                }

                val count = if (spec.id == "wm.weather.rainviewer") rainFrames.size else entities.size
                saveProviderState(
                    spec.id,
                    existingState,
                    ProviderSyncStatus.HEALTHY,
                    code,
                    count,
                    null,
                    nowEpochMs,
                    etag = response.header("ETag"),
                    lastMod = response.header("Last-Modified")
                )
                ProviderFetchOutcome(
                    providerId = spec.id,
                    status = ProviderSyncStatus.HEALTHY,
                    entities = entities,
                    rainViewerFrames = rainFrames
                )
            }
        } catch (e: Exception) {
            val failures = (existingState?.consecutiveFailures ?: 0) + 1
            val backoff = (20_000L * failures.coerceAtMost(6)).coerceAtMost(600_000L)
            saveProviderState(
                spec.id,
                existingState,
                ProviderSyncStatus.OFFLINE,
                null,
                existingState?.cachedItemCount ?: 0,
                e.message ?: "Network unreachable",
                nowEpochMs,
                consecutiveFailures = failures,
                backoffMs = backoff
            )
            ProviderFetchOutcome(spec.id, ProviderSyncStatus.OFFLINE, errorMessage = e.message)
        }
    }

    /**
     * Global geographic search: combines instant offline baseline matches (countries, capitals,
     * airports, seaports) with live OpenStreetMap Nominatim geocoding (cities, landmarks, addresses).
     */
    suspend fun searchLocations(query: String): List<GeoSearchResult> = withContext(Dispatchers.IO) {
        val clean = query.trim()
        if (clean.length < 2) return@withContext emptyList()

        // Coordinate literal support: e.g. "14.5995, 120.9842"
        val coordParts = clean.split(Regex("[,\\s]+")).filter { it.isNotBlank() }
        if (coordParts.size == 2) {
            val lat = coordParts[0].toDoubleOrNull()
            val lon = coordParts[1].toDoubleOrNull()
            if (lat != null && lon != null && GeoSpatialIndex.isValidCoordinate(lat, lon)) {
                return@withContext listOf(
                    GeoSearchResult(
                        displayName = "Coordinates %.4f°, %.4f°".format(Locale.US, lat, lon),
                        category = "Coordinate",
                        latitude = lat,
                        longitude = lon,
                        recommendedAltitudeMeters = 45_000.0,
                        source = "Direct WGS84 Input"
                    )
                )
            }
        }

        val offlineMatches = searchOfflineBaseline(clean)
        val liveMatches = runCatching { queryNominatim(clean) }.getOrDefault(emptyList())
        (offlineMatches + liveMatches)
            .distinctBy { "${"%.2f".format(Locale.US, it.latitude)}:${"%.2f".format(Locale.US, it.longitude)}" }
            .take(12)
    }

    suspend fun lookupElevationAndPlace(lat: Double, lon: Double): Pair<Int?, String?> = withContext(Dispatchers.IO) {
        val elev = runCatching {
            val url = "https://api.open-meteo.com/v1/elevation?latitude=${"%.4f".format(Locale.US, lat)}&longitude=${"%.4f".format(Locale.US, lon)}"
            val req = Request.Builder().url(url).header("User-Agent", USER_AGENT).get().build()
            httpClient.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) null
                else {
                    val obj = json.parseToJsonElement(readBoundedUtf8(resp.body.byteStream(), 16_384)).jsonObject
                    obj["elevation"]?.jsonArray?.firstOrNull()?.jsonPrimitive?.doubleOrNull?.toInt()
                }
            }
        }.getOrNull()

        val place = runCatching {
            nominatimMutex.withLock {
                val wait = 1_100L - (System.currentTimeMillis() - lastNominatimCallMs)
                if (wait > 0) kotlinx.coroutines.delay(wait)
                lastNominatimCallMs = System.currentTimeMillis()
                val url = "https://nominatim.openstreetmap.org/reverse?format=jsonv2&zoom=10&lat=${"%.4f".format(Locale.US, lat)}&lon=${"%.4f".format(Locale.US, lon)}"
                val req = Request.Builder()
                    .url(url)
                    .header("User-Agent", USER_AGENT)
                    .header("Accept-Language", "en")
                    .get()
                    .build()
                httpClient.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) null
                    else {
                        val obj = json.parseToJsonElement(readBoundedUtf8(resp.body.byteStream(), 32_768)).jsonObject
                        obj["display_name"]?.jsonPrimitive?.content
                    }
                }
            }
        }.getOrNull()

        elev to place
    }

    suspend fun fetchLiveWorldBankPopulation(iso2: String): Pair<Long, Int>? = withContext(Dispatchers.IO) {
        runCatching {
            val code = iso2.trim().lowercase(Locale.US)
            if (code.length != 2) return@runCatching null
            val url = "https://api.worldbank.org/v2/country/$code/indicator/SP.POP.TOTL?format=json&per_page=4"
            val req = Request.Builder().url(url).header("User-Agent", USER_AGENT).get().build()
            httpClient.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return@use null
                val root = json.parseToJsonElement(readBoundedUtf8(resp.body.byteStream(), 32_768)) as? JsonArray ?: return@use null
                val entries = root.getOrNull(1) as? JsonArray ?: return@use null
                for (el in entries) {
                    val obj = el as? JsonObject ?: continue
                    val value = obj["value"]?.jsonPrimitive?.longOrNull ?: continue
                    val yr = obj["date"]?.jsonPrimitive?.intOrNull ?: 2024
                    if (value > 0L) return@use (value to yr)
                }
                null
            }
        }.getOrNull()
    }

    private suspend fun queryNominatim(query: String): List<GeoSearchResult> = nominatimMutex.withLock {
        val wait = 1_100L - (System.currentTimeMillis() - lastNominatimCallMs)
        if (wait > 0) kotlinx.coroutines.delay(wait)
        lastNominatimCallMs = System.currentTimeMillis()

        val encoded = URLEncoder.encode(query, "UTF-8")
        val url = "https://nominatim.openstreetmap.org/search?format=jsonv2&limit=6&addressdetails=1&q=$encoded"
        val req = Request.Builder()
            .url(url)
            .header("User-Agent", USER_AGENT)
            .header("Accept-Language", "en")
            .get()
            .build()
        httpClient.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) return emptyList()
            val arr = json.parseToJsonElement(readBoundedUtf8(resp.body.byteStream(), 131_072)).jsonArray
            arr.mapNotNull { el ->
                val obj = el as? JsonObject ?: return@mapNotNull null
                val lat = obj["lat"]?.jsonPrimitive?.doubleOrNull ?: return@mapNotNull null
                val lon = obj["lon"]?.jsonPrimitive?.doubleOrNull ?: return@mapNotNull null
                if (!GeoSpatialIndex.isValidCoordinate(lat, lon)) return@mapNotNull null
                val name = obj["display_name"]?.jsonPrimitive?.content ?: return@mapNotNull null
                val type = obj["type"]?.jsonPrimitive?.content ?: "Place"
                val addr = obj["address"] as? JsonObject
                val cc = addr?.get("country_code")?.jsonPrimitive?.content?.uppercase(Locale.US)
                val alt = when (type) {
                    "country", "administrative" -> 1_800_000.0
                    "city", "state" -> 120_000.0
                    else -> 12_000.0
                }
                GeoSearchResult(
                    displayName = name,
                    category = type.replaceFirstChar { it.uppercase() },
                    latitude = lat,
                    longitude = lon,
                    countryCode = cc,
                    recommendedAltitudeMeters = alt,
                    source = "OpenStreetMap Nominatim"
                )
            }
        }
    }

    private fun searchOfflineBaseline(query: String): List<GeoSearchResult> {
        val q = query.lowercase(Locale.US)
        val payload = BaselineReferenceStore.load()
        val out = ArrayList<GeoSearchResult>()

        payload.countries.filter {
            it.name.lowercase(Locale.US).contains(q) ||
                it.capital.lowercase(Locale.US).contains(q) ||
                it.iso2.equals(query, ignoreCase = true) ||
                it.iso3.equals(query, ignoreCase = true)
        }.take(4).forEach { c ->
            out += GeoSearchResult(
                displayName = "${c.name} (Capital: ${c.capital})",
                category = "Country",
                latitude = c.lat,
                longitude = c.lon,
                countryCode = c.iso2,
                recommendedAltitudeMeters = 2_400_000.0,
                source = "Offline World Reference"
            )
        }

        payload.airports.filter {
            it.iata.equals(query, ignoreCase = true) ||
                it.icao.equals(query, ignoreCase = true) ||
                it.name.lowercase(Locale.US).contains(q) ||
                it.city.lowercase(Locale.US).contains(q)
        }.take(4).forEach { a ->
            out += GeoSearchResult(
                displayName = "${a.iata}/${a.icao} — ${a.name}, ${a.city}",
                category = "Airport",
                latitude = a.lat,
                longitude = a.lon,
                countryCode = a.country,
                recommendedAltitudeMeters = 18_000.0,
                source = "OurAirports Reference"
            )
        }

        payload.seaports.filter {
            it.locode.equals(query, ignoreCase = true) ||
                it.name.lowercase(Locale.US).contains(q)
        }.take(3).forEach { p ->
            out += GeoSearchResult(
                displayName = "${p.locode} — Port of ${p.name}",
                category = "Seaport",
                latitude = p.lat,
                longitude = p.lon,
                countryCode = p.country,
                recommendedAltitudeMeters = 22_000.0,
                source = "WPI Reference"
            )
        }
        return out
    }

    private fun resolveEndpointUrl(spec: WorldProviderSpec, secret: String?, viewport: GlobeViewport?): String {
        var url = spec.endpointDescription
        if (url.contains("{apiKey}") && !secret.isNullOrBlank()) {
            url = url.replace("{apiKey}", URLEncoder.encode(secret.trim(), "UTF-8"))
        }
        val west = viewport?.west ?: -180.0
        val south = viewport?.south ?: -70.0
        val east = viewport?.east ?: 180.0
        val north = viewport?.north ?: 75.0
        url = url.replace("{west}", "%.2f".format(Locale.US, west))
            .replace("{south}", "%.2f".format(Locale.US, south))
            .replace("{east}", "%.2f".format(Locale.US, east))
            .replace("{north}", "%.2f".format(Locale.US, north))
        return url
    }

    private suspend fun saveProviderState(
        providerId: String,
        previous: WorldProviderStateEntity?,
        status: ProviderSyncStatus,
        httpCode: Int?,
        itemCount: Int,
        error: String?,
        nowEpochMs: Long,
        etag: String? = previous?.etag,
        lastMod: String? = previous?.lastModifiedHeader,
        consecutiveFailures: Int = if (status == ProviderSyncStatus.HEALTHY) 0 else (previous?.consecutiveFailures ?: 0),
        backoffMs: Long = 0L
    ) {
        dao.upsertProviderState(
            WorldProviderStateEntity(
                providerId = providerId,
                enabled = previous?.enabled ?: true,
                status = status.name,
                lastSyncEpochMs = nowEpochMs,
                lastSuccessEpochMs = if (status == ProviderSyncStatus.HEALTHY) nowEpochMs else previous?.lastSuccessEpochMs,
                nextEligibleEpochMs = if (backoffMs > 0L) nowEpochMs + backoffMs else 0L,
                lastHttpCode = httpCode,
                lastError = error,
                etag = etag,
                lastModifiedHeader = lastMod,
                cachedItemCount = itemCount,
                consecutiveFailures = consecutiveFailures
            )
        )
    }

    private fun existingStateStatus(state: WorldProviderStateEntity): ProviderSyncStatus =
        runCatching { ProviderSyncStatus.valueOf(state.status) }.getOrDefault(ProviderSyncStatus.HEALTHY)

    companion object {
        private const val USER_AGENT = "OmniShieldX-WorldMonitor/2035.1 (Android; Passive-OSINT-Earth-Viewer)"
        private const val MAX_BODY_BYTES = 4 * 1024 * 1024 // 4 MB safety ceiling per provider response

        private val json = Json { ignoreUnknownKeys = true; isLenient = true }

        internal fun readBoundedUtf8(stream: java.io.InputStream, maxBytes: Int): String {
            val out = ByteArrayOutputStream(minOf(maxBytes, 65_536))
            val buf = ByteArray(8_192)
            var total = 0
            while (true) {
                val read = stream.read(buf)
                if (read <= 0) break
                val allowed = minOf(read, maxBytes - total)
                if (allowed > 0) {
                    out.write(buf, 0, allowed)
                    total += allowed
                }
                if (total >= maxBytes) break
            }
            return out.toString(StandardCharsets.UTF_8.name())
        }
    }
}
