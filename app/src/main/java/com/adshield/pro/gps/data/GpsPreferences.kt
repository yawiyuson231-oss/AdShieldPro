package com.adshield.pro.gps.data

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.security.LocationPrivacyPolicy
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AdShield Pro — GPS module settings.
 *
 * Separate DataStore file from the DNS preferences so the two modules stay independent: clearing
 * navigation settings can never alter filtering behaviour and vice versa.
 *
 * [reporterToken] is a random 128-bit value generated on first use. It exists only to let the
 * traffic backend ignore repeated submissions from the same install. It is not derived from any
 * device identifier, it is regenerated when the user resets it from the privacy screen, and it is
 * never sent together with a coordinate.
 */
internal val Context.gpsDataStore by preferencesDataStore(name = "adshield_gps_settings")

@Singleton
class GpsPreferences @Inject constructor(
    @ApplicationContext private val context: Context
) {

    private object Keys {
        val CONTRIBUTE_TRAFFIC = booleanPreferencesKey("contribute_traffic")
        val RECORD_HISTORY = booleanPreferencesKey("record_trip_history")
        val COARSE_HISTORY = booleanPreferencesKey("coarse_history_only")
        val RETENTION_DAYS = intPreferencesKey("history_retention_days")
        val ALLOW_EMERGENCY = booleanPreferencesKey("allow_emergency_sharing")
        val EMERGENCY_DISABLED = booleanPreferencesKey("emergency_sharing_disabled")
        val BACKGROUND_NAV = booleanPreferencesKey("background_navigation")
        val VOICE_GUIDANCE = booleanPreferencesKey("voice_guidance")
        val INCIDENT_REPORTING = booleanPreferencesKey("allow_incident_reporting")
        val REPORTER_TOKEN = stringPreferencesKey("reporter_token")
        val MAP_STYLE = stringPreferencesKey("map_style")
        val ROUTER = stringPreferencesKey("routing_provider")
        val CUSTOM_OSRM = stringPreferencesKey("custom_osrm_url")
        val CUSTOM_VALHALLA = stringPreferencesKey("custom_valhalla_url")
        val CUSTOM_NOMINATIM = stringPreferencesKey("custom_nominatim_url")
        val TRAFFIC_BACKEND = stringPreferencesKey("traffic_backend_url")
        val TRAFFIC_BACKEND_ENABLED = booleanPreferencesKey("traffic_backend_enabled")
        val LAST_LAT = stringPreferencesKey("last_lat")
        val LAST_LON = stringPreferencesKey("last_lon")
        val LAST_ZOOM = stringPreferencesKey("last_zoom")
        val LOCATION_DISCLOSURE_ACCEPTED = booleanPreferencesKey("location_disclosure_accepted")
        val VOICE_LANGUAGE = stringPreferencesKey("voice_language")
        val UNITS_METRIC = booleanPreferencesKey("units_metric")
        val CACHE_LIMIT_MB = intPreferencesKey("tile_cache_limit_mb")
    }

    val policy: Flow<LocationPrivacyPolicy> = context.gpsDataStore.data.map { it.toPolicy() }

    suspend fun currentPolicy(): LocationPrivacyPolicy =
        context.gpsDataStore.data.first().toPolicy()

    private fun Preferences.toPolicy(): LocationPrivacyPolicy = LocationPrivacyPolicy(
        contributeTraffic = this[Keys.CONTRIBUTE_TRAFFIC] ?: false,
        recordTripHistory = this[Keys.RECORD_HISTORY] ?: false,
        coarseHistoryOnly = this[Keys.COARSE_HISTORY] ?: true,
        historyRetentionDays = (this[Keys.RETENTION_DAYS] ?: 30).coerceIn(1, 365),
        allowEmergencySharing = this[Keys.ALLOW_EMERGENCY] ?: false,
        emergencySharingDisabled = this[Keys.EMERGENCY_DISABLED] ?: false,
        backgroundNavigation = this[Keys.BACKGROUND_NAV] ?: true,
        voiceGuidance = this[Keys.VOICE_GUIDANCE] ?: true,
        allowIncidentReporting = this[Keys.INCIDENT_REPORTING] ?: false
    )

    suspend fun setContributeTraffic(enabled: Boolean) {
        context.gpsDataStore.edit { it[Keys.CONTRIBUTE_TRAFFIC] = enabled }
    }

    suspend fun setRecordTripHistory(enabled: Boolean) {
        context.gpsDataStore.edit { it[Keys.RECORD_HISTORY] = enabled }
    }

    suspend fun setCoarseHistoryOnly(coarse: Boolean) {
        context.gpsDataStore.edit { it[Keys.COARSE_HISTORY] = coarse }
    }

    suspend fun setHistoryRetentionDays(days: Int) {
        context.gpsDataStore.edit { it[Keys.RETENTION_DAYS] = days.coerceIn(1, 365) }
    }

    suspend fun setAllowEmergencySharing(enabled: Boolean) {
        context.gpsDataStore.edit {
            it[Keys.ALLOW_EMERGENCY] = enabled
            if (!enabled) it[Keys.EMERGENCY_DISABLED] = false
        }
    }

    /** The kill switch: disabling it also clears the allowance so it cannot silently come back. */
    suspend fun setEmergencySharingDisabled(disabled: Boolean) {
        context.gpsDataStore.edit {
            it[Keys.EMERGENCY_DISABLED] = disabled
            if (disabled) it[Keys.ALLOW_EMERGENCY] = false
        }
    }

    suspend fun setBackgroundNavigation(enabled: Boolean) {
        context.gpsDataStore.edit { it[Keys.BACKGROUND_NAV] = enabled }
    }

    suspend fun setVoiceGuidance(enabled: Boolean) {
        context.gpsDataStore.edit { it[Keys.VOICE_GUIDANCE] = enabled }
    }

    suspend fun setIncidentReporting(enabled: Boolean) {
        context.gpsDataStore.edit { it[Keys.INCIDENT_REPORTING] = enabled }
    }

    suspend fun setLocationDisclosureAccepted(accepted: Boolean) {
        context.gpsDataStore.edit { it[Keys.LOCATION_DISCLOSURE_ACCEPTED] = accepted }
    }

    val locationDisclosureAccepted: Flow<Boolean> =
        context.gpsDataStore.data.map { it[Keys.LOCATION_DISCLOSURE_ACCEPTED] ?: false }

    // ------------------------------------------------------------------ map
    val mapStyle: Flow<String> = context.gpsDataStore.data.map { it[Keys.MAP_STYLE] ?: DEFAULT_MAP_STYLE }
    suspend fun setMapStyle(styleUrl: String) {
        context.gpsDataStore.edit { it[Keys.MAP_STYLE] = styleUrl }
    }

    val routerPreference: Flow<String> = context.gpsDataStore.data.map { it[Keys.ROUTER] ?: "OSRM" }
    suspend fun setRouterPreference(provider: String) {
        context.gpsDataStore.edit { it[Keys.ROUTER] = provider }
    }

    val customOsrmUrl: Flow<String?> = context.gpsDataStore.data.map { it[Keys.CUSTOM_OSRM] }
    val customValhallaUrl: Flow<String?> = context.gpsDataStore.data.map { it[Keys.CUSTOM_VALHALLA] }
    val customNominatimUrl: Flow<String?> = context.gpsDataStore.data.map { it[Keys.CUSTOM_NOMINATIM] }
    val trafficBackendUrl: Flow<String?> = context.gpsDataStore.data.map { it[Keys.TRAFFIC_BACKEND] }
    val trafficBackendEnabled: Flow<Boolean> = context.gpsDataStore.data.map { it[Keys.TRAFFIC_BACKEND_ENABLED] ?: false }

    suspend fun setEndpoint(key: String, value: String?) {
        val preferenceKey = when (key) {
            "osrm" -> Keys.CUSTOM_OSRM
            "valhalla" -> Keys.CUSTOM_VALHALLA
            "nominatim" -> Keys.CUSTOM_NOMINATIM
            "traffic" -> Keys.TRAFFIC_BACKEND
            else -> return
        }
        context.gpsDataStore.edit { prefs ->
            if (value.isNullOrBlank()) prefs.remove(preferenceKey) else prefs[preferenceKey] = value.trim()
        }
    }

    suspend fun setTrafficBackendEnabled(enabled: Boolean) {
        context.gpsDataStore.edit { it[Keys.TRAFFIC_BACKEND_ENABLED] = enabled }
    }

    val lastCamera: Flow<GeoPoint?> = context.gpsDataStore.data.map { prefs ->
        val lat = prefs[Keys.LAST_LAT]?.toDoubleOrNull()
        val lon = prefs[Keys.LAST_LON]?.toDoubleOrNull()
        if (lat != null && lon != null && lat in -90.0..90.0 && lon in -180.0..180.0) GeoPoint(lat, lon) else null
    }

    val lastZoom: Flow<Double> = context.gpsDataStore.data.map { it[Keys.LAST_ZOOM]?.toDoubleOrNull() ?: 14.0 }

    suspend fun rememberCamera(point: GeoPoint, zoom: Double) {
        context.gpsDataStore.edit {
            it[Keys.LAST_LAT] = point.latitude.toString()
            it[Keys.LAST_LON] = point.longitude.toString()
            it[Keys.LAST_ZOOM] = zoom.toString()
        }
    }

    val voiceLanguage: Flow<String> = context.gpsDataStore.data.map { it[Keys.VOICE_LANGUAGE] ?: "en-US" }
    suspend fun setVoiceLanguage(tag: String) {
        context.gpsDataStore.edit { it[Keys.VOICE_LANGUAGE] = tag }
    }

    val unitsMetric: Flow<Boolean> = context.gpsDataStore.data.map { it[Keys.UNITS_METRIC] ?: true }
    suspend fun setUnitsMetric(metric: Boolean) {
        context.gpsDataStore.edit { it[Keys.UNITS_METRIC] = metric }
    }

    val tileCacheLimitMb: Flow<Int> = context.gpsDataStore.data.map { it[Keys.CACHE_LIMIT_MB] ?: 512 }
    suspend fun setTileCacheLimitMb(mb: Int) {
        context.gpsDataStore.edit { it[Keys.CACHE_LIMIT_MB] = mb.coerceIn(64, 4096) }
    }

    // ------------------------------------------------------- reporter token
    /** Random per-install token; regenerating it detaches this device from past submissions. */
    suspend fun reporterToken(): String {
        var token: String? = null
        context.gpsDataStore.edit { prefs ->
            val existing = prefs[Keys.REPORTER_TOKEN]
            if (existing.isNullOrBlank()) {
                val generated = newToken()
                prefs[Keys.REPORTER_TOKEN] = generated
                token = generated
            } else {
                token = existing
            }
        }
        return token ?: newToken()
    }

    suspend fun regenerateReporterToken(): String {
        val generated = newToken()
        context.gpsDataStore.edit { it[Keys.REPORTER_TOKEN] = generated }
        return generated
    }

    private fun newToken(): String {
        val bytes = ByteArray(16)
        SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    companion object {
        /**
         * Free, keyless, OpenStreetMap vector styles published by OpenFreeMap (MIT).
         *
         * Their terms allow offline downloads of up to 3 000 tiles / 50 MB per download with at
         * most 4 parallel requests, which is exactly what the offline screen enforces. Any other
         * style server (self-hosted tilemaker/OpenMapTiles, a downloaded `.pmtiles` archive) can be
         * substituted in the UI without a code change.
         */
        const val DEFAULT_MAP_STYLE = "https://tiles.openfreemap.org/styles/liberty"
        const val DARK_MAP_STYLE = "https://tiles.openfreemap.org/styles/dark"
        const val BRIGHT_MAP_STYLE = "https://tiles.openfreemap.org/styles/bright"
        const val POSITRON_MAP_STYLE = "https://tiles.openfreemap.org/styles/positron"

        const val DEFAULT_OSRM = "https://routing.openstreetmap.de/routed-car"
        const val DEFAULT_VALHALLA = "https://valhalla1.openstreetmap.de"
        const val DEFAULT_NOMINATIM = "https://nominatim.openstreetmap.org"

        /** Identifying User-Agent required by the OSM usage policy for every public endpoint. */
        const val USER_AGENT = "AdShieldPro-GPS/2.10 (Android; +https://github.com/yawiyuson231-oss/AdShieldPro)"

        /** Nominatim allows 1 request per second; the app stays far below that. */
        const val NOMINATIM_MIN_INTERVAL_MS = 1_200L

        /** Free routing servers are shared infrastructure; never exceed this. */
        const val ROUTING_MIN_INTERVAL_MS = 1_000L

        /** Hard caps that keep the app inside the free-tier fair-use policies. */
        const val MAX_OFFLINE_TILES_PER_PACK = 3_000
        const val MAX_OFFLINE_BYTES_PER_PACK = 50L * 1024L * 1024L
        const val MAX_PARALLEL_TILE_REQUESTS = 4

        val STYLE_PRESETS: List<Pair<String, String>> = listOf(
            "Liberty (full detail)" to DEFAULT_MAP_STYLE,
            "Dark (cyber)" to DARK_MAP_STYLE,
            "Bright" to BRIGHT_MAP_STYLE,
            "Positron (minimal)" to POSITRON_MAP_STYLE
        )
    }
}
