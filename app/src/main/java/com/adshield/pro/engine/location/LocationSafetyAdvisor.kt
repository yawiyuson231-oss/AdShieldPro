package com.adshield.pro.engine.location

import java.util.Locale
import kotlin.math.roundToInt

/** Android settings the Safe GPS tools may offer to open. Never opened implicitly. */
enum class DeviceSettingTarget { LOCATION_SOURCE, LOCATION_SCAN, APP_LOCATION_PERMISSIONS, DEVELOPER_OPTIONS }

/**
 * A device-level fact, plus whether it could be read at all.
 *
 * A check whose value is [FactState.UNKNOWN] must be shown as "cannot read", never as "healthy":
 * the whole point of the checklist is that it does not flatter the device.
 */
enum class FactState { OK, WARN, BAD, UNKNOWN }

data class SafetyFact(
    val id: String,
    val label: String,
    val state: FactState,
    val detail: String,
    val setting: DeviceSettingTarget? = null
)

/** What the platform says about our own location permission. */
enum class LocationPermission { GRANTED, DENIED, NOT_DETERMINED, DENIED_PERMANENTLY }

/** Inputs the Android layer reads before an assessment; all default to "unknown". */
data class DeviceLocationContext(
    val permission: LocationPermission = LocationPermission.NOT_DETERMINED,
    val systemLocationEnabled: Boolean? = null,
    val wifiScanningEnabled: Boolean? = null,
    val precisePermissionGranted: Boolean? = null,
    val developerOptionsEnabled: Boolean? = null,
    val mockProvidersEnabled: Boolean? = null,
    val encryptedNetworkAvailable: Boolean? = null,
    val screenLockKnown: Boolean = false
)

/** What to do with the pin: the two share modes are deliberately different. */
enum class ShareMode { EVERYDAY, EMERGENCY }

data class SharePlan(
    val mode: ShareMode,
    val point: GeoPoint,
    val rounded: RoundedFix?,
    val worstCaseMeters: Double,
    val text: String,
    val smsUri: String,
    val blocked: Boolean,
    val blockReason: String?,
    val warnings: List<String>
)

/**
 * AdShield Pro — Safe GPS decisions.
 *
 * Pure Kotlin (no Android classes) so every rule below is unit-tested on the JVM: the device
 * checklist, the refusal to share an untrustworthy pin, the privacy rounding, and the exact
 * wording of the message an emergency contact or a barangay responder will read.
 *
 * The app cannot call 911, cannot alert anyone automatically and cannot track a phone in the
 * background. It produces a pin and a message the user sends themselves, and says so.
 */
object LocationSafetyAdvisor {

    const val CIVILIAN_GRID_METERS = 250
    const val NEIGHBOURHOOD_GRID_METERS = 1_000
    const val TOWN_GRID_METERS = 5_000

    /** Rounding choices offered in the UI; 0 means "share the exact fix". */
    val gridChoices: List<Int> = listOf(0, CIVILIAN_GRID_METERS, NEIGHBOURHOOD_GRID_METERS, TOWN_GRID_METERS)

    val gridChoiceLabels: List<String> = listOf(
        "Exact fix",
        "250 m grid (street)",
        "1 km grid (neighbourhood)",
        "5 km grid (town)"
    )

    fun analyse(fixes: List<LocationFix>, targetAccuracyMeters: Double = 10.0): LocationAnalysis =
        LocationAnalyzer.analyse(fixes, targetAccuracyMeters)

    /** Device checklist. Unknown is a first-class answer, not an assumed "ok". */
    fun deviceChecklist(context: DeviceLocationContext): List<SafetyFact> {
        val facts = mutableListOf<SafetyFact>()

        facts += SafetyFact(
            id = "permission",
            label = "Location permission",
            state = when (context.permission) {
                LocationPermission.GRANTED -> FactState.OK
                LocationPermission.NOT_DETERMINED -> FactState.WARN
                LocationPermission.DENIED, LocationPermission.DENIED_PERMANENTLY -> FactState.BAD
            },
            detail = when (context.permission) {
                LocationPermission.GRANTED -> "Granted for AdShield Pro. You can revoke it at any time in system settings."
                LocationPermission.NOT_DETERMINED -> "Not asked yet. The next Locate request will show the system dialog."
                LocationPermission.DENIED -> "Denied. Android will not show the dialog again from this screen — open App info to allow it."
                LocationPermission.DENIED_PERMANENTLY -> "Denied permanently. Only system settings can change this; the app cannot override it."
            },
            setting = if (context.permission == LocationPermission.GRANTED) null else DeviceSettingTarget.APP_LOCATION_PERMISSIONS
        )

        facts += SafetyFact(
            id = "system-location",
            label = "Device location switch",
            state = when (context.systemLocationEnabled) {
                true -> FactState.OK
                false -> FactState.BAD
                null -> FactState.UNKNOWN
            },
            detail = when (context.systemLocationEnabled) {
                true -> "Location is on at the system level."
                false -> "Location is switched off. No API can return a real fix until it is on."
                null -> "This Android version did not report the switch state."
            },
            setting = if (context.systemLocationEnabled == false) DeviceSettingTarget.LOCATION_SOURCE else null
        )

        facts += SafetyFact(
            id = "precise",
            label = "Precise location",
            state = when (context.precisePermissionGranted) {
                true -> FactState.OK
                false -> FactState.BAD
                null -> FactState.UNKNOWN
            },
            detail = when (context.precisePermissionGranted) {
                true -> "Approximate-only was not chosen, so GNSS is available."
                false -> "Approximate location only. Android downgrades every fix to a coarse radius — enable precise location for a usable pin."
                null -> "Not reported (pre-Android 12, where precise location was always granted)."
            }
        )

        facts += SafetyFact(
            id = "wifi-scan",
            label = "Wi-Fi scanning for location",
            state = when (context.wifiScanningEnabled) {
                true -> FactState.OK
                false -> FactState.WARN
                null -> FactState.UNKNOWN
            },
            detail = when (context.wifiScanningEnabled) {
                true -> "Wi-Fi scanning helps indoors, where satellites are weak."
                false -> "Off. Indoors the fix may stay coarse until you are outdoors."
                null -> "This Android version did not report the scanning setting."
            },
            setting = if (context.wifiScanningEnabled == false) DeviceSettingTarget.LOCATION_SCAN else null
        )

        facts += SafetyFact(
            id = "mock-provider",
            label = "Simulated location",
            state = when (context.mockProvidersEnabled) {
                true -> FactState.BAD
                false -> FactState.OK
                null -> FactState.UNKNOWN
            },
            detail = when (context.mockProvidersEnabled) {
                true -> "A mock-location provider is enabled. Fixes are flagged as simulated and cannot be trusted for an emergency."
                false -> "No mock-location provider is enabled."
                null -> "Android does not expose this without developer options being on."
            },
            setting = if (context.mockProvidersEnabled == true) DeviceSettingTarget.DEVELOPER_OPTIONS else null
        )

        facts += SafetyFact(
            id = "secure-network",
            label = "Encrypted connection",
            state = when (context.encryptedNetworkAvailable) {
                true -> FactState.OK
                false -> FactState.WARN
                null -> FactState.UNKNOWN
            },
            detail = when (context.encryptedNetworkAvailable) {
                true -> "The fix is computed on the device; the network is only used for map links you open."
                false -> "No encrypted network right now: a map link would open over plain HTTP on a network your provider can read. The pin itself is still local."
                null -> "Network state was not reported."
            }
        )

        facts += SafetyFact(
            id = "screen-lock",
            label = "Screen lock",
            state = if (context.screenLockKnown) FactState.OK else FactState.UNKNOWN,
            detail = if (context.screenLockKnown) {
                "The device reports a secure lock screen."
            } else {
                "Android does not expose lock-screen state to this app. Check it yourself: a shared pin on an " +
                    "unlocked, lost phone is the real risk, not the pin."
            }
        )

        return facts
    }

    /** Plain-language precision, so the share button is never a surprise. */
    fun describePrecision(analysis: LocationAnalysis, rounded: RoundedFix? = null): String {
        if (!analysis.hasFix) return "No fix — nothing to share yet."
        if (!analysis.consistent) return "Not shareable: the fixes contradict each other."
        val meters = rounded?.gridMeters?.toDouble() ?: analysis.bestAccuracyMeters ?: return "No fix."
        return when {
            meters <= 15 -> "Very precise — about ${LocationAnalyzer.formatMeters(meters)}. " +
                "This identifies a building entrance: fine for a friend meeting you, risky for a public post."
            meters <= 60 -> "Street level — about ${LocationAnalyzer.formatMeters(meters)}. " +
                "Enough to find the street or the block, not the door."
            meters <= 300 -> "Neighbourhood — about ${LocationAnalyzer.formatMeters(meters)}. " +
                "Useful for a rider or a responder; not precise enough to point at one house."
            else -> "Coarse — about ${LocationAnalyzer.formatMeters(meters)}. " +
                "This is network positioning: it names the town, not where you are standing."
        }
    }

    /** Why an exact pin must not be shared as-is, in the modes that matter. */
    fun shareWarnings(analysis: LocationAnalysis, radiusMeters: Double): List<String> {
        val warnings = mutableListOf<String>()
        if (!analysis.consistent) {
            warnings += "The fixes contradict each other, so the pin is withheld."
        }
        if (analysis.anyMocked) {
            warnings += "Android flagged this fix as simulated (mock location). Do not send it as an emergency pin."
        }
        if (analysis.implausibleMovement) {
            warnings += "Movement between fixes is not physically plausible; the pin is unverified."
        }
        if (radiusMeters > 500) {
            warnings += "The pin is a town-level estimate — say which landmark you are near as well."
        }
        if (radiusMeters <= 25) {
            warnings += "This pin identifies a doorway. For anyone you do not fully know, use a 250 m grid or a landmark."
        }
        return warnings
    }

    /**
     * Builds the share plan. Nothing here touches the network: the text and the SMS URI are the
     * only outputs, and the user sends them from their own messaging app.
     *
     * @param radiusMeters worst-case radius that must be disclosed with the pin
     */
    fun buildSharePlan(
        analysis: LocationAnalysis,
        mode: ShareMode = ShareMode.EVERYDAY,
        gridMeters: Int = 0,
        radiusMeters: Double? = null,
        nowWallClockMs: Long = System.currentTimeMillis(),
        timeZoneLabel: String = "local time",
        mapUrl: String? = null,
        note: String? = null,
        emergencyNumber: String = "911"
    ): SharePlan {
        val best = analysis.best
        if (best == null) {
            return blockedPlan(
                mode, analysis, radiusMeters ?: 0.0,
                "No usable fix yet — press Locate first."
            )
        }
        if (!analysis.consistent) {
            val reason = if (mode == ShareMode.EMERGENCY) {
                "Refusing to send an emergency pin the device contradicts itself about."
            } else {
                "The fixes disagree, so no pin is produced. Move to open sky and locate again."
            }
            return blockedPlan(mode, analysis, best.accuracyMeters, reason)
        }
        val chosen = if (gridMeters > 0) LocationAnalyzer.round(best, gridMeters) else null
        val point = chosen?.point ?: best.point
        // The disclosed radius must cover the rounding, not just the GPS figure.
        val disclosed = maxOf(best.accuracyMeters, radiusMeters ?: 0.0, chosen?.worstCaseMeters ?: 0.0)
        val text = when (mode) {
            ShareMode.EVERYDAY -> everydayMessage(
                point, disclosed, nowWallClockMs, timeZoneLabel, mapUrl, note, chosen
            )
            ShareMode.EMERGENCY -> emergencyMessage(
                point, disclosed, nowWallClockMs, timeZoneLabel, mapUrl, note, emergencyNumber, chosen
            )
        }
        return SharePlan(
            mode = mode,
            point = point,
            rounded = chosen,
            worstCaseMeters = disclosed,
            text = text,
            smsUri = smsUri(text),
            blocked = false,
            blockReason = null,
            warnings = shareWarnings(analysis, disclosed)
        )
    }

    private fun blockedPlan(
        mode: ShareMode,
        analysis: LocationAnalysis,
        radiusMeters: Double,
        reason: String
    ): SharePlan = SharePlan(
        mode = mode,
        point = GeoPoint(Double.NaN, Double.NaN),
        rounded = null,
        worstCaseMeters = radiusMeters,
        text = "",
        smsUri = "",
        blocked = true,
        blockReason = reason,
        warnings = shareWarnings(analysis, radiusMeters)
    )

    fun everydayMessage(
        point: GeoPoint,
        radiusMeters: Double,
        wallClockMs: Long,
        timeZoneLabel: String,
        mapUrl: String?,
        note: String?,
        rounded: RoundedFix? = null
    ): String = buildString {
        append("My location: ")
        append(LocationAnalyzer.formatCoordinates(point.latitude, point.longitude))
        append(" (±")
        append(LocationAnalyzer.formatMeters(radiusMeters))
        append(")\n")
        if (rounded != null) {
            append("Rounded to a ")
            append(rounded.gridMeters)
            append(" m grid before sending — the exact fix stayed on my phone.\n")
        }
        append("Sent ")
        append(formatTime(wallClockMs))
        append(" ")
        append(timeZoneLabel)
        if (mapUrl != null) {
            append("\n")
            append(mapUrl)
        }
        if (!note.isNullOrBlank()) {
            append("\n")
            append(note.trim())
        }
        append("\nThis is a fixed pin, not live tracking: it does not update after I send it.")
    }

    fun emergencyMessage(
        point: GeoPoint,
        radiusMeters: Double,
        wallClockMs: Long,
        timeZoneLabel: String,
        mapUrl: String?,
        note: String?,
        emergencyNumber: String,
        rounded: RoundedFix? = null
    ): String = buildString {
        append("EMERGENCY — my location is ")
        append(LocationAnalyzer.formatCoordinates(point.latitude, point.longitude))
        append(", accurate to about ")
        append(LocationAnalyzer.formatMeters(radiusMeters))
        append(", as of ")
        append(formatTime(wallClockMs))
        append(" ")
        append(timeZoneLabel)
        append(".\n")
        if (rounded != null) {
            append("The pin is rounded to a ")
            append(rounded.gridMeters)
            append(" m grid; search that area, not one house.\n")
        }
        if (mapUrl != null) {
            append(mapUrl)
            append("\n")
        }
        if (!note.isNullOrBlank()) {
            append(note.trim())
            append("\n")
        }
        append("This pin does not update. If I stop replying, search from these coordinates. ")
        append("I am calling ")
        append(emergencyNumber)
        append(" — if this message reached you and I cannot call, please call it for me.")
    }

    /** The intent URI only *starts* a message: the user still presses send. */
    fun smsUri(body: String): String = "sms:?body=" + percentEncode(body)

    /** Coordinates plus a name, for whatever map app the receiver has installed. */
    fun geoUri(point: GeoPoint, label: String = "My location"): String =
        "geo:" + String.format(Locale.US, "%.6f,%.6f", point.latitude, point.longitude) +
            "?q=" + String.format(Locale.US, "%.6f,%.6f", point.latitude, point.longitude) +
            "(" + percentEncode(label) + ")"

    fun openStreetMapUrl(point: GeoPoint): String {
        val lat = String.format(Locale.US, "%.6f", point.latitude)
        val lon = String.format(Locale.US, "%.6f", point.longitude)
        return "https://www.openstreetmap.org/?mlat=$lat&mlon=$lon#map=18/$lat/$lon"
    }

    fun formatTime(wallClockMs: Long, timeZone: java.util.TimeZone = java.util.TimeZone.getDefault()): String {
        val format = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
        format.timeZone = timeZone
        return format.format(java.util.Date(wallClockMs))
    }

    fun timeZoneLabel(timeZone: java.util.TimeZone = java.util.TimeZone.getDefault()): String =
        timeZone.getDisplayName(timeZone.inDaylightTime(java.util.Date()), java.util.TimeZone.SHORT)

    /** Minimal RFC 3986 encoding for the handful of characters an SMS body can contain. */
    fun percentEncode(value: String): String = buildString {
        for (byte in value.toByteArray(Charsets.UTF_8)) {
            val char = byte.toInt().toChar()
            if (char.isLetterOrDigit() && byte.toInt() in 0..127) append(char)
            else when (char) {
                '-', '_', '.', '~' -> append(char)
                else -> append('%').append(String.format(Locale.US, "%02X", byte.toInt() and 0xFF))
            }
        }
    }

    /** How many metres the disclosed radius covers, for the UI copy. */
    fun radiusLabel(meters: Double?): String {
        if (meters == null || !meters.isFinite()) return "radius unknown"
        val area = Math.PI * meters * meters
        val roundedArea = area.roundToInt()
        return "about ${LocationAnalyzer.formatMeters(meters)} radius (≈ ${String.format(Locale.US, "%,d", roundedArea)} m² searched)"
    }
}
