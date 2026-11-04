package com.adshield.pro.engine.platform

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.os.PowerManager
import android.os.StatFs
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Builds the exportable diagnostic report.
 *
 * This row was PLANNED because a report must not leak identifiers. The rule here: the report
 * contains **no DNS history, no app names, no user rules and no file paths** — only aggregate
 * counters, configuration choices and environment facts the user can already see on screen.
 * Every field is produced by a pure function so the JVM suite can assert both the content and
 * the absence of identifiers.
 *
 * Rendering is plain text/JSON built by hand: no JSON library is added for one report, and the
 * escaping is unit-tested.
 */
object DiagnosticReport {

    /** Identity of the build, as published. */
    data class BuildInfo(
        val versionName: String,
        val versionCode: Int,
        val applicationId: String
    )

    /** Coarse environment facts. Deliberately no serial, IMEI, MAC, SSID or account. */
    data class Environment(
        val sdkInt: Int,
        val manufacturer: String,
        val model: String,
        val isLowRamDevice: Boolean,
        val totalRamBytes: Long,
        val availableStorageBytes: Long,
        val thermalStatus: Int,
        val powerSaveMode: Boolean
    )

    /** Counters only — nothing that identifies a domain, app or person. */
    data class Counters(
        val protectionActive: Boolean,
        val protectionMode: String,
        val totalRules: Int,
        val blockRules: Int,
        val allowRules: Int,
        val userRules: Int,
        val lookupsToday: Long,
        val blockedToday: Long,
        val errorsToday: Long,
        val upstreamTransport: String,
        val resolversConfigured: Int,
        val lastFeedSyncAgeHours: Long?,
        val lastErrorCategory: String?
    )

    data class Report(
        val generatedAt: String,
        val formatVersion: Int,
        val build: BuildInfo,
        val environment: Environment,
        val counters: Counters,
        val notes: List<String>
    )

    const val FORMAT_VERSION = 1

    /**
     * Values that would be redacted if they ever appeared. Exposed so the tests can assert the
     * redactor itself rather than trusting the field list.
     */
    private val REDACTIONS = listOf(
        Regex("""[\w.+-]+@[\w-]+\.[\w.]+"""),                       // email
        Regex("""\b(?:\d{1,3}\.){3}\d{1,3}\b"""),                    // IPv4
        Regex("""\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"""),       // MAC
        Regex("""\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b""")  // IPv6
    )

    /** Defensive redaction applied to every string field, including device model. */
    fun redact(value: String): String =
        REDACTIONS.fold(value) { acc, pattern -> pattern.replace(acc, "[redacted]") }

    fun build(
        clockMillis: Long,
        build: BuildInfo,
        environment: Environment,
        counters: Counters
    ): Report = Report(
        generatedAt = formatTimestamp(clockMillis),
        formatVersion = FORMAT_VERSION,
        build = build.copy(
            versionName = redact(build.versionName),
            applicationId = redact(build.applicationId)
        ),
        environment = environment.copy(
            manufacturer = redact(environment.manufacturer),
            model = redact(environment.model)
        ),
        counters = counters.copy(
            protectionMode = redact(counters.protectionMode),
            upstreamTransport = redact(counters.upstreamTransport),
            lastErrorCategory = counters.lastErrorCategory?.let(::redact)
        ),
        notes = defaultNotes(counters)
    )

    /** Timestamp in ISO-8601 UTC — stable for tests and diffable. */
    fun formatTimestamp(clockMillis: Long): String =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
            timeZone = java.util.TimeZone.getTimeZone("UTC")
        }.format(Date(clockMillis))

    /**
     * States the limits of the report *inside* the report, so a reader cannot mistake what it
     * does not contain for something that was verified.
     */
    private fun defaultNotes(counters: Counters): List<String> = buildList {
        add("Aggregate counters only: this report contains no DNS history, no domain names, no app names and no file paths.")
        add("A DNS filter cannot observe content, certificates or the behaviour of other applications; nothing here is an antivirus verdict.")
        add("Values were read at generation time and are not a continuous monitor.")
        if (counters.lastErrorCategory == null) add("No error category was recorded for today.")
        if (counters.lastFeedSyncAgeHours == null) add("No remote list sync has run in this installation.")
    }

    /** Platform-neutral JSON with deterministic key order. */
    fun toJson(report: Report): String = buildString {
        append("{\n")
        append("  \"formatVersion\": ").append(report.formatVersion).append(",\n")
        append("  \"generatedAt\": ").append(quote(report.generatedAt)).append(",\n")
        append("  \"build\": {\n")
        append("    \"versionName\": ").append(quote(report.build.versionName)).append(",\n")
        append("    \"versionCode\": ").append(report.build.versionCode).append(",\n")
        append("    \"applicationId\": ").append(quote(report.build.applicationId)).append("\n")
        append("  },\n")
        append("  \"environment\": {\n")
        append("    \"sdkInt\": ").append(report.environment.sdkInt).append(",\n")
        append("    \"manufacturer\": ").append(quote(report.environment.manufacturer)).append(",\n")
        append("    \"model\": ").append(quote(report.environment.model)).append(",\n")
        append("    \"isLowRamDevice\": ").append(report.environment.isLowRamDevice).append(",\n")
        append("    \"totalRamBytes\": ").append(report.environment.totalRamBytes).append(",\n")
        append("    \"availableStorageBytes\": ").append(report.environment.availableStorageBytes).append(",\n")
        append("    \"thermalStatus\": ").append(report.environment.thermalStatus).append(",\n")
        append("    \"powerSaveMode\": ").append(report.environment.powerSaveMode).append("\n")
        append("  },\n")
        append("  \"counters\": {\n")
        append("    \"protectionActive\": ").append(report.counters.protectionActive).append(",\n")
        append("    \"protectionMode\": ").append(quote(report.counters.protectionMode)).append(",\n")
        append("    \"totalRules\": ").append(report.counters.totalRules).append(",\n")
        append("    \"blockRules\": ").append(report.counters.blockRules).append(",\n")
        append("    \"allowRules\": ").append(report.counters.allowRules).append(",\n")
        append("    \"userRules\": ").append(report.counters.userRules).append(",\n")
        append("    \"lookupsToday\": ").append(report.counters.lookupsToday).append(",\n")
        append("    \"blockedToday\": ").append(report.counters.blockedToday).append(",\n")
        append("    \"errorsToday\": ").append(report.counters.errorsToday).append(",\n")
        append("    \"upstreamTransport\": ").append(quote(report.counters.upstreamTransport)).append(",\n")
        append("    \"resolversConfigured\": ").append(report.counters.resolversConfigured).append(",\n")
        append("    \"lastFeedSyncAgeHours\": ").append(report.counters.lastFeedSyncAgeHours?.toString() ?: "null").append(",\n")
        append("    \"lastErrorCategory\": ").append(report.counters.lastErrorCategory?.let(::quote) ?: "null").append("\n")
        append("  },\n")
        append("  \"notes\": [\n")
        report.notes.forEachIndexed { index, note ->
            append("    ").append(quote(note))
            if (index != report.notes.lastIndex) append(",")
            append("\n")
        }
        append("  ]\n")
        append("}\n")
    }

    /** JSON string escaping — control characters, quotes and backslashes. */
    fun quote(value: String): String = buildString {
        append('"')
        for (char in value) {
            when (char) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (char < ' ') append(String.format(Locale.US, "\\u%04x", char.code)) else append(char)
            }
        }
        append('"')
    }

    /**
     * Reads the environment. Every value comes from a documented API; anything the device does
     * not report is left at a stated default rather than guessed.
     */
    fun environmentOf(context: Context): Environment {
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        val powerManager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
        val stat = runCatching { StatFs(context.filesDir.absolutePath) }.getOrNull()
        val thermal = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            runCatching { powerManager?.currentThermalStatus ?: -1 }.getOrDefault(-1)
        } else {
            -1
        }
        return Environment(
            sdkInt = Build.VERSION.SDK_INT,
            manufacturer = Build.MANUFACTURER ?: "unknown",
            model = Build.MODEL ?: "unknown",
            isLowRamDevice = activityManager?.isLowRamDevice == true,
            totalRamBytes = activityManager?.let(::totalRamOf) ?: 0L,
            availableStorageBytes = stat?.let { it.availableBytes } ?: 0L,
            thermalStatus = thermal,
            powerSaveMode = powerManager?.isPowerSaveMode == true
        )
    }

    private fun totalRamOf(manager: ActivityManager): Long {
        val info = ActivityManager.MemoryInfo()
        return runCatching {
            manager.getMemoryInfo(info)
            info.totalMem
        }.getOrDefault(0L)
    }

    /** Writes the report to app-private storage and returns the file, or the failure reason. */
    fun writeTo(context: Context, report: Report): Result<File> = runCatching {
        val directory = File(context.filesDir, "diagnostics").apply { mkdirs() }
        val stamp = report.generatedAt.replace(":", "-")
        val file = File(directory, "adshield-diagnostics-$stamp.json")
        file.writeText(toJson(report))
        file
    }
}
