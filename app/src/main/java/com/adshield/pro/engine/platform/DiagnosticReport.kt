package com.adshield.pro.engine.platform

import kotlin.math.abs
import kotlin.math.roundToInt

/**
 * The exportable diagnostic report: what the app can honestly say about its own state, in a form
 * the user can hand to a support thread without leaking their activity.
 *
 * Two hard rules shape this file:
 *
 *  1. **Nothing identifying leaves the app.** The report is built from counts, enum labels,
 *     booleans and timestamps. It never contains a queried domain, an app package, a file name,
 *     a file path, an account identifier, a device model/serial or an IP address from the local
 *     network. Free-form strings (a filter list's custom name, a VPN runtime error) are passed
 *     through [DiagnosticScrubber] first, and [DiagnosticScrubber] is the only place text is
 *     trusted at all.
 *  2. **Absence of evidence is reported as absence of evidence.** Zero logged queries, zero scan
 *     records or an unavailable battery reading produce explicit "not measured" lines instead of
 *     zeros that read like a clean bill of health.
 *
 * Everything here is pure Kotlin so the rules above are unit-testable on the JVM without Android.
 */
object DiagnosticReport {

    /** Bumped whenever a reader (support scripts, docs) would need to parse the report differently. */
    const val FORMAT_VERSION: Int = 1

    /** Filter lists rendered individually; beyond this the report only prints a count. */
    private const val MAX_SOURCES = 12

    private const val RULE = "----------------------------------------------------"

    fun build(input: DiagnosticReportInput): String = buildString {
        appendLine("AdShield Pro — Diagnostic Report")
        appendLine("Format version: $FORMAT_VERSION")
        appendLine("App version: ${input.appVersion}")
        appendLine("Generated (epoch ms): ${input.generatedAtEpochMs}")
        appendLine("=".repeat(52))
        appendLine()
        appendLine("WHAT THIS FILE IS")
        appendLine("A local snapshot of AdShield Pro's own configuration, counters and recent state.")
        appendLine("It was generated on the device. Nothing here was uploaded anywhere.")
        appendLine()
        appendLine("WHAT IT DELIBERATELY EXCLUDES")
        appendLine("No domains or URLs that were visited, no matched block rules, no app package names,")
        appendLine("no file names or paths, no account or device identifiers, no Wi-Fi or cell details,")
        appendLine("no IP addresses from your network, and no raw log lines.")
        appendLine("Every value below is a count, a setting, an enum label or a timestamp.")
        appendLine()

        appendLine("ENVIRONMENT")
        appendLine(RULE)
        appendLine("Android API level: ${input.androidApiLevel}")
        appendLine("Protection mode: ${input.protectionMode}")
        appendLine("VPN tunnel status: ${input.vpnStatus}")
        appendLine("Resolver preset: ${input.resolverLabel}")
        appendLine("DNS protocol: ${input.dnsProtocol}")
        appendLine("DNSSEC mode: ${input.dnssecMode}")
        appendLine("Resolver failover enabled: ${yesNo(input.failoverEnabled)}")
        appendLine("Rules loaded into the tunnel: ${input.loadedRuleCount}")
        appendLine()

        appendLine("DNS ACTIVITY (LIFETIME, ON THIS INSTALL)")
        appendLine(RULE)
        if (input.totalQueries <= 0L) {
            appendLine("Queries logged: 0")
            appendLine("NO DNS QUERIES ARE LOGGED YET — the block counts below are not protection evidence.")
        } else {
            appendLine("Queries logged: ${input.totalQueries}")
            appendLine("Blocked: ${input.blockedQueries} (${rate(input.blockedQueries, input.totalQueries)})")
            appendLine("Malware-category blocks: ${input.malwareBlocks}")
            appendLine(
                "Note: counters only cover queries retained for ${input.logRetentionDays} day(s) " +
                    "in the local database; they are a lower bound, not a total."
            )
        }
        appendLine("Detailed per-query logging: ${if (input.detailedLoggingEnabled) "enabled" else "disabled"}")
        appendLine("Log retention setting: ${input.logRetentionDays} day(s)")
        appendLine()

        appendLine("FILTER LISTS")
        appendLine(RULE)
        val enabledSources = input.filterSources.filter { it.enabled }
        appendLine("Sources configured: ${input.filterSources.size} · enabled: ${enabledSources.size}")
        appendLine("Custom rules: ${input.customRuleCount}")
        appendLine("Last filter update (epoch ms): ${input.lastFilterUpdateEpochMs}")
        if (enabledSources.isEmpty()) {
            appendLine("No filter list is enabled, so only custom rules and the app firewall apply.")
        } else {
            val rendered = enabledSources
                .sortedWith(
                    compareByDescending<DiagnosticFilterSource> { it.ruleCount }
                        .thenBy { it.name }
                )
                .take(MAX_SOURCES)
            rendered.forEach { source ->
                val name = DiagnosticScrubber.redactFreeText(source.name)
                appendLine("  - $name: ${source.ruleCount} rule(s)${statusSuffix(source.statusMessage)}")
            }
            val hidden = enabledSources.size - rendered.size
            if (hidden > 0) appendLine("  (+$hidden more enabled source(s) not listed)")
        }
        appendLine()

        appendLine("SECURITY SCANS")
        appendLine(RULE)
        val scans = input.scans
        if (scans.total <= 0) {
            appendLine("NO SCAN HAS BEEN PERFORMED YET.")
            appendLine("This report cannot show scan findings because there are none to show.")
        } else {
            appendLine("Records retained: ${scans.total}")
            appendLine("Clean: ${scans.clean} · Suspicious: ${scans.suspicious} · Dangerous: ${scans.dangerous}")
            appendLine("Last scan (epoch ms): ${scans.lastScanEpochMs ?: 0L}")
        }
        appendLine("Quarantined items in app-private storage: ${input.quarantinedCount}")
        appendLine("Quarantined items whose original was removed: ${input.quarantinedOriginalsRemoved}")
        appendLine()

        appendLine("CONFIGURATION SUMMARY")
        appendLine(RULE)
        appendLine("Excluded apps: ${input.excludedAppCount}")
        appendLine("Browser site exceptions: ${input.siteExceptionCount}")
        appendLine(
            "Scheduled scan: " +
                if (input.scheduledScanEnabled) "enabled every ${input.scheduledScanIntervalHours} hour(s)"
                else "disabled"
        )
        appendLine()

        appendLine("BATTERY (as read at generation time)")
        appendLine(RULE)
        val battery = input.battery
        if (battery == null) {
            appendLine("Battery telemetry was not available when this report was generated.")
        } else {
            appendLine("Level: ${battery.levelPercent?.let { "$it%" } ?: "not reported by this device"}")
            appendLine("Health: ${battery.healthLabel}")
            appendLine(
                "Temperature: " +
                    (battery.temperatureCelsius?.let { "${oneDecimal(it)} °C" } ?: "not reported by this device")
            )
            appendLine("Charging: ${yesNo(battery.isCharging)}")
        }
        appendLine()

        appendLine("LAST RECORDED ERROR")
        appendLine(RULE)
        val lastError = input.lastError?.let { DiagnosticScrubber.redactFreeText(it) }
        if (lastError.isNullOrBlank()) {
            appendLine("None recorded. Passing no error text is not proof that nothing failed.")
        } else {
            appendLine(lastError)
            appendLine("(Free-text errors are redacted: addresses, hosts, paths and tokens are removed.)")
        }
        appendLine()

        appendLine("DETERMINISTIC CHECKS")
        appendLine(RULE)
        suggestions(input).forEach { appendLine("  - $it") }
        appendLine()

        appendLine("LIMITS OF THIS REPORT")
        appendLine(RULE)
        appendLine("• It is not a security audit and not a statement that the device is clean.")
        appendLine("• It contains no evidence about websites, so it cannot be used to reconstruct browsing.")
        appendLine("• Counts come from a pruned local database and are lower bounds.")
        appendLine("• It describes Android-side behaviour only; nothing here proves any third-party app is safe.")
        appendLine("AdShield Pro — end of diagnostic report")
    }

    /**
     * Advisory lines derived only from the values in [input].
     *
     * Deliberately conservative: a check that cannot be answered from the report's own data is
     * not invented, and the empty case says the checks are limited rather than "all clear".
     */
    fun suggestions(input: DiagnosticReportInput): List<String> = buildList {
        if (!input.vpnStatus.equals("CONNECTED", ignoreCase = true)) {
            add("The tunnel is ${input.vpnStatus.lowercase()}: no DNS filtering is active while it is off.")
        }
        if (input.totalQueries <= 0L) {
            add("No DNS queries are logged, so no block counter in this report can be treated as evidence.")
        }
        if (input.filterSources.none { it.enabled }) {
            add("No filter list is enabled; only custom rules and the app firewall can block anything.")
        }
        if (!input.detailedLoggingEnabled) {
            add("Detailed DNS logging is disabled, so lifetime query totals in this report are partial.")
        }
        if (input.logRetentionDays <= 0) {
            add("Log retention is 0 days, so the activity section will always read as empty.")
        }
        if (input.scans.total <= 0) {
            add("No security scan has run yet; run one before treating the scan section as informative.")
        }
        if (input.quarantinedCount > 0) {
            add(
                "${input.quarantinedCount} quarantined item(s) still occupy app-private storage; " +
                    "review or delete them from the Security screen."
            )
        }
        if (input.scheduledScanEnabled && input.scheduledScanIntervalHours <= 0) {
            add("Scheduled scanning is enabled with an invalid interval; re-save it in Settings.")
        }
        if (!input.lastError.isNullOrBlank()) {
            add("The VPN reported a runtime error; it is recorded (redacted) above.")
        }
        val level = input.battery?.levelPercent
        if (level != null && level < 20) {
            add("Battery is at $level%; Android may defer scheduled work until the device is charging.")
        }
        if (isEmpty()) {
            add("None of the checks in this report found a problem. That is not a security audit.")
        }
    }

    private fun yesNo(value: Boolean): String = if (value) "yes" else "no"

    private fun statusSuffix(statusMessage: String): String {
        val cleaned = DiagnosticScrubber.redactFreeText(statusMessage)
        return if (cleaned.isBlank() || cleaned.equals("Bundled / Ready", ignoreCase = true)) "" else " · $cleaned"
    }

    /** Block ratio with one decimal, computed without locale-dependent formatting. */
    private fun rate(part: Long, whole: Long): String {
        if (whole <= 0L) return "n/a"
        val boundedPart = part.coerceIn(0L, whole)
        val tenths = (boundedPart * 1000L) / whole
        return "${tenths / 10}.${tenths % 10}%"
    }

    /** One decimal place, locale-independent (a comma decimal separator would break readers). */
    private fun oneDecimal(value: Float): String {
        val scaled = (value * 10f).roundToInt()
        return "${scaled / 10}.${abs(scaled % 10)}"
    }
}

/**
 * Removes anything identifying from text that came from outside this file.
 *
 * The default ([redact]) is intentionally blunt — a URL keeps nothing, not even its host — because
 * a diagnostic report is never worth leaking a hostname for. [redactFreeText] adds host names and
 * length bounding for free-form strings such as runtime errors.
 */
object DiagnosticScrubber {

    const val PLACEHOLDER_URL = "[url removed]"
    const val PLACEHOLDER_PATH = "[path removed]"
    const val PLACEHOLDER_EMAIL = "[email removed]"
    const val PLACEHOLDER_PRIVATE_IP = "[private address removed]"
    const val PLACEHOLDER_TOKEN = "[token removed]"
    const val PLACEHOLDER_HOST = "[host removed]"

    /** Free text is capped so a stack trace cannot smuggle bulk data into the report. */
    private const val MAX_FREE_TEXT = 240

    private val EMAIL = Regex("(?i)\\b[\\w.+-]+@[a-z0-9-]+(?:\\.[a-z0-9-]+)+\\b")
    private val URL = Regex("(?i)\\b(?:https?|ftp)://\\S+")
    private val WINDOWS_PATH = Regex("(?i)\\b[a-z]:\\\\[^\\s\"']*")
    private val UNIX_PATH = Regex("(?:^|\\s)(/(?:[\\w.@+-]+/)+[\\w.@+-]+)")
    private val PRIVATE_IPV4 = Regex(
        "\\b(?:10\\.\\d{1,3}|192\\.168|172\\.(?:1[6-9]|2\\d|3[01]))\\.\\d{1,3}\\.\\d{1,3}\\b"
    )
    // 24+ chars covers hex digests, JWTs fragments and device ids while leaving normal words alone.
    private val LONG_TOKEN = Regex("[A-Za-z0-9_\\-]{24,}")
    private val HOSTNAME = Regex("(?i)\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24}\\b")

    fun redact(text: String): String {
        val withoutEmail = EMAIL.replace(text, PLACEHOLDER_EMAIL)
        val withoutUrls = URL.replace(withoutEmail, PLACEHOLDER_URL)
        val withoutWindowsPaths = WINDOWS_PATH.replace(withoutUrls, PLACEHOLDER_PATH)
        // The regex consumes the whitespace that precedes a path; put a single space back so two
        // words never fuse into a synthetic token that a later rule could mangle differently.
        val withoutUnixPaths = UNIX_PATH.replace(withoutWindowsPaths) { _ -> " $PLACEHOLDER_PATH" }
        val withoutPrivateIps = PRIVATE_IPV4.replace(withoutUnixPaths, PLACEHOLDER_PRIVATE_IP)
        val withoutTokens = LONG_TOKEN.replace(withoutPrivateIps, PLACEHOLDER_TOKEN)
        return HOSTNAME.replace(withoutTokens, PLACEHOLDER_HOST)
    }

    /**
     * Same redaction plus host names, whitespace collapsing and a hard length cap.
     *
     * Order matters: URLs must go before host names, otherwise the URL rule would leave a bare
     * host behind that the host rule then has to chase.
     */
    fun redactFreeText(text: String): String {
        val scrubbed = redact(text)
            .replace(Regex("\\s+"), " ")
            .trim()
        return if (scrubbed.length <= MAX_FREE_TEXT) scrubbed else scrubbed.take(MAX_FREE_TEXT - 1) + "…"
    }
}

/** One filter list reduced to what is safe and useful to share. */
data class DiagnosticFilterSource(
    val name: String,
    val enabled: Boolean,
    val ruleCount: Int,
    val statusMessage: String = ""
)

/** Aggregated scan-journal totals; deliberately carries no scan targets. */
data class DiagnosticScanTotals(
    val total: Int = 0,
    val clean: Int = 0,
    val suspicious: Int = 0,
    val dangerous: Int = 0,
    val lastScanEpochMs: Long? = null
)

/** Battery readings as of report generation; nulls mean the device did not report them. */
data class DiagnosticBattery(
    val levelPercent: Int?,
    val healthLabel: String,
    val temperatureCelsius: Float?,
    val isCharging: Boolean
)

/** Everything [DiagnosticReport.build] is allowed to print. */
data class DiagnosticReportInput(
    val generatedAtEpochMs: Long,
    val appVersion: String,
    val androidApiLevel: Int,
    val protectionMode: String,
    val vpnStatus: String,
    val resolverLabel: String,
    val dnsProtocol: String,
    val dnssecMode: String,
    val failoverEnabled: Boolean = false,
    val loadedRuleCount: Int = 0,
    val totalQueries: Long = 0L,
    val blockedQueries: Long = 0L,
    val malwareBlocks: Long = 0L,
    val detailedLoggingEnabled: Boolean = false,
    val logRetentionDays: Int = 0,
    val filterSources: List<DiagnosticFilterSource> = emptyList(),
    val customRuleCount: Int = 0,
    val lastFilterUpdateEpochMs: Long = 0L,
    val scans: DiagnosticScanTotals = DiagnosticScanTotals(),
    val quarantinedCount: Int = 0,
    val quarantinedOriginalsRemoved: Int = 0,
    val excludedAppCount: Int = 0,
    val siteExceptionCount: Int = 0,
    val scheduledScanEnabled: Boolean = false,
    val scheduledScanIntervalHours: Int = 0,
    val battery: DiagnosticBattery? = null,
    val lastError: String? = null
)
