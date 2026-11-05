package com.adshield.pro.cybershield

/**
 * Parsers for REAL external data sources. Pure Kotlin + JsonLite so they are
 * fully unit-testable on the JVM. Both parsers are tolerant of missing/null
 * fields but never invent values: unknown fields stay null.
 */

/**
 * Feodo Tracker (abuse.ch) botnet C2 blocklist.
 * Feed: https://feodotracker.abuse.ch/downloads/ipblocklist.json
 * License: CC0. Fields: ip_address, port, status, hostname, as_number, as_name,
 * country (ISO 3166-1 alpha-2), first_seen_utc, last_online, malware.
 * Locations are country-level hosting locations of C2 infrastructure —
 * they are NOT attacks observed against this device.
 */
object FeodoParser {
    const val FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    const val FEED_NAME = "Feodo Tracker C2 (abuse.ch)"
    const val LICENSE = "CC0 1.0"
    const val MAX_INDICATORS = 20_000

    fun parse(jsonText: String, fetchedAtEpochMs: Long): IntelSnapshot {
        val root = JsonLite.parse(jsonText)
        val items = root.asListOrNull() ?: throw JsonParseException("Feodo feed: expected JSON array")
        val seen = HashSet<String>()
        val indicators = ArrayList<IntelIndicator>(minOf(items.size, MAX_INDICATORS))
        for (item in items) {
            if (indicators.size >= MAX_INDICATORS) break
            val obj = item as? JValue.JObj ?: continue
            val ip = obj.str("ip_address")?.trim() ?: continue
            if (!isValidIpv4(ip)) continue
            val port = obj.int("port") ?: 0
            val key = "$ip:$port"
            if (!seen.add(key)) continue
            val country = obj.str("country")?.trim()?.uppercase()?.takeIf { it.length == 2 && it.all { c -> c in 'A'..'Z' } }
            indicators.add(
                IntelIndicator(
                    ip = ip,
                    port = port,
                    status = obj.str("status")?.trim()?.lowercase() ?: "unknown",
                    countryCode = country,
                    asName = obj.str("as_name")?.trim()?.takeIf { it.isNotEmpty() },
                    asNumber = obj.int("as_number"),
                    malware = obj.str("malware")?.trim()?.takeIf { it.isNotEmpty() },
                    firstSeenUtc = (obj.str("first_seen_utc") ?: obj.str("first_seen"))?.takeIf { it.isNotBlank() },
                    lastOnline = obj.str("last_online")?.takeIf { it.isNotBlank() && it != "null" }
                )
            )
        }
        if (indicators.isEmpty()) throw JsonParseException("Feodo feed: no valid indicators")
        return IntelSnapshot(
            indicators = indicators,
            fetchedAtEpochMs = fetchedAtEpochMs,
            feedName = FEED_NAME,
            feedUrl = FEED_URL,
            license = LICENSE
        )
    }

    fun isValidIpv4(ip: String): Boolean {
        val parts = ip.split('.')
        if (parts.size != 4) return false
        for (p in parts) {
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return false
            val n = p.toIntOrNull() ?: return false
            if (n !in 0..255) return false
            if (p.length > 1 && p[0] == '0') return false
        }
        return true
    }
}

/**
 * Atlassian Statuspage v2 summary API used by GitHub, Cloudflare, DigitalOcean
 * and many other providers: GET {status-host}/api/v2/status.json
 * { "page": {...,"updated_at":...}, "status": {"indicator": "...", "description": "..."} }
 * This is provider PLATFORM status — not the security posture of the user's
 * own cloud tenant, which requires provider-specific authenticated APIs.
 */
object StatuspageParser {
    fun parseIndicator(raw: String?): CloudIndicator = when (raw?.trim()?.lowercase()) {
        "none" -> CloudIndicator.OPERATIONAL
        "minor" -> CloudIndicator.DEGRADED
        "major" -> CloudIndicator.PARTIAL_OUTAGE
        "critical" -> CloudIndicator.MAJOR_OUTAGE
        "maintenance" -> CloudIndicator.MAINTENANCE
        else -> CloudIndicator.UNKNOWN
    }

    fun parseInto(
        base: CloudProviderStatus,
        jsonText: String,
        fetchedAtEpochMs: Long
    ): CloudProviderStatus {
        val root = JsonLite.parse(jsonText)
        val status = root.obj("status") ?: throw JsonParseException("Statuspage: missing 'status' object")
        val indicator = status.str("indicator")
        val description = status.str("description") ?: ""
        val updatedAt = root.obj("page")?.str("updated_at")
        return base.copy(
            indicator = parseIndicator(indicator),
            description = description,
            providerUpdatedAt = updatedAt,
            fetchedAtEpochMs = fetchedAtEpochMs,
            loadState = CsLoadState.LIVE,
            error = null
        )
    }
}

/** Serialization of compliance reports for export (hand-rolled, deterministic). */
object ComplianceReportJson {
    fun render(report: ComplianceReport): String {
        val sb = StringBuilder()
        sb.append("{\n")
        sb.append("  \"report\": \"CyberShield AI device security report\",\n")
        sb.append("  \"generated_at_epoch_ms\": ").append(report.generatedAtEpochMs).append(",\n")
        sb.append("  \"device\": ").append(jsonString(report.deviceModel)).append(",\n")
        sb.append("  \"android_version\": ").append(jsonString(report.androidVersion)).append(",\n")
        sb.append("  \"score\": ").append(report.score).append(",\n")
        sb.append("  \"passed\": ").append(report.passed).append(",\n")
        sb.append("  \"warnings\": ").append(report.warnings).append(",\n")
        sb.append("  \"failed\": ").append(report.failed).append(",\n")
        sb.append("  \"unavailable\": ").append(report.unavailable).append(",\n")
        sb.append("  \"disclaimer\": \"Local configuration checks mapped to public best practices; not a formal certification.\",\n")
        sb.append("  \"checks\": [\n")
        report.checks.forEachIndexed { i, c ->
            sb.append("    {\"id\": ").append(jsonString(c.id))
            sb.append(", \"title\": ").append(jsonString(c.title))
            sb.append(", \"framework\": ").append(jsonString(c.framework))
            sb.append(", \"status\": ").append(jsonString(c.status.name))
            sb.append(", \"detail\": ").append(jsonString(c.detail))
            sb.append(", \"recommendation\": ").append(c.recommendation?.let { jsonString(it) } ?: "null")
            sb.append("}")
            if (i < report.checks.size - 1) sb.append(",")
            sb.append("\n")
        }
        sb.append("  ]\n}\n")
        return sb.toString()
    }

    fun jsonString(s: String): String {
        val sb = StringBuilder("\"")
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c < ' ' -> sb.append("\\u").append(String.format(java.util.Locale.US, "%04x", c.code))
                else -> sb.append(c)
            }
        }
        return sb.append('"').toString()
    }
}
