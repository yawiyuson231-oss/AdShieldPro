package com.adshield.pro.engine.connectors

import com.adshield.pro.domain.connectors.ConnectorSpec
import com.adshield.pro.domain.connectors.FeedParseException
import com.adshield.pro.domain.connectors.IndicatorKind
import com.adshield.pro.domain.connectors.ParsedFeed
import com.adshield.pro.domain.connectors.ThreatIndicator
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

/**
 * Pure parsers for every HTTP connector. No Android, no network: a payload string in, validated
 * indicators out. That is what makes each feed individually testable on the JVM.
 *
 * Every parser validates the shape of the response and throws [FeedParseException] when the
 * provider answers with something else (captive portal HTML, an error page disguised as 200, ...).
 * A green status therefore always means "we understood a real response".
 */
object ConnectorParsers {

    /** Hard bound per sync so a hostile 40 MB response cannot exhaust memory. */
    const val MAX_INDICATORS_PER_FEED = 4_000

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    private val domainRegex = Regex("^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$")
    private val hashRegex = Regex("^[a-f0-9]{64}$")
    private val ipv4Regex = Regex("^(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$")
    private val cveRegex = Regex("^CVE-\\d{4}-\\d{4,7}$", RegexOption.IGNORE_CASE)
    private val CVE_REGEX = Regex("CVE-\\d{4}-\\d{4,7}", RegexOption.IGNORE_CASE)
    private val CIDR_REGEX = Regex("^(?:\\d{1,3}\\.){3}\\d{1,3}/\\d{1,2}$")
    private val JA3_REGEX = Regex("^[a-f0-9]{32}$")
    private val SHA1_REGEX = Regex("^[a-f0-9]{40}$")

    fun parse(parserId: String, spec: ConnectorSpec, payload: String, fetchedAt: Long): ParsedFeed {
        if (payload.isBlank()) throw FeedParseException("empty response body")
        val ttl = spec.cacheTtlMs
        val indicators = when (parserId) {
            "urlhaus-csv", "urlhaus-online-csv" -> parseUrlhausCsv(spec, payload, fetchedAt, ttl)
            "urlhaus-text", "openphish-text" -> parseUrlLines(spec, payload, fetchedAt, ttl)
            "feodo-csv" -> parseFeodoCsv(spec, payload, fetchedAt, ttl)
            "cisa-kev" -> parseKev(spec, payload, fetchedAt, ttl)
            "epss" -> parseEpss(spec, payload, fetchedAt, ttl)
            "nvd-cves" -> parseNvd(spec, payload, fetchedAt, ttl)
            "github-advisories" -> parseGithubAdvisories(spec, payload, fetchedAt, ttl)
            "misp-list" -> parseMispList(spec, payload, fetchedAt, ttl)
            "stevenblack-hosts", "phishing-domains", "adblock-domain-list" ->
                parseDomainLines(spec, payload, fetchedAt, ttl)
            "json-domain-array" -> parseJsonDomainArray(spec, payload, fetchedAt, ttl)
            "ipsum" -> parseIpsum(spec, payload, fetchedAt, ttl)
            "ip-list" -> parseIpList(spec, payload, fetchedAt, ttl)
            "sslbl-ja3" -> parseSslblJa3(spec, payload, fetchedAt, ttl)
            "sslbl-cert" -> parseSslblCert(spec, payload, fetchedAt, ttl)
            "exploitdb-csv" -> parseExploitDb(spec, payload, fetchedAt, ttl)
            "gdacs-api" -> parseGdacsApi(spec, payload, fetchedAt, ttl)
            "eonet" -> parseEonet(spec, payload, fetchedAt, ttl)
            "open-meteo-context" -> parseOpenMeteoContext(spec, payload, fetchedAt, ttl)
            "usgs-quakes" -> parseUsgs(spec, payload, fetchedAt, ttl)
            "gdacs-rss" -> parseGdacs(spec, payload, fetchedAt, ttl)
            "nws-alerts" -> parseNws(spec, payload, fetchedAt, ttl)
            "reliefweb-disasters" -> parseReliefWeb(spec, payload, fetchedAt, ttl)
            "seismicportal" -> parseSeismicPortal(spec, payload, fetchedAt, ttl)
            "ripe-bgp-state" -> parseRipe(spec, payload)
            "rdap-lookup" -> parseRdap(spec, payload)
            "ipify" -> parseIpify(spec, payload)
            else -> throw FeedParseException("no parser for $parserId")
        }
        val bounded = indicators
            .asSequence()
            .filter { it.value.isNotBlank() }
            .distinctBy { it.kind to it.value }
            .take(MAX_INDICATORS_PER_FEED)
            .toList()
        if (bounded.isEmpty()) throw FeedParseException("response contained no usable indicators")
        return ParsedFeed(bounded, bounded.size, "${bounded.size} indicator(s) parsed")
    }

    // ------------------------------------------------------------------ URLhaus

    private fun parseUrlhausCsv(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val out = mutableListOf<ThreatIndicator>()
        csvLines(payload).forEach { row ->
            if (row.size < 6) return@forEach
            val url = normalizeUrl(row[2]) ?: return@forEach
            val threat = sanitizeShort(row.getOrNull(5) ?: "", 48).ifBlank { "malware" }
            val tags = sanitizeShort(row.getOrNull(6) ?: "", 64)
            val label = if (tags.isBlank()) threat else "$threat · $tags"
            out += indicator(spec, IndicatorKind.URL, url, label, 85, fetchedAt, ttl)
            hostOf(url)?.let { out += indicator(spec, IndicatorKind.DOMAIN, it, label, 80, fetchedAt, ttl) }
        }
        return out
    }

    private fun parseUrlLines(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val out = mutableListOf<ThreatIndicator>()
        payload.lineSequence().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
            val url = normalizeUrl(trimmed) ?: return@forEach
            out += indicator(spec, IndicatorKind.URL, url, "reported phishing/malware URL", 80, fetchedAt, ttl)
            hostOf(url)?.let { out += indicator(spec, IndicatorKind.DOMAIN, it, "reported URL host", 75, fetchedAt, ttl) }
        }
        return out
    }

    // ------------------------------------------------------------------ Feodo Tracker

    private fun parseFeodoCsv(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val out = mutableListOf<ThreatIndicator>()
        csvLines(payload).forEach { row ->
            if (row.size < 2) return@forEach
            val ip = row[1].trim().lowercase(Locale.US)
            if (!ipv4Regex.matches(ip)) return@forEach
            val malware = sanitizeShort(row.getOrNull(5) ?: "", 48).ifBlank { "botnet C2" }
            out += indicator(spec, IndicatorKind.IP, ip, "botnet C2 · $malware", 88, fetchedAt, ttl)
        }
        return out
    }

    // ------------------------------------------------------------------ CISA KEV

    private fun parseKev(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val root = jsonObjectOf(payload)
        val vulnerabilities = root["vulnerabilities"]?.jsonArray
            ?: throw FeedParseException("KEV feed has no vulnerabilities array")
        if (vulnerabilities.isEmpty()) throw FeedParseException("KEV feed is empty")
        return vulnerabilities.mapNotNull { element ->
            val item = runCatching { element.jsonObject }.getOrNull() ?: return@mapNotNull null
            val cve = item.string("cveID")?.uppercase(Locale.US) ?: return@mapNotNull null
            if (!cveRegex.matches(cve)) return@mapNotNull null
            val vendor = item.string("vendorProject").orEmpty()
            val product = item.string("product").orEmpty()
            val name = sanitizeShort(item.string("vulnerabilityName").orEmpty(), 72)
            val label = listOf(vendor, product).filter { it.isNotBlank() }.joinToString(" ")
            indicator(spec, IndicatorKind.CVE, cve, label.ifBlank { name }, 95, fetchedAt, ttl)
        }
    }

    // ------------------------------------------------------------------ EPSS

    private fun parseEpss(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val root = jsonObjectOf(payload)
        val data = root["data"]?.jsonArray ?: throw FeedParseException("EPSS feed has no data array")
        return data.mapNotNull { element ->
            val item = runCatching { element.jsonObject }.getOrNull() ?: return@mapNotNull null
            val cve = item.string("cve")?.uppercase(Locale.US) ?: return@mapNotNull null
            if (!cveRegex.matches(cve)) return@mapNotNull null
            val probability = item.double("epss") ?: 0.0
            val percentile = item.double("percentile") ?: 0.0
            val confidence = (percentile * 100).toInt().coerceIn(40, 95)
            indicator(
                spec, IndicatorKind.CVE, cve,
                "EPSS ${(probability * 100).toInt()}% · percentile ${(percentile * 100).toInt()}",
                confidence, fetchedAt, ttl
            )
        }
    }

    // ------------------------------------------------------------------ NVD

    private fun parseNvd(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val root = jsonObjectOf(payload)
        val vulnerabilities = root["vulnerabilities"]?.jsonArray
            ?: throw FeedParseException("NVD response has no vulnerabilities")
        return vulnerabilities.mapNotNull { element ->
            val wrapper = runCatching { element.jsonObject }.getOrNull() ?: return@mapNotNull null
            val cve = runCatching { wrapper["cve"]?.jsonObject }.getOrNull() ?: return@mapNotNull null
            val id = cve.string("id")?.uppercase(Locale.US) ?: return@mapNotNull null
            if (!cveRegex.matches(id)) return@mapNotNull null
            val description = cve["descriptions"]?.jsonArray
                ?.firstOrNull { runCatching { it.jsonObject.string("lang") }.getOrNull() == "en" }
                ?.let { runCatching { it.jsonObject.string("value") }.getOrNull() }
                .orEmpty()
            indicator(spec, IndicatorKind.CVE, id, sanitizeShort(description, 80).ifBlank { "NVD record" }, 72, fetchedAt, ttl)
        }
    }

    // ------------------------------------------------------------------ GitHub Advisories

    private fun parseGithubAdvisories(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val array = runCatching { json.parseToJsonElement(payload).jsonArray }.getOrNull()
            ?: throw FeedParseException("GitHub advisories response is not an array")
        return array.mapNotNull { element ->
            val item = runCatching { element.jsonObject }.getOrNull() ?: return@mapNotNull null
            val id = item.string("cve_id") ?: item.string("ghsa_id") ?: return@mapNotNull null
            val severity = item.string("severity").orEmpty()
            val summary = sanitizeShort(item.string("summary").orEmpty(), 80)
            val confidence = when (severity.lowercase(Locale.US)) {
                "critical" -> 92
                "high" -> 88
                "moderate", "medium" -> 78
                else -> 65
            }
            val kind = if (cveRegex.matches(id)) IndicatorKind.CVE else IndicatorKind.MALWARE_FAMILY
            indicator(spec, kind, id.uppercase(Locale.US), summary.ifBlank { "GitHub advisory" }, confidence, fetchedAt, ttl)
        }
    }

    // ------------------------------------------------------------------ MISP warninglists

    /**
     * Real MISP warninglist schema: `{"name":..., "type":"hostname|string|cidr|...",
     * "list":["value", ...]}`. Older copies also expose `values` objects, so both are accepted.
     *
     * These lists exist to *suppress* false positives. The repository stores them with confidence
     * 0 so they can only ever remove risk, never add it.
     */
    private fun parseMispList(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val root = jsonObjectOf(payload)
        val listName = sanitizeShort(root.string("name").orEmpty(), 48)
        val entries = mutableListOf<String>()
        root["list"]?.let { element ->
            runCatching {
                element.jsonArray.forEach { item ->
                    runCatching { item.jsonPrimitive.contentOrNull }.getOrNull()
                        ?.let { entries += it }
                }
            }
        }
        root["values"]?.let { element ->
            runCatching {
                element.jsonArray.forEach { item ->
                    runCatching { item.jsonObject.string("value") }.getOrNull()?.let { entries += it }
                }
            }
        }
        if (entries.isEmpty()) throw FeedParseException("MISP warninglist has no list values")
        return entries.mapNotNull { raw ->
            val value = raw.trim().trimStart('.').removePrefix("*.").lowercase(Locale.US)
            if (value.isBlank()) return@mapNotNull null
            val kind = when {
                ipv4Regex.matches(value) -> IndicatorKind.IP
                CIDR_REGEX.matches(value) -> IndicatorKind.IP_CIDR
                hashRegex.matches(value) -> IndicatorKind.HASH_SHA256
                domainRegex.matches(value) -> IndicatorKind.DOMAIN
                else -> return@mapNotNull null
            }
            indicator(
                spec, kind, value,
                listName.ifBlank { "MISP warninglist (false-positive suppression)" },
                60, fetchedAt, ttl
            )
        }
    }

    // ------------------------------------------------------------------ Domain blocklists

    private fun parseDomainLines(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val out = mutableListOf<ThreatIndicator>()
        payload.lineSequence().forEach { line ->
            val trimmed = line.trim().lowercase(Locale.US)
            if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
            val candidate = trimmed
                .removePrefix("0.0.0.0 ")
                .removePrefix("127.0.0.1 ")
                .removePrefix(":: ")
                .removePrefix("||")
                .removeSuffix("^")
                .substringBefore('#')
                .substringBefore(' ')
                .trimStart('.')
                .trim()
            if (!domainRegex.matches(candidate)) return@forEach
            if (candidate == "localhost" || candidate.endsWith(".local")) return@forEach
            out += indicator(spec, IndicatorKind.DOMAIN, candidate, "blocklisted domain", 70, fetchedAt, ttl)
        }
        return out
    }

    // ------------------------------------------------------------------ IP sum

    private fun parseIpsum(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val out = mutableListOf<ThreatIndicator>()
        payload.lineSequence().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
            val parts = trimmed.split('\t', ' ', ',')
            val ip = parts.firstOrNull()?.trim() ?: return@forEach
            if (!ipv4Regex.matches(ip)) return@forEach
            val score = parts.getOrNull(1)?.trim()?.toIntOrNull() ?: 0
            if (score < 3) return@forEach
            out += indicator(
                spec, IndicatorKind.IP, ip,
                "aggregated blocklist score $score/10", (55 + score * 4).coerceAtMost(95), fetchedAt, ttl
            )
        }
        return out
    }

    // ------------------------------------------------------------------ USGS

    private fun parseUsgs(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val root = jsonObjectOf(payload)
        val features = root["features"]?.jsonArray ?: throw FeedParseException("USGS feed has no features")
        return features.mapNotNull { element ->
            val properties = runCatching { element.jsonObject["properties"]?.jsonObject }.getOrNull()
                ?: return@mapNotNull null
            val id = properties.string("code") ?: properties.string("ids") ?: properties.string("url")
                ?: return@mapNotNull null
            val mag = properties.double("mag")
            val place = sanitizeShort(properties.string("place").orEmpty(), 64)
            val label = buildString {
                if (mag != null) append("M").append(mag).append(" · ")
                append(place.ifBlank { "earthquake" })
            }
            indicator(
                spec, IndicatorKind.ALERT, "usgs:$id", label, 90, fetchedAt,
                minOf(ttl, 24L * 60L * 60L * 1_000L)
            )
        }
    }

    // ------------------------------------------------------------------ GDACS

    private fun parseGdacs(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val items = rssItems(payload)
        if (items.isEmpty()) throw FeedParseException("GDACS RSS has no items")
        return items.mapNotNull { item ->
            val title = sanitizeShort(item.title, 90)
            val link = normalizeUrl(item.link) ?: "gdacs:${title.hashCode()}"
            if (title.isBlank()) return@mapNotNull null
            indicator(
                spec, IndicatorKind.ALERT, "gdacs:$link", title, 85, fetchedAt,
                minOf(ttl, 12L * 60L * 60L * 1_000L)
            )
        }
    }

    // ------------------------------------------------------------------ NWS

    private fun parseNws(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val root = jsonObjectOf(payload)
        val features = root["features"]?.jsonArray ?: throw FeedParseException("NWS alerts response has no features")
        return features.mapNotNull { element ->
            val properties = runCatching { element.jsonObject["properties"]?.jsonObject }.getOrNull()
                ?: return@mapNotNull null
            val id = properties.string("id") ?: return@mapNotNull null
            val event = sanitizeShort(properties.string("event").orEmpty(), 60).ifBlank { "weather alert" }
            val area = sanitizeShort(properties.string("areaDesc").orEmpty(), 60)
            val severity = properties.string("severity").orEmpty()
            val confidence = when (severity.lowercase(Locale.US)) {
                "extreme" -> 95
                "severe" -> 90
                "moderate" -> 80
                else -> 65
            }
            indicator(
                spec, IndicatorKind.ALERT, "nws:$id",
                listOf(event, area).filter { it.isNotBlank() }.joinToString(" · "),
                confidence, fetchedAt, minOf(ttl, 12L * 60L * 60L * 1_000L)
            )
        }
    }

    // ------------------------------------------------------------------ ReliefWeb

    private fun parseReliefWeb(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val root = jsonObjectOf(payload)
        val data = root["data"]?.jsonArray ?: throw FeedParseException("ReliefWeb response has no data array")
        return data.mapNotNull { element ->
            val fields = runCatching { element.jsonObject["fields"]?.jsonObject }.getOrNull()
                ?: return@mapNotNull null
            val id = runCatching { element.jsonObject.string("id") }.getOrNull() ?: return@mapNotNull null
            val name = sanitizeShort(fields.string("name").orEmpty(), 90)
            if (name.isBlank()) return@mapNotNull null
            indicator(
                spec, IndicatorKind.ALERT, "reliefweb:$id", name, 80, fetchedAt,
                minOf(ttl, 24L * 60L * 60L * 1_000L)
            )
        }
    }

    // ------------------------------------------------------------------ SeismicPortal (EMSC)

    private fun parseSeismicPortal(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val root = jsonObjectOf(payload)
        val features = root["features"]?.jsonArray ?: throw FeedParseException("EMSC feed has no features")
        return features.mapNotNull { element ->
            val item = runCatching { element.jsonObject }.getOrNull() ?: return@mapNotNull null
            val properties = runCatching { item["properties"]?.jsonObject }.getOrNull() ?: return@mapNotNull null
            val id = properties.string("unid") ?: properties.string("source_id") ?: return@mapNotNull null
            val mag = properties.double("mag")
            val place = sanitizeShort(properties.string("flynn_region").orEmpty(), 64)
            val label = buildString {
                if (mag != null) append("M").append(String.format(Locale.US, "%.1f", mag)).append(" · ")
                append(place.ifBlank { "earthquake" })
            }
            indicator(
                spec, IndicatorKind.ALERT, "emsc:$id", label, 85, fetchedAt,
                minOf(ttl, 24L * 60L * 60L * 1_000L)
            )
        }
    }

    // ------------------------------------------------------------------ generic IP / CIDR lists

    /**
     * Plain-text IP / CIDR feeds (IPsum, FireHOL, Emerging Threats, CINS, blocklist.de, Tor).
     * Comments are stripped. A CIDR entry is stored as IP_CIDR and matched by prefix, because
     * collapsing a /12 to one address would silently miss almost the whole range.
     */
    private fun parseIpList(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val (label, baseConfidence) = ipListPolicy(spec)
        val out = mutableListOf<ThreatIndicator>()
        payload.lineSequence().forEach { line ->
            val withoutComment = line.trim().substringBefore('#').substringBefore(';').trim()
            if (withoutComment.isNotEmpty()) {
                withoutComment.split(',', ' ', '\t').forEach tokenLoop@{ tokenRaw ->
                    val token = tokenRaw.trim()
                    if (token.isEmpty()) return@tokenLoop
                    when {
                        ipv4Regex.matches(token) ->
                            out += indicator(spec, IndicatorKind.IP, token, label, baseConfidence, fetchedAt, ttl)
                        CIDR_REGEX.matches(token) ->
                            out += indicator(spec, IndicatorKind.IP_CIDR, token, label, baseConfidence, fetchedAt, ttl)
                    }
                }
            }
        }
        return out
    }

    private fun ipListPolicy(spec: ConnectorSpec): Pair<String, Int> = when {
        spec.id.contains("tor") -> "Tor exit node (anonymising proxy, not malware)" to 30
        spec.id.contains("spamhaus") -> "Spamhaus DROP network" to 72
        spec.id.contains("firehol") -> "FireHOL level-1 blocked network" to 68
        spec.id.contains("blocklistde") -> "reported brute-flow attacker" to 66
        spec.id.contains("et.") -> "compromised host (Emerging Threats)" to 74
        spec.id.contains("cins") -> "low-reputation IP (CINS)" to 68
        spec.id.contains("ipsum") -> "aggregated blocklist IP (IPsum)" to 60
        spec.id.contains("sslbl") -> "SSLBL malicious TLS endpoint" to 78
        else -> "reported malicious IP" to 60
    }

    // ------------------------------------------------------------------ SSLBL fingerprints

    /** SSLBL JA3 CSV: one 32-hex client fingerprint per row plus a reason column. */
    private fun parseSslblJa3(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val out = mutableListOf<ThreatIndicator>()
        csvLines(payload).forEach { row ->
            val ja3 = row.firstOrNull { JA3_REGEX.matches(it.lowercase(Locale.US)) } ?: return@forEach
            val reason = sanitizeShort(row.lastOrNull().orEmpty(), 64)
            out += indicator(
                spec, IndicatorKind.JA3, ja3.lowercase(Locale.US),
                reason.ifBlank { "malicious TLS client fingerprint" }, 70, fetchedAt, ttl
            )
        }
        return out
    }

    /** SSLBL certificate CSV: a 40-hex SHA-1 of a certificate used by malware infrastructure. */
    private fun parseSslblCert(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val out = mutableListOf<ThreatIndicator>()
        csvLines(payload).forEach { row ->
            val sha1 = row.firstOrNull { SHA1_REGEX.matches(it.lowercase(Locale.US)) } ?: return@forEach
            val reason = sanitizeShort(row.lastOrNull().orEmpty(), 64)
            out += indicator(
                spec, IndicatorKind.CERT_SHA1, sha1.lowercase(Locale.US),
                reason.ifBlank { "malicious TLS certificate" }, 72, fetchedAt, ttl
            )
        }
        return out
    }

    // ------------------------------------------------------------------ Exploit-DB

    /** Exploit-DB CSV: extracts every CVE an exploit maps to. No executable content is stored. */
    private fun parseExploitDb(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val out = mutableListOf<ThreatIndicator>()
        csvLines(payload).forEach { row ->
            val codes = row.getOrNull(11).orEmpty()
            val description = sanitizeShort(row.getOrNull(2).orEmpty(), 60)
            CVE_REGEX.findAll(codes).forEach { match ->
                out += indicator(
                    spec, IndicatorKind.CVE, match.value.uppercase(Locale.US),
                    "public exploit available: $description", 82, fetchedAt, ttl
                )
            }
        }
        return out
    }

    // ------------------------------------------------------------------ JSON domain arrays

    private fun parseJsonDomainArray(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val array = runCatching { json.parseToJsonElement(payload).jsonArray }.getOrNull()
            ?: throw FeedParseException("response is not a JSON array of domains")
        return array.mapNotNull { element ->
            val raw = runCatching { element.jsonPrimitive.contentOrNull }.getOrNull()
                ?.trim()?.lowercase(Locale.US)?.removePrefix("*.")?.removePrefix(".")
                ?: return@mapNotNull null
            if (!domainRegex.matches(raw)) return@mapNotNull null
            indicator(spec, IndicatorKind.DOMAIN, raw, "reported scam/phishing domain", 70, fetchedAt, ttl)
        }
    }

    // ------------------------------------------------------------------ GDACS JSON API

    private fun parseGdacsApi(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val root = jsonObjectOf(payload)
        val features = root["features"]?.jsonArray ?: throw FeedParseException("GDACS API has no features")
        return features.mapNotNull { element ->
            val properties = runCatching { element.jsonObject["properties"]?.jsonObject }.getOrNull()
                ?: return@mapNotNull null
            val id = properties.string("eventid") ?: properties.string("episodeid") ?: return@mapNotNull null
            val type = properties.string("eventtype").orEmpty()
            val name = sanitizeShort(properties.string("name").orEmpty(), 60)
            val alert = properties.string("alertlevel").orEmpty()
            val country = properties.string("country").orEmpty()
            val label = listOf(type, alert, name, country).filter { it.isNotBlank() }.joinToString(" · ")
            indicator(spec, IndicatorKind.ALERT, "gdacs:$type:$id", label, 85, fetchedAt, ttl)
        }
    }

    // ------------------------------------------------------------------ NASA EONET

    private fun parseEonet(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val root = jsonObjectOf(payload)
        val events = root["events"]?.jsonArray ?: throw FeedParseException("EONET response has no events")
        return events.mapNotNull { element ->
            val item = runCatching { element.jsonObject }.getOrNull() ?: return@mapNotNull null
            val id = item.string("id") ?: return@mapNotNull null
            val title = sanitizeShort(item.string("title").orEmpty(), 70)
            val category = runCatching {
                item["categories"]?.jsonArray?.firstOrNull()?.jsonObject?.string("title")
            }.getOrNull().orEmpty()
            indicator(
                spec, IndicatorKind.ALERT, "eonet:$id",
                listOf(category, title).filter { it.isNotBlank() }.joinToString(" · "),
                70, fetchedAt, ttl
            )
        }
    }

    // ------------------------------------------------------------------ Open-Meteo context

    /**
     * Weather/flood/air-quality context. This is explicitly *not* an official warning: the parser
     * labels it as a forecast and the app never turns it into an emergency alert.
     */
    private fun parseOpenMeteoContext(
        spec: ConnectorSpec,
        payload: String,
        fetchedAt: Long,
        ttl: Long
    ): List<ThreatIndicator> {
        val root = jsonObjectOf(payload)
        val current = runCatching { root["current"]?.jsonObject }.getOrNull()
        val daily = runCatching { root["daily"]?.jsonObject }.getOrNull()
        val evidence = when {
            current != null -> current.entries.take(6).joinToString(" · ") { (key, value) ->
                "$key=${runCatching { value.jsonPrimitive.contentOrNull }.getOrNull() ?: "?"}"
            }
            daily != null -> {
                val discharge = runCatching { daily["river_discharge"]?.jsonArray }.getOrNull()
                val peak = discharge?.mapNotNull { runCatching { it.jsonPrimitive.doubleOrNull }.getOrNull() }?.maxOrNull()
                "river discharge forecast peak=${peak ?: "unavailable"} m³/s"
            }
            else -> throw FeedParseException("Open-Meteo response has neither current nor daily data")
        }
        return listOf(
            indicator(
                spec, IndicatorKind.ALERT, "forecast:${spec.id}",
                "Forecast context (not an official warning): $evidence",
                25, fetchedAt, ttl
            )
        )
    }

    // ------------------------------------------------------------------ Diagnostics (no indicators)

    private fun parseRipe(spec: ConnectorSpec, payload: String): List<ThreatIndicator> {
        val root = jsonObjectOf(payload)
        val data = runCatching { root["data"]?.jsonObject }.getOrNull()
            ?: throw FeedParseException("RIPEstat response has no data object")
        val records = data["records"]?.let { runCatching { it.jsonArray.size }.getOrNull() } ?: 0
        val origin = data.string("origin") ?: data.string("resource") ?: "bgp-state"
        return listOf(diagnostic(spec, "RIPEstat: $origin · $records BGP record(s)"))
    }

    private fun parseRdap(spec: ConnectorSpec, payload: String): List<ThreatIndicator> {
        val root = jsonObjectOf(payload)
        val handle = root.string("handle") ?: root.string("name")
            ?: throw FeedParseException("RDAP response has neither handle nor name")
        val country = root.string("country").orEmpty()
        val status = root["status"]?.let { runCatching { it.jsonArray.joinToString(",") { s -> s.toString().trim('"') } }.getOrNull() }
        val summary = listOf(handle, country, status.orEmpty()).filter { it.isNotBlank() }.joinToString(" · ")
        return listOf(diagnostic(spec, "RDAP: $summary"))
    }

    private fun parseIpify(spec: ConnectorSpec, payload: String): List<ThreatIndicator> {
        val ip = jsonObjectOf(payload).string("ip") ?: throw FeedParseException("ipify response has no ip")
        if (!ipv4Regex.matches(ip)) throw FeedParseException("ipify returned a non-IPv4 value")
        return listOf(diagnostic(spec, "Public IP observed by the probe: $ip"))
    }

    private fun diagnostic(spec: ConnectorSpec, summary: String): ThreatIndicator = ThreatIndicator(
        kind = IndicatorKind.ALERT,
        value = "diagnostic:${spec.id}",
        sourceId = spec.id,
        module = spec.module,
        label = summary.take(120),
        confidence = 100,
        firstSeenEpochMs = System.currentTimeMillis(),
        expiresAtEpochMs = System.currentTimeMillis() + spec.cacheTtlMs,
        attribution = spec.provider
    )

    // ------------------------------------------------------------------ helpers

    private fun indicator(
        spec: ConnectorSpec,
        kind: IndicatorKind,
        value: String,
        label: String,
        confidence: Int,
        fetchedAt: Long,
        ttl: Long
    ): ThreatIndicator = ThreatIndicator(
        kind = kind,
        value = value,
        sourceId = spec.id,
        module = spec.module,
        label = sanitizeShort(label, 120),
        confidence = confidence.coerceIn(0, 100),
        firstSeenEpochMs = fetchedAt,
        expiresAtEpochMs = fetchedAt + (ttl * 3).coerceIn(6L * 60L * 60L * 1_000L, 30L * 24L * 60L * 60L * 1_000L),
        attribution = "${spec.provider} (${spec.id})"
    )

    fun normalizeUrl(raw: String): String? {
        val trimmed = raw.trim().trim('"', '\'')
        if (trimmed.isEmpty() || trimmed.length > 2_000) return null
        val withScheme = if (trimmed.startsWith("http://", true) || trimmed.startsWith("https://", true)) {
            trimmed
        } else {
            return null
        }
        val host = hostOf(withScheme) ?: return null
        if (!domainRegex.matches(host) && !ipv4Regex.matches(host)) return null
        // Canonical form: lookups normalise to lowercase, so storage must agree.
        return withScheme.lowercase(Locale.US)
    }

    fun hostOf(url: String): String? {
        val withoutScheme = url.substringAfter("://", url)
        val host = withoutScheme.substringBefore('/').substringBefore('?').substringBefore('#')
            .substringBefore(':')
            .trim()
            .trimEnd('.')
            .lowercase(Locale.US)
        return host.takeIf { domainRegex.matches(it) || ipv4Regex.matches(it) }
    }

    fun isDomain(value: String): Boolean = domainRegex.matches(value.lowercase(Locale.US))

    fun isSha256(value: String): Boolean = hashRegex.matches(value.lowercase(Locale.US))

    fun isIpv4(value: String): Boolean = ipv4Regex.matches(value)

    fun isCve(value: String): Boolean = cveRegex.matches(value)

    /** Splits CSV respecting double quotes; ignores comment lines and an optional header. */
    private fun csvLines(payload: String): List<List<String>> {
        val rows = mutableListOf<List<String>>()
        payload.lineSequence().forEach { rawLine ->
            val line = rawLine.trimEnd('\r')
            if (line.isBlank() || line.startsWith("#")) return@forEach
            val cells = splitCsvLine(line)
            val joined = cells.joinToString(" ").lowercase(Locale.US)
            if (joined.startsWith("id ") || (cells.firstOrNull()?.equals("id", true) == true)) return@forEach
            if (cells.size >= 2) rows += cells
        }
        return rows
    }

    private fun splitCsvLine(line: String): List<String> {
        val cells = mutableListOf<String>()
        val current = StringBuilder()
        var inQuotes = false
        var index = 0
        while (index < line.length) {
            val char = line[index]
            when {
                char == '"' && inQuotes && index + 1 < line.length && line[index + 1] == '"' -> {
                    current.append('"'); index++
                }
                char == '"' -> inQuotes = !inQuotes
                char == ',' && !inQuotes -> {
                    cells += current.toString(); current.clear()
                }
                else -> current.append(char)
            }
            index++
        }
        cells += current.toString()
        return cells.map { it.trim() }
    }

    private data class RssItem(val title: String, val link: String, val date: String)

    private fun rssItems(payload: String): List<RssItem> {
        val itemRegex = Regex("<item[^>]*>(.*?)</item>", setOf(RegexOption.DOT_MATCHES_ALL, RegexOption.IGNORE_CASE))
        return itemRegex.findAll(payload).mapNotNull { match ->
            val body = match.groupValues[1]
            RssItem(
                title = tagText(body, "title"),
                link = tagText(body, "link").ifBlank { tagText(body, "guid") },
                date = tagText(body, "pubDate")
            )
        }.toList()
    }

    private fun tagText(body: String, tag: String): String {
        val regex = Regex("<$tag[^>]*>(.*?)</$tag>", setOf(RegexOption.DOT_MATCHES_ALL, RegexOption.IGNORE_CASE))
        val raw = regex.find(body)?.groupValues?.get(1) ?: return ""
        return raw
            .replace(Regex("<!\\[CDATA\\[(.*?)]]>", RegexOption.DOT_MATCHES_ALL)) { it.groupValues[1] }
            .replace(Regex("<[^>]+>"), "")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#039;", "'")
            .trim()
    }

    private fun jsonObjectOf(payload: String): JsonObject =
        runCatching { json.parseToJsonElement(payload).jsonObject }
            .getOrElse { throw FeedParseException("response is not a JSON object") }

    private fun JsonObject.string(key: String): String? =
        (this[key] as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() }

    private fun JsonObject.double(key: String): Double? = (this[key] as? JsonPrimitive)?.doubleOrNull

    @Suppress("unused")
    private fun JsonArray.firstObjectOrNull(): JsonObject? =
        firstOrNull()?.let { runCatching { it.jsonObject }.getOrNull() }

    private fun sanitizeShort(raw: String, max: Int): String {
        val cleaned = raw
            .replace(Regex("[\\u0000-\\u001F\\u007F]"), " ")
            .replace(Regex("\\s+"), " ")
            .trim()
        return if (cleaned.length <= max) cleaned else cleaned.take(max - 1).trimEnd() + "…"
    }

    /** Parses an RFC-1123 RSS timestamp; returns null rather than inventing a date. */
    fun parseRssDate(raw: String): Long? {
        if (raw.isBlank()) return null
        return runCatching {
            val format = SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US)
            format.timeZone = TimeZone.getTimeZone("GMT")
            format.parse(raw)?.time
        }.getOrNull()
    }
}
