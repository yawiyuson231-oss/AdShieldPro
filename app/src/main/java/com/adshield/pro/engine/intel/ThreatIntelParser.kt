package com.adshield.pro.engine.intel

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Defensive parsers for the two abuse.ch feeds. They accept the documented shapes and skip
 * malformed entries instead of failing the whole feed; a payload that is not the expected JSON
 * at all raises [IntelParseException] so the repository can keep the previous cache and report
 * the real error. Unit-tested against captured fixture payloads on the JVM.
 */
object ThreatIntelParser {

    class IntelParseException(message: String, cause: Throwable? = null) : Exception(message, cause)

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    /**
     * Feodo Tracker `ipblocklist_recommended.json`: a JSON array of objects like
     * `{"ip_address":"1.2.3.4","port":443,"status":"online","hostname":"",
     *   "as_number":1234,"as_name":"EXAMPLE","country":"RU",
     *   "first_seen_utc":"2024-01-01 00:00:00","last_online":"2024-05-01","malware":"QakBot"}`.
     */
    fun parseFeodo(raw: String): List<IntelIndicator> {
        val root = parseRoot(raw, "Feodo Tracker")
        val array = root as? JsonArray
            ?: throw IntelParseException("Feodo Tracker payload is not a JSON array")
        return array.mapNotNull { element ->
            val obj = element as? JsonObject ?: return@mapNotNull null
            val ip = obj.string("ip_address")?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
            IntelIndicator(
                key = "${IntelSource.FEODO_TRACKER.id}:$ip",
                sourceId = IntelSource.FEODO_TRACKER.id,
                kind = IndicatorKind.BOTNET_C2,
                value = ip,
                host = ip,
                port = obj["port"]?.jsonPrimitive?.intOrNull,
                country = obj.string("country")?.uppercase()?.takeIf { it.length == 2 },
                malwareFamily = obj.string("malware")?.takeIf { it.isNotBlank() },
                threat = "botnet_cc",
                status = obj.string("status"),
                firstSeenUtc = obj.string("first_seen_utc"),
                lastOnlineUtc = obj.string("last_online"),
                referenceUrl = "https://feodotracker.abuse.ch/browse/host/$ip/"
            )
        }
    }

    /**
     * URLhaus `json_recent`: a JSON object keyed by entry id, each value an array holding one
     * object like `{"id":"123","dateadded":"2024-05-01 12:00:00 UTC","url":"http://host/payload",
     * "url_status":"online","threat":"malware_download","tags":["exe"],
     * "urlhaus_link":"https://urlhaus.abuse.ch/url/123/","reporter":"anonymous"}`.
     * URLhaus publishes no country, so these indicators are never geolocated.
     */
    fun parseUrlhaus(raw: String): List<IntelIndicator> {
        val root = parseRoot(raw, "URLhaus")
        val obj = root as? JsonObject
            ?: throw IntelParseException("URLhaus payload is not a JSON object")
        val indicators = ArrayList<IntelIndicator>()
        obj.values.forEach { value ->
            val entries = value as? JsonArray ?: return@forEach
            entries.forEach { entry ->
                val item = entry as? JsonObject ?: return@forEach
                val url = item.string("url")?.takeIf { it.isNotBlank() } ?: return@forEach
                val id = item.string("id") ?: url
                indicators += IntelIndicator(
                    key = "${IntelSource.URLHAUS.id}:$id",
                    sourceId = IntelSource.URLHAUS.id,
                    kind = IndicatorKind.MALWARE_URL,
                    value = url,
                    host = hostOf(url),
                    port = null,
                    country = null,
                    malwareFamily = (item["tags"] as? JsonArray)
                        ?.mapNotNull { it.jsonPrimitive.contentOrNull }
                        ?.firstOrNull { it.isNotBlank() },
                    threat = item.string("threat"),
                    status = item.string("url_status"),
                    firstSeenUtc = item.string("dateadded"),
                    lastOnlineUtc = null,
                    referenceUrl = item.string("urlhaus_link")
                )
            }
        }
        return indicators
    }

    private fun parseRoot(raw: String, sourceName: String): kotlinx.serialization.json.JsonElement {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) throw IntelParseException("$sourceName returned an empty payload")
        return try {
            json.parseToJsonElement(trimmed)
        } catch (e: Exception) {
            throw IntelParseException("$sourceName returned malformed JSON: ${e.message}", e)
        }
    }

    private fun JsonObject.string(field: String): String? =
        (this[field] as? JsonPrimitive)?.contentOrNull

    /** Extracts the host from a URL without java.net so the parser stays pure and lenient. */
    internal fun hostOf(url: String): String {
        val withoutScheme = url.substringAfter("://", url)
        val authority = withoutScheme.substringBefore('/').substringBefore('?').substringBefore('#')
        val hostPart = authority.substringAfterLast('@')
        return if (hostPart.startsWith("[")) {
            hostPart.substringAfter('[').substringBefore(']')
        } else {
            hostPart.substringBefore(':')
        }.trimEnd('.').lowercase()
    }
}
