package com.adshield.pro.engine.cloud

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Cloud service monitoring through official, public status pages (Statuspage.io v2 API).
 *
 * This is real operational data published by each provider — incident indicator, component
 * health and the provider's own update timestamp. It is explicitly NOT account-level cloud
 * security posture: no credentials are collected and no tenant is accessed. Providers that
 * have not been checked render as "Not connected", never as "secure".
 */
enum class CloudProvider(
    val id: String,
    val displayName: String,
    val summaryEndpoint: String,
    val statusPageUrl: String,
    val role: String
) {
    GITHUB(
        id = "github",
        displayName = "GitHub",
        summaryEndpoint = "https://www.githubstatus.com/api/v2/summary.json",
        statusPageUrl = "https://www.githubstatus.com/",
        role = "Source control & CI"
    ),
    CLOUDFLARE(
        id = "cloudflare",
        displayName = "Cloudflare",
        summaryEndpoint = "https://www.cloudflarestatus.com/api/v2/summary.json",
        statusPageUrl = "https://www.cloudflarestatus.com/",
        role = "DNS, CDN & edge security"
    ),
    NPM(
        id = "npm",
        displayName = "npm",
        summaryEndpoint = "https://status.npmjs.org/api/v2/summary.json",
        statusPageUrl = "https://status.npmjs.org/",
        role = "Package registry / supply chain"
    ),
    BITBUCKET(
        id = "bitbucket",
        displayName = "Bitbucket",
        summaryEndpoint = "https://bitbucket.status.atlassian.com/api/v2/summary.json",
        statusPageUrl = "https://bitbucket.status.atlassian.com/",
        role = "Source control & pipelines"
    )
}

enum class CloudConnection { NOT_CHECKED, CONNECTED, ERROR }

/** Operational indicator levels defined by Statuspage. */
enum class ServiceIndicator(val label: String, val operational: Boolean) {
    NONE("Operational", true),
    MAINTENANCE("Under maintenance", true),
    MINOR("Minor incident", false),
    MAJOR("Major incident", false),
    CRITICAL("Critical incident", false),
    UNKNOWN("Unknown", false);

    companion object {
        fun from(raw: String?): ServiceIndicator = when (raw?.lowercase()) {
            "none" -> NONE
            "maintenance" -> MAINTENANCE
            "minor" -> MINOR
            "major" -> MAJOR
            "critical" -> CRITICAL
            else -> UNKNOWN
        }
    }
}

data class CloudComponent(val name: String, val status: String) {
    val healthy: Boolean get() = status == "operational"
}

data class CloudServiceStatus(
    val provider: CloudProvider,
    val connection: CloudConnection = CloudConnection.NOT_CHECKED,
    val indicator: ServiceIndicator = ServiceIndicator.UNKNOWN,
    val description: String? = null,
    val components: List<CloudComponent> = emptyList(),
    val providerUpdatedAt: String? = null,
    val fetchedAtEpochMs: Long = 0L,
    val error: String? = null
)

data class CloudStatusState(
    val services: List<CloudServiceStatus> = CloudProvider.entries.map { CloudServiceStatus(it) },
    val isRefreshing: Boolean = false
) {
    val connectedCount: Int get() = services.count { it.connection == CloudConnection.CONNECTED }
    val incidentCount: Int get() = services.count {
        it.connection == CloudConnection.CONNECTED && !it.indicator.operational
    }
}

object CloudStatusParser {

    class CloudParseException(message: String, cause: Throwable? = null) : Exception(message, cause)

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    /**
     * Parses a Statuspage v2 `summary.json` payload:
     * `{"page":{"updated_at":...},"status":{"indicator":"none","description":"All Systems Operational"},
     *   "components":[{"name":"Git Operations","status":"operational"},...]}`.
     */
    fun parse(provider: CloudProvider, raw: String, fetchedAtEpochMs: Long): CloudServiceStatus {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) throw CloudParseException("${provider.displayName} returned an empty payload")
        val root = try {
            json.parseToJsonElement(trimmed).jsonObject
        } catch (e: Exception) {
            throw CloudParseException("${provider.displayName} returned malformed JSON: ${e.message}", e)
        }
        val statusObj = root["status"] as? JsonObject
            ?: throw CloudParseException("${provider.displayName} payload has no status object")
        val indicator = ServiceIndicator.from(statusObj.string("indicator"))
        val components = (root["components"] as? JsonArray)?.mapNotNull { element ->
            val obj = element as? JsonObject ?: return@mapNotNull null
            val name = obj.string("name") ?: return@mapNotNull null
            CloudComponent(name = name, status = obj.string("status") ?: "unknown")
        } ?: emptyList()
        return CloudServiceStatus(
            provider = provider,
            connection = CloudConnection.CONNECTED,
            indicator = indicator,
            description = statusObj.string("description"),
            components = components,
            providerUpdatedAt = (root["page"] as? JsonObject)?.string("updated_at"),
            fetchedAtEpochMs = fetchedAtEpochMs,
            error = null
        )
    }

    private fun JsonObject.string(field: String): String? =
        (this[field] as? JsonPrimitive)?.contentOrNull
}
