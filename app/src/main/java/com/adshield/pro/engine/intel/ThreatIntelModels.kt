package com.adshield.pro.engine.intel

import kotlinx.serialization.Serializable

/**
 * External threat intelligence — real, public, key-less feeds operated by abuse.ch.
 *
 *  - Feodo Tracker: active botnet command-and-control IPs, including the country the IP is
 *    registered in. This is the only feed that carries geolocation, so it is the only feed
 *    drawn on the world map.
 *  - URLhaus: recently reported malware-distribution URLs. No geolocation is published, so
 *    these indicators appear in lists and filters but never as invented map markers.
 *
 * Nothing here is simulated: when a feed has not been fetched, the state says NOT_FETCHED;
 * when a fetch fails, the previous cache is kept and labelled stale with the real error.
 */
enum class IntelSource(
    val id: String,
    val displayName: String,
    val feedUrl: String,
    val siteUrl: String,
    val description: String,
    val hasGeoData: Boolean
) {
    FEODO_TRACKER(
        id = "feodo",
        displayName = "Feodo Tracker (abuse.ch)",
        feedUrl = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
        siteUrl = "https://feodotracker.abuse.ch/",
        description = "Active botnet command-and-control servers, with registered country.",
        hasGeoData = true
    ),
    URLHAUS(
        id = "urlhaus",
        displayName = "URLhaus (abuse.ch)",
        feedUrl = "https://urlhaus.abuse.ch/downloads/json_recent/",
        siteUrl = "https://urlhaus.abuse.ch/",
        description = "Recently reported malware-distribution URLs. No geolocation is published.",
        hasGeoData = false
    )
}

enum class IndicatorKind(val label: String) {
    BOTNET_C2("Botnet C2"),
    MALWARE_URL("Malware URL")
}

@Serializable
data class IntelIndicator(
    /** Stable unique key: source id + indicator value. */
    val key: String,
    val sourceId: String,
    val kind: IndicatorKind,
    /** IP address (Feodo) or full URL (URLhaus). */
    val value: String,
    val host: String,
    val port: Int? = null,
    /** ISO 3166-1 alpha-2 country code when the feed publishes one; null otherwise. */
    val country: String? = null,
    val malwareFamily: String? = null,
    val threat: String? = null,
    val status: String? = null,
    val firstSeenUtc: String? = null,
    val lastOnlineUtc: String? = null,
    val referenceUrl: String? = null
)

enum class FeedFetchStatus { NOT_FETCHED, OK, ERROR }

@Serializable
data class IntelFeedState(
    val sourceId: String,
    val status: FeedFetchStatus = FeedFetchStatus.NOT_FETCHED,
    val lastFetchEpochMs: Long = 0L,
    val lastError: String? = null,
    val itemCount: Int = 0
) {
    val isStale: Boolean
        get() = lastFetchEpochMs > 0L &&
            System.currentTimeMillis() - lastFetchEpochMs > STALE_AFTER_MS

    companion object {
        const val STALE_AFTER_MS = 12 * 60 * 60 * 1000L
    }
}

data class ThreatIntelState(
    val feeds: List<IntelFeedState> = IntelSource.entries.map { IntelFeedState(it.id) },
    val indicators: List<IntelIndicator> = emptyList(),
    val isRefreshing: Boolean = false
) {
    val lastSyncEpochMs: Long get() = feeds.maxOfOrNull { it.lastFetchEpochMs } ?: 0L
    val hasAnyData: Boolean get() = indicators.isNotEmpty()
    val geoIndicators: List<IntelIndicator> get() = indicators.filter { !it.country.isNullOrBlank() }

    fun feedState(source: IntelSource): IntelFeedState =
        feeds.firstOrNull { it.sourceId == source.id } ?: IntelFeedState(source.id)
}

/** One map marker: real indicator count for one country, with the families behind it. */
data class CountryThreat(
    val countryCode: String,
    val count: Int,
    val malwareFamilies: List<String>,
    val onlineCount: Int
)

object ThreatIntelAggregation {

    /** Aggregates geolocated indicators per country. Indicators without a country are excluded. */
    fun byCountry(indicators: List<IntelIndicator>): List<CountryThreat> =
        indicators
            .filter { !it.country.isNullOrBlank() }
            .groupBy { it.country!!.uppercase() }
            .map { (country, items) ->
                CountryThreat(
                    countryCode = country,
                    count = items.size,
                    malwareFamilies = items.mapNotNull { it.malwareFamily }.distinct().sorted(),
                    onlineCount = items.count { it.status.equals("online", ignoreCase = true) }
                )
            }
            .sortedByDescending { it.count }

    /** Indicators the map cannot place, surfaced honestly in the UI instead of hidden. */
    fun unmappedCount(indicators: List<IntelIndicator>): Int =
        indicators.count { it.country.isNullOrBlank() }
}
