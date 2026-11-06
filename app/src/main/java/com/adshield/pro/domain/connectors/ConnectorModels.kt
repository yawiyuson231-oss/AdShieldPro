package com.adshield.pro.domain.connectors

import com.adshield.pro.domain.intelligence.IntelligenceModule

/**
 * Connector platform models.
 *
 * A "connector" is one genuine, distinct integration: either a public HTTPS feed this app really
 * downloads and parses, or one Android platform interface this app really calls and reports on.
 * Nothing here is decorative — every [ConnectorSpec] must name a real endpoint or a real Android
 * API, and every runtime status is derived from an actual attempt.
 */

enum class ConnectorTransport { HTTP, NATIVE }

enum class ConnectorAuth {
    /** No account, key or registration. */
    NONE,

    /** Works without credentials, but some providers rate-limit anonymous callers. */
    OPTIONAL_KEY,

    /** The provider requires registration/API key for the endpoint to answer. Never mandatory. */
    REQUIRED_KEY,

    /** Android requires the user to grant access (usage access, notification access, ...). */
    USER_AUTHORIZATION
}

enum class ConnectorFormat { CSV, TEXT, JSON, RSS, ANDROID_API }

/**
 * Input a lookup connector accepts. A lookup is not a feed: it runs only when the user (or the
 * scanner) supplies a value, so it never spends background data on its own.
 */
enum class LookupField(val label: String) {
    HASH_SHA256("SHA-256 hash"),
    DOMAIN("Domain"),
    IP("IP address"),
    CVE("CVE identifier"),
    URL("URL"),
    PACKAGE("Package coordinate");

    companion object {
        /** Best-effort field detection for a typed value; null means "not a supported IOC". */
        fun detect(raw: String): LookupField? {
            val value = raw.trim()
            if (value.isEmpty()) return null
            val lowered = value.lowercase()
            return when {
                Regex("^[a-f0-9]{64}$").matches(lowered) -> HASH_SHA256
                Regex("^CVE-\\d{4}-\\d{4,7}$", RegexOption.IGNORE_CASE).matches(value) -> CVE
                lowered.startsWith("http://") || lowered.startsWith("https://") -> URL
                Regex("^(?:\\d{1,3}\\.){3}\\d{1,3}$").matches(lowered) -> IP
                lowered.contains(':') && lowered.contains('@') -> PACKAGE
                lowered.contains('.') -> DOMAIN
                else -> null
            }
        }
    }
}

/** Presentation status. `CONNECTED` is only ever set after a real, valid, successful operation. */
enum class ConnectorStatus {
    CONNECTED,
    SYNCING,
    OFFLINE,
    DEGRADED,
    RATE_LIMITED,
    ERROR,
    DISABLED,
    NOT_CONFIGURED,
    NOT_IMPLEMENTED;

    val label: String
        get() = when (this) {
            CONNECTED -> "CONNECTED"
            SYNCING -> "SYNCING"
            OFFLINE -> "OFFLINE"
            DEGRADED -> "DEGRADED"
            RATE_LIMITED -> "RATE LIMITED"
            ERROR -> "ERROR"
            DISABLED -> "DISABLED"
            NOT_CONFIGURED -> "NOT CONFIGURED"
            NOT_IMPLEMENTED -> "NOT IMPLEMENTED"
        }
}

/** Honest verification classes used by `docs/CONNECTOR_VERIFICATION.md`. */
enum class VerificationClass {
    IMPLEMENTED_AND_TESTED,
    IMPLEMENTED_NOT_FULLY_VERIFIED,
    FREE_WITH_RESTRICTIONS,
    ANDROID_LIMITED,
    SOURCE_UNAVAILABLE,
    NOT_IMPLEMENTED
}

/**
 * Immutable description of one connector. Static metadata lives in code; runtime state lives in
 * Room so a failed sync is still visible after a restart.
 */
data class ConnectorSpec(
    val id: String,
    val name: String,
    val module: IntelligenceModule,
    val provider: String,
    /** Exact HTTPS endpoint, or the exact Android API for native connectors. */
    val endpoint: String,
    val method: String = "GET",
    val format: ConnectorFormat,
    val transport: ConnectorTransport,
    val auth: ConnectorAuth = ConnectorAuth.NONE,
    /** What the provider/Android actually permits, in plain words. */
    val freeUse: String,
    val restrictions: String,
    val rateLimit: String,
    val cachePolicy: String = "",
    val cacheTtlMs: Long,
    val timeoutMs: Int = 15_000,
    val maxBytes: Int = 4_000_000,
    val defaultEnabled: Boolean = false,
    val implemented: Boolean = true,
    /** Parser id for HTTP connectors; probe id for native connectors. */
    val handlerId: String,
    val verification: VerificationClass,
    /** Stable reference for evidence/attribution, e.g. the feed home page. */
    val docsUrl: String = "",
    /** Non-null when this is an on-demand lookup rather than a scheduled feed. */
    val queryField: LookupField? = null,
    /** Request body template for POST feeds/lookups; `{value}` is substituted for lookups. */
    val requestBody: String? = null,
    /** Content type for [requestBody]; ignored for GET. */
    val contentType: String? = null,
    /** Immediate retry budget for transient transport failures (idempotent requests only). */
    val maxRetries: Int = 2,
    /** Seconds a provider's Retry-After may block this connector, capped defensively. */
    val maxRetryAfterSeconds: Long = 3_600L
) {
    val isFeed: Boolean get() = transport == ConnectorTransport.HTTP
    val isLookup: Boolean get() = isFeed && queryField != null
    val requiresKey: Boolean get() = auth == ConnectorAuth.REQUIRED_KEY
}

/** Persisted runtime state. Every field is the outcome of a real attempt. */
data class ConnectorRuntime(
    val connectorId: String,
    val status: ConnectorStatus,
    val enabled: Boolean,
    val lastAttemptEpochMs: Long? = null,
    val lastSuccessEpochMs: Long? = null,
    val lastError: String? = null,
    val httpCode: Int? = null,
    val indicatorCount: Int = 0,
    val etag: String? = null,
    val lastModified: String? = null,
    val nextAllowedEpochMs: Long? = null,
    val consecutiveFailures: Int = 0,
    val lastSummary: String? = null,
    val latencyMs: Long? = null
) {
    companion object {
        fun initial(spec: ConnectorSpec) = ConnectorRuntime(
            connectorId = spec.id,
            status = when {
                spec.requiresKey -> ConnectorStatus.NOT_CONFIGURED
                !spec.implemented -> ConnectorStatus.NOT_IMPLEMENTED
                spec.defaultEnabled -> ConnectorStatus.DEGRADED
                else -> ConnectorStatus.DISABLED
            },
            enabled = spec.implemented && !spec.requiresKey && spec.defaultEnabled,
            lastSummary = if (spec.defaultEnabled) "awaiting first sync" else null
        )
    }
}

/** Spec + runtime + derived freshness, ready for the UI. */
data class ConnectorSnapshot(
    val spec: ConnectorSpec,
    val runtime: ConnectorRuntime,
    val nowEpochMs: Long
) {
    val effectiveStatus: ConnectorStatus
        get() {
            val base = runtime.status
            if (spec.requiresKey && runtime.lastSuccessEpochMs == null) return ConnectorStatus.NOT_CONFIGURED
            if (!spec.implemented) return ConnectorStatus.NOT_IMPLEMENTED
            if (!runtime.enabled && base != ConnectorStatus.SYNCING) return ConnectorStatus.DISABLED
            if (base == ConnectorStatus.CONNECTED && isStale) return ConnectorStatus.DEGRADED
            return base
        }

    val lastSuccessAgeMs: Long?
        get() = runtime.lastSuccessEpochMs?.let { (nowEpochMs - it).coerceAtLeast(0L) }

    /**
     * Stale means: we have no successful sync, or the last success is older than twice the
     * declared cache TTL. Staleness is surfaced, never hidden behind a green pill.
     */
    val isStale: Boolean
        get() {
            val last = runtime.lastSuccessEpochMs ?: return runtime.status == ConnectorStatus.CONNECTED
            return nowEpochMs - last > spec.cacheTtlMs * 2
        }

    val freshnessLabel: String
        get() {
            val age = lastSuccessAgeMs ?: return "never synced"
            val minutes = age / 60_000L
            return when {
                minutes < 1L -> "synced just now"
                minutes < 60L -> "synced ${minutes} min ago"
                minutes < 60L * 24 -> "synced ${minutes / 60} h ago"
                else -> "synced ${minutes / (60 * 24)} d ago"
            }
        }
}

/** The seven statuses the existing UI already understands, mapped from [ConnectorStatus]. */
fun ConnectorStatus.preservedLabel(): String = when (this) {
    ConnectorStatus.CONNECTED -> "CONNECTED"
    ConnectorStatus.SYNCING -> "SYNCING"
    ConnectorStatus.OFFLINE -> "OFFLINE"
    ConnectorStatus.DEGRADED -> "DEGRADED"
    ConnectorStatus.RATE_LIMITED -> "RATE LIMITED"
    ConnectorStatus.ERROR -> "ERROR"
    ConnectorStatus.DISABLED -> "DISABLED"
    ConnectorStatus.NOT_CONFIGURED -> "NOT CONFIGURED"
    ConnectorStatus.NOT_IMPLEMENTED -> "NOT IMPLEMENTED"
}

enum class IndicatorKind {
    URL,
    DOMAIN,
    HASH_SHA256,
    IP,
    CVE,
    MALWARE_FAMILY,
    ALERT,
    /** SHA-1 of a TLS certificate seen in malware C2 infrastructure (SSLBL). */
    CERT_SHA1,
    /** JA3 TLS client fingerprint (SSLBL). */
    JA3,
    /** IPv4 network in CIDR form (FireHOL, Spamhaus DROP). Matched by containment. */
    IP_CIDR
}

/**
 * A normalized piece of intelligence with full provenance. Values are validated and canonicalised
 * before they are stored so the same indicator from two feeds cannot double count.
 */
data class ThreatIndicator(
    val kind: IndicatorKind,
    val value: String,
    val sourceId: String,
    val module: IntelligenceModule,
    val label: String,
    val confidence: Int,
    val firstSeenEpochMs: Long,
    val expiresAtEpochMs: Long,
    val attribution: String
)

data class ParsedFeed(
    val indicators: List<ThreatIndicator>,
    val rowsSeen: Int,
    val note: String = ""
)

class FeedParseException(message: String) : Exception(message)

/** Result of one HTTP sync attempt, before it is persisted. */
sealed interface SyncOutcome {
    data class Success(
        val indicators: List<ThreatIndicator>,
        val rowsSeen: Int,
        val httpCode: Int,
        val notModified: Boolean,
        val etag: String?,
        val lastModified: String?,
        val latencyMs: Long,
        val summary: String
    ) : SyncOutcome

    data class Retryable(
        val httpCode: Int?,
        val reason: String,
        val latencyMs: Long,
        val retryAfterMs: Long? = null,
        val offline: Boolean = false
    ) : SyncOutcome

    data class Failed(
        val httpCode: Int?,
        val reason: String,
        val latencyMs: Long
    ) : SyncOutcome

    data object NotConfigured : SyncOutcome

    data object Skipped : SyncOutcome
}

/** Result of one native connector probe. */
data class ProbeResult(
    val available: Boolean,
    val status: ConnectorStatus,
    val summary: String,
    val details: List<Pair<String, String>> = emptyList(),
    val restriction: String? = null
)

/** Per-module roll-up used by the map detail sheet and the verification report. */
data class ConnectorModuleSummary(
    val module: IntelligenceModule,
    val total: Int,
    val implemented: Int,
    val connected: Int,
    val degraded: Int,
    val notConfigured: Int,
    val lastSuccessEpochMs: Long?
)


/**
 * One on-demand intelligence query. `value` is validated and canonicalised before any request is
 * made; nothing is fetched for a malformed value.
 */
data class LookupQuery(
    val field: LookupField,
    val value: String
)

/** One labelled fact returned by a lookup connector, shown verbatim in the evidence sheet. */
data class LookupEvidence(
    val label: String,
    val value: String
)

/**
 * A single connector's answer about a query.
 *
 * [found] means the provider returned a record for the value. It is deliberately not the same as
 * "malicious": an OSV record means a vulnerable package version exists, while a CIRCL hit means
 * the file is publicly known. [riskScore] is produced by local deterministic rules, never by the
 * provider, and [attribution] always names the source so nothing is presented anonymously.
 */
data class LookupFinding(
    val connectorId: String,
    val connectorName: String,
    val provider: String,
    val module: IntelligenceModule,
    val query: LookupQuery,
    val found: Boolean,
    val riskScore: Int,
    val headline: String,
    val evidence: List<LookupEvidence>,
    val attribution: String,
    val fetchedAtEpochMs: Long,
    val fromCache: Boolean = false,
    val httpCode: Int? = null,
    val limitation: String? = null,
    val error: String? = null
)

/** Result of running every applicable lookup connector for one value. */
data class LookupReport(
    val query: LookupQuery,
    val findings: List<LookupFinding>,
    val offline: Boolean,
    val notes: List<String>
) {
    val anyFound: Boolean get() = findings.any { it.found }
    val maxRisk: Int get() = findings.maxOfOrNull { it.riskScore } ?: 0
}
