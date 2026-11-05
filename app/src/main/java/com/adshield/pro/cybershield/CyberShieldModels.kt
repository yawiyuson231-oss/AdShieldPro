package com.adshield.pro.cybershield

/**
 * CyberShield AI — pure Kotlin data models (no Android dependencies).
 *
 * Every item displayed by the dashboard carries an explicit [CsDataSource] so the
 * UI can never present external intelligence, local checks or demo samples as
 * if they were events detected on this device.
 */

enum class CsSeverity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

enum class CsDataSource(val label: String) {
    /** A real DNS event observed by the on-device VPN service. */
    ON_DEVICE("On-device"),
    /** A real local security configuration check. */
    LOCAL_CHECK("Local check"),
    /** Verified third-party threat intelligence (attributed, timestamped). */
    EXTERNAL_INTEL("External intel"),
    /** Explicitly user-enabled sample data. Never mixed into real counters. */
    DEMO("Demo")
}

enum class CsEventAction { BLOCKED, ALLOWED, FLAGGED }

enum class CsLoadState { NEVER_LOADED, LOADING, LIVE, CACHED, ERROR, DISABLED }

/** Pure projection of a persisted DNS log row (mapped by the Android layer). */
data class DnsEventSnapshot(
    val id: Long,
    val timestampEpochMs: Long,
    val domain: String,
    val queryType: String,
    val isBlocked: Boolean,
    val category: String?,
    val matchedRule: String?,
    val sourceList: String,
    val latencyMs: Int,
    val protocolUsed: String,
    val appPackageName: String? = null,
    val appName: String? = null
)

/** A normalized security event for the threat overview, feed and threat list. */
data class ThreatEvent(
    val id: String,
    val timestampEpochMs: Long,
    val domain: String,
    val severity: CsSeverity,
    val action: CsEventAction,
    val category: String,
    val description: String,
    val source: CsDataSource,
    val sourceDetail: String,
    val matchedRule: String? = null,
    val appName: String? = null,
    val appPackageName: String? = null,
    val confidence: Double? = null,
    val evidence: List<String> = emptyList()
)

data class ThreatStats(
    val windowLabel: String,
    val totalEvents: Long,
    val blocked: Long,
    val allowed: Long,
    val bySeverity: Map<CsSeverity, Long>,
    val activeThreatDomains: Int,
    val criticalCount: Long,
    val highCount: Long
)

/** One verified external indicator (Feodo Tracker botnet C2 entry). */
data class IntelIndicator(
    val ip: String,
    val port: Int,
    val status: String,
    val countryCode: String?,
    val asName: String?,
    val asNumber: Int?,
    val malware: String?,
    val firstSeenUtc: String?,
    val lastOnline: String?
)

data class IntelSnapshot(
    val indicators: List<IntelIndicator>,
    val fetchedAtEpochMs: Long,
    val feedName: String,
    val feedUrl: String,
    val license: String
)

data class IntelUiState(
    val loadState: CsLoadState = CsLoadState.NEVER_LOADED,
    val snapshot: IntelSnapshot? = null,
    val error: String? = null,
    val enabled: Boolean = true
)

/** Indicators grouped to country level for the world map (never device location). */
data class CountryThreatCluster(
    val countryCode: String,
    val countryName: String,
    val lat: Double,
    val lon: Double,
    val count: Int,
    val onlineCount: Int,
    val families: List<Pair<String, Int>>,
    val samples: List<IntelIndicator>
)

enum class CloudIndicator(val label: String) {
    OPERATIONAL("Operational"),
    DEGRADED("Degraded"),
    PARTIAL_OUTAGE("Partial outage"),
    MAJOR_OUTAGE("Major outage"),
    MAINTENANCE("Maintenance"),
    UNKNOWN("Unknown")
}

data class CloudProviderStatus(
    val id: String,
    val name: String,
    val statusUrl: String,
    val indicator: CloudIndicator = CloudIndicator.UNKNOWN,
    val description: String = "",
    val providerUpdatedAt: String? = null,
    val fetchedAtEpochMs: Long? = null,
    val loadState: CsLoadState = CsLoadState.NEVER_LOADED,
    val error: String? = null,
    val isCustom: Boolean = false,
    val hasToken: Boolean = false
)

/** Real device security signals collected through public Android APIs. */
data class DeviceSecuritySnapshot(
    val collectedAtEpochMs: Long = 0L,
    val deviceModel: String = "",
    val androidVersion: String = "",
    val sdkInt: Int = 0,
    val securityPatch: String? = null,
    val patchAgeDays: Int? = null,
    val screenLockSecure: Boolean? = null,
    val storageEncrypted: Boolean? = null,
    val adbEnabled: Boolean? = null,
    val developerOptionsEnabled: Boolean? = null,
    val totalApps: Int? = null,
    val userApps: Int? = null,
    val sideloadedApps: Int? = null,
    val sideloadedPackages: List<String> = emptyList(),
    val networkTransport: String? = null,
    val networkValidated: Boolean? = null,
    val networkMetered: Boolean? = null,
    val dnsServers: List<String> = emptyList(),
    val systemVpnActive: Boolean? = null,
    val unavailable: List<String> = emptyList()
)

enum class ComplianceStatus { PASS, WARN, FAIL, UNAVAILABLE }

data class ComplianceCheck(
    val id: String,
    val title: String,
    val framework: String,
    val status: ComplianceStatus,
    val detail: String,
    val recommendation: String? = null
)

data class ComplianceReport(
    val generatedAtEpochMs: Long,
    val deviceModel: String,
    val androidVersion: String,
    val checks: List<ComplianceCheck>,
    val score: Int,
    val passed: Int,
    val warnings: Int,
    val failed: Int,
    val unavailable: Int
)

enum class ShieldMode { OFF, STARTING, ACTIVE, PAUSED, ERROR }

data class ShieldState(
    val mode: ShieldMode,
    val headline: String,
    val subtitle: String,
    val recentBlocked: Int,
    val error: String? = null
)

/** Explainable local heuristic finding — flagged, never auto-blocked. */
data class AnomalyFinding(
    val id: String,
    val kind: String,
    val severity: CsSeverity,
    val title: String,
    val detail: String,
    val evidence: List<String>,
    val domain: String?,
    val firstSeenEpochMs: Long,
    val lastSeenEpochMs: Long,
    val eventCount: Int
)

/** Related events correlated into one investigable incident. */
data class ThreatIncident(
    val key: String,
    val domain: String,
    val severity: CsSeverity,
    val eventCount: Int,
    val blockedCount: Int,
    val firstSeenEpochMs: Long,
    val lastSeenEpochMs: Long,
    val sources: List<String>,
    val apps: List<String>,
    val summary: String,
    val events: List<ThreatEvent>
)

data class CategoryCount(val category: String, val count: Long, val share: Float)

data class HourBucket(val hourStartEpochMs: Long, val blocked: Long, val allowed: Long)

data class ProtocolCount(val protocol: String, val count: Long, val share: Float)

data class NetworkSummary(
    val windowEvents: Long,
    val windowBlocked: Long,
    val averageLatencyMs: Int,
    val cachedShare: Float,
    val protocols: List<ProtocolCount>,
    val upstreamLabel: String,
    val encryptedUpstream: Boolean,
    val protectionActive: Boolean,
    val blockedHistory: List<ThreatEvent>
)

/** Pure subset of app settings needed by the compliance evaluator. */
data class CsSettingsSnapshot(
    val vpnStatus: String,
    val protectionMode: String,
    val resolverProtocol: String,
    val aetherEnabled: Boolean,
    val aetherAutoBlock: Boolean,
    val autoUpdateFilters: Boolean,
    val detailedLogging: Boolean,
    val logRetentionDays: Int,
    val loadedRuleCount: Int
)
