package com.adshield.pro.domain.intelligence

import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.battery.BatteryTelemetry
import com.adshield.pro.engine.security.QuarantinedItem
import com.adshield.pro.engine.security.SecurityScanRecord
import kotlinx.serialization.Serializable

/**
 * OMNISHIELD X — Live Intelligence Map domain model.
 *
 * This file is the single vocabulary shared by every layer of the feature:
 * module services publish [IntelligenceEvent]s, the aggregator turns them plus real runtime
 * readings into [ModuleSnapshot]s, and the map renders only those values.
 *
 * Honesty contract enforced by this model (and asserted in `IntelligenceMapTestSuite`):
 *  - There is no "simulation" event type and no constructor that can create evidence.
 *  - Every event type is bound to exactly one module and one default severity.
 *  - A module state is only WARNING/CRITICAL when a *verified* reading or an unmitigated
 *    stored event says so. Missing data is reported as OFFLINE/DISABLED with a reason,
 *    never as "normal".
 */

/** The seven module nodes plus the central OMNISHIELD X intelligence node. */
enum class IntelligenceModule(
    val id: String,
    val displayName: String,
    val shortLabel: String,
    val purpose: String
) {
    CORE(
        id = "core",
        displayName = "OMNISHIELD X",
        shortLabel = "CORE",
        purpose = "Correlates every module signal into one live picture"
    ),
    CYBER_DEFENSE(
        id = "cyber",
        displayName = "Cyber Defense",
        shortLabel = "CYBER",
        purpose = "APK, file and link threat scanning with on-device evidence"
    ),
    FINANCIAL_DEFENSE(
        id = "financial",
        displayName = "Financial Defense",
        shortLabel = "FIN",
        purpose = "Payment-link, wallet and invoice scam analysis"
    ),
    PRIVACY_DEFENSE(
        id = "privacy",
        displayName = "Privacy Defense",
        shortLabel = "PRIV",
        purpose = "Permission exposure, tracker and cookie policy auditing"
    ),
    NETWORK_DEFENSE(
        id = "network",
        displayName = "Network Defense",
        shortLabel = "NET",
        purpose = "Local DNS firewall, resolver integrity and real block events"
    ),
    DEVICE_INTELLIGENCE(
        id = "device",
        displayName = "Device Intelligence",
        shortLabel = "DEV",
        purpose = "Measured battery, thermal and power telemetry"
    ),
    EMERGENCY_INTELLIGENCE(
        id = "emergency",
        displayName = "Emergency Intelligence",
        shortLabel = "EMRG",
        purpose = "Protection readiness and allowlist-only lockdown policy"
    ),
    AUTOMATION_CORE(
        id = "automation",
        displayName = "Automation Core",
        shortLabel = "AUTO",
        purpose = "Scheduled WorkManager jobs that keep protection current"
    );

    val isNode: Boolean get() = this != CORE

    companion object {
        /** Node modules in stable map order. CORE is drawn as the centre hub. */
        val nodes: List<IntelligenceModule> = entries.filter { it.isNode }

        fun fromIdOrNull(raw: String?): IntelligenceModule? =
            entries.firstOrNull { it.id == raw || it.name == raw }
    }
}

/** Visual and semantic severity. [rank] orders filters and incident sorting. */
enum class IntelligenceSeverity(val rank: Int, val label: String) {
    INFO(0, "INFO"),
    NOTICE(1, "NOTICE"),
    WARNING(2, "WARNING"),
    CRITICAL(3, "CRITICAL");

    val isAlerting: Boolean get() = rank >= NOTICE.rank

    companion object {
        fun fromNameOrNull(raw: String?): IntelligenceSeverity? =
            entries.firstOrNull { it.name == raw }
    }
}

/** The six operational states requested for module nodes. */
enum class IntelligenceModuleState(val label: String, val description: String) {
    NORMAL("NORMAL", "Operating normally; no issue detected"),
    MONITORING("MONITORING", "Actively observing real system activity"),
    WARNING("WARNING", "A verified issue requires attention"),
    CRITICAL("CRITICAL", "A serious verified issue is active"),
    OFFLINE("OFFLINE", "The module cannot observe its data source"),
    DISABLED("DISABLED", "The user turned this capability off");

    val isProblem: Boolean get() = this == WARNING || this == CRITICAL
}

/**
 * The unified event catalogue. Each entry names the one module that can publish it and the
 * severity it carries unless a verifier escalates it.
 *
 * [mitigatedByDefault] marks events where the protection layer already handled the condition
 * (a malicious domain was blocked). Those stay in the feed and on the map but do not raise the
 * module into WARNING by themselves — the issue was resolved by the block.
 */
enum class IntelligenceEventType(
    val code: String,
    val label: String,
    val module: IntelligenceModule,
    val defaultSeverity: IntelligenceSeverity,
    val mitigatedByDefault: Boolean = false
) {
    NETWORK_THREAT_BLOCKED(
        "network.threat_blocked",
        "Malicious domain blocked",
        IntelligenceModule.NETWORK_DEFENSE,
        IntelligenceSeverity.WARNING,
        mitigatedByDefault = true
    ),
    NETWORK_PROTECTION_STARTED(
        "network.protection_started",
        "DNS protection started",
        IntelligenceModule.NETWORK_DEFENSE,
        IntelligenceSeverity.INFO
    ),
    NETWORK_PROTECTION_STOPPED(
        "network.protection_stopped",
        "DNS protection stopped",
        IntelligenceModule.NETWORK_DEFENSE,
        IntelligenceSeverity.WARNING
    ),
    NETWORK_FILTERING_PAUSED(
        "network.filtering_paused",
        "DNS filtering paused",
        IntelligenceModule.NETWORK_DEFENSE,
        IntelligenceSeverity.WARNING
    ),
    NETWORK_RESOLVER_ERROR(
        "network.resolver_error",
        "Resolver reported an error",
        IntelligenceModule.NETWORK_DEFENSE,
        IntelligenceSeverity.CRITICAL
    ),
    NETWORK_RULES_MISSING(
        "network.rules_missing",
        "No filter rules loaded",
        IntelligenceModule.NETWORK_DEFENSE,
        IntelligenceSeverity.WARNING
    ),
    CYBER_SCAN_FINDING(
        "cyber.scan_finding",
        "Threat scan finding",
        IntelligenceModule.CYBER_DEFENSE,
        IntelligenceSeverity.WARNING
    ),
    CYBER_SCAN_CLEAN(
        "cyber.scan_clean",
        "Threat scan completed clean",
        IntelligenceModule.CYBER_DEFENSE,
        IntelligenceSeverity.INFO
    ),
    CYBER_QUARANTINE_ADDED(
        "cyber.quarantine_added",
        "File quarantined",
        IntelligenceModule.CYBER_DEFENSE,
        IntelligenceSeverity.NOTICE,
        mitigatedByDefault = true
    ),
    FINANCIAL_PAYMENT_RISK(
        "financial.payment_risk",
        "Payment link risk",
        IntelligenceModule.FINANCIAL_DEFENSE,
        IntelligenceSeverity.WARNING
    ),
    FINANCIAL_LINK_CLEAN(
        "financial.link_clean",
        "Payment link scanned clean",
        IntelligenceModule.FINANCIAL_DEFENSE,
        IntelligenceSeverity.INFO
    ),
    PRIVACY_PERMISSION_FINDING(
        "privacy.permission_finding",
        "Permission exposure finding",
        IntelligenceModule.PRIVACY_DEFENSE,
        IntelligenceSeverity.WARNING
    ),
    PRIVACY_AUDIT_CLEAN(
        "privacy.audit_clean",
        "Permission audit clean",
        IntelligenceModule.PRIVACY_DEFENSE,
        IntelligenceSeverity.INFO
    ),
    PRIVACY_SETTING_CHANGED(
        "privacy.setting_changed",
        "Privacy policy changed",
        IntelligenceModule.PRIVACY_DEFENSE,
        IntelligenceSeverity.INFO
    ),
    DEVICE_THERMAL_WARNING(
        "device.thermal_warning",
        "Battery temperature above threshold",
        IntelligenceModule.DEVICE_INTELLIGENCE,
        IntelligenceSeverity.WARNING
    ),
    DEVICE_THERMAL_RECOVERED(
        "device.thermal_recovered",
        "Battery temperature back to normal",
        IntelligenceModule.DEVICE_INTELLIGENCE,
        IntelligenceSeverity.INFO
    ),
    DEVICE_HEALTH_ALERT(
        "device.health_alert",
        "Battery health report",
        IntelligenceModule.DEVICE_INTELLIGENCE,
        IntelligenceSeverity.WARNING
    ),
    DEVICE_TELEMETRY_UNAVAILABLE(
        "device.telemetry_unavailable",
        "Device telemetry unavailable",
        IntelligenceModule.DEVICE_INTELLIGENCE,
        IntelligenceSeverity.NOTICE
    ),
    EMERGENCY_LOCKDOWN_ON(
        "emergency.lockdown_on",
        "Emergency lockdown engaged",
        IntelligenceModule.EMERGENCY_INTELLIGENCE,
        IntelligenceSeverity.WARNING
    ),
    EMERGENCY_LOCKDOWN_OFF(
        "emergency.lockdown_off",
        "Emergency lockdown released",
        IntelligenceModule.EMERGENCY_INTELLIGENCE,
        IntelligenceSeverity.NOTICE
    ),
    EMERGENCY_READINESS_DEGRADED(
        "emergency.readiness_degraded",
        "Protection readiness degraded",
        IntelligenceModule.EMERGENCY_INTELLIGENCE,
        IntelligenceSeverity.WARNING
    ),
    AUTOMATION_JOB_OK(
        "automation.job_ok",
        "Scheduled job completed",
        IntelligenceModule.AUTOMATION_CORE,
        IntelligenceSeverity.INFO
    ),
    AUTOMATION_JOB_FAILED(
        "automation.job_failed",
        "Scheduled job failed",
        IntelligenceModule.AUTOMATION_CORE,
        IntelligenceSeverity.WARNING
    ),
    AUTOMATION_SETTING_CHANGED(
        "automation.setting_changed",
        "Automation schedule changed",
        IntelligenceModule.AUTOMATION_CORE,
        IntelligenceSeverity.INFO
    );

    companion object {
        fun fromCodeOrNull(raw: String?): IntelligenceEventType? =
            entries.firstOrNull { it.code == raw }
    }
}

/**
 * Actions the map may offer. Every entry maps to a real, already-implemented app capability;
 * there is deliberately no "block", "fix" or "clean" action here that the app cannot perform.
 */
enum class IntelligenceAction(
    val label: String,
    val requiresConfirmation: Boolean,
    val description: String
) {
    OPEN_MODULE("Open module", false, "Jump to the screen that owns this data"),
    START_PROTECTION("Start protection", true, "Connect the local DNS firewall (Android asks for VPN consent)"),
    STOP_PROTECTION("Stop protection", true, "Disconnect the local DNS firewall"),
    TOGGLE_LOCKDOWN("Emergency lockdown", true, "Only explicit allowlist entries will resolve"),
    SYNC_FILTERS("Sync filter lists", false, "Download enabled lists now using WorkManager"),
    RUN_APP_AUDIT("Audit installed apps", false, "Re-run the permission risk audit"),
    RUN_DEVICE_DIAGNOSIS("Run battery diagnosis", false, "Re-run the measured battery diagnostics"),
    SCHEDULE_SCAN("Scheduled scan", false, "Open automation controls for the periodic scan");

    companion object {
        fun fromNameOrNull(raw: String?): IntelligenceAction? =
            entries.firstOrNull { it.name == raw }

        /** Controls exposed per module, derived from what that module can actually do. */
        fun forModule(module: IntelligenceModule): List<IntelligenceAction> = when (module) {
            IntelligenceModule.CORE -> emptyList()
            IntelligenceModule.CYBER_DEFENSE -> listOf(OPEN_MODULE, RUN_APP_AUDIT)
            IntelligenceModule.FINANCIAL_DEFENSE -> listOf(OPEN_MODULE)
            IntelligenceModule.PRIVACY_DEFENSE -> listOf(OPEN_MODULE, RUN_APP_AUDIT)
            IntelligenceModule.NETWORK_DEFENSE -> listOf(
                OPEN_MODULE, START_PROTECTION, STOP_PROTECTION, SYNC_FILTERS
            )
            IntelligenceModule.DEVICE_INTELLIGENCE -> listOf(OPEN_MODULE, RUN_DEVICE_DIAGNOSIS)
            IntelligenceModule.EMERGENCY_INTELLIGENCE -> listOf(
                OPEN_MODULE, TOGGLE_LOCKDOWN, START_PROTECTION
            )
            IntelligenceModule.AUTOMATION_CORE -> listOf(OPEN_MODULE, SYNC_FILTERS, SCHEDULE_SCAN)
        }
    }
}

/** Where a displayed metric value comes from. Nothing is ever rendered without one. */
@Serializable
enum class IntelligenceMetricSource(val label: String) {
    MEASURED("measured"),
    COMPUTED("computed"),
    CONFIGURED("configured"),
    UNAVAILABLE("unavailable")
}

@Serializable
data class IntelligenceMetric(
    val label: String,
    val value: String,
    val source: IntelligenceMetricSource,
    val detail: String = ""
)

/**
 * One stored, structured event. [evidence] is always derived from a real observation
 * (DNS log row, scan record, battery reading, worker result, settings transition).
 */
data class IntelligenceEvent(
    val id: Long = 0L,
    val module: IntelligenceModule,
    val type: IntelligenceEventType,
    val severity: IntelligenceSeverity,
    val timestampEpochMs: Long,
    val title: String,
    val description: String,
    val evidence: String,
    val evidenceRef: String? = null,
    val relatedObjectIds: List<String> = emptyList(),
    val actions: List<IntelligenceAction> = emptyList(),
    val metrics: List<IntelligenceMetric> = emptyList()
) {
    val isMitigated: Boolean get() = type.mitigatedByDefault
    val countsTowardAlerts: Boolean get() = severity.isAlerting && !type.mitigatedByDefault
}

/** Stable snapshot of one module, recomputed from real inputs and stored events only. */
data class ModuleSnapshot(
    val module: IntelligenceModule,
    val state: IntelligenceModuleState,
    val stateDetail: String,
    val latestEvent: IntelligenceEvent?,
    val activeAlerts: Int,
    val lastUpdateEpochMs: Long?,
    val metrics: List<IntelligenceMetric>,
    val actions: List<IntelligenceAction>,
    val unavailableReason: String? = null
) {
    val stateLabel: String get() = state.label

    /** Compact line used inside the node and the command panel. */
    val latestEventLabel: String
        get() = latestEvent?.title ?: when (state) {
            IntelligenceModuleState.DISABLED -> "Turned off by user"
            IntelligenceModuleState.OFFLINE -> unavailableReason ?: "No data source"
            else -> "No event recorded yet"
        }
}

/** Which slice of the event store the user is looking at. */
enum class IntelligenceTimeRange(val label: String, val durationMs: Long?) {
    LIVE_15M("15 min", 15 * 60_000L),
    HOUR_1("1 hour", 60 * 60_000L),
    HOURS_24("24 hours", 24 * 60 * 60_000L),
    DAYS_7("7 days", 7 * 24 * 60 * 60_000L),
    ALL("All stored", null)
}

/** Event feed filters. Pure and unit-tested (see IntelligenceMapTestSuite). */
data class IntelligenceFilters(
    val module: IntelligenceModule? = null,
    val severity: IntelligenceSeverity? = null,
    val range: IntelligenceTimeRange = IntelligenceTimeRange.HOURS_24,
    val query: String = ""
) {
    val isActive: Boolean
        get() = module != null || severity != null || query.isNotBlank() || range != IntelligenceTimeRange.HOURS_24

    fun windowStartMs(nowEpochMs: Long): Long? =
        range.durationMs?.let { (nowEpochMs - it).coerceAtLeast(0L) }

    fun matches(event: IntelligenceEvent, nowEpochMs: Long): Boolean {
        if (module != null && event.module != module) return false
        if (severity != null && event.severity != severity) return false
        val start = windowStartMs(nowEpochMs)
        if (start != null && event.timestampEpochMs < start) return false
        if (query.isNotBlank()) {
            val needle = query.trim()
            val haystack = buildString {
                append(event.title).append(' ')
                append(event.description).append(' ')
                append(event.module.displayName).append(' ')
                append(event.module.shortLabel).append(' ')
                append(event.type.label).append(' ')
                append(event.evidence)
            }
            if (!haystack.contains(needle, ignoreCase = true)) return false
        }
        return true
    }

    companion object {
        val DEFAULT = IntelligenceFilters()
    }
}

/**
 * Every real reading the aggregator is allowed to use. Built by the ViewModel from live app
 * state (VPN runtime, preferences, scan journal, battery telemetry, DNS counters).
 */
data class IntelligenceInputs(
    val nowEpochMs: Long,
    val vpnStatus: VpnStatus = VpnStatus.DISCONNECTED,
    /** True when the user asked protection to stay on (it should be connected). */
    val protectionExpected: Boolean = false,
    val connectedSinceEpochMs: Long? = null,
    val vpnLastError: String? = null,
    val protectionMode: ProtectionMode = ProtectionMode.STANDARD,
    val loadedRuleCount: Int = 0,
    val sessionTotalQueries: Long = 0L,
    val sessionBlockedQueries: Long = 0L,
    val sessionCachedQueries: Long = 0L,
    val averageLatencyMs: Int = 0,
    val resolverLabel: String = "",
    val dnsProtocolLabel: String = "",
    val emergencyAllowlistOnly: Boolean = false,
    val detailedDnsLogging: Boolean = true,
    val autoUpdateFiltersEnabled: Boolean = true,
    val lastFilterUpdateEpochMs: Long = 0L,
    val scheduledScanEnabled: Boolean = false,
    val scheduledScanIntervalHours: Int = 24,
    val smartAutoOptimizeEnabled: Boolean = true,
    val browserCosmeticFilteringEnabled: Boolean = true,
    val browserBlockThirdPartyCookies: Boolean = true,
    val browserSiteExceptionCount: Int = 0,
    val perAppDnsRuleCount: Int = 0,
    val trackerBlocksRecent: Long = 0L,
    val malwareBlocksTotal: Long = 0L,
    val filterSourceCount: Int = 0,
    val scans: List<SecurityScanRecord> = emptyList(),
    val quarantine: List<QuarantinedItem> = emptyList(),
    val batteryTelemetry: BatteryTelemetry? = null,
    val thermalWarningCelsius: Float = 41f,
    val moduleUnavailableReasons: Map<IntelligenceModule, String> = emptyMap()
) {
    companion object {
        fun empty(nowEpochMs: Long) = IntelligenceInputs(nowEpochMs = nowEpochMs)
    }
}

/** A derived, human-readable incident line for the command panel. */
data class IntelligenceIncident(
    val module: IntelligenceModule,
    val severity: IntelligenceSeverity,
    val title: String,
    val detail: String,
    val timestampEpochMs: Long,
    val eventId: Long?
)

/** The complete, render-ready system state. Nothing in here is invented by the UI. */
data class IntelligenceSystemState(
    val generatedAtEpochMs: Long,
    val buildDurationMs: Long,
    val overallState: IntelligenceModuleState,
    val overallLabel: String,
    val healthPercent: Int,
    val modules: List<ModuleSnapshot>,
    val incidents: List<IntelligenceIncident>,
    val filteredEvents: List<IntelligenceEvent>,
    val storedEventCount: Int,
    val filters: IntelligenceFilters,
    val commandMetrics: List<IntelligenceMetric>
) {
    fun snapshotFor(module: IntelligenceModule): ModuleSnapshot? = modules.firstOrNull { it.module == module }

    val activeIssueCount: Int get() = incidents.size

    val monitoringModuleCount: Int
        get() = modules.count {
            it.module.isNode && (it.state == IntelligenceModuleState.MONITORING || it.state == IntelligenceModuleState.NORMAL)
        }

    val disabledModuleCount: Int
        get() = modules.count { it.module.isNode && it.state == IntelligenceModuleState.DISABLED }

    val offlineModuleCount: Int
        get() = modules.count { it.module.isNode && it.state == IntelligenceModuleState.OFFLINE }
}

/**
 * Resolution-independent node position, stored in the map's own DataStore file.
 * Values are clamped to the [0,1] world square so a rotated or resized screen can never push a
 * node off the visible canvas.
 */
@Serializable
data class NodePosition(val x: Float, val y: Float) {
    fun clamped(): NodePosition = NodePosition(x.coerceIn(0f, 1f), y.coerceIn(0f, 1f))

    companion object {
        fun fromRaw(x: Float, y: Float): NodePosition? {
            if (x.isNaN() || y.isNaN() || x.isInfinite() || y.isInfinite()) return null
            return NodePosition(x, y).clamped()
        }
    }
}
