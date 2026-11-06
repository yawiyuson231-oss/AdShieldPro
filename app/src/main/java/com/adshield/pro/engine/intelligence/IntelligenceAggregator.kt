package com.adshield.pro.engine.intelligence

import com.adshield.pro.domain.intelligence.IntelligenceEvent
import com.adshield.pro.domain.intelligence.IntelligenceFilters
import com.adshield.pro.domain.intelligence.IntelligenceIncident
import com.adshield.pro.domain.intelligence.IntelligenceInputs
import com.adshield.pro.domain.intelligence.IntelligenceMetric
import com.adshield.pro.domain.intelligence.IntelligenceMetricSource
import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.domain.intelligence.IntelligenceModuleState
import com.adshield.pro.domain.intelligence.IntelligenceSeverity
import com.adshield.pro.domain.intelligence.IntelligenceSystemState
import com.adshield.pro.domain.intelligence.ModuleSnapshot
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.battery.BatteryHealthStatus
import com.adshield.pro.engine.battery.BatteryReadingSource
import com.adshield.pro.engine.security.ScanKind
import com.adshield.pro.engine.security.SecurityLevel
import kotlin.math.roundToInt

/**
 * Pure derivation of the whole map state from real inputs + stored events.
 *
 * The aggregator never invents an event. When a module has no stored event it may still be in
 * WARNING/CRITICAL because a *live measured reading* says so (battery temperature, VPN state,
 * missing rules). Those cases are surfaced as derived incidents, which is why the command panel
 * and the node can never disagree.
 */
object IntelligenceAggregator {

    const val ALERT_WINDOW_MS = 24L * 60L * 60L * 1_000L
    const val SCAN_FRESH_WINDOW_MS = 24L * 60L * 60L * 1_000L
    const val STALE_SCAN_WINDOW_MS = 30L * 24L * 60L * 60L * 1_000L
    const val MAX_FEED_EVENTS = 400
    const val MAX_INCIDENTS = 30
    const val DEFAULT_THERMAL_WARNING_CELSIUS = 41f

    private const val PENALTY_CRITICAL = 22
    private const val PENALTY_WARNING = 12
    private const val PENALTY_OFFLINE = 10
    private const val PENALTY_DISABLED = 3

    /** Builds the complete render-ready state. [buildDurationMs] is measured by the caller. */
    fun buildState(
        inputs: IntelligenceInputs,
        events: List<IntelligenceEvent>,
        filters: IntelligenceFilters,
        buildDurationMs: Long
    ): IntelligenceSystemState {
        val now = inputs.nowEpochMs
        val ordered = events.sortedByDescending { it.timestampEpochMs }
        val nodeSnapshots = IntelligenceModule.nodes.map { module ->
            snapshotFor(module, inputs, ordered, now)
        }
        val core = coreSnapshot(inputs, ordered, nodeSnapshots, now)
        val modules = listOf(core) + nodeSnapshots
        val derived = derivedIncidents(inputs, ordered, now)
        val storedIncidents = storedIncidents(ordered, now)
        val mergedIncidents = mergeIncidents(derived, storedIncidents)
        val health = healthPercent(nodeSnapshots)
        val overall = worstState(nodeSnapshots)
        return IntelligenceSystemState(
            generatedAtEpochMs = now,
            buildDurationMs = buildDurationMs.coerceAtLeast(0L),
            overallState = overall,
            overallLabel = overallLabel(overall, nodeSnapshots, mergedIncidents),
            healthPercent = health,
            modules = modules,
            incidents = mergedIncidents,
            filteredEvents = ordered.filter { filters.matches(it, now) }.take(MAX_FEED_EVENTS),
            storedEventCount = events.size,
            filters = filters,
            commandMetrics = commandMetrics(inputs, ordered, modules, health, now)
        )
    }

    // ------------------------------------------------------------------ module snapshots

    private fun snapshotFor(
        module: IntelligenceModule,
        inputs: IntelligenceInputs,
        events: List<IntelligenceEvent>,
        now: Long
    ): ModuleSnapshot = when (module) {
        IntelligenceModule.CYBER_DEFENSE -> cyberSnapshot(inputs, events, now)
        IntelligenceModule.FINANCIAL_DEFENSE -> financialSnapshot(inputs, events, now)
        IntelligenceModule.PRIVACY_DEFENSE -> privacySnapshot(inputs, events, now)
        IntelligenceModule.NETWORK_DEFENSE -> networkSnapshot(inputs, events, now)
        IntelligenceModule.DEVICE_INTELLIGENCE -> deviceSnapshot(inputs, events, now)
        IntelligenceModule.EMERGENCY_INTELLIGENCE -> emergencySnapshot(inputs, events, now)
        IntelligenceModule.AUTOMATION_CORE -> automationSnapshot(inputs, events, now)
        IntelligenceModule.CORE -> coreSnapshot(inputs, events, emptyList(), now)
    }

    private fun cyberSnapshot(
        inputs: IntelligenceInputs,
        events: List<IntelligenceEvent>,
        now: Long
    ): ModuleSnapshot {
        val scans = inputs.scans.filter { record ->
            when (record.kind) {
                ScanKind.FILE, ScanKind.APK -> true
                ScanKind.URL -> !FinancialTargetClassifier.isFinancialTarget(record.target, record.findings)
                ScanKind.APP_AUDIT -> false
            }
        }.sortedByDescending { it.timestampEpochMs }
        val latest = scans.firstOrNull()
        val freshFindings = scans.filter {
            it.threatLevel != SecurityLevel.CLEAN && now - it.timestampEpochMs <= SCAN_FRESH_WINDOW_MS
        }
        val state: IntelligenceModuleState
        val detail: String
        when {
            freshFindings.any { it.threatLevel == SecurityLevel.DANGEROUS } -> {
                state = IntelligenceModuleState.CRITICAL
                detail = "A dangerous verdict is less than 24 h old — review the scan evidence"
            }
            freshFindings.isNotEmpty() -> {
                state = IntelligenceModuleState.WARNING
                detail = "${freshFindings.size} suspicious verdict(s) recorded in the last 24 h"
            }
            latest == null -> {
                state = IntelligenceModuleState.NORMAL
                detail = "Scanner ready · no scan recorded yet"
            }
            now - latest.timestampEpochMs > STALE_SCAN_WINDOW_MS -> {
                state = IntelligenceModuleState.NORMAL
                detail = "Last scan ${relativeAge(now, latest.timestampEpochMs)} · nothing pending"
            }
            else -> {
                state = IntelligenceModuleState.NORMAL
                detail = "Last scan ${relativeAge(now, latest.timestampEpochMs)} · ${latest.threatLevel.name.lowercase()}"
            }
        }
        return ModuleSnapshot(
            module = IntelligenceModule.CYBER_DEFENSE,
            state = state,
            stateDetail = detail,
            latestEvent = latestEventFor(IntelligenceModule.CYBER_DEFENSE, events),
            activeAlerts = unmitigatedAlerts(IntelligenceModule.CYBER_DEFENSE, events, now),
            lastUpdateEpochMs = latest?.timestampEpochMs,
            metrics = listOf(
                metric("Scans stored", scans.size.toString(), IntelligenceMetricSource.MEASURED),
                metric("Findings 24 h", freshFindings.size.toString(), IntelligenceMetricSource.MEASURED),
                metric("Quarantined", inputs.quarantine.size.toString(), IntelligenceMetricSource.MEASURED),
                metric(
                    "Last scan",
                    latest?.let { relativeAge(now, it.timestampEpochMs) } ?: "never",
                    if (latest != null) IntelligenceMetricSource.MEASURED else IntelligenceMetricSource.UNAVAILABLE
                )
            ),
            actions = com.adshield.pro.domain.intelligence.IntelligenceAction.forModule(
                IntelligenceModule.CYBER_DEFENSE
            )
        )
    }

    private fun financialSnapshot(
        inputs: IntelligenceInputs,
        events: List<IntelligenceEvent>,
        now: Long
    ): ModuleSnapshot {
        val financialScans = inputs.scans.filter { record ->
            record.kind == ScanKind.URL &&
                FinancialTargetClassifier.isFinancialTarget(record.target, record.findings)
        }.sortedByDescending { it.timestampEpochMs }
        val latest = financialScans.firstOrNull()
        val recentRisk = financialScans.filter {
            it.threatLevel != SecurityLevel.CLEAN && now - it.timestampEpochMs <= SCAN_FRESH_WINDOW_MS
        }
        val state: IntelligenceModuleState
        val detail: String
        when {
            recentRisk.any { it.threatLevel == SecurityLevel.DANGEROUS } -> {
                state = IntelligenceModuleState.CRITICAL
                detail = "A scanned payment link is flagged dangerous"
            }
            recentRisk.isNotEmpty() -> {
                state = IntelligenceModuleState.WARNING
                detail = "${recentRisk.size} risky payment link(s) in the last 24 h"
            }
            latest == null -> {
                state = IntelligenceModuleState.NORMAL
                detail = "Analyzer ready · no payment link scanned yet"
            }
            else -> {
                state = IntelligenceModuleState.MONITORING
                detail = "Last payment link checked ${relativeAge(now, latest.timestampEpochMs)}"
            }
        }
        return ModuleSnapshot(
            module = IntelligenceModule.FINANCIAL_DEFENSE,
            state = state,
            stateDetail = detail,
            latestEvent = latestEventFor(IntelligenceModule.FINANCIAL_DEFENSE, events),
            activeAlerts = unmitigatedAlerts(IntelligenceModule.FINANCIAL_DEFENSE, events, now),
            lastUpdateEpochMs = latest?.timestampEpochMs,
            metrics = listOf(
                metric("Payment links", financialScans.size.toString(), IntelligenceMetricSource.MEASURED),
                metric("Risky 24 h", recentRisk.size.toString(), IntelligenceMetricSource.MEASURED),
                metric(
                    "Highest risk",
                    financialScans.maxOfOrNull { it.riskScore }?.let { "$it/100" } ?: "—",
                    if (financialScans.isEmpty()) IntelligenceMetricSource.UNAVAILABLE else IntelligenceMetricSource.COMPUTED
                ),
                metric(
                    "Last link",
                    latest?.let { relativeAge(now, it.timestampEpochMs) } ?: "never",
                    if (latest != null) IntelligenceMetricSource.MEASURED else IntelligenceMetricSource.UNAVAILABLE
                )
            ),
            actions = com.adshield.pro.domain.intelligence.IntelligenceAction.forModule(
                IntelligenceModule.FINANCIAL_DEFENSE
            )
        )
    }

    private fun privacySnapshot(
        inputs: IntelligenceInputs,
        events: List<IntelligenceEvent>,
        now: Long
    ): ModuleSnapshot {
        val audits = inputs.scans.filter { it.kind == ScanKind.APP_AUDIT }
            .sortedByDescending { it.timestampEpochMs }
        val latest = audits.firstOrNull()
        val elevated = audits.filter {
            it.threatLevel != SecurityLevel.CLEAN && now - it.timestampEpochMs <= SCAN_FRESH_WINDOW_MS
        }
        val browserProtected = inputs.browserCosmeticFilteringEnabled || inputs.browserBlockThirdPartyCookies
        val state: IntelligenceModuleState
        val detail: String
        when {
            !browserProtected -> {
                state = IntelligenceModuleState.DISABLED
                detail = "Cosmetic filtering and third-party cookie blocking are both off"
            }
            elevated.any { it.threatLevel == SecurityLevel.DANGEROUS } -> {
                state = IntelligenceModuleState.CRITICAL
                detail = "A permission audit found high-risk exposure"
            }
            elevated.isNotEmpty() -> {
                state = IntelligenceModuleState.WARNING
                detail = "${elevated.size} app audit(s) flagged elevated permissions"
            }
            latest == null -> {
                state = IntelligenceModuleState.NORMAL
                detail = "Auditor ready · no app audit recorded yet"
            }
            else -> {
                state = IntelligenceModuleState.MONITORING
                detail = "Last audit ${relativeAge(now, latest.timestampEpochMs)} · no fresh exposure"
            }
        }
        return ModuleSnapshot(
            module = IntelligenceModule.PRIVACY_DEFENSE,
            state = state,
            stateDetail = detail,
            latestEvent = latestEventFor(IntelligenceModule.PRIVACY_DEFENSE, events),
            activeAlerts = unmitigatedAlerts(IntelligenceModule.PRIVACY_DEFENSE, events, now),
            lastUpdateEpochMs = latest?.timestampEpochMs,
            metrics = listOf(
                metric("App audits", audits.size.toString(), IntelligenceMetricSource.MEASURED),
                metric("Elevated 24 h", elevated.size.toString(), IntelligenceMetricSource.MEASURED),
                metric("Per-app rules", inputs.perAppDnsRuleCount.toString(), IntelligenceMetricSource.CONFIGURED),
                metric("Trackers blocked", inputs.trackerBlocksRecent.toString(), IntelligenceMetricSource.MEASURED),
                metric(
                    "Browser shields",
                    if (browserProtected) "ON" else "OFF",
                    IntelligenceMetricSource.CONFIGURED
                )
            ),
            actions = com.adshield.pro.domain.intelligence.IntelligenceAction.forModule(
                IntelligenceModule.PRIVACY_DEFENSE
            )
        )
    }

    private fun networkSnapshot(
        inputs: IntelligenceInputs,
        events: List<IntelligenceEvent>,
        now: Long
    ): ModuleSnapshot {
        val state: IntelligenceModuleState
        val detail: String
        val unavailable: String?
        when (inputs.vpnStatus) {
            VpnStatus.ERROR -> {
                state = IntelligenceModuleState.CRITICAL
                detail = inputs.vpnLastError?.take(140) ?: "The local DNS tunnel reported an error"
                unavailable = null
            }
            VpnStatus.PAUSED -> {
                state = IntelligenceModuleState.WARNING
                detail = "Tunnel up, DNS passing through unfiltered"
                unavailable = null
            }
            VpnStatus.DISCONNECTED -> {
                if (inputs.protectionExpected) {
                    state = IntelligenceModuleState.CRITICAL
                    detail = "Protection is configured to stay on but the tunnel is down"
                } else {
                    state = IntelligenceModuleState.DISABLED
                    detail = "Protection turned off — DNS is not being filtered"
                }
                unavailable = null
            }
            VpnStatus.CONNECTED -> {
                if (inputs.loadedRuleCount <= 0) {
                    state = IntelligenceModuleState.WARNING
                    detail = "Tunnel is up but no filter rules are loaded"
                } else {
                    state = IntelligenceModuleState.MONITORING
                    detail = "Filtering on ${inputs.resolverLabel.ifBlank { "configured resolver" }} · " +
                        "${inputs.loadedRuleCount} rules"
                }
                unavailable = null
            }
            VpnStatus.STARTING, VpnStatus.RECONNECTING -> {
                state = IntelligenceModuleState.MONITORING
                detail = "Tunnel is ${inputs.vpnStatus.name.lowercase()} — no verdict yet"
                unavailable = null
            }
        }
        return ModuleSnapshot(
            module = IntelligenceModule.NETWORK_DEFENSE,
            state = state,
            stateDetail = detail,
            latestEvent = latestEventFor(IntelligenceModule.NETWORK_DEFENSE, events),
            activeAlerts = unmitigatedAlerts(IntelligenceModule.NETWORK_DEFENSE, events, now),
            lastUpdateEpochMs = inputs.connectedSinceEpochMs,
            metrics = listOf(
                metric("Queries (session)", inputs.sessionTotalQueries.toString(), IntelligenceMetricSource.MEASURED),
                metric("Blocked (session)", inputs.sessionBlockedQueries.toString(), IntelligenceMetricSource.MEASURED),
                metric("Rules loaded", inputs.loadedRuleCount.toString(), IntelligenceMetricSource.MEASURED),
                metric(
                    "Latency",
                    if (inputs.averageLatencyMs > 0) "${inputs.averageLatencyMs} ms" else "awaiting query",
                    if (inputs.averageLatencyMs > 0) IntelligenceMetricSource.MEASURED else IntelligenceMetricSource.UNAVAILABLE
                ),
                metric(
                    "Resolver",
                    inputs.resolverLabel.ifBlank { "not configured" },
                    if (inputs.resolverLabel.isBlank()) IntelligenceMetricSource.UNAVAILABLE else IntelligenceMetricSource.CONFIGURED
                )
            ),
            actions = com.adshield.pro.domain.intelligence.IntelligenceAction.forModule(
                IntelligenceModule.NETWORK_DEFENSE
            ),
            unavailableReason = unavailable
        )
    }

    private fun deviceSnapshot(
        inputs: IntelligenceInputs,
        events: List<IntelligenceEvent>,
        now: Long
    ): ModuleSnapshot {
        val telemetry = inputs.batteryTelemetry
        val sensorReason = inputs.moduleUnavailableReasons[IntelligenceModule.DEVICE_INTELLIGENCE]
        val temperature = telemetry?.temperatureCelsius?.rawValue
        val temperatureSupported = telemetry != null &&
            telemetry.temperatureCelsius.source != BatteryReadingSource.UNSUPPORTED
        val threshold = inputs.thermalWarningCelsius.takeIf { it > 0f } ?: DEFAULT_THERMAL_WARNING_CELSIUS

        var state = IntelligenceModuleState.MONITORING
        var detail = "Streaming measured battery telemetry"
        var unavailable: String? = null

        when {
            telemetry == null -> {
                state = IntelligenceModuleState.OFFLINE
                unavailable = sensorReason ?: "Battery telemetry has not been read yet"
                detail = unavailable
            }
            !temperatureSupported || temperature == null -> {
                state = IntelligenceModuleState.OFFLINE
                unavailable = sensorReason
                    ?: "This device does not expose battery temperature to Android apps"
                detail = "Level and charging are readable, temperature is not"
            }
            telemetry.health == BatteryHealthStatus.OVERHEAT || telemetry.health == BatteryHealthStatus.FAILURE -> {
                state = IntelligenceModuleState.CRITICAL
                detail = "Android reports battery health: ${telemetry.healthLabel}"
            }
            temperature >= threshold + 3f -> {
                state = IntelligenceModuleState.CRITICAL
                detail = "Battery at ${formatTemperature(temperature)} — well above the ${formatTemperature(threshold)} threshold"
            }
            temperature >= threshold -> {
                state = IntelligenceModuleState.WARNING
                detail = "Battery at ${formatTemperature(temperature)} — above the ${formatTemperature(threshold)} threshold"
            }
            else -> {
                state = IntelligenceModuleState.MONITORING
                detail = "Battery ${formatTemperature(temperature)} · threshold ${formatTemperature(threshold)}"
            }
        }

        return ModuleSnapshot(
            module = IntelligenceModule.DEVICE_INTELLIGENCE,
            state = state,
            stateDetail = detail,
            latestEvent = latestEventFor(IntelligenceModule.DEVICE_INTELLIGENCE, events),
            activeAlerts = unmitigatedAlerts(IntelligenceModule.DEVICE_INTELLIGENCE, events, now),
            lastUpdateEpochMs = telemetry?.timestampEpochMs,
            metrics = listOf(
                metric(
                    "Temperature",
                    temperature?.let { formatTemperature(it) } ?: "unavailable",
                    if (temperature != null) IntelligenceMetricSource.MEASURED else IntelligenceMetricSource.UNAVAILABLE
                ),
                metric(
                    "Level",
                    telemetry?.levelPercent?.rawValue?.let { "$it%" } ?: "unavailable",
                    if (telemetry?.levelPercent?.rawValue != null) IntelligenceMetricSource.MEASURED else IntelligenceMetricSource.UNAVAILABLE
                ),
                metric(
                    "Status",
                    telemetry?.statusLabel ?: "unavailable",
                    if (telemetry != null) IntelligenceMetricSource.MEASURED else IntelligenceMetricSource.UNAVAILABLE
                ),
                metric("Threshold", formatTemperature(threshold), IntelligenceMetricSource.CONFIGURED),
                metric(
                    "Health",
                    telemetry?.healthLabel ?: "unavailable",
                    if (telemetry != null) IntelligenceMetricSource.MEASURED else IntelligenceMetricSource.UNAVAILABLE
                )
            ),
            actions = com.adshield.pro.domain.intelligence.IntelligenceAction.forModule(
                IntelligenceModule.DEVICE_INTELLIGENCE
            ),
            unavailableReason = unavailable
        )
    }

    private fun emergencySnapshot(
        inputs: IntelligenceInputs,
        events: List<IntelligenceEvent>,
        now: Long
    ): ModuleSnapshot {
        val checks = readinessChecks(inputs)
        val readinessPercent = if (checks.isEmpty()) {
            100
        } else {
            (checks.count { it.second } * 100) / checks.size
        }
        val failed = checks.filterNot { it.second }.map { it.first }
        var state = IntelligenceModuleState.NORMAL
        var detail = "Readiness $readinessPercent% · ${checks.size} checks passed"
        when {
            inputs.emergencyAllowlistOnly && inputs.vpnStatus != VpnStatus.CONNECTED -> {
                state = IntelligenceModuleState.CRITICAL
                detail = "Lockdown is active but the DNS tunnel is not connected"
            }
            inputs.emergencyAllowlistOnly -> {
                state = IntelligenceModuleState.WARNING
                detail = "Allowlist-only lockdown is active by user choice"
            }
            inputs.vpnStatus == VpnStatus.ERROR -> {
                state = IntelligenceModuleState.CRITICAL
                detail = "The tunnel cannot start; lockdown would not filter anything"
            }
            failed.isNotEmpty() -> {
                state = IntelligenceModuleState.WARNING
                detail = "Readiness $readinessPercent% · ${failed.first()}"
            }
            else -> {
                state = IntelligenceModuleState.NORMAL
                detail = "Readiness $readinessPercent% · ${checks.size} checks passed"
            }
        }
        return ModuleSnapshot(
            module = IntelligenceModule.EMERGENCY_INTELLIGENCE,
            state = state,
            stateDetail = detail,
            latestEvent = latestEventFor(IntelligenceModule.EMERGENCY_INTELLIGENCE, events),
            activeAlerts = unmitigatedAlerts(IntelligenceModule.EMERGENCY_INTELLIGENCE, events, now),
            lastUpdateEpochMs = inputs.connectedSinceEpochMs,
            metrics = listOf(
                metric("Readiness", "$readinessPercent%", IntelligenceMetricSource.COMPUTED),
                metric(
                    "Lockdown",
                    if (inputs.emergencyAllowlistOnly) "ACTIVE" else "OFF",
                    IntelligenceMetricSource.CONFIGURED
                ),
                metric("Tunnel", inputs.vpnStatus.name, IntelligenceMetricSource.MEASURED),
                metric("Rules", inputs.loadedRuleCount.toString(), IntelligenceMetricSource.MEASURED),
                metric("Checks failed", failed.size.toString(), IntelligenceMetricSource.COMPUTED)
            ),
            actions = com.adshield.pro.domain.intelligence.IntelligenceAction.forModule(
                IntelligenceModule.EMERGENCY_INTELLIGENCE
            )
        )
    }

    private fun automationSnapshot(
        inputs: IntelligenceInputs,
        events: List<IntelligenceEvent>,
        now: Long
    ): ModuleSnapshot {
        val enabledCount = listOf(
            inputs.autoUpdateFiltersEnabled,
            inputs.scheduledScanEnabled,
            inputs.smartAutoOptimizeEnabled
        ).count { it }
        val failedJobs = events.filter {
            it.module == IntelligenceModule.AUTOMATION_CORE &&
                it.type == com.adshield.pro.domain.intelligence.IntelligenceEventType.AUTOMATION_JOB_FAILED &&
                now - it.timestampEpochMs <= ALERT_WINDOW_MS
        }
        val ranJobs = events.filter {
            it.module == IntelligenceModule.AUTOMATION_CORE &&
                now - it.timestampEpochMs <= ALERT_WINDOW_MS
        }
        var state = IntelligenceModuleState.MONITORING
        var detail = "$enabledCount of 3 automations enabled"
        when {
            enabledCount == 0 -> {
                state = IntelligenceModuleState.DISABLED
                detail = "Filter sync, scheduled scan and smart maintenance are all off"
            }
            failedJobs.size >= 2 -> {
                state = IntelligenceModuleState.CRITICAL
                detail = "${failedJobs.size} scheduled jobs failed in the last 24 h"
            }
            failedJobs.isNotEmpty() -> {
                state = IntelligenceModuleState.WARNING
                detail = "A scheduled job failed: ${failedJobs.first().title}"
            }
            else -> {
                state = IntelligenceModuleState.MONITORING
                detail = "$enabledCount of 3 automations enabled · ${ranJobs.size} job run(s) recorded in 24 h"
            }
        }
        val lastFilterSync = inputs.lastFilterUpdateEpochMs.takeIf { it > 0L }
        return ModuleSnapshot(
            module = IntelligenceModule.AUTOMATION_CORE,
            state = state,
            stateDetail = detail,
            latestEvent = latestEventFor(IntelligenceModule.AUTOMATION_CORE, events),
            activeAlerts = unmitigatedAlerts(IntelligenceModule.AUTOMATION_CORE, events, now),
            lastUpdateEpochMs = lastFilterSync,
            metrics = listOf(
                metric(
                    "Filter sync",
                    if (inputs.autoUpdateFiltersEnabled) "ON" else "OFF",
                    IntelligenceMetricSource.CONFIGURED
                ),
                metric(
                    "Last sync",
                    lastFilterSync?.let { relativeAge(now, it) } ?: "never",
                    if (lastFilterSync != null) IntelligenceMetricSource.MEASURED else IntelligenceMetricSource.UNAVAILABLE
                ),
                metric(
                    "Scheduled scan",
                    if (inputs.scheduledScanEnabled) "every ${inputs.scheduledScanIntervalHours} h" else "OFF",
                    IntelligenceMetricSource.CONFIGURED
                ),
                metric(
                    "Smart optimize",
                    if (inputs.smartAutoOptimizeEnabled) "ON" else "OFF",
                    IntelligenceMetricSource.CONFIGURED
                ),
                metric("Jobs 24 h", ranJobs.size.toString(), IntelligenceMetricSource.MEASURED)
            ),
            actions = com.adshield.pro.domain.intelligence.IntelligenceAction.forModule(
                IntelligenceModule.AUTOMATION_CORE
            )
        )
    }

    private fun coreSnapshot(
        inputs: IntelligenceInputs,
        events: List<IntelligenceEvent>,
        nodeSnapshots: List<ModuleSnapshot>,
        now: Long
    ): ModuleSnapshot {
        val snapshots = if (nodeSnapshots.isEmpty()) {
            IntelligenceModule.nodes.map { snapshotFor(it, inputs, events, now) }
        } else {
            nodeSnapshots
        }
        val state = worstState(snapshots)
        val health = healthPercent(snapshots)
        val critical = snapshots.count { it.state == IntelligenceModuleState.CRITICAL }
        val warning = snapshots.count { it.state == IntelligenceModuleState.WARNING }
        val detail = when {
            critical > 0 -> "$critical critical · $warning warning"
            warning > 0 -> "$warning module(s) need attention"
            snapshots.any { it.state == IntelligenceModuleState.OFFLINE } -> "Partial coverage — a data source is offline"
            else -> "All ${snapshots.size} modules reporting"
        }
        return ModuleSnapshot(
            module = IntelligenceModule.CORE,
            state = state,
            stateDetail = detail,
            latestEvent = events.firstOrNull(),
            activeAlerts = events.count { it.countsTowardAlerts && now - it.timestampEpochMs <= ALERT_WINDOW_MS },
            lastUpdateEpochMs = inputs.nowEpochMs,
            metrics = listOf(
                metric("Health", "$health%", IntelligenceMetricSource.COMPUTED),
                metric(
                    "Modules nominal",
                    snapshots.count {
                        it.state == IntelligenceModuleState.NORMAL || it.state == IntelligenceModuleState.MONITORING
                    }.toString(),
                    IntelligenceMetricSource.COMPUTED
                ),
                metric("Critical", critical.toString(), IntelligenceMetricSource.COMPUTED),
                metric("Warnings", warning.toString(), IntelligenceMetricSource.COMPUTED),
                metric("Events stored", events.size.toString(), IntelligenceMetricSource.MEASURED)
            ),
            actions = emptyList()
        )
    }

    // ------------------------------------------------------------------ incident handling

    private fun storedIncidents(events: List<IntelligenceEvent>, now: Long): List<IntelligenceIncident> =
        events.filter { it.countsTowardAlerts && now - it.timestampEpochMs <= ALERT_WINDOW_MS }
            .sortedWith(compareByDescending<IntelligenceEvent> { it.severity.rank }
                .thenByDescending { it.timestampEpochMs })
            .take(MAX_INCIDENTS)
            .map { event ->
                IntelligenceIncident(
                    module = event.module,
                    severity = event.severity,
                    title = event.title,
                    detail = event.description,
                    timestampEpochMs = event.timestampEpochMs,
                    eventId = event.id
                )
            }

    /**
     * Live readings that are an issue right now but may predate the event store (first launch,
     * cleared history, or a sensor crossing captured while the map was closed). Only added when
     * no stored incident for the same module already covers it, so nothing is double-counted.
     */
    private fun derivedIncidents(
        inputs: IntelligenceInputs,
        events: List<IntelligenceEvent>,
        now: Long
    ): List<IntelligenceIncident> {
        val result = mutableListOf<IntelligenceIncident>()
        fun hasStored(module: IntelligenceModule): Boolean = events.any {
            it.module == module && it.countsTowardAlerts && now - it.timestampEpochMs <= ALERT_WINDOW_MS
        }
        fun add(module: IntelligenceModule, severity: IntelligenceSeverity, title: String, detail: String) {
            if (hasStored(module)) return
            result += IntelligenceIncident(module, severity, title, detail, now, null)
        }

        when (inputs.vpnStatus) {
            VpnStatus.ERROR -> add(
                IntelligenceModule.NETWORK_DEFENSE,
                IntelligenceSeverity.CRITICAL,
                "DNS tunnel error",
                inputs.vpnLastError?.take(160) ?: "The local DNS tunnel reported an error"
            )
            VpnStatus.PAUSED -> add(
                IntelligenceModule.NETWORK_DEFENSE,
                IntelligenceSeverity.WARNING,
                "DNS filtering paused",
                "Queries are not being filtered while the tunnel is paused"
            )
            VpnStatus.DISCONNECTED -> if (inputs.protectionExpected) {
                add(
                    IntelligenceModule.NETWORK_DEFENSE,
                    IntelligenceSeverity.CRITICAL,
                    "Protection is down",
                    "Protection should be running but no DNS tunnel is connected"
                )
            }
            VpnStatus.CONNECTED -> if (inputs.loadedRuleCount <= 0) {
                add(
                    IntelligenceModule.NETWORK_DEFENSE,
                    IntelligenceSeverity.WARNING,
                    "No filter rules loaded",
                    "The tunnel is connected but every query would pass through unfiltered"
                )
            }
            else -> Unit
        }

        val temperature = inputs.batteryTelemetry?.temperatureCelsius?.rawValue
        val threshold = inputs.thermalWarningCelsius.takeIf { it > 0f } ?: DEFAULT_THERMAL_WARNING_CELSIUS
        if (temperature != null && temperature >= threshold) {
            add(
                IntelligenceModule.DEVICE_INTELLIGENCE,
                if (temperature >= threshold + 3f) IntelligenceSeverity.CRITICAL else IntelligenceSeverity.WARNING,
                "Battery at ${formatTemperature(temperature)}",
                "Measured temperature is above the configured ${formatTemperature(threshold)} threshold"
            )
        }
        val health = inputs.batteryTelemetry?.health
        if (health == BatteryHealthStatus.OVERHEAT || health == BatteryHealthStatus.FAILURE) {
            add(
                IntelligenceModule.DEVICE_INTELLIGENCE,
                IntelligenceSeverity.CRITICAL,
                "Battery health: ${inputs.batteryTelemetry?.healthLabel ?: "failure"}",
                "Android's battery service reports a hardware health problem"
            )
        }

        if (inputs.emergencyAllowlistOnly) {
            add(
                IntelligenceModule.EMERGENCY_INTELLIGENCE,
                if (inputs.vpnStatus == VpnStatus.CONNECTED) IntelligenceSeverity.WARNING else IntelligenceSeverity.CRITICAL,
                "Emergency lockdown active",
                if (inputs.vpnStatus == VpnStatus.CONNECTED) {
                    "Only explicit allowlist entries resolve until lockdown is released"
                } else {
                    "Lockdown is armed but the tunnel is not filtering anything"
                }
            )
        } else if (inputs.vpnStatus == VpnStatus.CONNECTED && inputs.loadedRuleCount > 0) {
            // Ready; nothing to derive.
        } else if (inputs.vpnStatus != VpnStatus.ERROR) {
            add(
                IntelligenceModule.EMERGENCY_INTELLIGENCE,
                IntelligenceSeverity.WARNING,
                "Emergency readiness degraded",
                "Lockdown would not filter DNS until protection is connected with rules loaded"
            )
        }

        val latestPrivacyAudit = inputs.scans
            .filter { it.kind == ScanKind.APP_AUDIT }
            .maxByOrNull { it.timestampEpochMs }
        if (latestPrivacyAudit != null &&
            latestPrivacyAudit.threatLevel == SecurityLevel.DANGEROUS &&
            now - latestPrivacyAudit.timestampEpochMs <= SCAN_FRESH_WINDOW_MS
        ) {
            add(
                IntelligenceModule.PRIVACY_DEFENSE,
                IntelligenceSeverity.CRITICAL,
                "High-risk permission exposure",
                IntelligenceEventSanitizer.sanitizeText(latestPrivacyAudit.recommendation, 160)
            )
        }

        val failedAutomations = events.count {
            it.type == com.adshield.pro.domain.intelligence.IntelligenceEventType.AUTOMATION_JOB_FAILED &&
                now - it.timestampEpochMs <= ALERT_WINDOW_MS
        }
        if (failedAutomations > 0) {
            add(
                IntelligenceModule.AUTOMATION_CORE,
                if (failedAutomations >= 2) IntelligenceSeverity.CRITICAL else IntelligenceSeverity.WARNING,
                "Scheduled job failure",
                "$failedAutomations automation run(s) failed in the last 24 h"
            )
        }

        return result
    }

    private fun mergeIncidents(
        derived: List<IntelligenceIncident>,
        stored: List<IntelligenceIncident>
    ): List<IntelligenceIncident> {
        val seenModules = stored.map { it.module }.toSet()
        val merged = stored + derived.filter { it.module !in seenModules }
        return merged.sortedWith(
            compareByDescending<IntelligenceIncident> { it.severity.rank }
                .thenByDescending { it.timestampEpochMs }
        ).take(MAX_INCIDENTS)
    }

    private fun unmitigatedAlerts(
        module: IntelligenceModule,
        events: List<IntelligenceEvent>,
        now: Long
    ): Int = events.count {
        it.module == module && it.countsTowardAlerts && now - it.timestampEpochMs <= ALERT_WINDOW_MS
    }

    fun latestEventFor(module: IntelligenceModule, events: List<IntelligenceEvent>): IntelligenceEvent? =
        events.firstOrNull { it.module == module }

    // ------------------------------------------------------------------ health & labels

    fun healthPercent(snapshots: List<ModuleSnapshot>): Int {
        val penalty = snapshots.filter { it.module.isNode }.sumOf { snapshot ->
            when (snapshot.state) {
                IntelligenceModuleState.CRITICAL -> PENALTY_CRITICAL
                IntelligenceModuleState.WARNING -> PENALTY_WARNING
                IntelligenceModuleState.OFFLINE -> PENALTY_OFFLINE
                IntelligenceModuleState.DISABLED -> PENALTY_DISABLED
                IntelligenceModuleState.MONITORING, IntelligenceModuleState.NORMAL -> 0
            }
        }
        return (100 - penalty).coerceIn(0, 100)
    }

    /**
     * A single disabled capability (for example, the user turning automation off) must not brand
     * the whole system as "protection disabled" while the other modules are actually protecting.
     * Disabled states therefore only drive the overall verdict when every node is disabled.
     */
    fun worstState(snapshots: List<ModuleSnapshot>): IntelligenceModuleState {
        val nodes = snapshots.filter { it.module.isNode }
        val meaningful = nodes.filter { it.state != IntelligenceModuleState.DISABLED }.ifEmpty { nodes }
        return meaningful.maxByOrNull { stateRank(it.state) }?.state ?: IntelligenceModuleState.NORMAL
    }

    private fun stateRank(state: IntelligenceModuleState): Int = when (state) {
        IntelligenceModuleState.NORMAL -> 0
        IntelligenceModuleState.MONITORING -> 1
        IntelligenceModuleState.DISABLED -> 2
        IntelligenceModuleState.OFFLINE -> 3
        IntelligenceModuleState.WARNING -> 4
        IntelligenceModuleState.CRITICAL -> 5
    }

    fun overallLabel(
        state: IntelligenceModuleState,
        snapshots: List<ModuleSnapshot>,
        incidents: List<IntelligenceIncident>
    ): String {
        val critical = snapshots.count { it.module.isNode && it.state == IntelligenceModuleState.CRITICAL }
        val warning = snapshots.count { it.module.isNode && it.state == IntelligenceModuleState.WARNING }
        val offline = snapshots.count { it.module.isNode && it.state == IntelligenceModuleState.OFFLINE }
        val disabled = snapshots.count { it.module.isNode && it.state == IntelligenceModuleState.DISABLED }
        return when (state) {
            IntelligenceModuleState.CRITICAL -> "CRITICAL INCIDENT · $critical"
            IntelligenceModuleState.WARNING -> "ATTENTION REQUIRED · $warning"
            IntelligenceModuleState.OFFLINE -> "PARTIAL COVERAGE · $offline OFFLINE"
            IntelligenceModuleState.DISABLED -> "PROTECTION DISABLED · $disabled"
            IntelligenceModuleState.MONITORING -> if (incidents.isNotEmpty()) {
                "MONITORING · ${incidents.size} INCIDENT(S)"
            } else {
                "MONITORING · ALL MODULES REPORTING"
            }
            IntelligenceModuleState.NORMAL -> "NOMINAL · NO ACTIVE ISSUE"
        }
    }

    private fun commandMetrics(
        inputs: IntelligenceInputs,
        events: List<IntelligenceEvent>,
        modules: List<ModuleSnapshot>,
        health: Int,
        now: Long
    ): List<IntelligenceMetric> = listOf(
        metric("System health", "$health%", IntelligenceMetricSource.COMPUTED),
        metric(
            "DNS protection",
            when (inputs.vpnStatus) {
                VpnStatus.CONNECTED -> "ACTIVE"
                VpnStatus.PAUSED -> "PAUSED"
                VpnStatus.ERROR -> "ERROR"
                VpnStatus.STARTING -> "STARTING"
                VpnStatus.RECONNECTING -> "RECONNECTING"
                VpnStatus.DISCONNECTED -> "OFF"
            },
            IntelligenceMetricSource.MEASURED
        ),
        metric("Blocked (session)", inputs.sessionBlockedQueries.toString(), IntelligenceMetricSource.MEASURED),
        metric("Queries (session)", inputs.sessionTotalQueries.toString(), IntelligenceMetricSource.MEASURED),
        metric("Privacy findings 24 h", countModuleAlerts(events, IntelligenceModule.PRIVACY_DEFENSE, now).toString(), IntelligenceMetricSource.MEASURED),
        metric("Financial risk 24 h", countModuleAlerts(events, IntelligenceModule.FINANCIAL_DEFENSE, now).toString(), IntelligenceMetricSource.MEASURED),
        metric("Device warnings 24 h", countModuleAlerts(events, IntelligenceModule.DEVICE_INTELLIGENCE, now).toString(), IntelligenceMetricSource.MEASURED),
        metric("Automation runs 24 h", events.count {
            it.module == IntelligenceModule.AUTOMATION_CORE && now - it.timestampEpochMs <= ALERT_WINDOW_MS
        }.toString(), IntelligenceMetricSource.MEASURED),
        metric("Events stored", events.size.toString(), IntelligenceMetricSource.MEASURED),
        metric("Modules reporting", modules.count { it.module.isNode && it.state != IntelligenceModuleState.OFFLINE }.toString(), IntelligenceMetricSource.COMPUTED)
    )

    private fun countModuleAlerts(
        events: List<IntelligenceEvent>,
        module: IntelligenceModule,
        now: Long
    ): Int = events.count { it.module == module && it.countsTowardAlerts && now - it.timestampEpochMs <= ALERT_WINDOW_MS }

    // ------------------------------------------------------------------ helpers

    /** A readiness checklist built only from state the app can actually verify. */
    fun readinessChecks(inputs: IntelligenceInputs): List<Pair<String, Boolean>> = listOf(
        "DNS tunnel connected" to (inputs.vpnStatus == VpnStatus.CONNECTED),
        "Filter rules loaded" to (inputs.loadedRuleCount > 0),
        "Resolver configured" to inputs.resolverLabel.isNotBlank(),
        "Emergency policy readable" to true
    )

    fun relativeAge(nowEpochMs: Long, thenEpochMs: Long): String {
        val delta = (nowEpochMs - thenEpochMs).coerceAtLeast(0L)
        val minutes = delta / 60_000L
        return when {
            minutes < 1L -> "just now"
            minutes < 60L -> "$minutes min ago"
            minutes < 60L * 24L -> "${minutes / 60L} h ago"
            else -> "${minutes / (60L * 24L)} d ago"
        }
    }

    fun formatTemperature(celsius: Float): String {
        val rounded = (celsius * 10f).roundToInt() / 10f
        return "$rounded °C"
    }

    private fun metric(
        label: String,
        value: String,
        source: IntelligenceMetricSource
    ): IntelligenceMetric = IntelligenceMetric(label, value, source)
}
