package com.adshield.pro.engine.intelligence

import com.adshield.pro.domain.intelligence.IntelligenceAction
import com.adshield.pro.domain.intelligence.IntelligenceEvent
import com.adshield.pro.domain.intelligence.IntelligenceEventType
import com.adshield.pro.domain.intelligence.IntelligenceMetric
import com.adshield.pro.domain.intelligence.IntelligenceMetricSource
import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.domain.intelligence.IntelligenceSeverity
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.battery.BatteryHealthStatus
import com.adshield.pro.engine.battery.BatteryTelemetry
import com.adshield.pro.engine.security.QuarantinedItem
import com.adshield.pro.engine.security.ScanKind
import com.adshield.pro.engine.security.SecurityLevel
import com.adshield.pro.engine.security.SecurityScanRecord
import kotlin.math.roundToInt

/**
 * Translates real observations into structured intelligence events.
 *
 * Every function here requires an actual observation (a DNS log row, a stored scan record, a
 * battery reading, a VPN status transition, a WorkManager result). There is no timer, no random
 * generator and no "demo" entry point: if a module produced nothing, no event exists.
 */
object IntelligenceEventFactory {

    private fun actionsFor(module: IntelligenceModule): List<IntelligenceAction> =
        IntelligenceAction.forModule(module)

    // ------------------------------------------------------------------ Network Defense

    fun dnsThreatBlocked(
        domain: String,
        category: RuleCategory?,
        matchedRule: String?,
        sourceList: String,
        protocolUsed: String,
        appName: String?,
        timestampEpochMs: Long
    ): IntelligenceEvent? {
        val host = IntelligenceEventSanitizer.sanitizeDomain(domain)
        if (host.isEmpty()) return null
        val categoryLabel = category?.displayName ?: "Security"
        val rule = matchedRule?.takeIf { it.isNotBlank() }
        val evidence = buildString {
            append("DNS block recorded on this device for ").append(host)
            append(" · category ").append(categoryLabel)
            if (rule != null) append(" · rule ").append(rule)
            if (sourceList.isNotBlank()) append(" · list ").append(sourceList)
            if (protocolUsed.isNotBlank()) append(" · transport ").append(protocolUsed)
            if (!appName.isNullOrBlank()) append(" · requesting app ").append(appName)
        }
        return IntelligenceEvent(
            module = IntelligenceModule.NETWORK_DEFENSE,
            type = IntelligenceEventType.NETWORK_THREAT_BLOCKED,
            severity = if (category == RuleCategory.MALWARE) {
                IntelligenceSeverity.WARNING
            } else {
                IntelligenceSeverity.NOTICE
            },
            timestampEpochMs = timestampEpochMs,
            title = "$categoryLabel block: $host",
            description = "The local DNS firewall stopped this request before it left the device.",
            evidence = evidence,
            evidenceRef = "dns:$host",
            relatedObjectIds = listOfNotNull(host, rule),
            actions = actionsFor(IntelligenceModule.NETWORK_DEFENSE),
            metrics = listOf(
                IntelligenceMetric("Domain", host, IntelligenceMetricSource.MEASURED),
                IntelligenceMetric("Rule", rule ?: "category match", IntelligenceMetricSource.MEASURED),
                IntelligenceMetric("List", sourceList.ifBlank { "bundled" }, IntelligenceMetricSource.CONFIGURED)
            )
        )
    }

    fun vpnTransition(
        previous: VpnStatus,
        current: VpnStatus,
        error: String?,
        ruleCount: Int,
        timestampEpochMs: Long
    ): IntelligenceEvent? {
        if (previous == current) return null
        val type = when (current) {
            VpnStatus.CONNECTED -> IntelligenceEventType.NETWORK_PROTECTION_STARTED
            VpnStatus.DISCONNECTED -> if (previous == VpnStatus.ERROR) {
                IntelligenceEventType.NETWORK_PROTECTION_STOPPED
            } else {
                IntelligenceEventType.NETWORK_PROTECTION_STOPPED
            }
            VpnStatus.PAUSED -> IntelligenceEventType.NETWORK_FILTERING_PAUSED
            VpnStatus.ERROR -> IntelligenceEventType.NETWORK_RESOLVER_ERROR
            VpnStatus.STARTING, VpnStatus.RECONNECTING -> return null
        }
        val severity = when (type) {
            IntelligenceEventType.NETWORK_RESOLVER_ERROR -> IntelligenceSeverity.CRITICAL
            IntelligenceEventType.NETWORK_PROTECTION_STARTED -> IntelligenceSeverity.INFO
            else -> IntelligenceSeverity.WARNING
        }
        val evidence = buildString {
            append("Tunnel state changed from ").append(previous.name).append(" to ").append(current.name)
            append(" · ").append(ruleCount).append(" rules loaded")
            if (!error.isNullOrBlank()) append(" · reported error: ").append(error)
        }
        val title = when (type) {
            IntelligenceEventType.NETWORK_PROTECTION_STARTED -> "DNS firewall connected"
            IntelligenceEventType.NETWORK_PROTECTION_STOPPED -> "DNS firewall disconnected"
            IntelligenceEventType.NETWORK_FILTERING_PAUSED -> "DNS filtering paused"
            else -> "Resolver error reported"
        }
        return IntelligenceEvent(
            module = IntelligenceModule.NETWORK_DEFENSE,
            type = type,
            severity = severity,
            timestampEpochMs = timestampEpochMs,
            title = title,
            description = when (type) {
                IntelligenceEventType.NETWORK_PROTECTION_STARTED ->
                    "On-device DNS filtering is active; queries are matched against loaded rules."
                IntelligenceEventType.NETWORK_PROTECTION_STOPPED ->
                    "The local DNS firewall is not running, so DNS filtering is not protecting this device."
                IntelligenceEventType.NETWORK_FILTERING_PAUSED ->
                    "The tunnel is up but DNS requests are passing through unfiltered."
                else -> "The resolver reported a failure; queries may fall back or fail."
            },
            evidence = evidence,
            evidenceRef = "vpn:${current.name}",
            relatedObjectIds = listOf("vpn"),
            actions = actionsFor(IntelligenceModule.NETWORK_DEFENSE),
            metrics = listOf(
                IntelligenceMetric("State", current.name, IntelligenceMetricSource.MEASURED),
                IntelligenceMetric("Rules", ruleCount.toString(), IntelligenceMetricSource.MEASURED)
            )
        )
    }

    // ------------------------------------------------------------------ Cyber / Financial / Privacy

    /**
     * Maps a persisted [SecurityScanRecord] to exactly one module event.
     *
     * Router policy:
     *  - FILE / APK scans → Cyber Defense
     *  - URL scans → Financial Defense when the URL really is a payment target, else Cyber Defense
     *  - APP_AUDIT → Privacy Defense (permission exposure)
     */
    fun scanRecord(record: SecurityScanRecord, nowEpochMs: Long): IntelligenceEvent? {
        if (record.timestampEpochMs <= 0L) return null
        val target = IntelligenceEventSanitizer.sanitizeText(record.target, 120)
        if (target.isBlank()) return null
        val findingEvidence = record.findings
            .map { IntelligenceEventSanitizer.sanitizeText(it, 140) }
            .filter { it.isNotBlank() }
            .take(3)
        if (findingEvidence.isEmpty() && record.threatName.isNullOrBlank() && record.riskScore <= 0) {
            // A record with no finding, no threat name and no score is not evidence of anything.
            return null
        }

        val financial = record.kind == ScanKind.URL &&
            FinancialTargetClassifier.isFinancialTarget(record.target, record.findings)

        val module = when {
            financial -> IntelligenceModule.FINANCIAL_DEFENSE
            record.kind == ScanKind.APP_AUDIT -> IntelligenceModule.PRIVACY_DEFENSE
            else -> IntelligenceModule.CYBER_DEFENSE
        }

        val type = when {
            financial && record.threatLevel != SecurityLevel.CLEAN -> IntelligenceEventType.FINANCIAL_PAYMENT_RISK
            financial -> IntelligenceEventType.FINANCIAL_LINK_CLEAN
            record.kind == ScanKind.APP_AUDIT && record.threatLevel != SecurityLevel.CLEAN ->
                IntelligenceEventType.PRIVACY_PERMISSION_FINDING
            record.kind == ScanKind.APP_AUDIT -> IntelligenceEventType.PRIVACY_AUDIT_CLEAN
            record.threatLevel != SecurityLevel.CLEAN -> IntelligenceEventType.CYBER_SCAN_FINDING
            else -> IntelligenceEventType.CYBER_SCAN_CLEAN
        }

        val severity = when (record.threatLevel) {
            SecurityLevel.DANGEROUS -> IntelligenceSeverity.CRITICAL
            SecurityLevel.SUSPICIOUS -> IntelligenceSeverity.WARNING
            SecurityLevel.CLEAN -> IntelligenceSeverity.INFO
        }

        val evidence = buildString {
            append(record.kind.name.replace('_', ' ').lowercase().replaceFirstChar { it.uppercase() })
            append(" scan of ").append(target)
            append(" · verdict ").append(record.threatLevel.name)
            append(" · risk ").append(record.riskScore.coerceIn(0, 100)).append("/100")
            append(" · source ").append(record.scanSource.label)
            if (findingEvidence.isNotEmpty()) append(" · findings: ").append(findingEvidence.joinToString("; "))
            if (record.recommendation.isNotBlank() && record.threatLevel != SecurityLevel.CLEAN) {
                append(" · recommended: ").append(IntelligenceEventSanitizer.sanitizeText(record.recommendation, 160))
            }
        }

        val title = when (type) {
            IntelligenceEventType.FINANCIAL_PAYMENT_RISK -> "Payment link risk: ${record.threatLevel.name.lowercase()}"
            IntelligenceEventType.FINANCIAL_LINK_CLEAN -> "Payment link scanned clean"
            IntelligenceEventType.PRIVACY_PERMISSION_FINDING -> "Permission exposure: ${record.threatLevel.name.lowercase()}"
            IntelligenceEventType.PRIVACY_AUDIT_CLEAN -> "Permission audit clean"
            IntelligenceEventType.CYBER_SCAN_FINDING -> "${record.kind.name.replace('_', ' ').lowercase().replaceFirstChar { it.uppercase() }} finding"
            else -> "Scan completed clean"
        }

        return IntelligenceEvent(
            module = module,
            type = type,
            severity = severity,
            timestampEpochMs = record.timestampEpochMs,
            title = title,
            description = when (module) {
                IntelligenceModule.FINANCIAL_DEFENSE ->
                    "A link the user scanned matches payment-scam indicators. The scanner never opens the link."
                IntelligenceModule.PRIVACY_DEFENSE ->
                    "Installed-app permission stacks were audited on this device."
                else -> "A real on-device scan finished and recorded this verdict."
            },
            evidence = evidence,
            evidenceRef = "scan:${record.id}",
            relatedObjectIds = listOfNotNull(target.take(64), record.threatName?.take(48)),
            actions = actionsFor(module),
            metrics = listOf(
                IntelligenceMetric("Risk", "${record.riskScore.coerceIn(0, 100)}/100", IntelligenceMetricSource.COMPUTED),
                IntelligenceMetric("Verdict", record.threatLevel.name, IntelligenceMetricSource.MEASURED),
                IntelligenceMetric("Source", record.scanSource.label, IntelligenceMetricSource.CONFIGURED),
                IntelligenceMetric("Scan kind", record.kind.name, IntelligenceMetricSource.MEASURED)
            )
        )
    }

    fun quarantineAdded(item: QuarantinedItem, timestampEpochMs: Long): IntelligenceEvent {
        val name = IntelligenceEventSanitizer.sanitizeText(item.displayName, 64).ifBlank { "file" }
        val evidence = buildString {
            append("Isolated copy stored for ").append(name)
            append(" · threat ").append(item.threatLevel.name)
            append(" · ").append(item.sizeBytes.coerceAtLeast(0L)).append(" bytes")
            append(" · SHA-256 ").append(item.sha256.take(16)).append("…")
            append(" · original deleted by user: ").append(item.originalRemoved)
        }
        return IntelligenceEvent(
            module = IntelligenceModule.CYBER_DEFENSE,
            type = IntelligenceEventType.CYBER_QUARANTINE_ADDED,
            severity = IntelligenceSeverity.NOTICE,
            timestampEpochMs = timestampEpochMs,
            title = "Quarantined $name",
            description = "The user isolated this file. Its hash stays recorded for integrity checks.",
            evidence = evidence,
            evidenceRef = "quarantine:${item.id}",
            relatedObjectIds = listOf(name),
            actions = listOf(IntelligenceAction.OPEN_MODULE),
            metrics = listOf(
                IntelligenceMetric("Size", "${item.sizeBytes.coerceAtLeast(0L)} B", IntelligenceMetricSource.MEASURED),
                IntelligenceMetric("Threat", item.threatLevel.name, IntelligenceMetricSource.MEASURED)
            )
        )
    }

    // ------------------------------------------------------------------ Device Intelligence

    fun thermalWarning(
        telemetry: BatteryTelemetry,
        thresholdCelsius: Float,
        timestampEpochMs: Long
    ): IntelligenceEvent? {
        val temperature = telemetry.temperatureCelsius.rawValue ?: return null
        if (temperature < thresholdCelsius) return null
        val critical = temperature >= thresholdCelsius + 3f ||
            telemetry.health == BatteryHealthStatus.OVERHEAT ||
            telemetry.health == BatteryHealthStatus.FAILURE
        val evidence = buildString {
            append("Measured battery temperature ").append(formatTemp(temperature))
            append(" crossed the configured ").append(formatTemp(thresholdCelsius)).append(" threshold")
            append(" · charging: ").append(telemetry.isCharging)
            append(" · status: ").append(telemetry.statusLabel)
            append(" · health: ").append(telemetry.healthLabel)
            append(" · source: ").append(telemetry.temperatureCelsius.source.name)
        }
        return IntelligenceEvent(
            module = IntelligenceModule.DEVICE_INTELLIGENCE,
            type = IntelligenceEventType.DEVICE_THERMAL_WARNING,
            severity = if (critical) IntelligenceSeverity.CRITICAL else IntelligenceSeverity.WARNING,
            timestampEpochMs = timestampEpochMs,
            title = "Battery at ${formatTemp(temperature)}",
            description = "A real thermal reading crossed the warning threshold configured in AdShield.",
            evidence = evidence,
            evidenceRef = "battery:temperature",
            relatedObjectIds = listOf("battery"),
            actions = actionsFor(IntelligenceModule.DEVICE_INTELLIGENCE),
            metrics = listOf(
                IntelligenceMetric("Temperature", formatTemp(temperature), IntelligenceMetricSource.MEASURED),
                IntelligenceMetric("Threshold", formatTemp(thresholdCelsius), IntelligenceMetricSource.CONFIGURED),
                IntelligenceMetric(
                    "Level",
                    telemetry.levelPercent.rawValue?.let { "$it%" } ?: "unavailable",
                    if (telemetry.levelPercent.rawValue != null) IntelligenceMetricSource.MEASURED else IntelligenceMetricSource.UNAVAILABLE
                )
            )
        )
    }

    fun thermalRecovered(
        telemetry: BatteryTelemetry,
        thresholdCelsius: Float,
        timestampEpochMs: Long
    ): IntelligenceEvent? {
        val temperature = telemetry.temperatureCelsius.rawValue ?: return null
        if (temperature > thresholdCelsius - 2f) return null
        val evidence = "Measured battery temperature returned to ${formatTemp(temperature)} " +
            "(threshold ${formatTemp(thresholdCelsius)}, ${formatTemp(thresholdCelsius - 2f)} hysteresis)"
        return IntelligenceEvent(
            module = IntelligenceModule.DEVICE_INTELLIGENCE,
            type = IntelligenceEventType.DEVICE_THERMAL_RECOVERED,
            severity = IntelligenceSeverity.INFO,
            timestampEpochMs = timestampEpochMs,
            title = "Battery temperature back to ${formatTemp(temperature)}",
            description = "The thermal warning condition has cleared on real hardware readings.",
            evidence = evidence,
            evidenceRef = "battery:temperature",
            relatedObjectIds = listOf("battery"),
            actions = actionsFor(IntelligenceModule.DEVICE_INTELLIGENCE),
            metrics = listOf(
                IntelligenceMetric("Temperature", formatTemp(temperature), IntelligenceMetricSource.MEASURED)
            )
        )
    }

    fun batteryHealthAlert(telemetry: BatteryTelemetry, timestampEpochMs: Long): IntelligenceEvent? {
        val problematic = when (telemetry.health) {
            BatteryHealthStatus.OVERHEAT,
            BatteryHealthStatus.FAILURE,
            BatteryHealthStatus.DEAD,
            BatteryHealthStatus.OVER_VOLTAGE,
            BatteryHealthStatus.COLD -> true
            BatteryHealthStatus.GOOD,
            BatteryHealthStatus.UNKNOWN -> false
        }
        if (!problematic) return null
        val critical = telemetry.health == BatteryHealthStatus.OVERHEAT ||
            telemetry.health == BatteryHealthStatus.FAILURE ||
            telemetry.health == BatteryHealthStatus.DEAD
        return IntelligenceEvent(
            module = IntelligenceModule.DEVICE_INTELLIGENCE,
            type = IntelligenceEventType.DEVICE_HEALTH_ALERT,
            severity = if (critical) IntelligenceSeverity.CRITICAL else IntelligenceSeverity.WARNING,
            timestampEpochMs = timestampEpochMs,
            title = "Battery health: ${telemetry.healthLabel}",
            description = "Android's battery service reported a hardware health condition.",
            evidence = "BatteryManager health code reported \"${telemetry.healthLabel}\" " +
                "with status \"${telemetry.statusLabel}\" " +
                "at ${telemetry.temperatureCelsius.rawValue?.let { formatTemp(it) } ?: "unavailable temperature"}",
            evidenceRef = "battery:health",
            relatedObjectIds = listOf("battery"),
            actions = actionsFor(IntelligenceModule.DEVICE_INTELLIGENCE),
            metrics = listOf(
                IntelligenceMetric("Health", telemetry.healthLabel, IntelligenceMetricSource.MEASURED),
                IntelligenceMetric("Status", telemetry.statusLabel, IntelligenceMetricSource.MEASURED)
            )
        )
    }

    fun telemetryUnavailable(reason: String, timestampEpochMs: Long): IntelligenceEvent {
        val detail = IntelligenceEventSanitizer.sanitizeText(reason, 160)
            .ifBlank { "This device does not expose the required sensor to Android apps." }
        return IntelligenceEvent(
            module = IntelligenceModule.DEVICE_INTELLIGENCE,
            type = IntelligenceEventType.DEVICE_TELEMETRY_UNAVAILABLE,
            severity = IntelligenceSeverity.NOTICE,
            timestampEpochMs = timestampEpochMs,
            title = "Device telemetry unavailable",
            description = "No fabricated sensor values are shown while Android withholds this reading.",
            evidence = "Battery telemetry source reported: $detail",
            evidenceRef = "battery:unavailable",
            relatedObjectIds = listOf("battery"),
            actions = actionsFor(IntelligenceModule.DEVICE_INTELLIGENCE)
        )
    }

    // ------------------------------------------------------------------ Emergency Intelligence

    fun lockdownChanged(enabled: Boolean, timestampEpochMs: Long): IntelligenceEvent {
        val type = if (enabled) {
            IntelligenceEventType.EMERGENCY_LOCKDOWN_ON
        } else {
            IntelligenceEventType.EMERGENCY_LOCKDOWN_OFF
        }
        return IntelligenceEvent(
            module = IntelligenceModule.EMERGENCY_INTELLIGENCE,
            type = type,
            severity = if (enabled) IntelligenceSeverity.WARNING else IntelligenceSeverity.NOTICE,
            timestampEpochMs = timestampEpochMs,
            title = if (enabled) "Emergency lockdown engaged" else "Emergency lockdown released",
            description = if (enabled) {
                "Only explicit allowlist entries and built-in safety domains will resolve."
            } else {
                "DNS filtering returned to the normal protection policy."
            },
            evidence = "DNS firewall policy emergencyAllowlistOnly changed to $enabled (user action)",
            evidenceRef = "policy:emergency",
            relatedObjectIds = listOf("policy"),
            actions = actionsFor(IntelligenceModule.EMERGENCY_INTELLIGENCE),
            metrics = listOf(
                IntelligenceMetric(
                    "Lockdown",
                    if (enabled) "ACTIVE" else "OFF",
                    IntelligenceMetricSource.CONFIGURED
                )
            )
        )
    }

    fun readinessDegraded(reason: String, timestampEpochMs: Long): IntelligenceEvent {
        val detail = IntelligenceEventSanitizer.sanitizeText(reason, 180)
        return IntelligenceEvent(
            module = IntelligenceModule.EMERGENCY_INTELLIGENCE,
            type = IntelligenceEventType.EMERGENCY_READINESS_DEGRADED,
            severity = IntelligenceSeverity.WARNING,
            timestampEpochMs = timestampEpochMs,
            title = "Protection readiness degraded",
            description = "The emergency path would not be able to filter DNS in the current state.",
            evidence = detail.ifBlank { "Protection readiness check failed" },
            evidenceRef = "policy:readiness",
            relatedObjectIds = listOf("policy"),
            actions = actionsFor(IntelligenceModule.EMERGENCY_INTELLIGENCE),
            metrics = listOf(
                IntelligenceMetric("Reason", detail.take(48), IntelligenceMetricSource.MEASURED)
            )
        )
    }

    // ------------------------------------------------------------------ Automation Core

    fun automationJob(
        jobLabel: String,
        success: Boolean,
        detail: String,
        durationMs: Long,
        timestampEpochMs: Long
    ): IntelligenceEvent {
        val name = IntelligenceEventSanitizer.sanitizeText(jobLabel, 48).ifBlank { "Scheduled job" }
        val evidence = buildString {
            append(name).append(if (success) " completed" else " failed")
            append(" · duration ").append(durationMs.coerceAtLeast(0L)).append(" ms")
            val clean = IntelligenceEventSanitizer.sanitizeText(detail, 200)
            if (clean.isNotBlank()) append(" · ").append(clean)
        }
        return IntelligenceEvent(
            module = IntelligenceModule.AUTOMATION_CORE,
            type = if (success) IntelligenceEventType.AUTOMATION_JOB_OK else IntelligenceEventType.AUTOMATION_JOB_FAILED,
            severity = if (success) IntelligenceSeverity.INFO else IntelligenceSeverity.WARNING,
            timestampEpochMs = timestampEpochMs,
            title = "$name ${if (success) "completed" else "failed"}",
            description = if (success) {
                "A WorkManager job actually ran on this device."
            } else {
                "A WorkManager job returned a failure; the previous data was kept."
            },
            evidence = evidence,
            evidenceRef = "worker:$name",
            relatedObjectIds = listOf(name),
            actions = actionsFor(IntelligenceModule.AUTOMATION_CORE),
            metrics = listOf(
                IntelligenceMetric("Duration", "$durationMs ms", IntelligenceMetricSource.MEASURED),
                IntelligenceMetric("Outcome", if (success) "SUCCESS" else "FAILURE", IntelligenceMetricSource.MEASURED)
            )
        )
    }

    fun automationSettingChanged(title: String, detail: String, timestampEpochMs: Long): IntelligenceEvent =
        settingChanged(IntelligenceEventType.AUTOMATION_SETTING_CHANGED, title, detail, timestampEpochMs)

    fun privacySettingChanged(title: String, detail: String, timestampEpochMs: Long): IntelligenceEvent =
        settingChanged(IntelligenceEventType.PRIVACY_SETTING_CHANGED, title, detail, timestampEpochMs)

    private fun settingChanged(
        type: IntelligenceEventType,
        title: String,
        detail: String,
        timestampEpochMs: Long
    ): IntelligenceEvent {
        val cleanTitle = IntelligenceEventSanitizer.sanitizeText(title, 64)
        val cleanDetail = IntelligenceEventSanitizer.sanitizeText(detail, 220)
        return IntelligenceEvent(
            module = type.module,
            type = type,
            severity = IntelligenceSeverity.INFO,
            timestampEpochMs = timestampEpochMs,
            title = cleanTitle.ifBlank { type.label },
            description = "A protection setting changed on this device.",
            evidence = cleanDetail.ifBlank { cleanTitle },
            evidenceRef = "settings:${type.code}",
            relatedObjectIds = listOf("settings"),
            actions = actionsFor(type.module)
        )
    }

    private fun formatTemp(celsius: Float): String = "${(celsius * 10f).roundToInt() / 10f} °C"
}
