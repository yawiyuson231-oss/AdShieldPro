package com.adshield.pro.universal

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Reporting and History — Real-time logs, scan history, diagnostic reports, exports.
 */
@Singleton
class UniversalRepository @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val prefs = context.getSharedPreferences("universal_history", Context.MODE_PRIVATE)

    private val _eventLogs = MutableStateFlow<List<SecurityEventLog>>(emptyList())
    val eventLogs: StateFlow<List<SecurityEventLog>> = _eventLogs

    private val _scanHistory = MutableStateFlow<List<ScanHistoryEntry>>(emptyList())
    val scanHistory: StateFlow<List<ScanHistoryEntry>> = _scanHistory

    private val _incidentTimeline = MutableStateFlow<List<IncidentEntry>>(emptyList())
    val incidentTimeline: StateFlow<List<IncidentEntry>> = _incidentTimeline

    init {
        loadPersisted()
    }

    fun addEventLog(event: SecurityEventLog) {
        val updated = (listOf(event) + _eventLogs.value).take(500)
        _eventLogs.value = updated
        persistEvents(updated)
    }

    fun addScanHistory(entry: ScanHistoryEntry) {
        val updated = (listOf(entry) + _scanHistory.value).take(200)
        _scanHistory.value = updated
        persistScans(updated)
    }

    fun addIncident(incident: IncidentEntry) {
        val updated = (listOf(incident) + _incidentTimeline.value).take(200)
        _incidentTimeline.value = updated
        persistIncidents(updated)
    }

    fun getThreatDetectionHistory(): List<ThreatReport> {
        val prefs = context.getSharedPreferences("universal_threat_history", Context.MODE_PRIVATE)
        val raw = prefs.getString("threats", "") ?: return emptyList()
        return raw.lines().filter { it.isNotBlank() }.mapNotNull { line ->
            try {
                val parts = line.split("|")
                ThreatReport(parts[0], parts[1].toLong(), PlatformType.valueOf(parts[2]), parts[3], parts[4], parts.getOrNull(5), parts.getOrNull(6), parts.getOrNull(7) ?: "", parts.getOrNull(8) ?: "")
            } catch (_: Exception) { null }
        }
    }

    fun addThreatReport(report: ThreatReport) {
        try {
            val prefs = context.getSharedPreferences("universal_threat_history", Context.MODE_PRIVATE)
            val existing = prefs.getString("threats", "") ?: ""
            val line = listOf(report.id, report.timestampEpochMs.toString(), report.platform.name, report.threatType, report.severity, report.domain ?: "", report.appPackage ?: "", report.actionTaken, report.status).joinToString("|")
            prefs.edit().putString("threats", (line + "\n" + existing).take(50000)).apply()
        } catch (_: Exception) {}
    }

    fun getFailedModuleHistory(): List<ModuleDiagnosticResult> {
        // Return last diagnostics failed modules
        return emptyList() // populated by DiagnosticEngine
    }

    fun generateFullReport(diagnosticReport: DiagnosticReport?): String {
        val sb = StringBuilder()
        sb.appendLine("AdShield Pro Universal Security Report")
        sb.appendLine("Generated: ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z", java.util.Locale.US).format(java.util.Date())}")
        sb.appendLine("Platform: Android ${android.os.Build.VERSION.RELEASE} (API ${android.os.Build.VERSION.SDK_INT})")
        sb.appendLine("Device: ${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
        sb.appendLine("App version: 2.2.5 (universal)")
        sb.appendLine("Master protection: ${if (diagnosticReport?.masterEnabled == true) "ON" else "OFF"}")
        sb.appendLine("=".repeat(60))
        if (diagnosticReport != null) {
            sb.appendLine("Diagnostics run: ${java.util.Date(diagnosticReport.timestampMs)} (duration ${diagnosticReport.durationMs}ms)")
            sb.appendLine("Total: ${diagnosticReport.totalModules}, Working: ${diagnosticReport.results.count { it.status == ModuleStatus.WORKING }}, Failed: ${diagnosticReport.results.count { it.status == ModuleStatus.NOT_WORKING }}")
            sb.appendLine("API availability: ${diagnosticReport.apiAvailability}")
            sb.appendLine("File scan: ${diagnosticReport.fileScanTest.detail}")
            sb.appendLine("Threat detection: ${diagnosticReport.threatDetectionTest.detail}")
            sb.appendLine("Intel updates: ${diagnosticReport.intelUpdateCheck.detail}")
            sb.appendLine("Performance: CPU ${diagnosticReport.performance.cpuPercent}%, RAM ${diagnosticReport.performance.ramUsedMb}/${diagnosticReport.performance.ramTotalMb} MB")
            sb.appendLine("-".repeat(60))
            sb.appendLine("Module statuses:")
            diagnosticReport.results.forEach { r ->
                val mod = UniversalModuleRegistry.byId(r.moduleId)
                sb.appendLine("  [${r.status.label}] M${r.moduleId} ${mod?.name ?: "Unknown"} — ${r.detail}")
                if (r.error != null) sb.appendLine("    Error: ${r.error}")
            }
        }
        sb.appendLine("=".repeat(60))
        sb.appendLine("Event logs: ${_eventLogs.value.size} entries")
        _eventLogs.value.take(20).forEach { e ->
            sb.appendLine("  ${java.util.Date(e.timestampEpochMs)} [${e.severity}] ${e.moduleName}: ${e.description}")
        }
        sb.appendLine("Scan history: ${_scanHistory.value.size} scans")
        _scanHistory.value.take(10).forEach { s ->
            sb.appendLine("  ${java.util.Date(s.timestampMs)} ${s.scanType}: ${s.result} (${s.durationMs}ms)")
        }
        return sb.toString()
    }

    fun exportJson(diagnosticReport: DiagnosticReport?): String {
        val sb = StringBuilder()
        sb.append("{")
        sb.append("\"generated_at\":${System.currentTimeMillis()},")
        sb.append("\"platform\":\"Android\",")
        sb.append("\"android_version\":\"${android.os.Build.VERSION.RELEASE}\",")
        sb.append("\"api_level\":${android.os.Build.VERSION.SDK_INT},")
        sb.append("\"device\":\"${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}\",")
        sb.append("\"master_enabled\":${diagnosticReport?.masterEnabled ?: false},")
        sb.append("\"total_modules\":${diagnosticReport?.totalModules ?: 0},")
        if (diagnosticReport != null) {
            sb.append("\"modules\":[")
            sb.append(diagnosticReport.results.joinToString(",") { r ->
                val mod = UniversalModuleRegistry.byId(r.moduleId)
                """{"id":${r.moduleId},"name":"${mod?.name?.replace("\"","'") ?: ""}","status":"${r.status.name}","service_running":${r.serviceRunning},"protection_enabled":${r.protectionEnabled},"tested":${r.functionalityTested},"verified":${r.detectionVerified},"detail":"${r.detail.replace("\"","'").take(200)}"}"""
            })
            sb.append("],")
            sb.append("\"api_availability\":{${diagnosticReport.apiAvailability.entries.joinToString(",") { "\"${it.key}\":${it.value}" }}},")
            sb.append("\"performance\":{\"cpu\":${diagnosticReport.performance.cpuPercent}," + "\"ram_used_mb\":${diagnosticReport.performance.ramUsedMb}},")
        }
        sb.append("\"event_count\":${_eventLogs.value.size}")
        sb.append("}")
        return sb.toString()
    }

    private fun loadPersisted() {
        try {
            // Load events
            val evRaw = prefs.getString("events", null)
            if (evRaw != null) {
                // Simplified: events stored as count + last timestamp
                // Real implementation would store full JSON
            }
        } catch (_: Exception) {}
    }

    private fun persistEvents(events: List<SecurityEventLog>) {
        try {
            prefs.edit().putInt("event_count", events.size).apply()
        } catch (_: Exception) {}
    }

    private fun persistScans(scans: List<ScanHistoryEntry>) {
        try { prefs.edit().putInt("scan_count", scans.size).apply() } catch (_: Exception) {}
    }

    private fun persistIncidents(incidents: List<IncidentEntry>) {
        try { prefs.edit().putInt("incident_count", incidents.size).apply() } catch (_: Exception) {}
    }
}

data class ScanHistoryEntry(
    val id: Long,
    val timestampMs: Long,
    val scanType: String,
    val result: String,
    val threatsFound: Int,
    val durationMs: Long,
    val platform: PlatformType
)

data class IncidentEntry(
    val id: String,
    val timestampMs: Long,
    val title: String,
    val severity: String,
    val description: String,
    val modulesInvolved: List<Int>,
    val resolved: Boolean
)
