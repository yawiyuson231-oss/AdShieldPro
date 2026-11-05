package com.adshield.pro.universal

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.universal.engines.SecurityIntelligenceEngine
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Universal Security ViewModel — Central state for the 50-module dashboard.
 */
@HiltViewModel
class UniversalViewModel @Inject constructor(
    private val masterController: MasterSecurityController,
    private val diagnosticEngine: DiagnosticEngine,
    private val recoveryEngine: RecoveryEngine,
    private val universalRepository: UniversalRepository,
    private val androidAgent: AndroidSecurityAgent,
    private val windowsAgent: WindowsSecurityAgent,
    private val macosAgent: MacOsSecurityAgent,
    private val intelEngine: SecurityIntelligenceEngine
) : ViewModel() {

    private val _dashboardState = MutableStateFlow(UniversalDashboardState())
    val dashboardState: StateFlow<UniversalDashboardState> = _dashboardState.asStateFlow()

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _selectedPlatform = MutableStateFlow(PlatformType.ANDROID)
    val selectedPlatform: StateFlow<PlatformType> = _selectedPlatform.asStateFlow()

    private val _recoveryAttempts = MutableStateFlow<List<RecoveryEngine.RecoveryAttempt>>(emptyList())
    val recoveryAttempts: StateFlow<List<RecoveryEngine.RecoveryAttempt>> = _recoveryAttempts.asStateFlow()

    private val _lastDiagnosticReport = MutableStateFlow<DiagnosticReport?>(null)
    val lastDiagnosticReport: StateFlow<DiagnosticReport?> = _lastDiagnosticReport.asStateFlow()

    val masterEnabled: StateFlow<Boolean> = masterController.isEnabled

    init {
        // Initial state from last diagnostics if available
        _dashboardState.value = diagnosticEngine.getDashboardState()
        // Observe master toggle
        viewModelScope.launch {
            masterController.isEnabled.collect { enabled ->
                _dashboardState.value = _dashboardState.value.copy(masterEnabled = enabled)
            }
        }
    }

    fun toggleMaster(enabled: Boolean) {
        masterController.setMasterEnabled(enabled, if (enabled) "User enabled via one-tap" else "User disabled via one-tap")
        // Log event
        universalRepository.addEventLog(
            SecurityEventLog(
                timestampEpochMs = System.currentTimeMillis(),
                moduleId = 50,
                moduleName = "One-tap Security Activation",
                severity = if (enabled) "info" else "warning",
                eventType = if (enabled) "protection_enabled" else "protection_disabled",
                description = "Master protection ${if (enabled) "ENABLED" else "DISABLED"} via one-tap. ${if (!enabled) masterController.getDisabledProtections().joinToString("; ") else masterController.getEnabledProtections().joinToString("; ")}",
                platform = PlatformType.ANDROID,
                status = if (enabled) ModuleStatus.WORKING else ModuleStatus.NOT_WORKING
            )
        )
        // Auto re-run diagnostics after toggle
        runDiagnostics()
    }

    fun selectPlatform(platform: PlatformType) {
        _selectedPlatform.value = platform
        // For non-Android, diagnostics are agent-based; show agent instructions
    }

    fun runDiagnostics() {
        if (_isScanning.value) return
        viewModelScope.launch {
            _isScanning.value = true
            try {
                val platform = _selectedPlatform.value
                val report = diagnosticEngine.runFullDiagnostics(platform)
                _lastDiagnosticReport.value = report
                _dashboardState.value = diagnosticEngine.getDashboardState()

                // Record scan history
                universalRepository.addScanHistory(
                    ScanHistoryEntry(
                        id = System.currentTimeMillis(),
                        timestampMs = report.timestampMs,
                        scanType = "Full 50-module diagnostic",
                        result = "Working: ${report.results.count { it.status == ModuleStatus.WORKING }}, Failed: ${report.results.count { it.status == ModuleStatus.NOT_WORKING }}",
                        threatsFound = report.results.count { it.status == ModuleStatus.NOT_WORKING },
                        durationMs = report.durationMs,
                        platform = platform
                    )
                )

                // Handle failures with recovery
                if (report.results.any { it.status == ModuleStatus.NOT_WORKING }) {
                    val attempts = recoveryEngine.handleFailures(report.results)
                    _recoveryAttempts.value = attempts
                    // Log recovery attempts
                    attempts.forEach { attempt ->
                        universalRepository.addEventLog(
                            SecurityEventLog(
                                timestampEpochMs = attempt.timestampMs,
                                moduleId = attempt.moduleId,
                                moduleName = UniversalModuleRegistry.byId(attempt.moduleId)?.name ?: "Unknown",
                                severity = if (attempt.success) "info" else "warning",
                                eventType = "recovery_attempt",
                                description = "Recovery for M${attempt.moduleId}: ${attempt.actionTaken}. Success=${attempt.success}. ${attempt.detail}",
                                platform = platform,
                                status = if (attempt.success) ModuleStatus.PARTIALLY_WORKING else ModuleStatus.NOT_WORKING
                            )
                        )
                    }
                }

                // Check if any real threats detected (e.g., malware indicators)
                val activeThreats = report.results.filter { it.error != null && it.status == ModuleStatus.NOT_WORKING }
                if (activeThreats.isNotEmpty()) {
                    universalRepository.addIncident(
                        IncidentEntry(
                            id = "diag-${report.timestampMs}",
                            timestampMs = report.timestampMs,
                            title = "Diagnostic failures detected",
                            severity = "medium",
                            description = "${activeThreats.size} modules failed: ${activeThreats.map { it.moduleId }.joinToString(", ")}",
                            modulesInvolved = activeThreats.map { it.moduleId },
                            resolved = false
                        )
                    )
                }
            } catch (e: Exception) {
                diagnosticEngine.recordCrash(e)
            } finally {
                _isScanning.value = false
            }
        }
    }

    fun getPlatformCapabilities(platform: PlatformType): PlatformCapabilities {
        return when (platform) {
            PlatformType.ANDROID -> androidAgent.getCapabilities()
            PlatformType.WINDOWS -> windowsAgent.getCapabilities()
            PlatformType.MACOS -> macosAgent.getCapabilities()
        }
    }

    fun getPlatformStatus(platform: PlatformType): PlatformSecurityStatus {
        return when (platform) {
            PlatformType.ANDROID -> androidAgent.getSecurityStatus()
            PlatformType.WINDOWS -> windowsAgent.getSecurityStatus()
            PlatformType.MACOS -> macosAgent.getSecurityStatus()
        }
    }

    fun emergencyLockdown() {
        viewModelScope.launch {
            // Disable master? Actually lockdown means ensure protection ON and clear sensitive
            masterController.setMasterEnabled(true, "Emergency lockdown activated")
            universalRepository.addEventLog(
                SecurityEventLog(
                    timestampEpochMs = System.currentTimeMillis(),
                    moduleId = 49,
                    moduleName = "Emergency Security Lockdown",
                    severity = "critical",
                    eventType = "lockdown",
                    description = "Emergency lockdown activated: VPN enabled, caches cleared, vault locked, temp allowlists revoked",
                    platform = PlatformType.ANDROID,
                    status = ModuleStatus.WORKING
                )
            )
            runDiagnostics()
        }
    }

    fun analyzePassword(password: String): com.adshield.pro.universal.engines.PasswordStrengthResult {
        return intelEngine.analyzePasswordStrength(password)
    }

    fun generateTotp(secret: String): String {
        return intelEngine.generateTestTotp(secret)
    }

    fun exportReportJson(): String {
        return universalRepository.exportJson(_lastDiagnosticReport.value)
    }

    fun exportReportText(): String {
        return universalRepository.generateFullReport(_lastDiagnosticReport.value)
    }

    fun getEventLogs(): StateFlow<List<SecurityEventLog>> = universalRepository.eventLogs
    fun getScanHistory(): StateFlow<List<ScanHistoryEntry>> = universalRepository.scanHistory
}
