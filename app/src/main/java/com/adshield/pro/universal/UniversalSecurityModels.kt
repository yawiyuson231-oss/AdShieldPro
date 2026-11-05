package com.adshield.pro.universal

import androidx.compose.ui.graphics.Color

/**
 * Universal Security Super App — 50 Module Unified Architecture.
 * Supports Android, Windows, macOS only. iOS permanently excluded.
 *
 * Each module has verified status determined by 4 conditions:
 * - Service running
 * - Protection enabled
 * - Functionality tested
 * - Detection capability verified
 */
enum class ModuleStatus(val label: String, val colorHex: String) {
    WORKING("WORKING", "#22C55E"),              // GREEN
    PARTIALLY_WORKING("PARTIALLY WORKING", "#EAB308"), // YELLOW
    SCANNING("SCANNING", "#3B82F6"),            // BLUE
    PERMISSION_REQUIRED("PERMISSION REQUIRED", "#F97316"), // ORANGE
    NOT_WORKING("NOT WORKING", "#EF4444"),      // RED
    NOT_SUPPORTED("NOT SUPPORTED", "#6B7280"),  // GRAY
    NOT_TESTED("NOT TESTED", "#FFFFFF");        // WHITE

    fun toColor(): Color = try {
        Color(android.graphics.Color.parseColor(colorHex))
    } catch (e: Exception) { Color.Gray }
}

enum class PlatformType { ANDROID, WINDOWS, MACOS }

enum class ModuleCategory(val title: String) {
    AI_PROTECTION("AI Protection"),
    DEVICE_PROTECTION("Device Protection"),
    PRIVACY_PROTECTION("Privacy Protection"),
    ADVANCED_CYBER_DEFENSE("Advanced Cyber Defense"),
    SECURITY_INTELLIGENCE("Security Intelligence")
}

data class UniversalModule(
    val id: Int,
    val name: String,
    val description: String,
    val category: ModuleCategory,
    val androidSupported: Boolean = true,
    val windowsSupported: Boolean = true,
    val macosSupported: Boolean = true,
    val requiresPermission: String? = null,
    val requiresRoot: Boolean = false,
    val requiresEntitlement: Boolean = false
)

object UniversalModuleRegistry {
    val ALL_MODULES: List<UniversalModule> = listOf(
        // AI Protection (1-10)
        UniversalModule(1, "AI Real-time Threat Detection", "On-device AI analyzes DNS queries and behavior in real time", ModuleCategory.AI_PROTECTION),
        UniversalModule(2, "Malware Behavior Detection", "Detects malicious behavior patterns via heuristics and intel", ModuleCategory.AI_PROTECTION),
        UniversalModule(3, "Ransomware Detection", "Monitors file operations and entropy for ransomware indicators", ModuleCategory.AI_PROTECTION),
        UniversalModule(4, "Phishing Detection", "Identifies phishing domains via intel + heuristic analysis", ModuleCategory.AI_PROTECTION),
        UniversalModule(5, "Scam Message Detection", "Analyzes links in messages for scam indicators", ModuleCategory.AI_PROTECTION, requiresPermission = "RECEIVE_SMS"),
        UniversalModule(6, "Malicious Link Analysis", "Deep analysis of URLs for malicious payloads and redirects", ModuleCategory.AI_PROTECTION),
        UniversalModule(7, "Suspicious Activity Detection", "Detects anomalous device and network behavior", ModuleCategory.AI_PROTECTION),
        UniversalModule(8, "Zero-day Anomaly Detection", "Heuristic detection of unknown/new threats via entropy & patterns", ModuleCategory.AI_PROTECTION),
        UniversalModule(9, "Threat Intelligence Analysis", "Correlates local events with global threat intelligence", ModuleCategory.AI_PROTECTION),
        UniversalModule(10, "Automatic Threat Response", "Auto-blocks confirmed threats and notifies user", ModuleCategory.AI_PROTECTION),

        // Device Protection (11-20)
        UniversalModule(11, "Real-time Malware Scanning", "Scans installed apps against malware signatures", ModuleCategory.DEVICE_PROTECTION),
        UniversalModule(12, "File and Document Scanning", "Scans accessible files for malicious content", ModuleCategory.DEVICE_PROTECTION),
        UniversalModule(13, "Downloaded File Inspection", "Inspects downloads for malware and suspicious files", ModuleCategory.DEVICE_PROTECTION),
        UniversalModule(14, "APK Security Scanning", "Verifies APK signatures and scans for threats", ModuleCategory.DEVICE_PROTECTION, androidSupported = true, windowsSupported = false, macosSupported = false),
        UniversalModule(15, "Application Vulnerability Assessment", "Checks installed apps for known vulnerabilities", ModuleCategory.DEVICE_PROTECTION),
        UniversalModule(16, "Dangerous Permission Detection", "Flags apps requesting excessive dangerous permissions", ModuleCategory.DEVICE_PROTECTION),
        UniversalModule(17, "Spyware Detection", "Detects spyware indicators and hidden monitoring", ModuleCategory.DEVICE_PROTECTION),
        UniversalModule(18, "Stalkerware Detection", "Identifies stalkerware via package signatures", ModuleCategory.DEVICE_PROTECTION),
        UniversalModule(19, "Background Activity Monitoring", "Monitors background processes and services", ModuleCategory.DEVICE_PROTECTION),
        UniversalModule(20, "Device Security Health Assessment", "Overall device security posture score", ModuleCategory.DEVICE_PROTECTION),

        // Privacy Protection (21-30)
        UniversalModule(21, "Camera Access Monitoring", "Monitors and alerts on camera access by apps", ModuleCategory.PRIVACY_PROTECTION, requiresPermission = "CAMERA"),
        UniversalModule(22, "Microphone Access Monitoring", "Monitors and alerts on microphone access", ModuleCategory.PRIVACY_PROTECTION, requiresPermission = "RECORD_AUDIO"),
        UniversalModule(23, "Location Access Monitoring", "Monitors location access and alerts", ModuleCategory.PRIVACY_PROTECTION, requiresPermission = "ACCESS_FINE_LOCATION"),
        UniversalModule(24, "Clipboard Privacy Monitoring", "Monitors clipboard access for sensitive data", ModuleCategory.PRIVACY_PROTECTION),
        UniversalModule(25, "Tracker Detection", "Detects third-party trackers via DNS intelligence", ModuleCategory.PRIVACY_PROTECTION),
        UniversalModule(26, "Application Privacy Reports", "Per-app privacy reports from permissions + trackers", ModuleCategory.PRIVACY_PROTECTION),
        UniversalModule(27, "Hidden Tracker Analysis", "Deep analysis of hidden and fingerprinting trackers", ModuleCategory.PRIVACY_PROTECTION),
        UniversalModule(28, "Personal Information Exposure Alerts", "Alerts if personal data appears in breach indicators", ModuleCategory.PRIVACY_PROTECTION),
        UniversalModule(29, "Secure Private Vault", "Hardware-backed encrypted vault for sensitive files", ModuleCategory.PRIVACY_PROTECTION),
        UniversalModule(30, "Encrypted File Protection", "Encrypts and protects files with AES-256-GCM", ModuleCategory.PRIVACY_PROTECTION),

        // Advanced Cyber Defense (31-40)
        UniversalModule(31, "Anti-Ransomware Protection", "Proactive ransomware protection via file monitoring", ModuleCategory.ADVANCED_CYBER_DEFENSE),
        UniversalModule(32, "Anti-Keylogger Detection", "Detects keylogging via accessibility/overlay abuse", ModuleCategory.ADVANCED_CYBER_DEFENSE),
        UniversalModule(33, "Anti-Rootkit Detection", "Detects rootkits and persistent threats", ModuleCategory.ADVANCED_CYBER_DEFENSE, requiresRoot = true),
        UniversalModule(34, "Brute-force Attack Detection", "Detects brute-force authentication attempts", ModuleCategory.ADVANCED_CYBER_DEFENSE),
        UniversalModule(35, "Network Attack Monitoring", "Monitors network for attack patterns and port scans", ModuleCategory.ADVANCED_CYBER_DEFENSE),
        UniversalModule(36, "Man-in-the-Middle Detection", "Detects MITM via cert pinning and network analysis", ModuleCategory.ADVANCED_CYBER_DEFENSE),
        UniversalModule(37, "Certificate Security Verification", "Validates TLS certificates and pinning", ModuleCategory.ADVANCED_CYBER_DEFENSE),
        UniversalModule(38, "Secure Connection Monitoring", "Monitors encrypted connections (DoH/DoT/TLS)", ModuleCategory.ADVANCED_CYBER_DEFENSE),
        UniversalModule(39, "Intrusion Detection System", "Network + host-based intrusion detection", ModuleCategory.ADVANCED_CYBER_DEFENSE),
        UniversalModule(40, "Suspicious Process Isolation", "Isolates suspicious processes where OS permits", ModuleCategory.ADVANCED_CYBER_DEFENSE, requiresRoot = true),

        // Security Intelligence (41-50)
        UniversalModule(41, "Global Threat Intelligence", "Integrates multiple signed threat intelligence feeds", ModuleCategory.SECURITY_INTELLIGENCE),
        UniversalModule(42, "CVE Vulnerability Database", "Local CVE database for vulnerability matching", ModuleCategory.SECURITY_INTELLIGENCE),
        UniversalModule(43, "Automatic Security Rule Updates", "Auto-updates security rules every 6 hours", ModuleCategory.SECURITY_INTELLIGENCE),
        UniversalModule(44, "Security Incident Investigation", "Timeline and forensics for security incidents", ModuleCategory.SECURITY_INTELLIGENCE),
        UniversalModule(45, "Device Breach Detection", "Detects indicators of device compromise", ModuleCategory.SECURITY_INTELLIGENCE),
        UniversalModule(46, "Account Compromise Monitoring", "Monitors for account breach indicators", ModuleCategory.SECURITY_INTELLIGENCE),
        UniversalModule(47, "Password Strength Analysis", "Analyzes password strength with entropy scoring", ModuleCategory.SECURITY_INTELLIGENCE),
        UniversalModule(48, "Multi-factor Authentication Manager", "Manages TOTP MFA codes securely", ModuleCategory.SECURITY_INTELLIGENCE),
        UniversalModule(49, "Emergency Security Lockdown", "One-tap lockdown of device and network", ModuleCategory.SECURITY_INTELLIGENCE),
        UniversalModule(50, "One-tap Security Activation", "Master ON/OFF for all protection modules", ModuleCategory.SECURITY_INTELLIGENCE)
    )

    fun byId(id: Int): UniversalModule? = ALL_MODULES.find { it.id == id }
    fun byCategory(cat: ModuleCategory): List<UniversalModule> = ALL_MODULES.filter { it.category == cat }
}

data class ModuleDiagnosticResult(
    val moduleId: Int,
    val status: ModuleStatus,
    val serviceRunning: Boolean,
    val protectionEnabled: Boolean,
    val functionalityTested: Boolean,
    val detectionVerified: Boolean,
    val lastTestEpochMs: Long,
    val detail: String,
    val error: String? = null,
    val cpuUsagePercent: Float = 0f,
    val memoryUsageKb: Long = 0L,
    val permissionGranted: Boolean = true
)

data class SecurityEventLog(
    val id: Long = 0,
    val timestampEpochMs: Long,
    val moduleId: Int,
    val moduleName: String,
    val severity: String,
    val eventType: String,
    val description: String,
    val platform: PlatformType,
    val status: ModuleStatus
)

data class UniversalDashboardState(
    val masterEnabled: Boolean = true,
    val lastVerificationEpochMs: Long = 0L,
    val totalFeatures: Int = 50,
    val working: Int = 0,
    val partiallyWorking: Int = 0,
    val scanning: Int = 0,
    val permissionRequired: Int = 0,
    val failed: Int = 0,
    val unsupported: Int = 0,
    val pendingTests: Int = 0,
    val activeThreats: Int = 0,
    val engineStatus: String = "INITIALIZING",
    val results: List<ModuleDiagnosticResult> = emptyList(),
    val events: List<SecurityEventLog> = emptyList(),
    val cpuPercent: Float = 0f,
    val ramUsedMb: Long = 0L,
    val batteryOptimized: Boolean = true
)

data class ThreatReport(
    val id: String,
    val timestampEpochMs: Long,
    val platform: PlatformType,
    val threatType: String,
    val severity: String,
    val domain: String?,
    val appPackage: String?,
    val actionTaken: String,
    val status: String
)

data class PerformanceMetrics(
    val cpuPercent: Float,
    val ramUsedMb: Long,
    val ramTotalMb: Long,
    val batteryPercent: Int,
    val batteryTempC: Float,
    val scanTimeMs: Long,
    val modulesActive: Int
)
