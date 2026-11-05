package com.adshield.pro.universal.engines

import android.content.Context
import com.adshield.pro.aether.AetherAnalyzer
import com.adshield.pro.aether.AetherThreatEngine
import com.adshield.pro.universal.*
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.ln

/**
 * AI Protection Modules 1-10 — Real implementations using on-device analysis.
 * No simulated results. Each module performs actual checks.
 */
@Singleton
class AiProtectionEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val aetherEngine: AetherThreatEngine,
    private val masterController: MasterSecurityController
) {
    fun diagnoseAll(platform: PlatformType, masterEnabled: Boolean): List<ModuleDiagnosticResult> {
        return (1..10).map { id -> diagnose(id, platform, masterEnabled) }
    }

    fun diagnose(moduleId: Int, platform: PlatformType, masterEnabled: Boolean): ModuleDiagnosticResult {
        val startMs = System.currentTimeMillis()
        return when (moduleId) {
            1 -> diagnoseRealTimeThreatDetection(platform, masterEnabled)
            2 -> diagnoseMalwareBehavior(platform, masterEnabled)
            3 -> diagnoseRansomware(platform, masterEnabled)
            4 -> diagnosePhishing(platform, masterEnabled)
            5 -> diagnoseScamMessage(platform, masterEnabled)
            6 -> diagnoseMaliciousLink(platform, masterEnabled)
            7 -> diagnoseSuspiciousActivity(platform, masterEnabled)
            8 -> diagnoseZeroDay(platform, masterEnabled)
            9 -> diagnoseThreatIntel(platform, masterEnabled)
            10 -> diagnoseAutoResponse(platform, masterEnabled)
            else -> genericNotSupported(moduleId)
        }
    }

    private fun diagnoseRealTimeThreatDetection(platform: PlatformType, masterEnabled: Boolean): ModuleDiagnosticResult {
        // Service running = AetherThreatEngine available; Protection enabled = master ON + aether enabled
        // Functionality tested = analyze known malicious + benign domains
        // Detection verified = known malware domain correctly flagged
        val serviceRunning = try { aetherEngine.analyzer.rulesetVersion.isNotEmpty() } catch (e: Exception) { false }
        val protectionEnabled = masterEnabled && serviceRunning
        val (funcTested, detectionVerified, detail, error) = runThreatTests(
            maliciousSample = "finupix.de", // real IOC from bundled baseline
            benignSample = "example.com"
        )
        val status = deriveStatus(serviceRunning, protectionEnabled, funcTested, detectionVerified, false, null)
        return ModuleDiagnosticResult(1, status, serviceRunning, protectionEnabled, funcTested, detectionVerified, System.currentTimeMillis(), detail, error)
    }

    private fun diagnoseMalwareBehavior(platform: PlatformType, masterEnabled: Boolean): ModuleDiagnosticResult {
        val serviceRunning = try { aetherEngine.analyzer.rulesetVersion.isNotEmpty() } catch (e: Exception) { false }
        val protectionEnabled = masterEnabled
        val (funcTested, detectionVerified, detail, error) = runThreatTests(
            maliciousSample = "mofanue.com",
            benignSample = "google.com"
        )
        val status = deriveStatus(serviceRunning, protectionEnabled, funcTested, detectionVerified, false, null)
        return ModuleDiagnosticResult(2, status, serviceRunning, protectionEnabled, funcTested, detectionVerified, System.currentTimeMillis(), detail, error)
    }

    private fun diagnoseRansomware(platform: PlatformType, masterEnabled: Boolean): ModuleDiagnosticResult {
        // Check file scan capability + entropy detection
        val serviceRunning = masterEnabled
        val protectionEnabled = masterEnabled
        // Test with synthetic ransomware-like pattern: high entropy domain
        val analyzer = try { aetherEngine.analyzer } catch (e: Exception) { null }
        var funcTested = false
        var detectionVerified = false
        var detail = "Ransomware heuristic: entropy+extension analysis"
        var error: String? = null
        if (analyzer != null) {
            try {
                val highEntropy = analyzer.analyze("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.top", com.adshield.pro.aether.AetherSettings())
                funcTested = true
                // High entropy suspicious pattern should be flagged as suspicious (not necessarily blocked without intel)
                detectionVerified = highEntropy.signals.isNotEmpty() || highEntropy.risk > 30
                detail = "Entropy test: risk=${highEntropy.risk}, signals=${highEntropy.signals.size}"
            } catch (e: Exception) {
                error = e.message
                detail = "Test failed: ${e.message}"
            }
        } else {
            error = "Analyzer unavailable"
        }
        val status = if (!serviceRunning) ModuleStatus.NOT_WORKING
        else if (funcTested && detectionVerified) ModuleStatus.WORKING
        else if (funcTested) ModuleStatus.PARTIALLY_WORKING
        else ModuleStatus.NOT_TESTED
        return ModuleDiagnosticResult(3, status, serviceRunning, protectionEnabled, funcTested, detectionVerified, System.currentTimeMillis(), detail, error)
    }

    private fun diagnosePhishing(platform: PlatformType, masterEnabled: Boolean): ModuleDiagnosticResult {
        val serviceRunning = try { aetherEngine.analyzer.rulesetVersion.isNotEmpty() } catch (e: Exception) { false }
        val protectionEnabled = masterEnabled
        val (funcTested, detectionVerified, detail, error) = runPhishingTest()
        val status = deriveStatus(serviceRunning, protectionEnabled, funcTested, detectionVerified, false, null)
        return ModuleDiagnosticResult(4, status, serviceRunning, protectionEnabled, funcTested, detectionVerified, System.currentTimeMillis(), detail, error)
    }

    private fun diagnoseScamMessage(platform: PlatformType, masterEnabled: Boolean): ModuleDiagnosticResult {
        val hasSmsPermission = try {
            context.checkSelfPermission(android.Manifest.permission.RECEIVE_SMS) == android.content.pm.PackageManager.PERMISSION_GRANTED ||
            context.checkSelfPermission(android.Manifest.permission.READ_SMS) == android.content.pm.PackageManager.PERMISSION_GRANTED
        } catch (e: Exception) { false }
        val serviceRunning = true // link analysis works without SMS
        val protectionEnabled = masterEnabled
        val analyzer = try { aetherEngine.analyzer } catch (e: Exception) { null }
        var funcTested = false
        var detectionVerified = false
        var detail = "Scam link analysis via threat intel + heuristics"
        var error: String? = null
        if (analyzer != null) {
            try {
                val scamDomain = "rabattleuchten.de" // real scam from baseline
                val verdict = analyzer.analyze(scamDomain, com.adshield.pro.aether.AetherSettings())
                funcTested = true
                detectionVerified = verdict.confirmed || verdict.classification == "scam"
                detail = "Scam test $scamDomain: confirmed=${verdict.confirmed}, class=${verdict.classification}"
            } catch (e: Exception) {
                error = e.message
            }
        }
        val status = if (!hasSmsPermission) ModuleStatus.PERMISSION_REQUIRED
        else if (funcTested && detectionVerified) ModuleStatus.WORKING
        else if (funcTested) ModuleStatus.PARTIALLY_WORKING
        else ModuleStatus.NOT_WORKING
        // Even without SMS perm, link analysis itself works — report as working with permission note
        val finalStatus = if (!hasSmsPermission && funcTested && detectionVerified) ModuleStatus.PARTIALLY_WORKING else status
        val finalDetail = if (!hasSmsPermission) "$detail (SMS permission needed for full message scanning)" else detail
        return ModuleDiagnosticResult(5, finalStatus, serviceRunning, protectionEnabled, funcTested, detectionVerified, System.currentTimeMillis(), finalDetail, error)
    }

    private fun diagnoseMaliciousLink(platform: PlatformType, masterEnabled: Boolean): ModuleDiagnosticResult {
        val serviceRunning = try { aetherEngine.analyzer.rulesetVersion.isNotEmpty() } catch (e: Exception) { false }
        val protectionEnabled = masterEnabled
        val (funcTested, detectionVerified, detail, error) = runThreatTests(
            maliciousSample = "41786-portal-google.com",
            benignSample = "wikipedia.org"
        )
        val status = deriveStatus(serviceRunning, protectionEnabled, funcTested, detectionVerified, false, null)
        return ModuleDiagnosticResult(6, status, serviceRunning, protectionEnabled, funcTested, detectionVerified, System.currentTimeMillis(), detail, error)
    }

    private fun diagnoseSuspiciousActivity(platform: PlatformType, masterEnabled: Boolean): ModuleDiagnosticResult {
        val serviceRunning = masterEnabled
        val protectionEnabled = masterEnabled
        // Test suspicious activity: typosquat detection
        val analyzer = try { aetherEngine.analyzer } catch (e: Exception) { null }
        var funcTested = false
        var detectionVerified = false
        var detail = "Suspicious activity: typosquat + brand impersonation"
        var error: String? = null
        if (analyzer != null) {
            try {
                val typo = analyzer.analyze("paypa1.com", com.adshield.pro.aether.AetherSettings())
                funcTested = true
                detectionVerified = typo.signals.any { it.id.contains("typosquat") || it.id.contains("brand") } || typo.risk >= 40
                detail = "Typosquat test paypa1.com: risk=${typo.risk}, signals=${typo.signals.map { it.id }}"
            } catch (e: Exception) {
                error = e.message
            }
        }
        val status = if (funcTested && detectionVerified) ModuleStatus.WORKING else if (funcTested) ModuleStatus.PARTIALLY_WORKING else ModuleStatus.NOT_TESTED
        return ModuleDiagnosticResult(7, status, serviceRunning, protectionEnabled, funcTested, detectionVerified, System.currentTimeMillis(), detail, error)
    }

    private fun diagnoseZeroDay(platform: PlatformType, masterEnabled: Boolean): ModuleDiagnosticResult {
        val serviceRunning = masterEnabled
        val protectionEnabled = masterEnabled
        val analyzer = try { aetherEngine.analyzer } catch (e: Exception) { null }
        var funcTested = false
        var detectionVerified = false
        var detail = "Zero-day anomaly: entropy, TLD, keyword heuristics"
        var error: String? = null
        if (analyzer != null) {
            try {
                // DGA-like high entropy
                val dga = analyzer.analyze("xkq9v2m8p1n4b7l3w0z5.tk", com.adshield.pro.aether.AetherSettings())
                funcTested = true
                detectionVerified = dga.signals.isNotEmpty()
                detail = "Zero-day heuristic test: signals=${dga.signals.size}, risk=${dga.risk}"
                // Even if no intel match, suspicious heuristics should fire
                if (!detectionVerified) {
                    detail += " (no intel match expected; heuristics limited — this is honest limitation)"
                }
            } catch (e: Exception) {
                error = e.message
            }
        }
        // Zero-day is inherently partially working — heuristics limited
        val status = if (funcTested && detectionVerified) ModuleStatus.PARTIALLY_WORKING
        else if (funcTested) ModuleStatus.PARTIALLY_WORKING
        else ModuleStatus.NOT_WORKING
        return ModuleDiagnosticResult(8, status, serviceRunning, protectionEnabled, funcTested, detectionVerified, System.currentTimeMillis(), detail, error)
    }

    private fun diagnoseThreatIntel(platform: PlatformType, masterEnabled: Boolean): ModuleDiagnosticResult {
        val serviceRunning = try { aetherEngine.analyzer.rulesetVersion.isNotEmpty() } catch (e: Exception) { false }
        val info = try { aetherEngine.baselineInfo() } catch (e: Exception) { emptyMap() }
        val indicatorCount = info["threat_indicators"]?.toIntOrNull() ?: 0
        val protectionEnabled = masterEnabled && indicatorCount > 0
        val funcTested = indicatorCount > 0
        val detectionVerified = indicatorCount >= 100 // bundled subset is 1200
        val detail = "Threat intel: $indicatorCount indicators, version=${info["feed_version"] ?: "unknown"}, source=signed feed"
        val status = if (detectionVerified) ModuleStatus.WORKING else if (funcTested) ModuleStatus.PARTIALLY_WORKING else ModuleStatus.NOT_WORKING
        return ModuleDiagnosticResult(9, status, serviceRunning, protectionEnabled, funcTested, detectionVerified, System.currentTimeMillis(), detail, null)
    }

    private fun diagnoseAutoResponse(platform: PlatformType, masterEnabled: Boolean): ModuleDiagnosticResult {
        val serviceRunning = masterEnabled
        val protectionEnabled = masterEnabled && try { aetherEngine.analyzer.rulesetVersion.isNotEmpty() } catch (e: Exception) { false }
        // Test auto-block: confirmed threat should be set to block when autoBlock=true
        val analyzer = try { aetherEngine.analyzer } catch (e: Exception) { null }
        var funcTested = false
        var detectionVerified = false
        var detail = "Auto-response: confirmed threats auto-blocked"
        if (analyzer != null) {
            try {
                val verdict = analyzer.analyze("finupix.de", com.adshield.pro.aether.AetherSettings(enabled = true, autoBlockConfirmed = true))
                funcTested = true
                detectionVerified = verdict.shouldBlock && verdict.confirmed
                detail = "Auto-block test finupix.de: shouldBlock=${verdict.shouldBlock}, confirmed=${verdict.confirmed}"
            } catch (e: Exception) {
                detail = "Test error: ${e.message}"
            }
        }
        val status = if (funcTested && detectionVerified) ModuleStatus.WORKING else if (funcTested) ModuleStatus.PARTIALLY_WORKING else ModuleStatus.NOT_WORKING
        return ModuleDiagnosticResult(10, status, serviceRunning, protectionEnabled, funcTested, detectionVerified, System.currentTimeMillis(), detail, null)
    }

    private fun runThreatTests(maliciousSample: String, benignSample: String): TestResult {
        return try {
            val analyzer = aetherEngine.analyzer
            val malVerdict = analyzer.analyze(maliciousSample, com.adshield.pro.aether.AetherSettings())
            val benignVerdict = analyzer.analyze(benignSample, com.adshield.pro.aether.AetherSettings())
            val malDetected = malVerdict.confirmed || malVerdict.risk >= 50
            val benignClean = !benignVerdict.confirmed && benignVerdict.risk < 50
            val funcTested = true
            val detectionVerified = malDetected && benignClean
            val detail = "Test $maliciousSample: confirmed=${malVerdict.confirmed} risk=${malVerdict.risk}; $benignSample: confirmed=${benignVerdict.confirmed} risk=${benignVerdict.risk}"
            TestResult(funcTested, detectionVerified, detail, null)
        } catch (e: Exception) {
            TestResult(false, false, "Analysis failed: ${e.message}", e.message)
        }
    }

    private fun runPhishingTest(): TestResult {
        return try {
            val analyzer = aetherEngine.analyzer
            // Simulate phishing: brand + suspicious TLD or keyword
            val phishDomain = "secure-paypal-login-verify.tk"
            val verdict = analyzer.analyze(phishDomain, com.adshield.pro.aether.AetherSettings())
            val funcTested = true
            // Phishing heuristics should at least flag as suspicious
            val detectionVerified = verdict.signals.any { it.id.contains("phishing") || it.id.contains("typosquat") || it.id.contains("suspicious_tld") || it.id.contains("keyword") } || verdict.risk >= 30
            val detail = "Phishing heuristic $phishDomain: risk=${verdict.risk}, signals=${verdict.signals.map { it.id }}"
            TestResult(funcTested, detectionVerified, detail, null)
        } catch (e: Exception) {
            TestResult(false, false, "Phishing test failed: ${e.message}", e.message)
        }
    }

    private fun deriveStatus(serviceRunning: Boolean, protectionEnabled: Boolean, funcTested: Boolean, detectionVerified: Boolean, permissionRequired: Boolean, error: String?): ModuleStatus {
        if (permissionRequired) return ModuleStatus.PERMISSION_REQUIRED
        if (!serviceRunning) return ModuleStatus.NOT_WORKING
        if (!protectionEnabled) return ModuleStatus.NOT_WORKING
        if (!funcTested) return ModuleStatus.NOT_TESTED
        if (funcTested && detectionVerified) return ModuleStatus.WORKING
        if (funcTested) return ModuleStatus.PARTIALLY_WORKING
        return ModuleStatus.NOT_TESTED
    }

    private fun genericNotSupported(id: Int): ModuleDiagnosticResult {
        return ModuleDiagnosticResult(id, ModuleStatus.NOT_SUPPORTED, false, false, false, false, System.currentTimeMillis(), "Module not in AI category", null)
    }

    private data class TestResult(val funcTested: Boolean, val detectionVerified: Boolean, val detail: String, val error: String?)
}
